// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 7.9 (task 15): the signed
// GroupMembers frame, its layout, its rules both ways, and signing.

#define BOOST_TEST_MODULE proto_group_members_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "ed25519_test_support.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/group_members.hpp"
#include "proto/link.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using proto::RouteFamily;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 1;
constexpr std::uint32_t sample_vni = 0x00AB'CDEF;
constexpr std::size_t off_group_count = 0x14;
constexpr std::size_t off_reserved = 0x16;
constexpr std::size_t off_groups = 0x20;

auto vtep(std::uint8_t last) -> proto::Ipv6Address {
    proto::Ipv6Address a{};
    a[0] = std::byte{0xFD};
    a[15] = std::byte{last};
    return a;
}

auto group4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> proto::Ipv6Address {
    proto::Ipv6Address g{};
    g[0] = std::byte{a};
    g[1] = std::byte{b};
    g[2] = std::byte{c};
    g[3] = std::byte{d};
    return g;
}

auto group6(std::uint8_t scope, std::uint8_t last) -> proto::Ipv6Address {
    proto::Ipv6Address g{};
    g[0] = std::byte{0xFF};
    g[1] = std::byte{scope};
    g[15] = std::byte{last};
    return g;
}

auto sample() -> proto::GroupMembers {
    proto::GroupMembers m{};
    m.server_id = sample_server;
    m.key_id = sample_key;
    m.vni = sample_vni;
    m.members_version = 9;
    m.groups = {
        {.family = RouteFamily::ipv4, .group = group4(224, 0, 0, 251), .vteps = {vtep(1)}},
        {.family = RouteFamily::ipv4,
         .group = group4(239, 1, 2, 3),
         .vteps = {vtep(1), vtep(2), vtep(3)}},
        {.family = RouteFamily::ipv6, .group = group6(0x05, 0x42), .vteps = {vtep(2)}},
    };
    return m;
}

auto encoded(const proto::GroupMembers& m) -> std::vector<std::byte> {
    auto b = proto::encode_group_members(m);
    BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : proto::to_string(b.error())));
    return *b;
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto r = proto::decode_group_members(b);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto encode_error(const proto::GroupMembers& m) -> DecodeError {
    auto r = proto::encode_group_members(m);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(group_members, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(layout) {
    static_assert(proto::min_group_members_size == 96);
    static_assert(proto::max_group_members_size == 77'920);
    static_assert(proto::max_group_members_size <= proto::max_record_payload);
    const auto b = encoded(sample());
    BOOST_REQUIRE_EQUAL(b.size(), proto::group_members_size(3, 5));
    const auto header = ak::test::bytes_of('A', 'K', 'G', 'M', 0x01, 0x00, 0x01, 0x00, 0x08, 0x07,
                                           0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xEF, 0xCD, 0xAB,
                                           0x00, 0x03, 0x00, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0, 0, 0);
    BOOST_TEST(std::ranges::equal(std::span{b}.first(proto::group_members_header_size), header));
    // The first group: IPv4 224.0.0.251 with one VTEP.
    const auto g = ak::test::bytes_of(4, 1, 0, 0, 0, 0, 0, 0, 224, 0, 0, 251, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0);
    BOOST_TEST(std::ranges::equal(std::span{b}.subspan(off_groups, proto::member_group_size), g));
    const auto v = vtep(1);
    BOOST_TEST(std::ranges::equal(
        std::span{b}.subspan(off_groups + proto::member_group_size, proto::vtep_address_size), v));
}

BOOST_AUTO_TEST_CASE(round_trips_including_empty) {
    for (auto m : {sample(), proto::GroupMembers{
                                 .server_id = 1, .key_id = 2, .vni = 3, .members_version = 1}}) {
        m.signature[0] = std::byte{0x5A};
        const auto b = encoded(m);
        const auto back = proto::decode_group_members(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == m));
        BOOST_TEST((encoded(*back) == b));
    }
}

BOOST_AUTO_TEST_CASE(largest_frame_round_trips) {
    // 64 groups of 64 VTEPs fill the frame's VTEP budget exactly.
    proto::GroupMembers m = sample();
    m.groups.clear();
    constexpr std::size_t full_groups = proto::max_member_vteps / proto::max_group_vteps;
    for (std::size_t i = 0; i < full_groups; ++i) {
        proto::MemberGroup g{.family = RouteFamily::ipv4,
                             .group = group4(239, 0, 0, static_cast<std::uint8_t>(i)),
                             .vteps = {}};
        for (std::size_t v = 0; v < proto::max_group_vteps; ++v) {
            g.vteps.push_back(vtep(static_cast<std::uint8_t>(v + 1)));
        }
        m.groups.push_back(g);
    }
    const auto b = encoded(m);
    BOOST_TEST(b.size() == proto::group_members_size(full_groups, proto::max_member_vteps));
    BOOST_TEST(proto::decode_group_members(b).has_value());
    // One VTEP more is too many, in either direction.
    m.groups.push_back({.family = RouteFamily::ipv6, .group = group6(0x05, 1), .vteps = {vtep(1)}});
    BOOST_TEST((encode_error(m) == DecodeError::too_many_entries));
    m.groups.pop_back();
    m.groups[0].vteps.push_back(vtep(200));
    BOOST_TEST((encode_error(m) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(rules_both_ways) {
    auto m = sample();
    m.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(m) == DecodeError::bad_key_id));
    m = sample();
    m.server_id = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_server_id));
    m = sample();
    m.vni = proto::max_vni + 1;
    BOOST_TEST((encode_error(m) == DecodeError::bad_vni));
    m = sample();
    m.members_version = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_members_version));
    m = sample();
    m.groups[0].group = group4(10, 0, 0, 1);  // unicast
    BOOST_TEST((encode_error(m) == DecodeError::bad_group));
    m = sample();
    m.groups[0].group = group4(240, 0, 0, 1);  // class E
    BOOST_TEST((encode_error(m) == DecodeError::bad_group));
    m = sample();
    m.groups[0].group[4] = std::byte{1};  // IPv4 with trailing bytes
    BOOST_TEST((encode_error(m) == DecodeError::bad_group));
    m = sample();
    m.groups[2].group = group6(0x02, 0x42);
    m.groups[2].group[11] = std::byte{0x01};
    m.groups[2].group[12] = std::byte{0xFF};  // solicited-node
    BOOST_TEST((encode_error(m) == DecodeError::bad_group));
    m = sample();
    m.groups[2].group[0] = std::byte{0xFE};  // not multicast
    BOOST_TEST((encode_error(m) == DecodeError::bad_group));
    m = sample();
    std::swap(m.groups[0], m.groups[1]);
    BOOST_TEST((encode_error(m) == DecodeError::not_ascending));
    m = sample();
    m.groups[1] = m.groups[0];  // twice
    BOOST_TEST((encode_error(m) == DecodeError::not_ascending));
    m = sample();
    m.groups[1].vteps = {vtep(2), vtep(1)};
    BOOST_TEST((encode_error(m) == DecodeError::not_ascending));
    m = sample();
    m.groups[1].vteps = {vtep(2), vtep(2)};
    BOOST_TEST((encode_error(m) == DecodeError::not_ascending));
    m = sample();
    m.groups[1].vteps.clear();
    BOOST_TEST((encode_error(m) == DecodeError::too_many_entries));
    m = sample();
    m.groups[1].vteps = {proto::Ipv6Address{}};
    BOOST_TEST((encode_error(m) == DecodeError::bad_vtep));
    m = sample();
    m.groups[1].vteps = {group6(0x05, 1)};  // multicast VTEP
    BOOST_TEST((encode_error(m) == DecodeError::bad_vtep));
    m = sample();
    m.groups[1].family = static_cast<RouteFamily>(5);
    BOOST_TEST((encode_error(m) == DecodeError::unknown_value));
}

BOOST_AUTO_TEST_CASE(strict_decode) {
    const auto good = encoded(sample());
    BOOST_REQUIRE(proto::decode_group_members(good).has_value());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
    b = good;
    b[0] = std::byte{'X'};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    b = good;
    b[off_reserved] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_groups + 2] = std::byte{1};  // a group's reserved bytes
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_group_count] = std::byte{0x01};
    b[off_group_count + 1] = std::byte{0x02};  // 513
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    b[off_groups + 1] = std::byte{65};  // vtep_count
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    std::vector<std::byte> huge(proto::max_group_members_size + 1);
    BOOST_TEST((decode_error(huge) == DecodeError::trailing_bytes));
}

// Signed like the controller signs it, verified like oar-net verifies it.
BOOST_AUTO_TEST_CASE(signature_covers_the_lists) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(sample_key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());

    auto frame = encoded(sample());
    proto::set_group_members_signature(frame,
                                       signer.sign(proto::group_members_signed_bytes(frame)));
    const auto decoded = proto::decode_group_members(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(
        verifier
            ->verify(proto::group_members_signed_bytes(frame), decoded->signature, decoded->key_id)
            .has_value());
    // Adding a VTEP to a group after signing breaks it.
    auto tampered = frame;
    tampered[off_groups + proto::member_group_size + 15] = std::byte{9};
    const auto t = proto::decode_group_members(tampered);
    BOOST_REQUIRE(t.has_value());
    BOOST_TEST(
        !verifier->verify(proto::group_members_signed_bytes(tampered), t->signature, t->key_id)
             .has_value());
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_members_version, DecodeError::bad_group}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
