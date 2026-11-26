// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 7.3 (task 8): the signed
// GroupPolicy frame, its layout, its rules both ways, and signing.

#define BOOST_TEST_MODULE proto_group_policy_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "ed25519_test_support.hpp"
#include "helm/oar_protocol.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/group_policy.hpp"
#include "proto/link.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 1;
constexpr std::uint32_t sample_vni = 0x00AB'CDEF;
constexpr std::size_t off_mode = 0x14;
constexpr std::size_t off_reserved1 = 0x15;
constexpr std::size_t off_version_field = 0x18;
constexpr std::size_t off_rate_bytes = 0x28;
constexpr std::size_t off_reserved2 = 0x3E;

auto multicast() -> proto::GroupPolicy {
    return {.server_id = sample_server,
            .key_id = sample_key,
            .vni = sample_vni,
            .mode = proto::GroupMode::multicast,
            .policy_version = 7,
            .rate_frames = 1000,
            .burst_frames = 100,
            .rate_bytes = 1'250'000,
            .burst_bytes = 150'000,
            .max_remote_vteps = 64,
            .max_groups_per_nic = 0,
            .signature = {}};
}

auto drop() -> proto::GroupPolicy {
    return {.server_id = sample_server,
            .key_id = sample_key,
            .vni = sample_vni,
            .mode = proto::GroupMode::drop,
            .policy_version = 8};
}

auto encoded(const proto::GroupPolicy& p) -> std::vector<std::byte> {
    auto b = proto::encode_group_policy(p);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto r = proto::decode_group_policy(b);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto encode_error(const proto::GroupPolicy& p) -> DecodeError {
    auto r = proto::encode_group_policy(p);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto le64_at(std::span<const std::byte> b, std::size_t off) -> std::uint64_t {
    ak::wire::Reader r{b.subspan(off)};
    return r.le64().value_or(0);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(group_policy, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips) {
    for (auto p : {multicast(), drop()}) {
        p.signature.fill(std::byte{0x5A});
        const auto b = encoded(p);
        BOOST_TEST(b.size() == proto::group_policy_size);
        auto back = proto::decode_group_policy(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == p));
    }
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian) {
    const auto b = encoded(multicast());
    BOOST_TEST(std::to_integer<int>(b[0]) == 'A');
    BOOST_TEST(std::to_integer<int>(b[3]) == 'P');
    BOOST_TEST(le64_at(b, 0x08) == sample_server);
    BOOST_TEST(std::to_integer<int>(b[off_mode]) == 1);
    BOOST_TEST(le64_at(b, off_version_field) == 7U);
    BOOST_TEST(le64_at(b, off_rate_bytes) == 1'250'000U);
    BOOST_TEST(proto::group_policy_signed_bytes(b).size() == proto::group_policy_signed_size);
}

// The frame size is what OarLink carries. (The limit bounds mirror oar-net's
// vswitch.hpp group_*_max; that pin lives with the VSwitch group policy.)
BOOST_AUTO_TEST_CASE(mirrors_stay_in_step) {
    static_assert(proto::group_policy_size == ak::helm::oar::group_policy_frame_size);
    static_assert(proto::group_policy_size <= proto::max_record_payload);
    BOOST_TEST(true);
}

BOOST_AUTO_TEST_CASE(rules_are_enforced_both_ways) {
    auto p = multicast();
    p.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(p) == DecodeError::bad_key_id));
    p = multicast();
    p.server_id = 0;
    BOOST_TEST((encode_error(p) == DecodeError::bad_server_id));
    p = multicast();
    p.vni = 0;
    BOOST_TEST((encode_error(p) == DecodeError::bad_vni));
    p.vni = proto::max_vni + 1;
    BOOST_TEST((encode_error(p) == DecodeError::bad_vni));
    p = multicast();
    p.policy_version = 0;
    BOOST_TEST((encode_error(p) == DecodeError::bad_policy_version));
    p = multicast();
    p.mode = static_cast<proto::GroupMode>(2);
    BOOST_TEST((encode_error(p) == DecodeError::unknown_value));

    // multicast: every limit set and bounded; the group cap may be zero.
    for (int field = 0; field < 11; ++field) {
        p = multicast();
        switch (field) {
            case 0:
                p.rate_frames = 0;
                break;
            case 1:
                p.burst_frames = 0;
                break;
            case 2:
                p.rate_bytes = 0;
                break;
            case 3:
                p.burst_bytes = 0;
                break;
            case 4:
                p.max_remote_vteps = 0;
                break;
            case 5:
                p.rate_frames = proto::max_group_rate_frames + 1;
                break;
            case 6:
                p.burst_frames = proto::max_group_burst_frames + 1;
                break;
            case 7:
                p.rate_bytes = proto::max_group_rate_bytes + 1;
                break;
            case 8:
                p.burst_bytes = proto::max_group_burst_bytes + 1;
                break;
            case 9:
                p.max_remote_vteps = proto::max_group_remote_vteps + 1;
                break;
            default:
                p.max_groups_per_nic = proto::max_group_groups_per_nic + 1;
                break;
        }
        BOOST_TEST((encode_error(p) == DecodeError::bad_group_limits));
    }
    p = multicast();
    p.max_groups_per_nic = proto::max_group_groups_per_nic;
    BOOST_TEST(proto::encode_group_policy(p).has_value());
    // drop: no limits at all.
    p = drop();
    p.max_groups_per_nic = 1;
    BOOST_TEST((encode_error(p) == DecodeError::bad_group_limits));
    p = drop();
    p.rate_frames = 1;
    BOOST_TEST((encode_error(p) == DecodeError::bad_group_limits));

    // The decoder applies the same rules to bytes.
    auto b = encoded(drop());
    b[off_mode] = std::byte{1};  // multicast with zero limits
    BOOST_TEST((decode_error(b) == DecodeError::bad_group_limits));
    b = encoded(multicast());
    b[off_mode] = std::byte{9};
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
}

BOOST_AUTO_TEST_CASE(strict_framing) {
    const auto good = encoded(multicast());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((decode_error(longer) == DecodeError::trailing_bytes));
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{3};  // version 2 is the per-subnet layout
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    for (const std::size_t off :
         {off_reserved1, off_reserved1 + 2, off_reserved2, off_reserved2 + 1}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    }
}

// Signed like the controller signs it, verified like oar-net verifies it:
// every byte before the signature is covered.
BOOST_AUTO_TEST_CASE(signature_covers_the_policy) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(sample_key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());

    auto frame = encoded(multicast());
    proto::set_group_policy_signature(frame, signer.sign(proto::group_policy_signed_bytes(frame)));
    const auto decoded = proto::decode_group_policy(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(
        verifier
            ->verify(proto::group_policy_signed_bytes(frame), decoded->signature, decoded->key_id)
            .has_value());

    // Raising the rate after signing breaks it.
    frame[off_rate_bytes + 1] ^= std::byte{0x01};
    const auto tampered = proto::decode_group_policy(frame);
    BOOST_REQUIRE(tampered.has_value());
    BOOST_TEST(!verifier
                    ->verify(proto::group_policy_signed_bytes(frame), tampered->signature,
                             tampered->key_id)
                    .has_value());
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_policy_version, DecodeError::bad_group_limits}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()

// .kiro/specs/vpc-subnets-routing/ task 12: version 2, one entry per
// opted-in subnet.
namespace {

constexpr std::size_t v2_entries = 0x20;
constexpr std::size_t v2_count = 0x14;

auto limits(std::uint64_t subnet) -> proto::GroupSubnetLimits {
    return {.subnet_id = subnet,
            .rate_frames = 1000,
            .burst_frames = 100,
            .rate_bytes = 1'250'000,
            .burst_bytes = 150'000,
            .max_remote_vteps = 16,
            .max_groups_per_nic = 8};
}

auto per_subnet(std::vector<proto::GroupSubnetLimits> subnets) -> proto::GroupPolicy {
    return {.server_id = sample_server,
            .key_id = sample_key,
            .vni = sample_vni,
            .mode = proto::GroupMode::drop,
            .policy_version = 9,
            .signature = {},
            .format = proto::group_policy_version_subnets,
            .subnets = std::move(subnets)};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(group_policy_v2, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_from_none_to_every_subnet) {
    std::vector<proto::GroupSubnetLimits> all;
    for (std::uint64_t s = 1; s <= proto::max_group_policy_subnets; ++s) {
        all.push_back(limits(s));
    }
    for (auto p : {per_subnet({}), per_subnet({limits(0x5A01), limits(0x5A03)}), per_subnet(all)}) {
        p.signature.fill(std::byte{0x5A});
        const auto b = encoded(p);
        BOOST_TEST(b.size() == proto::min_group_policy_v2_size +
                                   (p.subnets.size() * proto::group_policy_entry_size));
        BOOST_TEST(b.size() <= proto::max_group_policy_size);
        auto back = proto::decode_group_policy(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == p));
        BOOST_TEST(proto::group_policy_signed_bytes(b).size() == b.size() - 64);
    }
    BOOST_TEST(proto::max_group_policy_size == 8096U);
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian) {
    const auto b = encoded(per_subnet({limits(0x5A01), limits(0x5A03)}));
    BOOST_TEST(std::to_integer<int>(b[4]) == 2);
    BOOST_TEST(std::to_integer<int>(b[v2_count]) == 2);
    BOOST_TEST(le64_at(b, off_version_field) == 9U);
    BOOST_TEST(le64_at(b, v2_entries) == 0x5A01U);
    BOOST_TEST(le64_at(b, v2_entries + 0x10) == 1'250'000U);
    BOOST_TEST(le64_at(b, v2_entries + proto::group_policy_entry_size) == 0x5A03U);
    BOOST_TEST(std::to_integer<int>(b[v2_entries + 0x24]) == 8);
}

BOOST_AUTO_TEST_CASE(rules_hold_both_ways) {
    // Each broken policy is refused by the encoder, and the same bytes
    // (patched from a good frame) by the decoder.
    BOOST_TEST((encode_error(per_subnet({limits(0)})) == DecodeError::bad_id));
    BOOST_TEST((encode_error(per_subnet({limits(2), limits(1)})) == DecodeError::not_ascending));
    BOOST_TEST((encode_error(per_subnet({limits(2), limits(2)})) == DecodeError::not_ascending));
    auto zero_rate = limits(1);
    zero_rate.rate_frames = 0;
    BOOST_TEST((encode_error(per_subnet({zero_rate})) == DecodeError::bad_group_limits));
    auto too_many_groups = limits(1);
    too_many_groups.max_groups_per_nic = proto::max_group_groups_per_nic + 1;
    BOOST_TEST((encode_error(per_subnet({too_many_groups})) == DecodeError::bad_group_limits));
    auto vpc_wide = per_subnet({});
    vpc_wide.mode = proto::GroupMode::multicast;
    BOOST_TEST((encode_error(vpc_wide) == DecodeError::bad_group_limits));
    auto v1_with_subnets = multicast();
    v1_with_subnets.subnets = {limits(1)};
    BOOST_TEST((encode_error(v1_with_subnets) == DecodeError::bad_group_limits));
    auto format3 = per_subnet({});
    format3.format = 3;
    BOOST_TEST((encode_error(format3) == DecodeError::bad_version));
    std::vector<proto::GroupSubnetLimits> over;
    for (std::uint64_t s = 1; s <= proto::max_group_policy_subnets + 1; ++s) {
        over.push_back(limits(s));
    }
    BOOST_TEST((encode_error(per_subnet(over)) == DecodeError::too_many_entries));

    const auto good = encoded(per_subnet({limits(1), limits(2)}));
    auto b = good;
    b[v2_entries] = std::byte{0};  // subnet 1 becomes 0
    BOOST_TEST((decode_error(b) == DecodeError::bad_id));
    b = good;
    b[v2_entries + proto::group_policy_entry_size] = std::byte{1};  // 2 becomes 1
    BOOST_TEST((decode_error(b) == DecodeError::not_ascending));
    b = good;
    b[v2_entries + 0x08] = std::byte{0};  // rate_frames 1000 becomes 0
    b[v2_entries + 0x09] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_group_limits));
    b = good;
    b[v2_count] = std::byte{201};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    for (const std::size_t off : {std::size_t{0x16}, v2_entries + 0x26, v2_entries + 0x27}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    }
}

BOOST_AUTO_TEST_CASE(strict_framing) {
    const auto good = encoded(per_subnet({limits(1), limits(2)}));
    for (std::size_t n = 6; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((decode_error(longer) == DecodeError::trailing_bytes));
    // One entry fewer than the count claims is short by an entry.
    auto b = good;
    b[v2_count] = std::byte{3};
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(signature_covers_every_entry) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(sample_key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());
    auto frame = encoded(per_subnet({limits(1), limits(2)}));
    proto::set_group_policy_signature(frame, signer.sign(proto::group_policy_signed_bytes(frame)));
    const auto decoded = proto::decode_group_policy(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(
        verifier
            ->verify(proto::group_policy_signed_bytes(frame), decoded->signature, decoded->key_id)
            .has_value());
    // The last entry's byte rate, raised after signing.
    frame[v2_entries + proto::group_policy_entry_size + 0x11] ^= std::byte{0x01};
    const auto tampered = proto::decode_group_policy(frame);
    BOOST_REQUIRE(tampered.has_value());
    BOOST_TEST(!verifier
                    ->verify(proto::group_policy_signed_bytes(frame), tampered->signature,
                             tampered->key_id)
                    .has_value());
}

BOOST_AUTO_TEST_SUITE_END()
