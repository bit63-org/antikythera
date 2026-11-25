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
    b[4] = std::byte{2};
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
