// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/fleet-scale-networking/ Requirements 2 and 3, design "VTEP
// credentials": the VtepCredential and CredentialRevocations codecs, their
// layouts, their signed bytes, and their strict decode.

#define BOOST_TEST_MODULE proto_vtep_credential_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>
#include <algorithm>

#include "proto/vtep_credential.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::size_t last = 15;

auto vtep(std::uint8_t tag) -> proto::VtepAddress {
    proto::VtepAddress a{};
    a[0] = std::byte{ula_prefix};
    a[last] = std::byte{tag};
    return a;
}

auto sample() -> proto::VtepCredential {
    proto::VtepCredential c{.key_id = 3,
                            .server_id = sample_server,
                            .cell_id = 7,
                            .modes = proto::tunnel_mode_bit(proto::TunnelMode::wireguard),
                            .slot = 2,
                            .key_epoch = 4,
                            .vtep = vtep(1),
                            .public_key = {},
                            .not_before = 1'000,
                            .not_after = 87'400,
                            .serial = 42,
                            .signature = {}};
    c.public_key.fill(std::byte{0x22});
    c.signature.fill(std::byte{0x5A});
    return c;
}

auto sample_list() -> proto::CredentialRevocations {
    proto::CredentialRevocations l{
        .key_id = 3,
        .cell_id = 7,
        .list_version = 9,
        .entries = {{.serial = 5, .not_after = 100}, {.serial = 11, .not_after = 200}},
        .signature = {}};
    l.signature.fill(std::byte{0x6B});
    return l;
}

auto le_at(const std::vector<std::byte>& b, std::size_t off, std::size_t n) -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        v |= std::to_integer<std::uint64_t>(b[off + i]) << (8 * i);
    }
    return v;
}

auto put_le(std::vector<std::byte>& b, std::size_t off, std::size_t n, std::uint64_t v) -> void {
    for (std::size_t i = 0; i < n; ++i) {
        b[off + i] = static_cast<std::byte>((v >> (8 * i)) & 0xFF);
    }
}

auto encoded(const proto::VtepCredential& c) -> std::vector<std::byte> {
    auto b = proto::encode_vtep_credential(c);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto encoded(const proto::CredentialRevocations& l) -> std::vector<std::byte> {
    auto b = proto::encode_credential_revocations(l);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto credential_error(std::span<const std::byte> b) -> DecodeError {
    auto c = proto::decode_vtep_credential(b);
    BOOST_REQUIRE(!c.has_value());
    return c.error();
}

auto list_error(std::span<const std::byte> b) -> DecodeError {
    auto l = proto::decode_credential_revocations(b);
    BOOST_REQUIRE(!l.has_value());
    return l.error();
}

auto encode_error(const proto::VtepCredential& c) -> DecodeError {
    auto b = proto::encode_vtep_credential(c);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto encode_error(const proto::CredentialRevocations& l) -> DecodeError {
    auto b = proto::encode_credential_revocations(l);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(credential_layout_is_pinned,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    const auto b = encoded(sample());
    BOOST_REQUIRE(b.size() == proto::vtep_credential_size);
    BOOST_TEST(le_at(b, 0x00, 4) == 0x4356'4B41U);  // "AKVC"
    BOOST_TEST(std::to_integer<char>(b[0]) == 'A');
    BOOST_TEST(le_at(b, 0x04, 2) == 1U);
    BOOST_TEST(le_at(b, 0x06, 2) == 3U);
    BOOST_TEST(le_at(b, 0x08, 8) == sample_server);
    BOOST_TEST(le_at(b, 0x10, 4) == 7U);
    BOOST_TEST(le_at(b, 0x14, 1) == 1U);
    BOOST_TEST(le_at(b, 0x15, 1) == 2U);
    BOOST_TEST(le_at(b, 0x16, 2) == 4U);
    BOOST_TEST(std::to_integer<int>(b[0x18]) == ula_prefix);
    BOOST_TEST(std::to_integer<int>(b[0x18 + last]) == 1);
    BOOST_TEST(std::to_integer<int>(b[0x28]) == 0x22);
    BOOST_TEST(std::to_integer<int>(b[0x47]) == 0x22);
    BOOST_TEST(le_at(b, 0x48, 8) == 1'000U);
    BOOST_TEST(le_at(b, 0x50, 8) == 87'400U);
    BOOST_TEST(le_at(b, 0x58, 8) == 42U);
    BOOST_TEST(std::to_integer<int>(b[0x60]) == 0x5A);
    BOOST_TEST(std::to_integer<int>(b[0x9F]) == 0x5A);
    BOOST_TEST(proto::credential_signed_bytes(b).size() == 0x60U);
}

BOOST_AUTO_TEST_CASE(credential_round_trips,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    auto c = sample();
    c.modes = proto::tunnel_mode_bit(proto::TunnelMode::wireguard) |
              proto::tunnel_mode_bit(proto::TunnelMode::psp);
    c.cell_id = 0;
    const auto b = encoded(c);
    auto d = proto::decode_vtep_credential(b);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((*d == c));
    BOOST_TEST((encoded(*d) == b));
}

BOOST_AUTO_TEST_CASE(set_signature_fills_the_trailing_bytes,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    auto b = encoded(sample());
    std::array<std::byte, proto::ed25519_signature_size> sig{};
    sig.fill(std::byte{0x77});
    proto::set_credential_signature(b, sig);
    auto d = proto::decode_vtep_credential(b);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((d->signature == sig));
}

BOOST_AUTO_TEST_CASE(credential_decode_is_strict,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    const auto good = encoded(sample());
    // Every truncation, and a trailing byte.
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((credential_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((credential_error(longer) == DecodeError::trailing_bytes));

    const auto with = [&good](std::size_t off, std::size_t n, std::uint64_t v) {
        auto b = good;
        put_le(b, off, n, v);
        return b;
    };
    BOOST_TEST((credential_error(with(0x00, 4, 0x4356'4B42)) == DecodeError::bad_magic));
    BOOST_TEST((credential_error(with(0x04, 2, 2)) == DecodeError::bad_version));
    BOOST_TEST((credential_error(with(0x06, 2, 0)) == DecodeError::bad_key_id));
    BOOST_TEST((credential_error(with(0x08, 8, 0)) == DecodeError::bad_server_id));
    BOOST_TEST((credential_error(with(0x14, 1, 0)) == DecodeError::unknown_value));
    BOOST_TEST((credential_error(with(0x14, 1, 0x81)) == DecodeError::unknown_value));
    BOOST_TEST((credential_error(with(0x16, 2, 0)) == DecodeError::bad_id));
    BOOST_TEST((credential_error(with(0x58, 8, 0)) == DecodeError::bad_id));
    // A multicast and an all-zero VTEP.
    BOOST_TEST((credential_error(with(0x18, 1, 0xFF)) == DecodeError::bad_vtep));
    auto zero_vtep = good;
    std::fill_n(zero_vtep.begin() + 0x18, proto::vtep_address_size, std::byte{0});
    BOOST_TEST((credential_error(zero_vtep) == DecodeError::bad_vtep));
    auto zero_key = good;
    std::fill_n(zero_key.begin() + 0x28, proto::tunnel_key_size, std::byte{0});
    BOOST_TEST((credential_error(zero_key) == DecodeError::bad_public_key));
    // not_before == not_after and not_before > not_after.
    BOOST_TEST((credential_error(with(0x48, 8, 87'400)) == DecodeError::bad_validity));
    BOOST_TEST((credential_error(with(0x48, 8, 90'000)) == DecodeError::bad_validity));
}

BOOST_AUTO_TEST_CASE(credential_encode_enforces_the_decoder_rules,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    auto c = sample();
    c.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(c) == DecodeError::bad_key_id));
    c = sample();
    c.server_id = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_server_id));
    c = sample();
    c.modes = 0;
    BOOST_TEST((encode_error(c) == DecodeError::unknown_value));
    c = sample();
    c.key_epoch = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_id));
    c = sample();
    c.serial = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_id));
    c = sample();
    c.vtep = {};
    BOOST_TEST((encode_error(c) == DecodeError::bad_vtep));
    c = sample();
    c.public_key = {};
    BOOST_TEST((encode_error(c) == DecodeError::bad_public_key));
    c = sample();
    c.not_after = c.not_before;
    BOOST_TEST((encode_error(c) == DecodeError::bad_validity));
}

BOOST_AUTO_TEST_CASE(revocations_layout_is_pinned,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    const auto b = encoded(sample_list());
    BOOST_REQUIRE(b.size() == proto::credential_revocations_size(2));
    BOOST_TEST(b.size() == 0x20U + (2 * 16) + 64);
    BOOST_TEST(le_at(b, 0x00, 4) == 0x5243'4B41U);  // "AKCR"
    BOOST_TEST(le_at(b, 0x04, 2) == 1U);
    BOOST_TEST(le_at(b, 0x06, 2) == 3U);
    BOOST_TEST(le_at(b, 0x08, 4) == 7U);
    BOOST_TEST(le_at(b, 0x0C, 4) == 0U);
    BOOST_TEST(le_at(b, 0x10, 8) == 9U);
    BOOST_TEST(le_at(b, 0x18, 4) == 2U);
    BOOST_TEST(le_at(b, 0x1C, 4) == 0U);
    BOOST_TEST(le_at(b, 0x20, 8) == 5U);
    BOOST_TEST(le_at(b, 0x28, 8) == 100U);
    BOOST_TEST(le_at(b, 0x30, 8) == 11U);
    BOOST_TEST(le_at(b, 0x38, 8) == 200U);
    BOOST_TEST(std::to_integer<int>(b[0x40]) == 0x6B);
    BOOST_TEST(proto::credential_signed_bytes(b).size() == 0x40U);
    BOOST_TEST(proto::max_credential_revocations_size ==
               proto::credential_revocations_size(proto::max_revocations));
}

BOOST_AUTO_TEST_CASE(revocations_round_trip,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    for (const auto& l :
         {sample_list(),
          proto::CredentialRevocations{
              .key_id = 1, .cell_id = 0, .list_version = 1, .entries = {}, .signature = {}}}) {
        const auto b = encoded(l);
        auto d = proto::decode_credential_revocations(b);
        BOOST_REQUIRE(d.has_value());
        BOOST_TEST((*d == l));
        BOOST_TEST((encoded(*d) == b));
    }
}

BOOST_AUTO_TEST_CASE(a_full_list_round_trips,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    auto l = sample_list();
    l.entries.clear();
    for (std::uint64_t i = 1; i <= proto::max_revocations; ++i) {
        l.entries.push_back({.serial = i * 3, .not_after = i});
    }
    const auto b = encoded(l);
    BOOST_TEST(b.size() == proto::max_credential_revocations_size);
    auto d = proto::decode_credential_revocations(b);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((*d == l));
    l.entries.push_back({.serial = (proto::max_revocations + 1) * 3, .not_after = 1});
    BOOST_TEST((encode_error(l) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(revocations_decode_is_strict,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    const auto good = encoded(sample_list());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((list_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((list_error(longer) == DecodeError::trailing_bytes));

    const auto with = [&good](std::size_t off, std::size_t n, std::uint64_t v) {
        auto b = good;
        put_le(b, off, n, v);
        return b;
    };
    BOOST_TEST((list_error(with(0x00, 4, 0)) == DecodeError::bad_magic));
    BOOST_TEST((list_error(with(0x04, 2, 2)) == DecodeError::bad_version));
    BOOST_TEST((list_error(with(0x06, 2, 0)) == DecodeError::bad_key_id));
    BOOST_TEST((list_error(with(0x0C, 4, 1)) == DecodeError::reserved_not_zero));
    BOOST_TEST((list_error(with(0x1C, 4, 1)) == DecodeError::reserved_not_zero));
    BOOST_TEST((list_error(with(0x10, 8, 0)) == DecodeError::bad_list_version));
    // A count that disagrees with the length, and a hostile count.
    BOOST_TEST((list_error(with(0x18, 4, 3)) == DecodeError::truncated));
    BOOST_TEST((list_error(with(0x18, 4, 1)) == DecodeError::trailing_bytes));
    BOOST_TEST(
        (list_error(with(0x18, 4, proto::max_revocations + 1)) == DecodeError::too_many_entries));
    BOOST_TEST((list_error(with(0x18, 4, 0xFFFF'FFFF)) == DecodeError::too_many_entries));
    // Serial zero, a repeat, and a descent.
    BOOST_TEST((list_error(with(0x20, 8, 0)) == DecodeError::bad_id));
    BOOST_TEST((list_error(with(0x30, 8, 5)) == DecodeError::not_ascending));
    BOOST_TEST((list_error(with(0x30, 8, 4)) == DecodeError::not_ascending));
}

BOOST_AUTO_TEST_CASE(revocations_encode_enforces_the_decoder_rules,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    auto l = sample_list();
    l.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(l) == DecodeError::bad_key_id));
    l = sample_list();
    l.list_version = 0;
    BOOST_TEST((encode_error(l) == DecodeError::bad_list_version));
    l = sample_list();
    l.entries[0].serial = 0;
    BOOST_TEST((encode_error(l) == DecodeError::bad_id));
    l = sample_list();
    l.entries[1].serial = l.entries[0].serial;
    BOOST_TEST((encode_error(l) == DecodeError::not_ascending));
}

BOOST_AUTO_TEST_CASE(new_errors_have_names,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    BOOST_TEST(std::string_view{proto::to_string(DecodeError::bad_validity)} ==
               "credential validity window is empty");
    BOOST_TEST(std::string_view{proto::to_string(DecodeError::bad_list_version)} ==
               "revocation list version is zero");
}
