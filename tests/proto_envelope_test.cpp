// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 1 and design "Envelope":
// the envelope codec, its strict decode, and its agreement with the
// mailbox slot layout it wraps.

#define BOOST_TEST_MODULE proto_envelope_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "helm/mailbox.hpp"
#include "proto/envelope.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 0x0A0B;
constexpr std::uint64_t sample_seq = 0x1122'3344'5566'7788;
constexpr std::uint8_t sig_fill = 0xEE;

// A command slot as hull would see it (signature bytes are filler: the
// envelope never verifies).
auto sample_slot() -> proto::Slot {
    const mb::Header h{.type = mb::Type::list_vms, .seq = sample_seq, .key_id = sample_key};
    std::array<std::byte, mb::signature_size> sig{};
    sig.fill(std::byte{sig_fill});
    auto slot = mb::encode(h, {}, sig);
    BOOST_REQUIRE(slot.has_value());
    return *slot;
}

auto sample_envelope() -> proto::Envelope {
    return {.server_id = sample_server, .key_id = sample_key, .slot = sample_slot()};
}

auto encoded() -> std::vector<std::byte> {
    auto bytes = proto::encode_envelope(sample_envelope());
    BOOST_REQUIRE(bytes.has_value());
    return {bytes->begin(), bytes->end()};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(envelope, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(slot_geometry_matches_the_mailbox) {
    static_assert(proto::slot_size == mb::slot_size);
    static_assert(proto::slot_key_id_offset == mb::header_key_id_offset);
    static_assert(proto::slot_signed_size == mb::signature_offset);
    static_assert(std::is_same_v<proto::KeyId, mb::KeyId>);
    static_assert(proto::no_key_id == mb::no_key_id);
    static_assert(proto::envelope_size == 272);
    const auto slot = sample_slot();
    BOOST_TEST(proto::slot_key_id(slot) == sample_key);
    BOOST_TEST(proto::slot_seq(slot) == sample_seq);
    BOOST_TEST(proto::slot_signed_bytes(slot).data() == slot.data());
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian_header_then_slot) {
    const auto bytes = encoded();
    BOOST_REQUIRE_EQUAL(bytes.size(), proto::envelope_size);
    const auto expect = ak::test::bytes_of('A', 'K', 'E', 'V', 0x01, 0x00, 0x0B, 0x0A, 0x08, 0x07,
                                           0x06, 0x05, 0x04, 0x03, 0x02, 0x01);
    BOOST_TEST(std::ranges::equal(std::span{bytes}.first(proto::envelope_header_size), expect));
    const auto slot = sample_slot();
    BOOST_TEST(std::ranges::equal(std::span{bytes}.subspan(proto::envelope_header_size), slot));
}

BOOST_AUTO_TEST_CASE(round_trips) {
    const auto bytes = encoded();
    auto env = proto::decode_envelope(bytes);
    BOOST_REQUIRE(env.has_value());
    BOOST_TEST((*env == sample_envelope()));
    auto again = proto::encode_envelope(*env);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(std::ranges::equal(*again, bytes));
}

BOOST_AUTO_TEST_CASE(every_short_length_is_truncated) {
    const auto bytes = encoded();
    for (std::size_t n = 0; n < bytes.size(); ++n) {
        auto env = proto::decode_envelope(std::span{bytes}.first(n));
        BOOST_REQUIRE(!env.has_value());
        BOOST_TEST((env.error() == DecodeError::truncated), "length " << n);
    }
}

BOOST_AUTO_TEST_CASE(trailing_bytes_are_rejected) {
    auto bytes = encoded();
    bytes.push_back(std::byte{0});
    auto env = proto::decode_envelope(bytes);
    BOOST_REQUIRE(!env.has_value());
    BOOST_TEST((env.error() == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(bad_magic_and_version_are_rejected) {
    auto bytes = encoded();
    bytes[0] = std::byte{'B'};
    BOOST_TEST((proto::decode_envelope(bytes).error() == DecodeError::bad_magic));

    for (const std::uint8_t v : std::array<std::uint8_t, 3>{0, 2, 0xFF}) {
        bytes = encoded();
        bytes[4] = std::byte{v};
        BOOST_TEST((proto::decode_envelope(bytes).error() == DecodeError::bad_version));
    }
}

BOOST_AUTO_TEST_CASE(key_and_server_id_zero_are_rejected) {
    auto env = sample_envelope();
    env.key_id = proto::no_key_id;
    env.slot[proto::slot_key_id_offset] = std::byte{0};
    env.slot[proto::slot_key_id_offset + 1] = std::byte{0};
    // No key at all: rejected before the slot comparison.
    BOOST_TEST((proto::encode_envelope(env).error() == DecodeError::bad_key_id));

    env = sample_envelope();
    env.server_id = 0;
    BOOST_TEST((proto::encode_envelope(env).error() == DecodeError::bad_server_id));

    auto bytes = encoded();
    bytes[6] = std::byte{0};
    bytes[7] = std::byte{0};
    BOOST_TEST((proto::decode_envelope(bytes).error() == DecodeError::bad_key_id));

    bytes = encoded();
    std::fill_n(bytes.begin() + 8, 8, std::byte{0});
    BOOST_TEST((proto::decode_envelope(bytes).error() == DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_CASE(envelope_key_must_match_slot_key) {
    auto env = sample_envelope();
    env.key_id = sample_key + 1;
    BOOST_TEST((proto::encode_envelope(env).error() == DecodeError::key_id_mismatch));

    // Rewriting only the slot's key ID (as a tampering relay might) ...
    auto bytes = encoded();
    bytes[proto::envelope_header_size + proto::slot_key_id_offset] ^= std::byte{1};
    BOOST_TEST((proto::decode_envelope(bytes).error() == DecodeError::key_id_mismatch));
    // ... or only the envelope's.
    bytes = encoded();
    bytes[6] ^= std::byte{1};
    BOOST_TEST((proto::decode_envelope(bytes).error() == DecodeError::key_id_mismatch));
}

BOOST_AUTO_TEST_CASE(slot_contents_pass_through_unparsed) {
    // helm relays the slot as-is: the envelope does not judge it, so even a
    // slot hull would reject (here, bad slot magic) survives a round trip
    // byte for byte, and hull is the one that refuses it.
    auto env = sample_envelope();
    env.slot[0] = std::byte{0};
    auto bytes = proto::encode_envelope(env);
    BOOST_REQUIRE(bytes.has_value());
    auto back = proto::decode_envelope(*bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->slot == env.slot));
    BOOST_TEST(!mb::decode(mb::Slot{back->slot}).has_value());
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e = static_cast<std::uint8_t>(DecodeError::truncated);
         e <= static_cast<std::uint8_t>(DecodeError::bad_vtep); ++e) {
        BOOST_TEST(std::string_view{proto::to_string(static_cast<DecodeError>(e))} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
