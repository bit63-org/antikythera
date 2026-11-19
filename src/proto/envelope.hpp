// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Envelope: one signed mailbox command addressed to one server's helm
// (.kiro/specs/controller-interface/ Requirement 1, design "Envelope").
//
// The controller builds the exact 256-byte mailbox slot image, signs its
// bytes [0x00, 0xC0) with Ed25519 under key `key_id`, and wraps it:
//
//   0x00  magic      u32  'AKEV'
//   0x04  version    u16  envelope format version (1)
//   0x06  key_id     u16  controller key that signed the slot; non-zero
//   0x08  server_id  u64  target server; non-zero
//   0x10  slot       256 bytes, the mailbox slot image, signature included
//   0x110 (end: an envelope is always exactly 272 bytes)
//
// helm relays `slot` into the mailbox unmodified (Requirement 1.4). hull
// trusts only the slot: it verifies the signature and takes the key ID,
// server ID and sequence number from the signed slot header (mailbox
// protocol v3), never from this wrapper. The envelope's key_id and
// server_id must still equal the slot's, so a helm that routes or logs by
// the envelope sees the truth, and a relay that rewrote one but not the
// other is caught before the mailbox.
//
// The decoder does not otherwise parse the slot: hull decodes it strictly
// (helm::mailbox::decode) and verifies it. Only the header fields helm
// needs for routing and reporting are exposed, by slot_key_id,
// slot_server_id and slot_seq.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "common/wire.hpp"
#include "proto/codec.hpp"

namespace ak::proto {

// Mailbox slot geometry, mirrored from helm/mailbox.hpp so this header
// stays dependency-free; tests/proto_envelope_test.cpp pins both together.
inline constexpr std::size_t slot_size = 256;
inline constexpr std::size_t slot_seq_offset = 0x08;
inline constexpr std::size_t slot_key_id_offset = 0x12;
inline constexpr std::size_t slot_server_id_offset = 0x18;
inline constexpr std::size_t slot_signed_size = 0xC0;
using Slot = std::array<std::byte, slot_size>;

inline constexpr std::uint32_t envelope_magic = 0x5645'4B41;  // "AKEV" as little-endian bytes
inline constexpr std::uint16_t envelope_version = 1;
inline constexpr std::size_t envelope_header_size = 16;
inline constexpr std::size_t envelope_size = envelope_header_size + slot_size;  // 272

using EnvelopeBytes = std::array<std::byte, envelope_size>;

struct Envelope {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    Slot slot{};

    friend auto operator==(const Envelope&, const Envelope&) -> bool = default;
};

// The key ID in the slot header (little-endian u16 at 0x12).
[[nodiscard]] inline auto slot_key_id(const Slot& slot) noexcept -> KeyId {
    wire::Reader r{std::span<const std::byte>{slot}.subspan(slot_key_id_offset)};
    return r.le16().value_or(no_key_id);
}

// The server ID in the slot header (little-endian u64 at 0x18).
[[nodiscard]] inline auto slot_server_id(const Slot& slot) noexcept -> std::uint64_t {
    wire::Reader r{std::span<const std::byte>{slot}.subspan(slot_server_id_offset)};
    return r.le64().value_or(0);
}

// The per-server command sequence number in the slot header (u64 at 0x08).
[[nodiscard]] inline auto slot_seq(const Slot& slot) noexcept -> std::uint64_t {
    wire::Reader r{std::span<const std::byte>{slot}.subspan(slot_seq_offset)};
    return r.le64().value_or(0);
}

// The bytes of the slot the controller signs and hull verifies.
[[nodiscard]] inline auto slot_signed_bytes(const Slot& slot) noexcept
    -> std::span<const std::byte, slot_signed_size> {
    return std::span<const std::byte>{slot}.first<slot_signed_size>();
}

namespace detail {

[[nodiscard]] inline auto check_envelope(std::uint64_t server_id, KeyId key_id,
                                         const Slot& slot) noexcept
    -> std::expected<void, DecodeError> {
    if (key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (slot_key_id(slot) != key_id) {
        return std::unexpected(DecodeError::key_id_mismatch);
    }
    if (slot_server_id(slot) != server_id) {
        return std::unexpected(DecodeError::server_id_mismatch);
    }
    return {};
}

}  // namespace detail

// Strict decode: exactly envelope_size bytes, known magic and version,
// non-zero key and server IDs, each equal to the slot's.
[[nodiscard]] inline auto decode_envelope(std::span<const std::byte> bytes) noexcept
    -> std::expected<Envelope, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto slot = r.bytes(slot_size);
    if (!magic || !version || !key_id || !server_id || !slot) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != envelope_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != envelope_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    Envelope env{.server_id = *server_id, .key_id = *key_id, .slot = {}};
    std::ranges::copy(*slot, env.slot.begin());
    if (auto ok = detail::check_envelope(env.server_id, env.key_id, env.slot); !ok) {
        return std::unexpected(ok.error());
    }
    return env;
}

// Encodes an envelope, enforcing the rules decode_envelope checks so the
// controller cannot emit a frame helm would refuse.
[[nodiscard]] inline auto encode_envelope(const Envelope& env) noexcept
    -> std::expected<EnvelopeBytes, DecodeError> {
    if (auto ok = detail::check_envelope(env.server_id, env.key_id, env.slot); !ok) {
        return std::unexpected(ok.error());
    }
    EnvelopeBytes out{};
    wire::SpanWriter w{out};
    // The buffer is exactly envelope_size, so none of these can overflow.
    (void)w.write(envelope_magic, wire::Order::little);
    (void)w.write(envelope_version, wire::Order::little);
    (void)w.write(env.key_id, wire::Order::little);
    (void)w.write(env.server_id, wire::Order::little);
    (void)w.bytes(env.slot);
    return out;
}

}  // namespace ak::proto
