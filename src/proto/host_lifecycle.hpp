// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// HostPower and Decommission: the controller's signed orders to a server's
// helm to power its host and to leave the fleet
// (.kiro/specs/server-provisioning/ Requirements 3 and 5, design
// "Records"; kythira .kiro/specs/metal-host-lifecycle/). Link record types
// 21 and 22, controller -> helm. helm verifies both itself, because helm
// is the one that acts on them.
//
// host_power (link type 21; little-endian, fixed 0x60 bytes):
//   0x00  magic      u32  'AKHP'
//   0x04  version    u16  frame format version (1)
//   0x06  key_id     u16  controller key that signed it; non-zero
//   0x08  server_id  u64  target server; non-zero
//   0x10  seq        u64  non-zero; the server's envelope sequence space
//   0x18  action     u8   HostPowerAction
//   0x19  force      u8   0 or 1: off, cycle or hold even with VMs running
//   0x1A  reserved   [6]  zero
//   0x20  signature  [64] Ed25519 over bytes [0x00, 0x20)
//
// decommission (link type 22; little-endian, fixed 0x60 bytes):
//   0x00  magic      u32  'AKDC'
//   0x04  version    u16  frame format version (1)
//   0x06  key_id     u16  controller key that signed it; non-zero
//   0x08  server_id  u64  target server; non-zero
//   0x10  seq        u64  non-zero; the server's envelope sequence space
//   0x18  reserved   [8]  zero
//   0x20  signature  [64] Ed25519 over bytes [0x00, 0x20)
//
// Both carry a sequence number from the same per-server space as
// envelopes, so a replayed power or decommission order is refused like a
// replayed command. `force` is meaningless for `on` and must be 0 there.
//
// The design's table lists the fields without a magic and version; they
// are added here, as on every other frame the controller key signs
// (power_policy, standing_set), so that the signed bytes of one kind of
// frame can never also parse as another kind signed by the same key.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint32_t host_power_magic = 0x5048'4B41;    // "AKHP" as little-endian bytes
inline constexpr std::uint32_t decommission_magic = 0x4344'4B41;  // "AKDC" as little-endian bytes
inline constexpr std::uint16_t host_lifecycle_version = 1;
inline constexpr std::size_t host_lifecycle_signed_size = 0x20;
inline constexpr std::size_t host_power_size = host_lifecycle_signed_size + ed25519_signature_size;
inline constexpr std::size_t decommission_size = host_power_size;

// Values are part of the wire protocol: never renumber.
enum class HostPowerAction : std::uint8_t {
    on = 1,     // release the host from reset (slots first)
    off = 2,    // hold the host in reset and power it off
    cycle = 3,  // off, then on
    hold = 4,   // keep the host in reset; slots stay powered
};

[[nodiscard]] constexpr auto to_string(HostPowerAction a) noexcept -> const char* {
    switch (a) {
        case HostPowerAction::on:
            return "on";
        case HostPowerAction::off:
            return "off";
        case HostPowerAction::cycle:
            return "cycle";
        case HostPowerAction::hold:
            return "hold";
    }
    return "unknown";
}

struct HostPower {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t seq{0};
    HostPowerAction action{HostPowerAction::on};
    bool force{false};
    Ed25519Signature signature{};
    friend auto operator==(const HostPower&, const HostPower&) -> bool = default;
};

struct Decommission {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t seq{0};
    Ed25519Signature signature{};
    friend auto operator==(const Decommission&, const Decommission&) -> bool = default;
};

// The bytes the controller signs: the frame less its trailing signature.
[[nodiscard]] inline auto host_lifecycle_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), host_lifecycle_signed_size));
}

inline auto set_host_lifecycle_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() == host_power_size) {
        std::ranges::copy(signature, frame.begin() + host_lifecycle_signed_size);
    }
}

namespace detail {

[[nodiscard]] constexpr auto known(HostPowerAction a) noexcept -> bool {
    return a >= HostPowerAction::on && a <= HostPowerAction::hold;
}

[[nodiscard]] inline auto check_lifecycle_header(KeyId key_id, std::uint64_t server_id,
                                                 std::uint64_t seq) noexcept
    -> std::expected<void, DecodeError> {
    if (key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (seq == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

[[nodiscard]] inline auto check_host_power(const HostPower& p) noexcept
    -> std::expected<void, DecodeError> {
    if (auto ok = check_lifecycle_header(p.key_id, p.server_id, p.seq); !ok) {
        return ok;
    }
    if (!known(p.action) || (p.force && p.action == HostPowerAction::on)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

struct LifecycleHeader {
    std::uint32_t magic{0};
    std::uint16_t version{0};
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t seq{0};
};

// Reads the common head of an exact-length frame; the reads cannot fail.
[[nodiscard]] inline auto read_lifecycle_header(wire::Reader& r) -> LifecycleHeader {
    LifecycleHeader h;
    h.magic = r.le32().value_or(0);
    h.version = r.le16().value_or(0);
    h.key_id = r.le16().value_or(0);
    h.server_id = r.le64().value_or(0);
    h.seq = r.le64().value_or(0);
    return h;
}

[[nodiscard]] inline auto check_frame_size(std::size_t got, std::size_t want) noexcept
    -> std::expected<void, DecodeError> {
    if (got < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (got > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    return {};
}

[[nodiscard]] inline auto check_magic_version(const LifecycleHeader& h,
                                              std::uint32_t magic) noexcept
    -> std::expected<void, DecodeError> {
    if (h.magic != magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (h.version != host_lifecycle_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    return {};
}

inline auto write_lifecycle_header(wire::Writer& w, std::uint32_t magic, KeyId key_id,
                                   std::uint64_t server_id, std::uint64_t seq) -> void {
    w.le32(magic);
    w.le16(host_lifecycle_version);
    w.le16(key_id);
    w.le64(server_id);
    w.le64(seq);
}

}  // namespace detail

// Strict decode. Does not verify the signature: helm verifies
// host_lifecycle_signed_bytes(frame) against `signature` under `key_id`.
[[nodiscard]] inline auto decode_host_power(std::span<const std::byte> bytes)
    -> std::expected<HostPower, DecodeError> {
    if (auto ok = detail::check_frame_size(bytes.size(), host_power_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{bytes};
    const auto h = detail::read_lifecycle_header(r);
    HostPower p;
    p.key_id = h.key_id;
    p.server_id = h.server_id;
    p.seq = h.seq;
    p.action = static_cast<HostPowerAction>(r.u8().value_or(0));
    const auto force = r.u8().value_or(0);
    const bool zero = detail::all_zero(r.bytes(6).value_or(std::span<const std::byte>{}));
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      p.signature.begin());
    if (auto ok = detail::check_magic_version(h, host_power_magic); !ok) {
        return std::unexpected(ok.error());
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (force > 1) {
        return std::unexpected(DecodeError::unknown_value);
    }
    p.force = force == 1;
    if (auto ok = detail::check_host_power(p); !ok) {
        return std::unexpected(ok.error());
    }
    return p;
}

// Encodes a HostPower (with whatever is in `signature`), enforcing every
// rule decode_host_power checks.
[[nodiscard]] inline auto encode_host_power(const HostPower& p)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_host_power(p); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(host_power_size);
    wire::Writer w{out};
    detail::write_lifecycle_header(w, host_power_magic, p.key_id, p.server_id, p.seq);
    w.u8(static_cast<std::uint8_t>(p.action));
    w.u8(p.force ? 1 : 0);
    w.bytes(std::array<std::byte, 6>{});
    w.bytes(p.signature);
    return out;
}

// Strict decode. Does not verify the signature.
[[nodiscard]] inline auto decode_decommission(std::span<const std::byte> bytes)
    -> std::expected<Decommission, DecodeError> {
    if (auto ok = detail::check_frame_size(bytes.size(), decommission_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{bytes};
    const auto h = detail::read_lifecycle_header(r);
    Decommission d;
    d.key_id = h.key_id;
    d.server_id = h.server_id;
    d.seq = h.seq;
    const bool zero = detail::all_zero(r.bytes(8).value_or(std::span<const std::byte>{}));
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      d.signature.begin());
    if (auto ok = detail::check_magic_version(h, decommission_magic); !ok) {
        return std::unexpected(ok.error());
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_lifecycle_header(d.key_id, d.server_id, d.seq); !ok) {
        return std::unexpected(ok.error());
    }
    return d;
}

[[nodiscard]] inline auto encode_decommission(const Decommission& d)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_lifecycle_header(d.key_id, d.server_id, d.seq); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(decommission_size);
    wire::Writer w{out};
    detail::write_lifecycle_header(w, decommission_magic, d.key_id, d.server_id, d.seq);
    w.bytes(std::array<std::byte, 8>{});
    w.bytes(d.signature);
    return out;
}

}  // namespace ak::proto
