// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// PowerPolicy: when a server's helm releases its host after helm's own
// power returns, and which hull image it keeps as last-known-good
// (.kiro/specs/cold-start/ Requirements 2.3 and 3, design "Records";
// kythira .kiro/specs/az-cold-start/ Requirement 5). Link record type 24,
// controller -> helm. helm stores the newest version in its sealed store
// and applies it with no controller.
//
// Layout (little-endian, fixed 0x90 bytes):
//   0x00  magic             u32  'AKPP'
//   0x04  version           u16  frame format version (1)
//   0x06  key_id            u16  controller key that signed it; non-zero
//   0x08  server_id         u64  target server; non-zero
//   0x10  policy_version    u64  non-zero, increases on every change
//   0x18  time_floor        u64  Unix seconds the controller's clock had passed (0 = none)
//   0x20  tier              u8   0 .. max_power_tier
//   0x21  reserved          u8   zero
//   0x22  slot              u16  power-on slot within the server's power domain
//   0x24  tier_delay_s      u16  seconds to wait for this tier, at most max_tier_delay_s
//   0x26  slot_interval_ms  u16  milliseconds between slots, at most max_slot_interval_ms
//   0x28  max_jitter_ms     u16  jitter drawn from [0, max_jitter_ms], at most max_power_jitter_ms
//   0x2A  reserved          [6]  zero
//   0x30  keep_image        [32] SHA-256 of the hull UKI to promote to LKG; zero = none
//   0x50  signature         [64] Ed25519 over bytes [0x00, 0x50)
//
// After its own power returns, helm holds the host in reset for
// tier_delay_s + slot x slot_interval_ms + jitter. With no stored policy it
// uses default_power_policy(): tier 3 and kythira az-cold-start
// Requirement 5.2's defaults. keep_image promotes an image helm has booted
// to LKG (Requirement 2.3): the controller sets it only after the server
// booted that image, renewed its certificate with a fresh attestation and
// passed its checks.
//
// tier_delay_s + slot x slot_interval_ms may be at most one hour
// (max_power_wait_ms): 65,535 slots of 30 s would be weeks, and a policy
// that holds a server off longer than an operator would wait is a mistake
// helm should refuse rather than obey.

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
#include "proto/standing_set.hpp"

namespace ak::proto {

inline constexpr std::uint32_t power_policy_magic = 0x5050'4B41;  // "AKPP" as little-endian bytes
inline constexpr std::uint16_t power_policy_version = 1;
inline constexpr std::size_t power_policy_signed_size = 0x50;
inline constexpr std::size_t power_policy_size = power_policy_signed_size + ed25519_signature_size;

inline constexpr std::uint8_t max_power_tier = 3;
inline constexpr std::uint16_t max_tier_delay_s = 1800;
inline constexpr std::uint16_t max_slot_interval_ms = 30'000;
inline constexpr std::uint16_t max_power_jitter_ms = 30'000;
// The longest tier_delay + slot x slot_interval a policy may ask, in
// milliseconds (jitter comes on top).
inline constexpr std::uint64_t max_power_wait_ms = 3'600'000;

// kythira az-cold-start Requirement 5.2: tier delays 0 s, 60 s, 180 s,
// 300 s; slot interval 5 s; jitter 0-2 s.
inline constexpr std::array<std::uint16_t, max_power_tier + 1> default_tier_delays_s{0, 60, 180,
                                                                                     300};
inline constexpr std::uint16_t default_slot_interval_ms = 5000;
inline constexpr std::uint16_t default_power_jitter_ms = 2000;

struct PowerPolicy {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint64_t policy_version{0};
    std::uint64_t time_floor{0};
    std::uint8_t tier{max_power_tier};
    std::uint16_t slot{0};
    std::uint16_t tier_delay_s{default_tier_delays_s[max_power_tier]};
    std::uint16_t slot_interval_ms{default_slot_interval_ms};
    std::uint16_t max_jitter_ms{default_power_jitter_ms};
    ImageDigest keep_image{};  // all zero: promote nothing
    Ed25519Signature signature{};
    friend auto operator==(const PowerPolicy&, const PowerPolicy&) -> bool = default;
};

// What helm applies with no stored policy (cold-start Requirement 3.4):
// tier 3, slot 0, the defaults. Not a frame: version and key ID stay 0.
[[nodiscard]] constexpr auto default_power_policy(std::uint64_t server_id) noexcept -> PowerPolicy {
    return PowerPolicy{.server_id = server_id};
}

// The hold time before jitter, in milliseconds.
[[nodiscard]] constexpr auto power_wait_ms(const PowerPolicy& p) noexcept -> std::uint64_t {
    return (std::uint64_t{p.tier_delay_s} * 1000) +
           (std::uint64_t{p.slot} * std::uint64_t{p.slot_interval_ms});
}

[[nodiscard]] inline auto power_policy_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), power_policy_signed_size));
}

inline auto set_power_policy_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() == power_policy_size) {
        std::ranges::copy(signature, frame.begin() + power_policy_signed_size);
    }
}

namespace detail {

[[nodiscard]] inline auto check_power_policy(const PowerPolicy& p) noexcept
    -> std::expected<void, DecodeError> {
    if (p.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (p.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (p.policy_version == 0) {
        return std::unexpected(DecodeError::bad_generation);
    }
    if (p.tier > max_power_tier || p.tier_delay_s > max_tier_delay_s ||
        p.slot_interval_ms > max_slot_interval_ms || p.max_jitter_ms > max_power_jitter_ms ||
        power_wait_ms(p) > max_power_wait_ms) {
        return std::unexpected(DecodeError::bad_power_policy);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: helm verifies
// power_policy_signed_bytes(frame) against `signature` under `key_id`.
[[nodiscard]] inline auto decode_power_policy(std::span<const std::byte> bytes)
    -> std::expected<PowerPolicy, DecodeError> {
    if (bytes.size() < power_policy_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > power_policy_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    PowerPolicy p;
    p.key_id = r.le16().value_or(0);
    p.server_id = r.le64().value_or(0);
    p.policy_version = r.le64().value_or(0);
    p.time_floor = r.le64().value_or(0);
    p.tier = r.u8().value_or(0);
    bool zero = r.u8().value_or(1) == 0;
    p.slot = r.le16().value_or(0);
    p.tier_delay_s = r.le16().value_or(0);
    p.slot_interval_ms = r.le16().value_or(0);
    p.max_jitter_ms = r.le16().value_or(0);
    zero = detail::all_zero(r.bytes(6).value_or(std::span<const std::byte>{})) && zero;
    std::ranges::copy(r.bytes(image_digest_size).value_or(std::span<const std::byte>{}),
                      p.keep_image.begin());
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      p.signature.begin());
    if (magic != power_policy_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != power_policy_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_power_policy(p); !ok) {
        return std::unexpected(ok.error());
    }
    return p;
}

// Encodes a PowerPolicy (with whatever is in `signature`), enforcing every
// rule decode_power_policy checks.
[[nodiscard]] inline auto encode_power_policy(const PowerPolicy& p)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_power_policy(p); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(power_policy_size);
    wire::Writer w{out};
    w.le32(power_policy_magic);
    w.le16(power_policy_version);
    w.le16(p.key_id);
    w.le64(p.server_id);
    w.le64(p.policy_version);
    w.le64(p.time_floor);
    w.u8(p.tier);
    w.u8(0);
    w.le16(p.slot);
    w.le16(p.tier_delay_s);
    w.le16(p.slot_interval_ms);
    w.le16(p.max_jitter_ms);
    w.bytes(std::array<std::byte, 6>{});
    w.bytes(p.keep_image);
    w.bytes(p.signature);
    return out;
}

}  // namespace ak::proto
