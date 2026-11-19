// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// GroupPolicy: the controller's broadcast/multicast policy for one VPC,
// sent to every server hosting a NIC in it (.kiro/specs/controller-interface/
// Requirement 7, design "Multicast policy and usage"; oar-net Requirement
// 10). helm forwards it unmodified to the network roles, which check the
// signature and apply it to the VSwitch (VSwitch::set_group_policy).
//
// Like MapUpdate it is a full per-VNI snapshot at `policy_version`, so
// applying it is idempotent and a server that missed versions catches up
// from the newest alone. It carries its own server and key IDs inside the
// signed bytes, so it cannot be replayed to another server.
//
// Layout (little-endian, 0x80 bytes):
//   0x00  magic             u32  'AKGP'
//   0x04  version           u16  frame format version (1)
//   0x06  key_id            u16  controller key that signed it; non-zero
//   0x08  server_id         u64  target server; non-zero
//   0x10  vni               u32  VPC's 24-bit Geneve VNI; non-zero
//   0x14  mode              u8   GroupMode
//   0x15  reserved          3 bytes, zero
//   0x18  policy_version    u64  per VPC, starts at 1, increases on every change
//   0x20  rate_frames       u32  replicated frames per second, per source NIC
//   0x24  burst_frames      u32  bucket depth in frames
//   0x28  rate_bytes        u64  replicated bytes per second, per source NIC
//   0x30  burst_bytes       u64  bucket depth in bytes
//   0x38  max_remote_vteps  u32  flood-list cap
//   0x3C  max_groups_per_nic u16 snooped-group cap (0 until snooping exists)
//   0x3E  reserved          2 bytes, zero
//   0x40  signature         64 bytes, Ed25519 over every byte before it
//
// A `drop` policy (the default every VPC starts with) has every limit zero.
// A `multicast` policy has every rate, burst and the flood-list cap
// non-zero and within the bounds below; max_groups_per_nic may be zero.
// The bounds are oar-net's (vswitch.hpp group_*_max), mirrored so this
// header depends on nothing else.

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

inline constexpr std::uint32_t group_policy_magic = 0x5047'4B41;  // "AKGP" as little-endian bytes
inline constexpr std::uint16_t group_policy_version = 1;
inline constexpr std::size_t group_policy_signed_size = 0x40;
inline constexpr std::size_t group_policy_size = group_policy_signed_size + ed25519_signature_size;

inline constexpr std::uint32_t max_group_rate_frames = 1U << 24U;
inline constexpr std::uint32_t max_group_burst_frames = 1U << 20U;
inline constexpr std::uint64_t max_group_rate_bytes = std::uint64_t{1} << 37U;
inline constexpr std::uint64_t max_group_burst_bytes = std::uint64_t{1} << 32U;
inline constexpr std::uint32_t max_group_remote_vteps = 1U << 16U;

// Values are part of the wire protocol: never renumber.
enum class GroupMode : std::uint8_t {
    drop = 0,       // no broadcast or multicast (the default)
    multicast = 1,  // opted in: IP multicast replicated within the VNI
};

struct GroupPolicy {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint32_t vni{0};
    GroupMode mode{GroupMode::drop};
    std::uint64_t policy_version{0};
    std::uint32_t rate_frames{0};
    std::uint32_t burst_frames{0};
    std::uint64_t rate_bytes{0};
    std::uint64_t burst_bytes{0};
    std::uint32_t max_remote_vteps{0};
    std::uint16_t max_groups_per_nic{0};
    Ed25519Signature signature{};

    friend auto operator==(const GroupPolicy&, const GroupPolicy&) -> bool = default;
};

// The bytes a GroupPolicy signature covers: all but the trailing 64.
[[nodiscard]] inline auto group_policy_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), group_policy_signed_size));
}

inline auto set_group_policy_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() == group_policy_size) {
        std::ranges::copy(signature, frame.begin() + group_policy_signed_size);
    }
}

namespace detail {

[[nodiscard]] inline auto check_group_policy(const GroupPolicy& p) noexcept
    -> std::expected<void, DecodeError> {
    if (p.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (p.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (p.vni == 0 || p.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (p.policy_version == 0) {
        return std::unexpected(DecodeError::bad_policy_version);
    }
    switch (p.mode) {
        case GroupMode::drop:
            if (p.rate_frames != 0 || p.burst_frames != 0 || p.rate_bytes != 0 ||
                p.burst_bytes != 0 || p.max_remote_vteps != 0 || p.max_groups_per_nic != 0) {
                return std::unexpected(DecodeError::bad_group_limits);
            }
            return {};
        case GroupMode::multicast:
            if (p.rate_frames == 0 || p.burst_frames == 0 || p.rate_bytes == 0 ||
                p.burst_bytes == 0 || p.max_remote_vteps == 0 ||
                p.rate_frames > max_group_rate_frames || p.burst_frames > max_group_burst_frames ||
                p.rate_bytes > max_group_rate_bytes || p.burst_bytes > max_group_burst_bytes ||
                p.max_remote_vteps > max_group_remote_vteps) {
                return std::unexpected(DecodeError::bad_group_limits);
            }
            return {};
    }
    return std::unexpected(DecodeError::unknown_value);
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// group_policy_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_group_policy(std::span<const std::byte> bytes)
    -> std::expected<GroupPolicy, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto vni = r.le32();
    auto mode = r.u8();
    auto reserved1 = r.bytes(3);
    auto policy_version = r.le64();
    auto rate_frames = r.le32();
    auto burst_frames = r.le32();
    auto rate_bytes = r.le64();
    auto burst_bytes = r.le64();
    auto max_remote_vteps = r.le32();
    auto max_groups = r.le16();
    auto reserved2 = r.bytes(2);
    auto signature = r.bytes(ed25519_signature_size);
    if (!magic || !version || !key_id || !server_id || !vni || !mode || !reserved1 ||
        !policy_version || !rate_frames || !burst_frames || !rate_bytes || !burst_bytes ||
        !max_remote_vteps || !max_groups || !reserved2 || !signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*magic != group_policy_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != group_policy_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!detail::all_zero(*reserved1) || !detail::all_zero(*reserved2)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    GroupPolicy out{.server_id = *server_id,
                    .key_id = *key_id,
                    .vni = *vni,
                    .mode = static_cast<GroupMode>(*mode),
                    .policy_version = *policy_version,
                    .rate_frames = *rate_frames,
                    .burst_frames = *burst_frames,
                    .rate_bytes = *rate_bytes,
                    .burst_bytes = *burst_bytes,
                    .max_remote_vteps = *max_remote_vteps,
                    .max_groups_per_nic = *max_groups,
                    .signature = {}};
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = detail::check_group_policy(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a GroupPolicy (with whatever is in `signature`), enforcing every
// rule decode_group_policy checks.
[[nodiscard]] inline auto encode_group_policy(const GroupPolicy& p)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_group_policy(p); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(group_policy_size);
    wire::Writer w{out};
    w.le32(group_policy_magic);
    w.le16(group_policy_version);
    w.le16(p.key_id);
    w.le64(p.server_id);
    w.le32(p.vni);
    w.u8(static_cast<std::uint8_t>(p.mode));
    w.bytes(std::array<std::byte, 3>{});
    w.le64(p.policy_version);
    w.le32(p.rate_frames);
    w.le32(p.burst_frames);
    w.le64(p.rate_bytes);
    w.le64(p.burst_bytes);
    w.le32(p.max_remote_vteps);
    w.le16(p.max_groups_per_nic);
    w.le16(0);
    w.bytes(p.signature);
    return out;
}

}  // namespace ak::proto
