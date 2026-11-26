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
//   0x3C  max_groups_per_nic u16 snooped joins per NIC, at most 256; 0 refuses
//                                every join
//   0x3E  reserved          2 bytes, zero
//   0x40  signature         64 bytes, Ed25519 over every byte before it
//
// A `drop` policy (the default every VPC starts with) has every limit zero.
// A `multicast` policy has every rate, burst and the flood-list cap
// non-zero and within the bounds below; max_groups_per_nic may be zero
// (no NIC in the VPC may join a group).
// The bounds are oar-net's (vswitch.hpp group_*_max), mirrored so this
// header depends on nothing else.
//
// Version 2 (.kiro/specs/vpc-subnets-routing/ task 12, design "GroupPolicy
// version 2") opts in per subnet: one entry per opted-in subnet, each with
// a multicast policy's limits; a subnet without an entry drops broadcast
// and multicast, and no entries at all is the whole VPC's `drop`:
//
//   0x00  magic             u32  'AKGP'
//   0x04  version           u16  2
//   0x06  key_id            u16
//   0x08  server_id         u64
//   0x10  vni               u32
//   0x14  entry_count       u16  0 .. max_group_policy_subnets
//   0x16  reserved          u16  zero
//   0x18  policy_version    u64  one sequence per VPC across both versions
//   0x20  entries           entry_count x 0x28, strictly ascending subnet_id:
//         +0x00 subnet_id u64 (non-zero) | +0x08 rate_frames u32
//         +0x0C burst_frames u32 | +0x10 rate_bytes u64 | +0x18 burst_bytes u64
//         +0x20 max_remote_vteps u32 | +0x24 max_groups_per_nic u16
//         +0x26 reserved u16 (zero)
//   then  signature         64 bytes, Ed25519 over every byte before it
//
// Version 1 stays valid: a VPC-wide policy for every subnet. The decoded
// GroupPolicy says which it is in `format`; a version 2 policy keeps the
// version 1 fields at `drop` and zero.

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
inline constexpr std::uint16_t group_policy_version_subnets = 2;
inline constexpr std::size_t group_policy_signed_size = 0x40;
inline constexpr std::size_t group_policy_size = group_policy_signed_size + ed25519_signature_size;
// Version 2: a header, the entries, the signature.
inline constexpr std::size_t group_policy_v2_header_size = 0x20;
inline constexpr std::size_t group_policy_entry_size = 0x28;
inline constexpr std::size_t max_group_policy_subnets = 200;  // proto::max_vpc_subnets
inline constexpr std::size_t min_group_policy_v2_size =
    group_policy_v2_header_size + ed25519_signature_size;
inline constexpr std::size_t max_group_policy_size =
    min_group_policy_v2_size + (max_group_policy_subnets * group_policy_entry_size);

inline constexpr std::uint32_t max_group_rate_frames = 1U << 24U;
inline constexpr std::uint32_t max_group_burst_frames = 1U << 20U;
inline constexpr std::uint64_t max_group_rate_bytes = std::uint64_t{1} << 37U;
inline constexpr std::uint64_t max_group_burst_bytes = std::uint64_t{1} << 32U;
inline constexpr std::uint32_t max_group_remote_vteps = 1U << 16U;
inline constexpr std::uint16_t max_group_groups_per_nic = 256;

// Values are part of the wire protocol: never renumber.
enum class GroupMode : std::uint8_t {
    drop = 0,       // no broadcast or multicast (the default)
    multicast = 1,  // opted in: IP multicast replicated within the VNI
};

// One opted-in subnet's limits (version 2): a multicast policy's.
struct GroupSubnetLimits {
    std::uint64_t subnet_id{0};
    std::uint32_t rate_frames{0};
    std::uint32_t burst_frames{0};
    std::uint64_t rate_bytes{0};
    std::uint64_t burst_bytes{0};
    std::uint32_t max_remote_vteps{0};
    std::uint16_t max_groups_per_nic{0};

    friend auto operator==(const GroupSubnetLimits&, const GroupSubnetLimits&) -> bool = default;
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
    // group_policy_version (VPC-wide, the fields above) or
    // group_policy_version_subnets (per subnet, `subnets`).
    std::uint16_t format{group_policy_version};
    std::vector<GroupSubnetLimits> subnets{};  // version 2: strictly ascending subnet_id

    friend auto operator==(const GroupPolicy&, const GroupPolicy&) -> bool = default;
};

// The bytes a GroupPolicy signature covers: all but the trailing 64, in
// either version.
[[nodiscard]] inline auto group_policy_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

inline auto set_group_policy_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= min_group_policy_v2_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

namespace detail {

// A multicast policy's limits: every rate, burst and the flood-list cap
// non-zero and in bounds.
[[nodiscard]] inline auto multicast_limits_ok(std::uint32_t rate_frames, std::uint32_t burst_frames,
                                              std::uint64_t rate_bytes, std::uint64_t burst_bytes,
                                              std::uint32_t max_remote_vteps,
                                              std::uint16_t max_groups) noexcept -> bool {
    return rate_frames != 0 && burst_frames != 0 && rate_bytes != 0 && burst_bytes != 0 &&
           max_remote_vteps != 0 && rate_frames <= max_group_rate_frames &&
           burst_frames <= max_group_burst_frames && rate_bytes <= max_group_rate_bytes &&
           burst_bytes <= max_group_burst_bytes && max_remote_vteps <= max_group_remote_vteps &&
           max_groups <= max_group_groups_per_nic;
}

[[nodiscard]] inline auto check_group_policy(const GroupPolicy& p) noexcept
    -> std::expected<void, DecodeError> {
    if (p.format != group_policy_version && p.format != group_policy_version_subnets) {
        return std::unexpected(DecodeError::bad_version);
    }
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
    if (p.format == group_policy_version_subnets) {
        // The VPC-wide fields have no meaning here and stay at drop.
        if (p.mode != GroupMode::drop || p.rate_frames != 0 || p.burst_frames != 0 ||
            p.rate_bytes != 0 || p.burst_bytes != 0 || p.max_remote_vteps != 0 ||
            p.max_groups_per_nic != 0) {
            return std::unexpected(DecodeError::bad_group_limits);
        }
        if (p.subnets.size() > max_group_policy_subnets) {
            return std::unexpected(DecodeError::too_many_entries);
        }
        for (std::size_t i = 0; i < p.subnets.size(); ++i) {
            const GroupSubnetLimits& e = p.subnets[i];
            if (e.subnet_id == 0) {
                return std::unexpected(DecodeError::bad_id);
            }
            if (i > 0 && p.subnets[i - 1].subnet_id >= e.subnet_id) {
                return std::unexpected(DecodeError::not_ascending);
            }
            if (!multicast_limits_ok(e.rate_frames, e.burst_frames, e.rate_bytes, e.burst_bytes,
                                     e.max_remote_vteps, e.max_groups_per_nic)) {
                return std::unexpected(DecodeError::bad_group_limits);
            }
        }
        return {};
    }
    if (!p.subnets.empty()) {
        return std::unexpected(DecodeError::bad_group_limits);
    }
    switch (p.mode) {
        case GroupMode::drop:
            if (p.rate_frames != 0 || p.burst_frames != 0 || p.rate_bytes != 0 ||
                p.burst_bytes != 0 || p.max_remote_vteps != 0 || p.max_groups_per_nic != 0) {
                return std::unexpected(DecodeError::bad_group_limits);
            }
            return {};
        case GroupMode::multicast:
            if (!multicast_limits_ok(p.rate_frames, p.burst_frames, p.rate_bytes, p.burst_bytes,
                                     p.max_remote_vteps, p.max_groups_per_nic)) {
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
namespace detail {

[[nodiscard]] inline auto decode_group_policy_v2(std::span<const std::byte> bytes)
    -> std::expected<GroupPolicy, DecodeError> {
    wire::Reader r{bytes};
    static_cast<void>(r.le32());  // magic and version: checked by the caller
    static_cast<void>(r.le16());
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto vni = r.le32();
    auto count = r.le16();
    auto reserved = r.le16();
    auto policy_version = r.le64();
    if (!key_id || !server_id || !vni || !count || !reserved || !policy_version) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*count > max_group_policy_subnets) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    GroupPolicy out{.server_id = *server_id,
                    .key_id = *key_id,
                    .vni = *vni,
                    .mode = GroupMode::drop,
                    .policy_version = *policy_version,
                    .signature = {},
                    .format = group_policy_version_subnets,
                    .subnets = {}};
    out.subnets.reserve(*count);
    for (std::size_t i = 0; i < *count; ++i) {
        auto subnet = r.le64();
        auto rate_frames = r.le32();
        auto burst_frames = r.le32();
        auto rate_bytes = r.le64();
        auto burst_bytes = r.le64();
        auto max_remote_vteps = r.le32();
        auto max_groups = r.le16();
        auto pad = r.le16();
        if (!subnet || !rate_frames || !burst_frames || !rate_bytes || !burst_bytes ||
            !max_remote_vteps || !max_groups || !pad) {
            return std::unexpected(DecodeError::truncated);
        }
        if (*pad != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        out.subnets.push_back({.subnet_id = *subnet,
                               .rate_frames = *rate_frames,
                               .burst_frames = *burst_frames,
                               .rate_bytes = *rate_bytes,
                               .burst_bytes = *burst_bytes,
                               .max_remote_vteps = *max_remote_vteps,
                               .max_groups_per_nic = *max_groups});
    }
    auto signature = r.bytes(ed25519_signature_size);
    if (!signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = check_group_policy(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

}  // namespace detail

[[nodiscard]] inline auto decode_group_policy(std::span<const std::byte> bytes)
    -> std::expected<GroupPolicy, DecodeError> {
    {
        wire::Reader head{bytes};
        auto magic = head.le32();
        auto version = head.le16();
        if (magic && version && *magic == group_policy_magic &&
            *version == group_policy_version_subnets) {
            return detail::decode_group_policy_v2(bytes);
        }
    }
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
    wire::Writer w{out};
    if (p.format == group_policy_version_subnets) {
        out.reserve(min_group_policy_v2_size + (p.subnets.size() * group_policy_entry_size));
        w.le32(group_policy_magic);
        w.le16(group_policy_version_subnets);
        w.le16(p.key_id);
        w.le64(p.server_id);
        w.le32(p.vni);
        w.le16(static_cast<std::uint16_t>(p.subnets.size()));
        w.le16(0);
        w.le64(p.policy_version);
        for (const GroupSubnetLimits& e : p.subnets) {
            w.le64(e.subnet_id);
            w.le32(e.rate_frames);
            w.le32(e.burst_frames);
            w.le64(e.rate_bytes);
            w.le64(e.burst_bytes);
            w.le32(e.max_remote_vteps);
            w.le16(e.max_groups_per_nic);
            w.le16(0);
        }
        w.bytes(p.signature);
        return out;
    }
    out.reserve(group_policy_size);
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
