// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// GroupMembers: the controller's per-group VTEP lists for one VPC that has
// opted in to multicast (.kiro/specs/controller-interface/ Requirement 7.9,
// design "Multicast policy and usage"; oar-net Requirement 10.5). The
// controller builds them from the network roles' snooped joins
// (group_membership reports): a group's VTEPs are the servers hosting at
// least one NIC that joined it. helm forwards the frame unmodified to the
// network roles, which check the signature and hand the lists to the
// VSwitch (VSwitch::set_group_members). A frame for a known group then goes
// only to its listed VTEPs; a group not listed is unknown and still goes to
// the whole VPC.
//
// Like GroupPolicy it is a full per-VNI snapshot at `members_version`, so
// applying it is idempotent and a server that missed versions catches up
// from the newest alone. Its server and key IDs are inside the signed
// bytes, so it cannot be replayed to another server.
//
// Layout (little-endian):
//   0x00  magic           u32  'AKGM'
//   0x04  version         u16  frame format version (1)
//   0x06  key_id          u16  controller key that signed it; non-zero
//   0x08  server_id       u64  target server; non-zero
//   0x10  vni             u32  VPC's 24-bit Geneve VNI; non-zero
//   0x14  group_count     u16  at most max_member_groups
//   0x16  reserved        u16  zero
//   0x18  members_version u64  per VPC, starts at 1, increases on every change
//   0x20  groups          group_count entries, strictly ascending by
//                         (family, group):
//           +0x00 family u8 (4 or 6) | +0x01 vtep_count u8 (1..max_group_vteps)
//           +0x02 reserved [6] | +0x08 group [16] (IPv4 in the first 4 bytes,
//           the rest zero)
//           +0x18 vteps: vtep_count x [16], strictly ascending
//   then  signature       64 bytes, Ed25519 over every byte before it
//
// A group is an IPv4 multicast address (224.0.0.0/4) or an IPv6 one
// (ff00::/8) other than a solicited-node group (ff02::1:ff00:0/104), which
// belongs to neighbor discovery and is never replicated. A VTEP is a
// unicast IPv6 address, as in MapUpdate. The list may name this server's
// own VTEP; the receiver skips it. At most max_member_vteps VTEP entries
// in all, which bounds the largest frame (max_group_members_size, 77,920
// bytes); helm forwards it to network roles in OarLink chunks, like
// TunnelPeers.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"
#include "proto/vpc_config.hpp"

namespace ak::proto {

inline constexpr std::uint32_t group_members_magic = 0x4D47'4B41;  // "AKGM" as little-endian bytes
inline constexpr std::uint16_t group_members_version = 1;
inline constexpr std::size_t group_members_header_size = 0x20;
inline constexpr std::size_t member_group_size = 0x18;
inline constexpr std::size_t max_member_groups = 512;
inline constexpr std::size_t max_group_vteps = 64;     // per group
inline constexpr std::size_t max_member_vteps = 4096;  // in one frame

struct MemberGroup {
    RouteFamily family{RouteFamily::ipv4};
    Ipv6Address group{};               // IPv4 in the first four bytes, the rest zero
    std::vector<Ipv6Address> vteps{};  // strictly ascending

    friend auto operator==(const MemberGroup&, const MemberGroup&) -> bool = default;
};

struct GroupMembers {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint32_t vni{0};
    std::uint64_t members_version{0};
    std::vector<MemberGroup> groups{};  // strictly ascending (family, group)
    Ed25519Signature signature{};

    friend auto operator==(const GroupMembers&, const GroupMembers&) -> bool = default;
};

[[nodiscard]] inline constexpr auto group_members_size(std::size_t groups,
                                                       std::size_t vteps) noexcept -> std::size_t {
    return group_members_header_size + (groups * member_group_size) + (vteps * vtep_address_size) +
           ed25519_signature_size;
}

inline constexpr std::size_t min_group_members_size = group_members_size(0, 0);
inline constexpr std::size_t max_group_members_size =
    group_members_size(max_member_groups, max_member_vteps);

// The bytes a GroupMembers signature covers: all but the trailing 64.
[[nodiscard]] inline auto group_members_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

inline auto set_group_members_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= min_group_members_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

namespace detail {

// A replicable group of its family (see the header).
[[nodiscard]] inline auto valid_member_group(RouteFamily family, const Ipv6Address& g) noexcept
    -> bool {
    constexpr std::uint8_t ipv4_multicast_last_octet = 239;
    constexpr std::size_t solicited_node_size = 13;  // ff02::1:ff00:0/104
    constexpr std::array<std::uint8_t, solicited_node_size> solicited_node{
        0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF};
    const auto first = std::to_integer<std::uint8_t>(g[0]);
    switch (family) {
        case RouteFamily::ipv4:
            return first >= ipv4_multicast_first_octet && first <= ipv4_multicast_last_octet &&
                   all_zero(std::span{g}.subspan(ipv4_address_size));
        case RouteFamily::ipv6:
            return first == ipv6_multicast_prefix &&
                   !std::ranges::equal(std::span{g}.first(solicited_node_size), solicited_node,
                                       [](std::byte b, std::uint8_t v) {
                                           return std::to_integer<std::uint8_t>(b) == v;
                                       });
    }
    return false;
}

[[nodiscard]] inline auto member_group_less(const MemberGroup& a, const MemberGroup& b) noexcept
    -> bool {
    if (a.family != b.family) {
        return a.family < b.family;
    }
    return a.group < b.group;
}

[[nodiscard]] inline auto check_group_members(const GroupMembers& m) noexcept
    -> std::expected<void, DecodeError> {
    if (m.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (m.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (m.vni == 0 || m.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (m.members_version == 0) {
        return std::unexpected(DecodeError::bad_members_version);
    }
    if (m.groups.size() > max_member_groups) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    std::size_t vteps = 0;
    for (std::size_t i = 0; i < m.groups.size(); ++i) {
        const MemberGroup& g = m.groups[i];
        if (g.family != RouteFamily::ipv4 && g.family != RouteFamily::ipv6) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (!valid_member_group(g.family, g.group)) {
            return std::unexpected(DecodeError::bad_group);
        }
        if (i > 0 && !member_group_less(m.groups[i - 1], g)) {
            return std::unexpected(DecodeError::not_ascending);
        }
        if (g.vteps.empty() || g.vteps.size() > max_group_vteps) {
            return std::unexpected(DecodeError::too_many_entries);
        }
        vteps += g.vteps.size();
        for (std::size_t v = 0; v < g.vteps.size(); ++v) {
            if (!unicast(g.vteps[v])) {
                return std::unexpected(DecodeError::bad_vtep);
            }
            if (v > 0 && !(g.vteps[v - 1] < g.vteps[v])) {
                return std::unexpected(DecodeError::not_ascending);
            }
        }
    }
    if (vteps > max_member_vteps) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// group_members_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_group_members(std::span<const std::byte> bytes)
    -> std::expected<GroupMembers, DecodeError> {
    if (bytes.size() > max_group_members_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto vni = r.le32();
    auto group_count = r.le16();
    auto reserved = r.le16();
    auto members_version = r.le64();
    if (!magic || !version || !key_id || !server_id || !vni || !group_count || !reserved ||
        !members_version) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != group_members_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != group_members_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*group_count > max_member_groups) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    GroupMembers out{.server_id = *server_id,
                     .key_id = *key_id,
                     .vni = *vni,
                     .members_version = *members_version};
    out.groups.reserve(*group_count);
    std::size_t total = 0;
    for (std::uint16_t i = 0; i < *group_count; ++i) {
        auto family = r.u8();
        auto vtep_count = r.u8();
        auto pad = r.bytes(6);
        auto group = r.bytes(ipv6_address_size);
        if (!family || !vtep_count || !pad || !group) {
            return std::unexpected(DecodeError::truncated);
        }
        if (!detail::all_zero(*pad)) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        total += *vtep_count;
        if (*vtep_count > max_group_vteps || total > max_member_vteps) {
            return std::unexpected(DecodeError::too_many_entries);
        }
        MemberGroup& g = out.groups.emplace_back();
        g.family = static_cast<RouteFamily>(*family);
        std::ranges::copy(*group, g.group.begin());
        g.vteps.reserve(*vtep_count);
        for (std::uint8_t v = 0; v < *vtep_count; ++v) {
            auto vtep = r.bytes(vtep_address_size);
            if (!vtep) {
                return std::unexpected(DecodeError::truncated);
            }
            std::ranges::copy(*vtep, g.vteps.emplace_back().begin());
        }
    }
    auto signature = r.bytes(ed25519_signature_size);
    if (!signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = detail::check_group_members(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a GroupMembers frame (with whatever is in `signature`),
// enforcing every rule decode_group_members checks.
[[nodiscard]] inline auto encode_group_members(const GroupMembers& m)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_group_members(m); !ok) {
        return std::unexpected(ok.error());
    }
    std::size_t vteps = 0;
    for (const auto& g : m.groups) {
        vteps += g.vteps.size();
    }
    std::vector<std::byte> out;
    out.reserve(group_members_size(m.groups.size(), vteps));
    wire::Writer w{out};
    w.le32(group_members_magic);
    w.le16(group_members_version);
    w.le16(m.key_id);
    w.le64(m.server_id);
    w.le32(m.vni);
    w.le16(static_cast<std::uint16_t>(m.groups.size()));
    w.le16(0);
    w.le64(m.members_version);
    for (const auto& g : m.groups) {
        w.u8(static_cast<std::uint8_t>(g.family));
        w.u8(static_cast<std::uint8_t>(g.vteps.size()));
        w.bytes(std::array<std::byte, 6>{});
        w.bytes(g.group);
        for (const auto& v : g.vteps) {
            w.bytes(v);
        }
    }
    w.bytes(m.signature);
    return out;
}

}  // namespace ak::proto
