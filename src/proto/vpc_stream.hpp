// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VpcStream: one VPC's network state as a signed snapshot plus signed
// deltas (.kiro/specs/fleet-scale-networking/ Requirements 4 and 5,
// design "VPC streams", task 5). Where today's per-VPC frames (MapUpdate,
// VpcConfig, GroupPolicy, GroupMembers, SecurityPolicy) are each a full
// copy re-sent on every change, a stream sends a snapshot once and then
// only what changed, so a 50,000-NIC VPC costs a few hundred bytes per
// change instead of a megabyte.
//
// The controller signs each frame once per VPC change, not per server:
// unlike the per-server frames it names no server, and the same bytes go
// to the frame store (fetched over the bulk channel, task 12) and to
// every helm (link record 32, OarLink vendor type 0x30).
//
// Layout (little-endian):
//   0x00  magic          u32  'AKVS'
//   0x04  version        u16  frame format version (1)
//   0x06  key_id         u16  controller key that signed it; non-zero
//   0x08  vpc_id         u64  the VPC; non-zero, separate from the VNI
//   0x10  vni            u32  the VPC's 24-bit Geneve VNI; non-zero
//   0x14  incarnation    u32  the VNI's reuse count; non-zero
//   0x18  cell_scope     u32  0: every cell
//   0x1C  kind           u8   1 snapshot part, 2 delta
//   0x1D  flags          u8   bit 0: lookup VNI; others zero
//   0x1E  part           u16  snapshot: 0 .. part_count-1; delta: 0
//   0x20  part_count     u16  snapshot: 1 .. max_stream_parts; delta: 1
//   0x22  reserved       [6]  zero
//   0x28  snapshot_id    u64  snapshot: non-zero, one per snapshot; delta: 0
//   0x30  from_sequence  u64  snapshot: 0; delta: first sequence covered, >= 1
//   0x38  to_sequence    u64  snapshot: consistent at; delta: last covered,
//                             >= from_sequence; never 0
//   0x40  record_count   u32  the records that follow
//   0x44  records_len    u32  their bytes, headers included
//   0x48  records        record_count x { type u8 | op u8 (1 put, 2 remove)
//                             | len u16 | body [len] }
//   then  signature      64 bytes, Ed25519 over every byte before it
//
// A frame is at most max_vpc_stream_size bytes (491,624, the largest
// MapUpdate and so proto::max_record_payload), so a 4,096-part snapshot
// holds well over a million NICs.
//
// Records (bodies little-endian; a remove carries only the key, which is
// always the put body's first `key size` bytes):
//
//   type  record              body                                    key size
//    1    NIC binding         nic_id u64 | subnet_id u64 |                  8
//                             owner_vtep [16] | mac [6] | flags u8 |
//                             reserved u8                           (40)
//    2    IPv4 address        address [4] | nic_id u64              (12)    4
//    3    IPv6 address        address [16] | nic_id u64             (24)   16
//    4    VPC settings        gateway_mac [6] | ipv4_block_count u8 |       0
//                             flags u8 (bit 0: ipv6 block) |
//                             dns4_count u8 | dns6_count u8 |
//                             domain_size u8 | reserved u8 |
//                             lease_seconds u32 | reserved u32 |
//                             ipv6_block [16] (zero without the flag)
//                             | blocks x { prefix [4] | length u8 |
//                             reserved [3] } | dns4 x [4] | dns6 x [16]
//                             | domain                     (36 + ...)
//                             put only: a VPC always has its settings
//    5    subnet              subnet_id u64 | ipv4_prefix [4] |             8
//                             table u16 | flags u8 (bit 0: ipv6) |
//                             ipv4_length u8 | ipv6_prefix [16]     (32)
//    6    route table         table u16 | flags u8 (bit 0: main) |          2
//                             reserved [5]                           (8)
//    7    route               table u16 | family u8 (4, 6) |               20
//                             length u8 | prefix [16] | kind u8
//                             (1 local, 2 nic, 3 igw, 4 nat, 5 eigw)
//                             | reserved [3] | target u64           (32)
//    8    gateway             gateway_id u64 | subnet_id u64 |              8
//                             kind u8 (1 igw, 2 eigw, 3 nat) |
//                             address_count u8 | reserved [6] |
//                             addresses x [4]              (24 + 4n)
//    9    NAT port block      gateway_id u64 | address_index u8 |          16
//                             block u8 | reserved [6] |
//                             owner_server u64                      (24)
//   10    security group      group_id u64                           (8)    8
//   11    SG rule             group_id u64 | direction u8 (1 in,          48
//                             2 out) | reserved [7] | the 32-byte
//                             SecurityPolicy rule                   (48)
//   12    membership          nic_id u64 | group_count u8 (1..16) |         8
//                             reserved [7] | group_id x u64,
//                             strictly ascending           (16 + 8n)
//   13    tracking setting    nic_id u64 | tcp_established u32 |            8
//                             udp_stream u16 | udp u16 | max_flows u32
//                             | reserved u32                        (24)
//   14    group policy        subnet_id u64 | rate_frames u32 |             8
//                             burst_frames u32 | rate_bytes u64 |
//                             burst_bytes u64 | max_remote_vteps u32
//                             | max_groups_per_nic u16 | reserved u16 (40)
//   15    group member list   family u8 (4, 6) | reserved [7] |            24
//                             group [16] | vtep_count u16 (1..64) |
//                             reserved [6] | vteps x [16],
//                             strictly ascending          (32 + 16n)
//   16    lookup interest     nic_id u64                             (8)    8
//
// Bodies follow the per-VPC frames they replace: VpcConfig version 3
// (vpc-internet-gateways design) for types 4 to 9, SecurityPolicy
// (vpc-security-groups design) for 10 to 13, GroupPolicy version 2 for
// 14 and GroupMembers for 15. A route carries its table and a gateway's
// NAT port blocks are their own records, because a stream changes them
// one at a time.
//
// Rules (check_vpc_stream; the role checks them again):
//   - Every body obeys its type's field rules, which are the frame's it
//     replaces: non-zero IDs, locally administered unicast MACs, unicast
//     VTEPs and guest addresses, prefixes with no bits past their length,
//     known kinds, limits in range, reserved bytes zero.
//   - A snapshot part holds only puts, in strictly ascending (type, key)
//     order, comparing a key's integers by value and its addresses as
//     bytes; a remove would mean nothing there.
//   - A delta holds puts and removes in change order; the same key may
//     appear more than once. Type 4 is never removed.
//   - Cross-record rules (an address naming a missing NIC, two NICs with
//     one MAC, a route to an unknown table, budgets) need the VNI's state
//     and belong to the StreamApplier (task 6), which refuses a whole
//     delta that breaks one.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/group_members.hpp"
#include "proto/group_policy.hpp"
#include "proto/map_update.hpp"
#include "proto/vpc_config.hpp"

namespace ak::proto {

inline constexpr std::uint32_t vpc_stream_magic = 0x5356'4B41;  // "AKVS" as little-endian bytes
inline constexpr std::uint16_t vpc_stream_version = 1;
inline constexpr std::size_t vpc_stream_header_size = 0x48;
inline constexpr std::size_t stream_record_header_size = 4;
inline constexpr std::size_t max_stream_parts = 4096;
inline constexpr std::uint8_t vpc_stream_flag_lookup = 0x01;
// The largest frame: the largest MapUpdate (491,624 bytes, which sets
// proto::max_record_payload), so streams do not grow it.
inline constexpr std::size_t max_vpc_stream_size = max_map_update_size;
static_assert(max_vpc_stream_size == 491'624);
inline constexpr std::size_t min_vpc_stream_size = vpc_stream_header_size + ed25519_signature_size;
inline constexpr std::size_t max_stream_records =
    (max_vpc_stream_size - min_vpc_stream_size) / stream_record_header_size;

// Values are part of the wire protocol: never renumber.
enum class StreamKind : std::uint8_t {
    snapshot = 1,
    delta = 2,
};

// Values are part of the wire protocol: never renumber.
enum class StreamOp : std::uint8_t {
    put = 1,
    remove = 2,
};

// Values are part of the wire protocol: never renumber.
enum class StreamRecordType : std::uint8_t {
    nic_binding = 1,
    ipv4_address = 2,
    ipv6_address = 3,
    vpc_settings = 4,
    subnet = 5,
    route_table = 6,
    route = 7,
    gateway = 8,
    nat_port_block = 9,
    security_group = 10,
    sg_rule = 11,
    membership = 12,
    tracking = 13,
    group_policy = 14,
    group_member_list = 15,
    lookup_interest = 16,
};

// Values are part of the wire protocol: never renumber.
enum class StreamRouteKind : std::uint8_t {
    local = 1,
    nic = 2,
    igw = 3,
    nat = 4,
    eigw = 5,
};

// Values are part of the wire protocol: never renumber.
enum class StreamGatewayKind : std::uint8_t {
    igw = 1,
    eigw = 2,
    nat = 3,
};

inline constexpr std::size_t stream_nic_binding_size = 40;
inline constexpr std::size_t stream_ipv4_address_size = 12;
inline constexpr std::size_t stream_ipv6_address_size = 24;
inline constexpr std::size_t stream_settings_fixed_size = 36;
inline constexpr std::size_t stream_subnet_size = 32;
inline constexpr std::size_t stream_route_table_size = 8;
inline constexpr std::size_t stream_route_size = 32;
inline constexpr std::size_t stream_gateway_fixed_size = 24;
inline constexpr std::size_t stream_nat_block_size = 24;
inline constexpr std::size_t stream_security_group_size = 8;
inline constexpr std::size_t stream_sg_rule_size = 48;
inline constexpr std::size_t stream_membership_fixed_size = 16;
inline constexpr std::size_t stream_tracking_size = 24;
inline constexpr std::size_t stream_group_policy_size = 40;
inline constexpr std::size_t stream_member_list_fixed_size = 32;
inline constexpr std::size_t stream_lookup_interest_size = 8;
inline constexpr std::size_t max_stream_nat_addresses = 8;
inline constexpr std::uint8_t max_stream_nat_block = 62;   // ports 1024 + 1024 x block ..
inline constexpr std::size_t max_stream_memberships = 16;  // groups per NIC
inline constexpr std::uint32_t min_tcp_established = 60;
inline constexpr std::uint32_t max_tcp_established = 432'000;
inline constexpr std::uint16_t min_udp_stream = 60;
inline constexpr std::uint16_t max_udp_stream = 180;
inline constexpr std::uint16_t min_udp_timeout = 30;
inline constexpr std::uint16_t max_udp_timeout = 60;
inline constexpr std::uint32_t max_tracked_flows = 1U << 24U;

struct StreamRecord {
    StreamRecordType type{StreamRecordType::nic_binding};
    StreamOp op{StreamOp::put};
    std::vector<std::byte> body;  // the put body, or the key for a remove

    friend auto operator==(const StreamRecord&, const StreamRecord&) -> bool = default;
};

struct VpcStream {
    KeyId key_id{no_key_id};
    std::uint64_t vpc_id{0};
    std::uint32_t vni{0};
    std::uint32_t incarnation{0};
    std::uint32_t cell_scope{0};
    StreamKind kind{StreamKind::delta};
    bool lookup{false};
    std::uint16_t part{0};
    std::uint16_t part_count{1};
    std::uint64_t snapshot_id{0};
    std::uint64_t from_sequence{0};
    std::uint64_t to_sequence{0};
    std::vector<StreamRecord> records;
    Ed25519Signature signature{};

    friend auto operator==(const VpcStream&, const VpcStream&) -> bool = default;
};

// The bytes a VpcStream signature covers: all but the trailing 64.
[[nodiscard]] inline auto vpc_stream_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

inline auto set_vpc_stream_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= min_vpc_stream_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

// How many key bytes a record type has: the put body's leading bytes,
// and the whole of a remove's body. Zero for an unknown type.
[[nodiscard]] constexpr auto stream_key_size(StreamRecordType t) noexcept -> std::size_t {
    switch (t) {
        case StreamRecordType::nic_binding:
        case StreamRecordType::subnet:
        case StreamRecordType::gateway:
        case StreamRecordType::security_group:
        case StreamRecordType::membership:
        case StreamRecordType::tracking:
        case StreamRecordType::group_policy:
        case StreamRecordType::lookup_interest:
            return 8;
        case StreamRecordType::ipv4_address:
            return ipv4_address_size;
        case StreamRecordType::ipv6_address:
            return ipv6_address_size;
        case StreamRecordType::vpc_settings:
            return 0;
        case StreamRecordType::route_table:
            return 2;
        case StreamRecordType::route:
            return 20;
        case StreamRecordType::nat_port_block:
            return 16;
        case StreamRecordType::sg_rule:
            return stream_sg_rule_size;
        case StreamRecordType::group_member_list:
            return 24;
    }
    return 0;
}

[[nodiscard]] constexpr auto known(StreamRecordType t) noexcept -> bool {
    return t >= StreamRecordType::nic_binding && t <= StreamRecordType::lookup_interest;
}

namespace detail {

[[nodiscard]] inline auto stream_le64(std::span<const std::byte> b, std::size_t at) noexcept
    -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        v |= std::to_integer<std::uint64_t>(b[at + i]) << (8U * i);
    }
    return v;
}

[[nodiscard]] inline auto stream_le32(std::span<const std::byte> b, std::size_t at) noexcept
    -> std::uint32_t {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        v |= std::to_integer<std::uint32_t>(b[at + i]) << (8U * i);
    }
    return v;
}

[[nodiscard]] inline auto stream_le16(std::span<const std::byte> b, std::size_t at) noexcept
    -> std::uint16_t {
    return static_cast<std::uint16_t>(std::to_integer<unsigned>(b[at]) |
                                      (std::to_integer<unsigned>(b[at + 1]) << 8U));
}

[[nodiscard]] inline auto stream_u8(std::span<const std::byte> b, std::size_t at) noexcept
    -> std::uint8_t {
    return std::to_integer<std::uint8_t>(b[at]);
}

[[nodiscard]] inline auto stream_zero(std::span<const std::byte> b, std::size_t at,
                                      std::size_t n) noexcept -> bool {
    return all_zero(b.subspan(at, n));
}

[[nodiscard]] inline auto stream_nic(std::uint64_t id) noexcept -> bool {
    return id != 0 && id != vpc_route_nic_broadcast;
}

[[nodiscard]] inline auto stream_mac(std::span<const std::byte> b, std::size_t at) noexcept
    -> bool {
    const auto mac0 = stream_u8(b, at);
    return (mac0 & mac_multicast_bit) == 0 && (mac0 & mac_local_bit) != 0;
}

[[nodiscard]] inline auto stream_ipv4(std::span<const std::byte> b, std::size_t at) noexcept
    -> Ipv4Address {
    Ipv4Address a{};
    std::ranges::copy(b.subspan(at, ipv4_address_size), a.begin());
    return a;
}

[[nodiscard]] inline auto stream_ipv6(std::span<const std::byte> b, std::size_t at) noexcept
    -> Ipv6Address {
    Ipv6Address a{};
    std::ranges::copy(b.subspan(at, ipv6_address_size), a.begin());
    return a;
}

// An IPv4 prefix of a VPC block or subnet: /16 to /28, no host bits.
[[nodiscard]] inline auto stream_vpc_prefix4(std::span<const std::byte> prefix,
                                             std::uint8_t length) noexcept -> bool {
    return length >= min_vpc_ipv4_length && length <= max_vpc_ipv4_length &&
           vpc_host_bits_clear(prefix, length);
}

// A route's family, length and prefix: the key's bytes after the table.
[[nodiscard]] inline auto check_stream_route_key(std::span<const std::byte> b) noexcept
    -> std::expected<void, DecodeError> {
    const auto family = stream_u8(b, 2);
    const auto length = stream_u8(b, 3);
    const auto prefix = b.subspan(4, ipv6_address_size);
    if (family == static_cast<std::uint8_t>(RouteFamily::ipv4)) {
        if (length > 32 || !all_zero(prefix.subspan(ipv4_address_size)) ||
            !vpc_host_bits_clear(prefix, length)) {
            return std::unexpected(DecodeError::bad_route);
        }
        return {};
    }
    if (family == static_cast<std::uint8_t>(RouteFamily::ipv6)) {
        if (length > 128 || !vpc_host_bits_clear(prefix, length)) {
            return std::unexpected(DecodeError::bad_route);
        }
        return {};
    }
    return std::unexpected(DecodeError::unknown_value);
}

// A SecurityPolicy rule (vpc-security-groups design), 32 bytes.
[[nodiscard]] inline auto check_stream_sg_rule(std::span<const std::byte> r) noexcept
    -> std::expected<void, DecodeError> {
    constexpr std::uint8_t all_protocols = 0x01;
    constexpr std::uint8_t peer_group = 0x02;
    constexpr std::uint8_t icmp = 1;
    constexpr std::uint8_t tcp = 6;
    constexpr std::uint8_t udp = 17;
    constexpr std::uint8_t icmpv6 = 58;
    constexpr std::uint16_t any = 0xFFFF;
    constexpr std::uint16_t max_icmp_value = 255;
    const auto protocol = stream_u8(r, 0);
    const auto flags = stream_u8(r, 1);
    const auto family = stream_u8(r, 2);
    const auto length = stream_u8(r, 3);
    const auto from = stream_le16(r, 4);
    const auto to = stream_le16(r, 6);
    const auto peer = r.subspan(16, ipv6_address_size);
    if ((flags & ~(all_protocols | peer_group)) != 0 || !stream_zero(r, 8, 8)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if ((flags & peer_group) != 0) {
        if (family != 0 || length != 0 || stream_le64(peer, 0) == 0 || !all_zero(peer.subspan(8))) {
            return std::unexpected(DecodeError::bad_stream_record);
        }
    } else if (family == static_cast<std::uint8_t>(RouteFamily::ipv4)) {
        if (length > 32 || !all_zero(peer.subspan(ipv4_address_size)) ||
            !vpc_host_bits_clear(peer, length)) {
            return std::unexpected(DecodeError::bad_route);
        }
    } else if (family == static_cast<std::uint8_t>(RouteFamily::ipv6)) {
        if (length > 128 || !vpc_host_bits_clear(peer, length)) {
            return std::unexpected(DecodeError::bad_route);
        }
    } else {
        return std::unexpected(DecodeError::unknown_value);
    }
    if ((flags & all_protocols) != 0) {
        return protocol == 0 && from == 0 && to == 0
                   ? std::expected<void, DecodeError>{}
                   : std::unexpected(DecodeError::bad_stream_record);
    }
    if (protocol == tcp || protocol == udp) {
        return from <= to ? std::expected<void, DecodeError>{}
                          : std::unexpected(DecodeError::bad_stream_record);
    }
    if (protocol == icmp || protocol == icmpv6) {
        const bool type_ok = from <= max_icmp_value || from == any;
        const bool code_ok = to <= max_icmp_value || to == any;
        const bool code_needs_type = to == any || from != any;
        const auto want = protocol == icmp ? RouteFamily::ipv4 : RouteFamily::ipv6;
        const bool family_ok =
            (flags & peer_group) != 0 || family == static_cast<std::uint8_t>(want);
        return type_ok && code_ok && code_needs_type && family_ok
                   ? std::expected<void, DecodeError>{}
                   : std::unexpected(DecodeError::bad_stream_record);
    }
    return from == 0 && to == 0 ? std::expected<void, DecodeError>{}
                                : std::unexpected(DecodeError::bad_stream_record);
}

// Type 4's variable body.
[[nodiscard]] inline auto check_stream_settings(std::span<const std::byte> b) noexcept
    -> std::expected<void, DecodeError> {
    if (b.size() < stream_settings_fixed_size) {
        return std::unexpected(DecodeError::truncated);
    }
    const auto blocks = stream_u8(b, 6);
    const auto flags = stream_u8(b, 7);
    const auto dns4 = stream_u8(b, 8);
    const auto dns6 = stream_u8(b, 9);
    const auto domain_size = stream_u8(b, 10);
    const auto lease = stream_le32(b, 12);
    const std::size_t want = stream_settings_fixed_size + (blocks * vpc_ipv4_block_size) +
                             (dns4 * ipv4_address_size) + (dns6 * ipv6_address_size) + domain_size;
    if (b.size() != want) {
        return std::unexpected(b.size() < want ? DecodeError::truncated
                                               : DecodeError::trailing_bytes);
    }
    if (!stream_mac(b, 0)) {
        return std::unexpected(DecodeError::bad_mac);
    }
    if ((flags & ~vpc_flag_ipv6) != 0 || stream_u8(b, 11) != 0 || stream_le32(b, 16) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (blocks == 0 || blocks > max_vpc_ipv4_blocks || dns4 > max_vpc_dns || dns6 > max_vpc_dns ||
        domain_size > max_vpc_domain_size || lease < min_vpc_lease_seconds ||
        lease > max_vpc_lease_seconds) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    const auto v6 = stream_ipv6(b, 20);
    if ((flags & vpc_flag_ipv6) != 0 ? !vpc_valid_ipv6_block(v6) : !all_zero(v6)) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    std::size_t at = stream_settings_fixed_size;
    std::vector<VpcIpv4Block> seen;
    for (std::uint8_t i = 0; i < blocks; ++i, at += vpc_ipv4_block_size) {
        const VpcIpv4Block block{.prefix = stream_ipv4(b, at), .length = stream_u8(b, at + 4)};
        if (!stream_zero(b, at + 5, 3)) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        if (!stream_vpc_prefix4(block.prefix, block.length)) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
        for (const auto& other : seen) {
            if (vpc_overlap4(other.prefix, other.length, block.prefix, block.length)) {
                return std::unexpected(DecodeError::bad_vpc_config);
            }
        }
        seen.push_back(block);
    }
    for (std::uint8_t i = 0; i < dns4; ++i, at += ipv4_address_size) {
        if (!unicast(stream_ipv4(b, at))) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
    }
    for (std::uint8_t i = 0; i < dns6; ++i, at += ipv6_address_size) {
        if (!unicast(stream_ipv6(b, at))) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
    }
    const std::string_view domain{reinterpret_cast<const char*>(b.data() + at), domain_size};
    if (domain_size != 0 && !vpc_valid_domain(domain)) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    return {};
}

// One put body by its type's rules (sizes included).
[[nodiscard]] inline auto check_stream_put(StreamRecordType type,
                                           std::span<const std::byte> b) noexcept
    -> std::expected<void, DecodeError> {
    const auto size_is = [&b](std::size_t n) -> std::expected<void, DecodeError> {
        if (b.size() != n) {
            return std::unexpected(b.size() < n ? DecodeError::truncated
                                                : DecodeError::trailing_bytes);
        }
        return {};
    };
    const auto fail = [](DecodeError e) {
        return std::expected<void, DecodeError>{std::unexpect, e};
    };
    switch (type) {
        case StreamRecordType::nic_binding: {
            if (auto ok = size_is(stream_nic_binding_size); !ok) {
                return ok;
            }
            if (!stream_nic(stream_le64(b, 0))) {
                return fail(DecodeError::bad_nic_id);
            }
            if (!unicast(stream_ipv6(b, 16))) {
                return fail(DecodeError::bad_vtep);
            }
            if (!stream_mac(b, 32)) {
                return fail(DecodeError::bad_mac);
            }
            if ((stream_u8(b, 38) & ~map_entry_known_flags) != 0 || stream_u8(b, 39) != 0) {
                return fail(DecodeError::reserved_not_zero);
            }
            return {};
        }
        case StreamRecordType::ipv4_address:
            if (auto ok = size_is(stream_ipv4_address_size); !ok) {
                return ok;
            }
            if (!unicast(stream_ipv4(b, 0))) {
                return fail(DecodeError::bad_guest_address);
            }
            return stream_nic(stream_le64(b, 4)) ? std::expected<void, DecodeError>{}
                                                 : fail(DecodeError::bad_nic_id);
        case StreamRecordType::ipv6_address:
            if (auto ok = size_is(stream_ipv6_address_size); !ok) {
                return ok;
            }
            if (!unicast(stream_ipv6(b, 0))) {
                return fail(DecodeError::bad_guest_address);
            }
            return stream_nic(stream_le64(b, 16)) ? std::expected<void, DecodeError>{}
                                                  : fail(DecodeError::bad_nic_id);
        case StreamRecordType::vpc_settings:
            return check_stream_settings(b);
        case StreamRecordType::subnet: {
            if (auto ok = size_is(stream_subnet_size); !ok) {
                return ok;
            }
            const auto flags = stream_u8(b, 14);
            if (stream_le64(b, 0) == 0) {
                return fail(DecodeError::bad_id);
            }
            if ((flags & ~vpc_subnet_flag_ipv6) != 0) {
                return fail(DecodeError::reserved_not_zero);
            }
            if (!stream_vpc_prefix4(b.subspan(8, ipv4_address_size), stream_u8(b, 15))) {
                return fail(DecodeError::bad_vpc_config);
            }
            const auto v6 = b.subspan(16, ipv6_address_size);
            const bool v6_ok =
                (flags & vpc_subnet_flag_ipv6) != 0
                    ? !all_zero(v6) && vpc_host_bits_clear(v6, vpc_ipv6_subnet_length)
                    : all_zero(v6);
            return v6_ok ? std::expected<void, DecodeError>{} : fail(DecodeError::bad_vpc_config);
        }
        case StreamRecordType::route_table:
            if (auto ok = size_is(stream_route_table_size); !ok) {
                return ok;
            }
            if ((stream_u8(b, 2) & ~vpc_table_flag_main) != 0 || !stream_zero(b, 3, 5)) {
                return fail(DecodeError::reserved_not_zero);
            }
            return {};
        case StreamRecordType::route: {
            if (auto ok = size_is(stream_route_size); !ok) {
                return ok;
            }
            if (auto ok = check_stream_route_key(b); !ok) {
                return ok;
            }
            if (!stream_zero(b, 21, 3)) {
                return fail(DecodeError::reserved_not_zero);
            }
            const auto family = static_cast<RouteFamily>(stream_u8(b, 2));
            const auto target = stream_le64(b, 24);
            switch (static_cast<StreamRouteKind>(stream_u8(b, 20))) {
                case StreamRouteKind::local:
                    return target == 0 ? std::expected<void, DecodeError>{}
                                       : fail(DecodeError::bad_route);
                case StreamRouteKind::nic:
                    return stream_nic(target) ? std::expected<void, DecodeError>{}
                                              : fail(DecodeError::bad_nic_id);
                case StreamRouteKind::igw:
                    return target != 0 ? std::expected<void, DecodeError>{}
                                       : fail(DecodeError::bad_route);
                case StreamRouteKind::nat:
                    return target != 0 && family == RouteFamily::ipv4
                               ? std::expected<void, DecodeError>{}
                               : fail(DecodeError::bad_route);
                case StreamRouteKind::eigw:
                    return target != 0 && family == RouteFamily::ipv6
                               ? std::expected<void, DecodeError>{}
                               : fail(DecodeError::bad_route);
            }
            return fail(DecodeError::unknown_value);
        }
        case StreamRecordType::gateway: {
            if (b.size() < stream_gateway_fixed_size) {
                return fail(DecodeError::truncated);
            }
            const auto count = stream_u8(b, 17);
            if (auto ok = size_is(stream_gateway_fixed_size + (count * ipv4_address_size)); !ok) {
                return ok;
            }
            if (stream_le64(b, 0) == 0) {
                return fail(DecodeError::bad_id);
            }
            if (!stream_zero(b, 18, 6)) {
                return fail(DecodeError::reserved_not_zero);
            }
            const auto subnet = stream_le64(b, 8);
            switch (static_cast<StreamGatewayKind>(stream_u8(b, 16))) {
                case StreamGatewayKind::igw:
                case StreamGatewayKind::eigw:
                    return count == 0 && subnet == 0 ? std::expected<void, DecodeError>{}
                                                     : fail(DecodeError::bad_stream_record);
                case StreamGatewayKind::nat: {
                    if (count == 0 || count > max_stream_nat_addresses || subnet == 0) {
                        return fail(DecodeError::bad_stream_record);
                    }
                    for (std::size_t i = 0; i < count; ++i) {
                        const auto a = stream_ipv4(b, stream_gateway_fixed_size + (4 * i));
                        if (!unicast(a)) {
                            return fail(DecodeError::bad_guest_address);
                        }
                        for (std::size_t j = 0; j < i; ++j) {
                            if (stream_ipv4(b, stream_gateway_fixed_size + (4 * j)) == a) {
                                return fail(DecodeError::bad_stream_record);
                            }
                        }
                    }
                    return {};
                }
            }
            return fail(DecodeError::unknown_value);
        }
        case StreamRecordType::nat_port_block:
            if (auto ok = size_is(stream_nat_block_size); !ok) {
                return ok;
            }
            if (stream_le64(b, 0) == 0 || stream_le64(b, 16) == 0) {
                return fail(DecodeError::bad_id);
            }
            if (!stream_zero(b, 10, 6)) {
                return fail(DecodeError::reserved_not_zero);
            }
            return stream_u8(b, 8) < max_stream_nat_addresses &&
                           stream_u8(b, 9) <= max_stream_nat_block
                       ? std::expected<void, DecodeError>{}
                       : fail(DecodeError::bad_stream_record);
        case StreamRecordType::security_group:
            if (auto ok = size_is(stream_security_group_size); !ok) {
                return ok;
            }
            return stream_le64(b, 0) != 0 ? std::expected<void, DecodeError>{}
                                          : fail(DecodeError::bad_id);
        case StreamRecordType::sg_rule: {
            if (auto ok = size_is(stream_sg_rule_size); !ok) {
                return ok;
            }
            if (stream_le64(b, 0) == 0) {
                return fail(DecodeError::bad_id);
            }
            const auto direction = stream_u8(b, 8);
            if (direction != 1 && direction != 2) {
                return fail(DecodeError::unknown_value);
            }
            if (!stream_zero(b, 9, 7)) {
                return fail(DecodeError::reserved_not_zero);
            }
            return check_stream_sg_rule(b.subspan(16));
        }
        case StreamRecordType::membership: {
            if (b.size() < stream_membership_fixed_size) {
                return fail(DecodeError::truncated);
            }
            const auto count = stream_u8(b, 8);
            if (auto ok = size_is(stream_membership_fixed_size + (count * std::size_t{8})); !ok) {
                return ok;
            }
            if (!stream_nic(stream_le64(b, 0))) {
                return fail(DecodeError::bad_nic_id);
            }
            if (!stream_zero(b, 9, 7)) {
                return fail(DecodeError::reserved_not_zero);
            }
            if (count == 0 || count > max_stream_memberships) {
                return fail(DecodeError::too_many_entries);
            }
            std::uint64_t prev = 0;
            for (std::size_t i = 0; i < count; ++i) {
                const auto g = stream_le64(b, stream_membership_fixed_size + (8 * i));
                if (g == 0) {
                    return fail(DecodeError::bad_id);
                }
                if (g <= prev) {
                    return fail(DecodeError::not_ascending);
                }
                prev = g;
            }
            return {};
        }
        case StreamRecordType::tracking: {
            if (auto ok = size_is(stream_tracking_size); !ok) {
                return ok;
            }
            if (!stream_nic(stream_le64(b, 0))) {
                return fail(DecodeError::bad_nic_id);
            }
            const auto tcp = stream_le32(b, 8);
            const auto udp_stream = stream_le16(b, 12);
            const auto udp = stream_le16(b, 14);
            const auto flows = stream_le32(b, 16);
            if (stream_le32(b, 20) != 0) {
                return fail(DecodeError::reserved_not_zero);
            }
            return tcp >= min_tcp_established && tcp <= max_tcp_established &&
                           udp_stream >= min_udp_stream && udp_stream <= max_udp_stream &&
                           udp >= min_udp_timeout && udp <= max_udp_timeout &&
                           flows <= max_tracked_flows
                       ? std::expected<void, DecodeError>{}
                       : fail(DecodeError::bad_stream_record);
        }
        case StreamRecordType::group_policy:
            if (auto ok = size_is(stream_group_policy_size); !ok) {
                return ok;
            }
            if (stream_le64(b, 0) == 0) {
                return fail(DecodeError::bad_id);
            }
            if (stream_le16(b, 38) != 0) {
                return fail(DecodeError::reserved_not_zero);
            }
            return multicast_limits_ok(stream_le32(b, 8), stream_le32(b, 12), stream_le64(b, 16),
                                       stream_le64(b, 24), stream_le32(b, 32), stream_le16(b, 36))
                       ? std::expected<void, DecodeError>{}
                       : fail(DecodeError::bad_group_limits);
        case StreamRecordType::group_member_list: {
            if (b.size() < stream_member_list_fixed_size) {
                return fail(DecodeError::truncated);
            }
            const auto count = stream_le16(b, 24);
            if (auto ok = size_is(stream_member_list_fixed_size + (count * vtep_address_size));
                !ok) {
                return ok;
            }
            const auto family = stream_u8(b, 0);
            if (family != static_cast<std::uint8_t>(RouteFamily::ipv4) &&
                family != static_cast<std::uint8_t>(RouteFamily::ipv6)) {
                return fail(DecodeError::unknown_value);
            }
            if (!stream_zero(b, 1, 7) || !stream_zero(b, 26, 6)) {
                return fail(DecodeError::reserved_not_zero);
            }
            if (!valid_member_group(static_cast<RouteFamily>(family), stream_ipv6(b, 8))) {
                return fail(DecodeError::bad_group);
            }
            if (count == 0 || count > max_group_vteps) {
                return fail(DecodeError::too_many_entries);
            }
            for (std::size_t i = 0; i < count; ++i) {
                const auto v = stream_ipv6(b, stream_member_list_fixed_size + (16 * i));
                if (!unicast(v)) {
                    return fail(DecodeError::bad_vtep);
                }
                if (i > 0 &&
                    !(stream_ipv6(b, stream_member_list_fixed_size + (16 * (i - 1))) < v)) {
                    return fail(DecodeError::not_ascending);
                }
            }
            return {};
        }
        case StreamRecordType::lookup_interest:
            if (auto ok = size_is(stream_lookup_interest_size); !ok) {
                return ok;
            }
            return stream_nic(stream_le64(b, 0)) ? std::expected<void, DecodeError>{}
                                                 : fail(DecodeError::bad_nic_id);
    }
    return fail(DecodeError::unknown_value);
}

// One remove body: exactly the type's key, by the key fields' rules.
[[nodiscard]] inline auto check_stream_remove(StreamRecordType type,
                                              std::span<const std::byte> b) noexcept
    -> std::expected<void, DecodeError> {
    if (type == StreamRecordType::vpc_settings) {
        return std::unexpected(DecodeError::bad_stream_record);
    }
    const auto n = stream_key_size(type);
    if (b.size() != n) {
        return std::unexpected(b.size() < n ? DecodeError::truncated : DecodeError::trailing_bytes);
    }
    switch (type) {
        case StreamRecordType::nic_binding:
        case StreamRecordType::membership:
        case StreamRecordType::tracking:
        case StreamRecordType::lookup_interest:
            return stream_nic(stream_le64(b, 0)) ? std::expected<void, DecodeError>{}
                                                 : std::unexpected(DecodeError::bad_nic_id);
        case StreamRecordType::subnet:
        case StreamRecordType::gateway:
        case StreamRecordType::security_group:
        case StreamRecordType::group_policy:
            return stream_le64(b, 0) != 0 ? std::expected<void, DecodeError>{}
                                          : std::unexpected(DecodeError::bad_id);
        case StreamRecordType::ipv4_address:
            return unicast(stream_ipv4(b, 0)) ? std::expected<void, DecodeError>{}
                                              : std::unexpected(DecodeError::bad_guest_address);
        case StreamRecordType::ipv6_address:
            return unicast(stream_ipv6(b, 0)) ? std::expected<void, DecodeError>{}
                                              : std::unexpected(DecodeError::bad_guest_address);
        case StreamRecordType::route_table:
            return {};
        case StreamRecordType::route:
            return check_stream_route_key(b);
        case StreamRecordType::nat_port_block:
            if (stream_le64(b, 0) == 0) {
                return std::unexpected(DecodeError::bad_id);
            }
            if (!stream_zero(b, 10, 6)) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            return stream_u8(b, 8) < max_stream_nat_addresses &&
                           stream_u8(b, 9) <= max_stream_nat_block
                       ? std::expected<void, DecodeError>{}
                       : std::unexpected(DecodeError::bad_stream_record);
        case StreamRecordType::sg_rule:
            return check_stream_put(type, b);  // the key is the whole rule
        case StreamRecordType::group_member_list: {
            const auto family = stream_u8(b, 0);
            if (family != static_cast<std::uint8_t>(RouteFamily::ipv4) &&
                family != static_cast<std::uint8_t>(RouteFamily::ipv6)) {
                return std::unexpected(DecodeError::unknown_value);
            }
            if (!stream_zero(b, 1, 7)) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            return valid_member_group(static_cast<RouteFamily>(family), stream_ipv6(b, 8))
                       ? std::expected<void, DecodeError>{}
                       : std::unexpected(DecodeError::bad_group);
        }
        case StreamRecordType::vpc_settings:
            break;
    }
    return std::unexpected(DecodeError::unknown_value);
}

// A key in the order snapshots sort by: integers big-endian (so bytes
// compare as values), addresses as they are, fields in the key's order
// (a route sorts by table, family, prefix, then length).
[[nodiscard]] inline auto stream_sort_key(StreamRecordType type, std::span<const std::byte> body)
    -> std::vector<std::byte> {
    std::vector<std::byte> k;
    const auto be = [&k, &body](std::size_t at, std::size_t n) {
        for (std::size_t i = n; i > 0; --i) {
            k.push_back(body[at + i - 1]);
        }
    };
    const auto raw = [&k, &body](std::size_t at, std::size_t n) {
        const auto s = body.subspan(at, n);
        k.insert(k.end(), s.begin(), s.end());
    };
    switch (type) {
        case StreamRecordType::ipv4_address:
            raw(0, ipv4_address_size);
            break;
        case StreamRecordType::ipv6_address:
            raw(0, ipv6_address_size);
            break;
        case StreamRecordType::vpc_settings:
            break;
        case StreamRecordType::route_table:
            be(0, 2);
            break;
        case StreamRecordType::route:
            be(0, 2);
            raw(2, 1);
            raw(4, ipv6_address_size);
            raw(3, 1);
            break;
        case StreamRecordType::nat_port_block:
            be(0, 8);
            raw(8, 2);
            break;
        case StreamRecordType::sg_rule:
            be(0, 8);
            raw(8, stream_sg_rule_size - 8);
            break;
        case StreamRecordType::group_member_list:
            raw(0, 1);
            raw(8, ipv6_address_size);
            break;
        case StreamRecordType::nic_binding:
        case StreamRecordType::subnet:
        case StreamRecordType::gateway:
        case StreamRecordType::security_group:
        case StreamRecordType::membership:
        case StreamRecordType::tracking:
        case StreamRecordType::group_policy:
        case StreamRecordType::lookup_interest:
            be(0, 8);
            break;
    }
    return k;
}

[[nodiscard]] inline auto check_stream_header(const VpcStream& s) noexcept
    -> std::expected<void, DecodeError> {
    if (s.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (s.vpc_id == 0 || s.incarnation == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (s.vni == 0 || s.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (s.to_sequence == 0) {
        return std::unexpected(DecodeError::bad_stream_header);
    }
    switch (s.kind) {
        case StreamKind::snapshot:
            if (s.part_count == 0 || s.part_count > max_stream_parts || s.part >= s.part_count ||
                s.snapshot_id == 0 || s.from_sequence != 0) {
                return std::unexpected(DecodeError::bad_stream_header);
            }
            return {};
        case StreamKind::delta:
            if (s.part != 0 || s.part_count != 1 || s.snapshot_id != 0 || s.from_sequence == 0 ||
                s.from_sequence > s.to_sequence) {
                return std::unexpected(DecodeError::bad_stream_header);
            }
            return {};
    }
    return std::unexpected(DecodeError::unknown_value);
}

[[nodiscard]] inline auto check_vpc_stream(const VpcStream& s) -> std::expected<void, DecodeError> {
    if (auto ok = check_stream_header(s); !ok) {
        return ok;
    }
    if (s.records.size() > max_stream_records) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    std::size_t size = min_vpc_stream_size;
    std::vector<std::byte> prev_key;
    std::uint8_t prev_type = 0;
    for (const auto& r : s.records) {
        size += stream_record_header_size + r.body.size();
        if (size > max_vpc_stream_size || r.body.size() > UINT16_MAX) {
            return std::unexpected(DecodeError::record_too_large);
        }
        if (!known(r.type)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (r.op == StreamOp::put) {
            if (auto ok = check_stream_put(r.type, r.body); !ok) {
                return ok;
            }
        } else if (r.op == StreamOp::remove) {
            if (s.kind == StreamKind::snapshot) {
                return std::unexpected(DecodeError::bad_stream_record);
            }
            if (auto ok = check_stream_remove(r.type, r.body); !ok) {
                return ok;
            }
        } else {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (s.kind == StreamKind::snapshot) {
            const auto type = static_cast<std::uint8_t>(r.type);
            auto key = stream_sort_key(r.type, r.body);
            if (type < prev_type || (type == prev_type && !(prev_key < key))) {
                return std::unexpected(DecodeError::not_ascending);
            }
            prev_type = type;
            prev_key = std::move(key);
        }
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// vpc_stream_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_vpc_stream(std::span<const std::byte> bytes)
    -> std::expected<VpcStream, DecodeError> {
    if (bytes.size() > max_vpc_stream_size) {
        return std::unexpected(DecodeError::record_too_large);
    }
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto vpc_id = r.le64();
    auto vni = r.le32();
    auto incarnation = r.le32();
    auto cell_scope = r.le32();
    auto kind = r.u8();
    auto flags = r.u8();
    auto part = r.le16();
    auto part_count = r.le16();
    auto reserved = r.bytes(6);
    auto snapshot_id = r.le64();
    auto from = r.le64();
    auto to = r.le64();
    auto record_count = r.le32();
    auto records_len = r.le32();
    if (!magic || !version || !key_id || !vpc_id || !vni || !incarnation || !cell_scope || !kind ||
        !flags || !part || !part_count || !reserved || !snapshot_id || !from || !to ||
        !record_count || !records_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != vpc_stream_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != vpc_stream_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if ((*flags & ~vpc_stream_flag_lookup) != 0 || !detail::all_zero(*reserved)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*kind != static_cast<std::uint8_t>(StreamKind::snapshot) &&
        *kind != static_cast<std::uint8_t>(StreamKind::delta)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (*record_count > max_stream_records || r.remaining() < ed25519_signature_size ||
        *records_len != r.remaining() - ed25519_signature_size) {
        return std::unexpected(*record_count > max_stream_records ? DecodeError::too_many_entries
                                                                  : DecodeError::bad_stream_header);
    }
    VpcStream out{.key_id = *key_id,
                  .vpc_id = *vpc_id,
                  .vni = *vni,
                  .incarnation = *incarnation,
                  .cell_scope = *cell_scope,
                  .kind = static_cast<StreamKind>(*kind),
                  .lookup = (*flags & vpc_stream_flag_lookup) != 0,
                  .part = *part,
                  .part_count = *part_count,
                  .snapshot_id = *snapshot_id,
                  .from_sequence = *from,
                  .to_sequence = *to,
                  .records = {},
                  .signature = {}};
    out.records.reserve(*record_count);
    for (std::uint32_t i = 0; i < *record_count; ++i) {
        if (r.remaining() < ed25519_signature_size + stream_record_header_size) {
            return std::unexpected(DecodeError::truncated);
        }
        auto type = r.u8();
        auto op = r.u8();
        auto len = r.le16();
        if (!type || !op || !len || r.remaining() < ed25519_signature_size + *len) {
            return std::unexpected(DecodeError::truncated);
        }
        auto body = r.bytes(*len);
        if (!body) {
            return std::unexpected(DecodeError::truncated);
        }
        out.records.push_back({.type = static_cast<StreamRecordType>(*type),
                               .op = static_cast<StreamOp>(*op),
                               .body = {body->begin(), body->end()}});
    }
    auto signature = r.bytes(ed25519_signature_size);
    if (!signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = detail::check_vpc_stream(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a VpcStream frame (with whatever is in `signature`), enforcing
// every rule decode_vpc_stream checks.
[[nodiscard]] inline auto encode_vpc_stream(const VpcStream& s)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_vpc_stream(s); !ok) {
        return std::unexpected(ok.error());
    }
    std::size_t records_len = 0;
    for (const auto& rec : s.records) {
        records_len += stream_record_header_size + rec.body.size();
    }
    std::vector<std::byte> out;
    out.reserve(min_vpc_stream_size + records_len);
    wire::Writer w{out};
    w.le32(vpc_stream_magic);
    w.le16(vpc_stream_version);
    w.le16(s.key_id);
    w.le64(s.vpc_id);
    w.le32(s.vni);
    w.le32(s.incarnation);
    w.le32(s.cell_scope);
    w.u8(static_cast<std::uint8_t>(s.kind));
    w.u8(s.lookup ? vpc_stream_flag_lookup : std::uint8_t{0});
    w.le16(s.part);
    w.le16(s.part_count);
    w.bytes(std::array<std::byte, 6>{});
    w.le64(s.snapshot_id);
    w.le64(s.from_sequence);
    w.le64(s.to_sequence);
    w.le32(static_cast<std::uint32_t>(s.records.size()));
    w.le32(static_cast<std::uint32_t>(records_len));
    for (const auto& rec : s.records) {
        w.u8(static_cast<std::uint8_t>(rec.type));
        w.u8(static_cast<std::uint8_t>(rec.op));
        w.le16(static_cast<std::uint16_t>(rec.body.size()));
        w.bytes(rec.body);
    }
    w.bytes(s.signature);
    return out;
}

}  // namespace ak::proto
