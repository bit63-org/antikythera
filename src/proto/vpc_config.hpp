// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VpcConfig: the controller's configuration for one VPC, sent to every
// server hosting a NIC in it (.kiro/specs/controller-interface/ Requirement
// 10; .kiro/specs/vpc-subnets-routing/ design "VpcConfig version 2"). helm
// forwards it unmodified to the network roles, which check the signature
// and apply it to the VSwitch.
//
// Like MapUpdate and GroupPolicy it is a full per-VNI snapshot at
// `config_version`, so applying it is idempotent and a server that missed
// versions catches up from the newest alone. Its server and key IDs are
// inside the signed bytes, so it cannot be replayed to another server.
//
// Version 2 carries the VPC's CIDR blocks, its subnets and its route
// tables in one frame, so a server switches all three atomically: routing
// needs the sender's subnet, the table associated with it and the table's
// routes together, and separate frames would need an ordering rule on
// every change. Version 1's VPC-wide prefix, gateway and routes are gone.
// Nothing outside this repository spoke version 1, so decode accepts
// version 2 only.
//
// Layout (little-endian):
//   0x00  magic            u32  'AKVC'
//   0x04  version          u16  frame format version (2)
//   0x06  key_id           u16  controller key that signed it; non-zero
//   0x08  server_id        u64  target server; non-zero
//   0x10  vni              u32  VPC's 24-bit Geneve VNI; non-zero
//   0x14  ipv4_block_count u8   1 .. max_vpc_ipv4_blocks
//   0x15  flags            u8   bit 0: ipv6_block present; others zero
//   0x16  dns4_count       u8   at most max_vpc_dns
//   0x17  dns6_count       u8   at most max_vpc_dns
//   0x18  config_version   u64  per VPC, starts at 1, increases on every change
//   0x20  gateway_mac      [6]  locally administered unicast
//   0x26  domain_size      u8   at most max_vpc_domain_size
//   0x27  reserved         u8   zero
//   0x28  lease_seconds    u32  min_vpc_lease_seconds .. max_vpc_lease_seconds
//   0x2C  subnet_count     u16  1 .. max_vpc_subnets
//   0x2E  table_count      u16  1 .. max_vpc_tables
//   0x30  route_count      u16  at most max_vpc_routes, every table's routes
//   0x32  reserved         [6]  zero
//   0x38  ipv6_block       [16] a /56; all zero without the flag
//   0x48  ipv4_blocks      ipv4_block_count x 8 bytes, the primary first:
//           +0x00 prefix [4] | +0x04 length u8 | +0x05 reserved [3]
//   then  dns4             dns4_count x [4]
//   then  dns6             dns6_count x [16]
//   then  subnets          subnet_count x 32 bytes, subnet IDs strictly ascending:
//           +0x00 subnet_id u64 | +0x08 table u16 | +0x0A flags u8 (bit 0:
//           ipv6) | +0x0B ipv4_length u8 | +0x0C ipv4_prefix [4]
//           +0x10 ipv6_prefix [16] (a /64; all zero without the flag)
//   then  tables           table_count x 8 bytes, table numbers strictly ascending:
//           +0x00 table u16 | +0x02 flags u8 (bit 0: main) | +0x03 reserved u8
//           +0x04 route_count u16 | +0x06 reserved u16
//   then  routes           route_count x 32 bytes, table by table in table
//                          order, each table's strictly ascending by
//                          (family, prefix, length):
//           +0x00 target_nic u64 (0 for local) | +0x08 kind u8 (1 local, 2 NIC)
//           +0x09 family u8 (4, 6) | +0x0A length u8 | +0x0B reserved [5]
//           +0x10 prefix [16] (IPv4 in the first 4 bytes, the rest zero)
//   then  domain           domain_size bytes, RFC 1035 preferred name syntax
//   then  signature        64 bytes, Ed25519 over every byte before it
//
// Rules (check_vpc_config; the network role checks them again):
//   - IPv4 blocks /16 to /28, no host bits, not overlapping, the
//     secondaries ascending after the primary. The IPv6 block is a /56
//     inside 2000::/3 or fc00::/7.
//   - Subnets: non-zero IDs; an IPv4 prefix /16 to /28 inside one IPv4
//     block; with the flag, an IPv6 /64 inside the IPv6 block; no two
//     overlapping in either family; `table` names a listed table (the
//     controller resolves "no association" to the main table). The
//     gateway is not carried: it is the IPv4 prefix's base + 1.
//   - Tables: exactly one main; their route counts add up to route_count.
//   - Routes: no bits past the length. Exactly one `local` route per VPC
//     block in every table, with the block as its prefix and target 0. NIC
//     routes name a real NIC (not 0 or the broadcast ID), at most
//     max_vpc_nic_routes per table, never with a `local` route's prefix
//     and length. Any other kind refuses the frame: a new target comes
//     with a new version and a role that understands it.
//
// The largest frame (five IPv4 blocks, four DNS servers of each family,
// 200 subnets, 200 tables, 4,096 routes and the longest domain) is
// max_vpc_config_size, 139,581 bytes: under the largest MapUpdate, so
// proto::max_record_payload does not grow. helm sends it over OarLink in
// chunks.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint32_t vpc_config_magic = 0x4356'4B41;  // "AKVC" as little-endian bytes
inline constexpr std::uint16_t vpc_config_version = 2;
inline constexpr std::size_t vpc_config_header_size = 0x48;
inline constexpr std::size_t vpc_ipv4_block_size = 0x08;
inline constexpr std::size_t vpc_subnet_size = 0x20;
inline constexpr std::size_t vpc_table_size = 0x08;
inline constexpr std::size_t vpc_route_size = 0x20;
inline constexpr std::size_t max_vpc_ipv4_blocks = 5;  // a primary and four secondaries
inline constexpr std::size_t max_vpc_dns = 4;
inline constexpr std::size_t max_vpc_domain_size = 253;
inline constexpr std::size_t max_vpc_subnets = 200;      // EC2's default quota
inline constexpr std::size_t max_vpc_tables = 200;       // EC2's default quota
inline constexpr std::size_t max_vpc_routes = 4096;      // every table's, local routes included
inline constexpr std::size_t max_vpc_nic_routes = 1000;  // per table
inline constexpr std::uint32_t min_vpc_lease_seconds = 60;
inline constexpr std::uint32_t max_vpc_lease_seconds = 0x7FFF'FFFF;
inline constexpr std::uint8_t min_vpc_ipv4_length = 16;  // blocks and subnets alike
inline constexpr std::uint8_t max_vpc_ipv4_length = 28;
inline constexpr std::uint8_t vpc_ipv6_block_length = 56;
inline constexpr std::uint8_t vpc_ipv6_subnet_length = 64;
inline constexpr std::uint8_t vpc_flag_ipv6 = 0x01;
inline constexpr std::uint8_t vpc_subnet_flag_ipv6 = 0x01;
inline constexpr std::uint8_t vpc_table_flag_main = 0x01;
inline constexpr std::uint64_t vpc_route_nic_broadcast = ~std::uint64_t{0};

// Values are part of the wire protocol: never renumber.
enum class RouteFamily : std::uint8_t {
    ipv4 = 4,
    ipv6 = 6,
};

// Values are part of the wire protocol: never renumber.
enum class RouteKind : std::uint8_t {
    local = 1,  // the NIC in the VPC owning the destination address
    nic = 2,    // target_nic (oar-net Requirement 12.7)
};

struct VpcIpv4Block {
    Ipv4Address prefix{};
    std::uint8_t length{0};

    friend auto operator==(const VpcIpv4Block&, const VpcIpv4Block&) -> bool = default;
};

struct VpcSubnet {
    std::uint64_t subnet_id{0};
    std::uint16_t table{0};  // the associated table, or the main one
    Ipv4Address ipv4_prefix{};
    std::uint8_t ipv4_length{0};
    std::optional<Ipv6Address> ipv6_prefix{};  // a /64

    friend auto operator==(const VpcSubnet&, const VpcSubnet&) -> bool = default;
};

struct VpcRoute {
    RouteKind kind{RouteKind::nic};
    RouteFamily family{RouteFamily::ipv4};
    std::uint8_t length{0};
    Ipv6Address prefix{};         // IPv4 prefixes in the first four bytes, the rest zero
    std::uint64_t target_nic{0};  // 0 for local

    friend auto operator==(const VpcRoute&, const VpcRoute&) -> bool = default;
};

struct VpcRouteTable {
    std::uint16_t table{0};
    bool main{false};
    std::vector<VpcRoute> routes{};  // strictly ascending (family, prefix, length)

    friend auto operator==(const VpcRouteTable&, const VpcRouteTable&) -> bool = default;
};

struct VpcConfigFrame {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint32_t vni{0};
    std::uint64_t config_version{0};
    Mac gateway_mac{};
    std::vector<VpcIpv4Block> ipv4_blocks{};  // the primary first
    std::optional<Ipv6Address> ipv6_block{};  // a /56
    std::vector<Ipv4Address> dns4{};
    std::vector<Ipv6Address> dns6{};
    std::string domain{};
    std::uint32_t lease_seconds{0};
    std::vector<VpcSubnet> subnets{};     // subnet IDs strictly ascending
    std::vector<VpcRouteTable> tables{};  // table numbers strictly ascending
    Ed25519Signature signature{};

    friend auto operator==(const VpcConfigFrame&, const VpcConfigFrame&) -> bool = default;
};

[[nodiscard]] inline constexpr auto vpc_config_size(std::size_t ipv4_blocks, std::size_t dns4,
                                                    std::size_t dns6, std::size_t subnets,
                                                    std::size_t tables, std::size_t routes,
                                                    std::size_t domain) noexcept -> std::size_t {
    return vpc_config_header_size + (ipv4_blocks * vpc_ipv4_block_size) +
           (dns4 * ipv4_address_size) + (dns6 * ipv6_address_size) + (subnets * vpc_subnet_size) +
           (tables * vpc_table_size) + (routes * vpc_route_size) + domain + ed25519_signature_size;
}

// One block, one subnet, one table holding the block's local route.
inline constexpr std::size_t min_vpc_config_size = vpc_config_size(1, 0, 0, 1, 1, 1, 0);
inline constexpr std::size_t max_vpc_config_size =
    vpc_config_size(max_vpc_ipv4_blocks, max_vpc_dns, max_vpc_dns, max_vpc_subnets, max_vpc_tables,
                    max_vpc_routes, max_vpc_domain_size);
static_assert(max_vpc_config_size == 139'581);

// The bytes a VpcConfig signature covers: all but the trailing 64.
[[nodiscard]] inline auto vpc_config_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

inline auto set_vpc_config_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= min_vpc_config_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

// The subnet's IPv4 gateway: its prefix's base + 1 (vpc-subnets-routing
// Requirement 2.2). The prefix is at most a /28, so base + 1 is inside it.
[[nodiscard]] inline auto vpc_subnet_gateway(const VpcSubnet& s) noexcept -> Ipv4Address {
    Ipv4Address g = s.ipv4_prefix;
    g[ipv4_address_size - 1] |= std::byte{1};
    return g;
}

namespace detail {

[[nodiscard]] inline auto vpc_u32(const Ipv4Address& a) noexcept -> std::uint32_t {
    std::uint32_t v = 0;
    for (const std::byte b : a) {
        v = (v << 8U) | std::to_integer<std::uint32_t>(b);
    }
    return v;
}

// The netmask for a /`length`; any length past 32 is a full mask, so the
// shift is defined whatever an untrusted frame carries.
[[nodiscard]] inline auto vpc_mask4(std::uint8_t length) noexcept -> std::uint32_t {
    if (length == 0) {
        return 0;
    }
    if (length >= 32) {
        return ~std::uint32_t{0};
    }
    return ~std::uint32_t{0} << (32U - length);
}

// No bit set past `length` in `prefix`.
[[nodiscard]] inline auto vpc_host_bits_clear(std::span<const std::byte> prefix,
                                              std::size_t length) noexcept -> bool {
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const std::size_t first_bit = i * 8;
        const auto b = std::to_integer<std::uint8_t>(prefix[i]);
        if (first_bit >= length) {
            if (b != 0) {
                return false;
            }
        } else if (first_bit + 8 > length) {
            const auto keep = static_cast<std::uint8_t>(0xFFU << (8U - (length - first_bit)));
            if ((b & static_cast<std::uint8_t>(~keep)) != 0) {
                return false;
            }
        }
    }
    return true;
}

// The first `length` bits of `a` and `b` agree.
[[nodiscard]] inline auto vpc_prefix_match(std::span<const std::byte> a,
                                           std::span<const std::byte> b,
                                           std::size_t length) noexcept -> bool {
    for (std::size_t i = 0; i < a.size() && i < b.size() && i * 8 < length; ++i) {
        const std::size_t bits = std::min<std::size_t>(8, length - (i * 8));
        const auto keep = static_cast<std::uint8_t>(0xFFU << (8U - bits));
        if (((std::to_integer<std::uint8_t>(a[i]) ^ std::to_integer<std::uint8_t>(b[i])) & keep) !=
            0) {
            return false;
        }
    }
    return true;
}

// Two IPv4 prefixes share an address: the shorter one's mask agrees.
[[nodiscard]] inline auto vpc_overlap4(const Ipv4Address& a, std::uint8_t a_length,
                                       const Ipv4Address& b, std::uint8_t b_length) noexcept
    -> bool {
    const std::uint32_t mask = vpc_mask4(std::min(a_length, b_length));
    return (vpc_u32(a) & mask) == (vpc_u32(b) & mask);
}

// `inner`/`inner_length` lies inside `outer`/`outer_length`.
[[nodiscard]] inline auto vpc_inside4(const Ipv4Address& inner, std::uint8_t inner_length,
                                      const Ipv4Address& outer, std::uint8_t outer_length) noexcept
    -> bool {
    return inner_length >= outer_length && vpc_overlap4(inner, inner_length, outer, outer_length);
}

[[nodiscard]] inline auto vpc_valid_domain(std::string_view name) noexcept -> bool {
    constexpr std::size_t max_label = 63;
    if (name.empty()) {
        return true;
    }
    if (name.size() > max_vpc_domain_size) {
        return false;
    }
    std::size_t start = 0;
    while (start <= name.size()) {
        const std::size_t dot = std::min(name.find('.', start), name.size());
        const std::string_view label = name.substr(start, dot - start);
        if (label.empty() || label.size() > max_label || label.front() == '-' ||
            label.back() == '-') {
            return false;
        }
        for (const char c : label) {
            const bool alnum =
                (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alnum && c != '-') {
                return false;
            }
        }
        start = dot + 1;
    }
    return true;
}

[[nodiscard]] inline auto vpc_route_key_less(const VpcRoute& a, const VpcRoute& b) noexcept
    -> bool {
    if (a.family != b.family) {
        return a.family < b.family;
    }
    if (a.prefix != b.prefix) {
        return a.prefix < b.prefix;
    }
    return a.length < b.length;
}

// A /56 inside 2000::/3 (global unicast) or fc00::/7 (unique local).
[[nodiscard]] inline auto vpc_valid_ipv6_block(const Ipv6Address& b) noexcept -> bool {
    const auto first = std::to_integer<std::uint8_t>(b[0]);
    const bool global = (first & 0xE0U) == 0x20U;
    const bool ula = (first & 0xFEU) == 0xFCU;
    return (global || ula) && vpc_host_bits_clear(b, vpc_ipv6_block_length);
}

// The route is a VPC block's own prefix and length: what `local` routes
// carry and NIC routes may not.
[[nodiscard]] inline auto vpc_is_block_route(const VpcConfigFrame& c, const VpcRoute& r) noexcept
    -> bool {
    if (r.family == RouteFamily::ipv6) {
        return c.ipv6_block && r.length == vpc_ipv6_block_length && r.prefix == *c.ipv6_block;
    }
    return std::ranges::any_of(c.ipv4_blocks, [&](const VpcIpv4Block& b) {
        return r.length == b.length && std::ranges::equal(std::span{r.prefix}.first(4), b.prefix) &&
               all_zero(std::span{r.prefix}.subspan(ipv4_address_size));
    });
}

[[nodiscard]] inline auto check_vpc_route(const VpcRoute& r) noexcept
    -> std::expected<void, DecodeError> {
    if (r.kind == RouteKind::local) {
        if (r.target_nic != 0) {
            return std::unexpected(DecodeError::bad_route);
        }
    } else if (r.kind == RouteKind::nic) {
        if (r.target_nic == 0 || r.target_nic == vpc_route_nic_broadcast) {
            return std::unexpected(DecodeError::bad_nic_id);
        }
    } else {
        return std::unexpected(DecodeError::unknown_value);
    }
    switch (r.family) {
        case RouteFamily::ipv4:
            if (r.length > 32 || !all_zero(std::span{r.prefix}.subspan(ipv4_address_size)) ||
                !vpc_host_bits_clear(r.prefix, r.length)) {
                return std::unexpected(DecodeError::bad_route);
            }
            return {};
        case RouteFamily::ipv6:
            if (r.length > 128 || !vpc_host_bits_clear(r.prefix, r.length)) {
                return std::unexpected(DecodeError::bad_route);
            }
            return {};
    }
    return std::unexpected(DecodeError::unknown_value);
}

[[nodiscard]] inline auto check_vpc_blocks(const VpcConfigFrame& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.ipv4_blocks.empty() || c.ipv4_blocks.size() > max_vpc_ipv4_blocks) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    for (std::size_t i = 0; i < c.ipv4_blocks.size(); ++i) {
        const auto& b = c.ipv4_blocks[i];
        if (b.length < min_vpc_ipv4_length || b.length > max_vpc_ipv4_length ||
            !vpc_host_bits_clear(b.prefix, b.length)) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
        // Secondaries ascend after the primary, so the order is canonical.
        if (i > 1 && vpc_u32(c.ipv4_blocks[i - 1].prefix) >= vpc_u32(b.prefix)) {
            return std::unexpected(DecodeError::not_ascending);
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (vpc_overlap4(c.ipv4_blocks[j].prefix, c.ipv4_blocks[j].length, b.prefix,
                             b.length)) {
                return std::unexpected(DecodeError::bad_vpc_config);
            }
        }
    }
    if (c.ipv6_block && !vpc_valid_ipv6_block(*c.ipv6_block)) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    return {};
}

[[nodiscard]] inline auto check_vpc_subnets(const VpcConfigFrame& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.subnets.empty() || c.subnets.size() > max_vpc_subnets) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < c.subnets.size(); ++i) {
        const auto& s = c.subnets[i];
        if (s.subnet_id == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (i > 0 && c.subnets[i - 1].subnet_id >= s.subnet_id) {
            return std::unexpected(DecodeError::not_ascending);
        }
        if (s.ipv4_length < min_vpc_ipv4_length || s.ipv4_length > max_vpc_ipv4_length ||
            !vpc_host_bits_clear(s.ipv4_prefix, s.ipv4_length) ||
            std::ranges::none_of(c.ipv4_blocks, [&](const VpcIpv4Block& b) {
                return vpc_inside4(s.ipv4_prefix, s.ipv4_length, b.prefix, b.length);
            })) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
        if (s.ipv6_prefix &&
            (!c.ipv6_block || !vpc_host_bits_clear(*s.ipv6_prefix, vpc_ipv6_subnet_length) ||
             !vpc_prefix_match(*s.ipv6_prefix, *c.ipv6_block, vpc_ipv6_block_length))) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
        for (std::size_t j = 0; j < i; ++j) {
            const auto& o = c.subnets[j];
            if (vpc_overlap4(o.ipv4_prefix, o.ipv4_length, s.ipv4_prefix, s.ipv4_length) ||
                (o.ipv6_prefix && s.ipv6_prefix && *o.ipv6_prefix == *s.ipv6_prefix)) {
                return std::unexpected(DecodeError::bad_vpc_config);
            }
        }
        if (!std::ranges::binary_search(c.tables, s.table, std::ranges::less{},
                                        &VpcRouteTable::table)) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
    }
    return {};
}

[[nodiscard]] inline auto check_vpc_tables(const VpcConfigFrame& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.tables.empty() || c.tables.size() > max_vpc_tables) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t blocks = c.ipv4_blocks.size() + (c.ipv6_block ? std::size_t{1} : 0);
    std::size_t mains = 0;
    std::size_t total = 0;
    for (std::size_t t = 0; t < c.tables.size(); ++t) {
        const auto& table = c.tables[t];
        if (t > 0 && c.tables[t - 1].table >= table.table) {
            return std::unexpected(DecodeError::not_ascending);
        }
        if (table.main) {
            ++mains;
        }
        total += table.routes.size();
        if (total > max_vpc_routes) {
            return std::unexpected(DecodeError::too_many_entries);
        }
        std::size_t locals = 0;
        std::size_t nics = 0;
        for (std::size_t i = 0; i < table.routes.size(); ++i) {
            const auto& r = table.routes[i];
            if (auto ok = check_vpc_route(r); !ok) {
                return ok;
            }
            if (i > 0 && !vpc_route_key_less(table.routes[i - 1], r)) {
                return std::unexpected(DecodeError::not_ascending);
            }
            // Routes are unique by key, so one block's local route
            // cannot appear twice: counting them is enough.
            const bool block = vpc_is_block_route(c, r);
            if (r.kind == RouteKind::local) {
                if (!block) {
                    return std::unexpected(DecodeError::bad_route);
                }
                ++locals;
            } else {
                if (block) {
                    return std::unexpected(DecodeError::bad_route);
                }
                ++nics;
            }
        }
        if (locals != blocks) {
            return std::unexpected(DecodeError::bad_route);
        }
        if (nics > max_vpc_nic_routes) {
            return std::unexpected(DecodeError::too_many_entries);
        }
    }
    if (mains != 1) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    return {};
}

[[nodiscard]] inline auto check_vpc_config(const VpcConfigFrame& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (c.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (c.vni == 0 || c.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (c.config_version == 0) {
        return std::unexpected(DecodeError::bad_config_version);
    }
    const auto mac0 = std::to_integer<std::uint8_t>(c.gateway_mac[0]);
    if ((mac0 & mac_multicast_bit) != 0 || (mac0 & mac_local_bit) == 0) {
        return std::unexpected(DecodeError::bad_mac);
    }
    if (auto ok = check_vpc_blocks(c); !ok) {
        return ok;
    }
    if (c.dns4.size() > max_vpc_dns || c.dns6.size() > max_vpc_dns) {
        return std::unexpected(DecodeError::too_many_addresses);
    }
    for (const auto& a : c.dns4) {
        const auto v = vpc_u32(a);
        if (v == 0 || std::to_integer<std::uint8_t>(a[0]) >= ipv4_multicast_first_octet) {
            return std::unexpected(DecodeError::bad_guest_address);
        }
    }
    for (const auto& a : c.dns6) {
        if (all_zero(a) || std::to_integer<std::uint8_t>(a[0]) == ipv6_multicast_prefix) {
            return std::unexpected(DecodeError::bad_guest_address);
        }
    }
    if (!vpc_valid_domain(c.domain)) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    if (c.lease_seconds < min_vpc_lease_seconds || c.lease_seconds > max_vpc_lease_seconds) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    // Tables before subnets: a subnet names a table.
    if (auto ok = check_vpc_tables(c); !ok) {
        return ok;
    }
    return check_vpc_subnets(c);
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// vpc_config_signed_bytes(frame) against `signature` under `key_id` before
// acting on anything else in the result.
[[nodiscard]] inline auto decode_vpc_config(std::span<const std::byte> bytes)
    -> std::expected<VpcConfigFrame, DecodeError> {
    if (bytes.size() > max_vpc_config_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto vni = r.le32();
    auto block_count = r.u8();
    auto flags = r.u8();
    auto dns4_count = r.u8();
    auto dns6_count = r.u8();
    auto config_version = r.le64();
    auto gateway_mac = r.bytes(mac_size);
    auto domain_size = r.u8();
    auto reserved1 = r.u8();
    auto lease = r.le32();
    auto subnet_count = r.le16();
    auto table_count = r.le16();
    auto route_count = r.le16();
    auto reserved2 = r.bytes(6);
    auto ipv6_block = r.bytes(ipv6_address_size);
    if (!magic || !version || !key_id || !server_id || !vni || !block_count || !flags ||
        !dns4_count || !dns6_count || !config_version || !gateway_mac || !domain_size ||
        !reserved1 || !lease || !subnet_count || !table_count || !route_count || !reserved2 ||
        !ipv6_block) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != vpc_config_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != vpc_config_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved1 != 0 || !detail::all_zero(*reserved2) || (*flags & ~vpc_flag_ipv6) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    // Bounds before any list is read, so a hostile count costs nothing.
    if (*block_count == 0 || *block_count > max_vpc_ipv4_blocks ||
        *domain_size > max_vpc_domain_size) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    if (*dns4_count > max_vpc_dns || *dns6_count > max_vpc_dns) {
        return std::unexpected(DecodeError::too_many_addresses);
    }
    if (*subnet_count == 0 || *subnet_count > max_vpc_subnets || *table_count == 0 ||
        *table_count > max_vpc_tables || *route_count > max_vpc_routes) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t want = vpc_config_size(*block_count, *dns4_count, *dns6_count, *subnet_count,
                                             *table_count, *route_count, *domain_size) -
                             vpc_config_header_size;
    if (r.remaining() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }

    // The length is exact from here on: these reads cannot fail.
    const auto take = [&r](std::span<std::byte> out) {
        std::ranges::copy(r.bytes(out.size()).value_or(std::span<const std::byte>{}), out.begin());
    };
    VpcConfigFrame out{};
    out.server_id = *server_id;
    out.key_id = *key_id;
    out.vni = *vni;
    out.config_version = *config_version;
    out.lease_seconds = *lease;
    std::ranges::copy(*gateway_mac, out.gateway_mac.begin());
    if ((*flags & vpc_flag_ipv6) != 0) {
        out.ipv6_block.emplace();
        std::ranges::copy(*ipv6_block, out.ipv6_block->begin());
    } else if (!detail::all_zero(*ipv6_block)) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    for (std::uint8_t i = 0; i < *block_count; ++i) {
        VpcIpv4Block b{};
        take(b.prefix);
        b.length = r.u8().value_or(0);
        if (!detail::all_zero(r.bytes(3).value_or(std::span<const std::byte>{}))) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        out.ipv4_blocks.push_back(b);
    }
    for (std::uint8_t i = 0; i < *dns4_count; ++i) {
        take(out.dns4.emplace_back());
    }
    for (std::uint8_t i = 0; i < *dns6_count; ++i) {
        take(out.dns6.emplace_back());
    }
    out.subnets.reserve(*subnet_count);
    for (std::uint16_t i = 0; i < *subnet_count; ++i) {
        VpcSubnet s{};
        s.subnet_id = r.le64().value_or(0);
        s.table = r.le16().value_or(0);
        const auto subnet_flags = r.u8().value_or(0);
        s.ipv4_length = r.u8().value_or(0);
        take(s.ipv4_prefix);
        Ipv6Address v6{};
        take(v6);
        if ((subnet_flags & ~vpc_subnet_flag_ipv6) != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        if ((subnet_flags & vpc_subnet_flag_ipv6) != 0) {
            s.ipv6_prefix = v6;
        } else if (!detail::all_zero(v6)) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
        out.subnets.push_back(s);
    }
    out.tables.reserve(*table_count);
    std::size_t routes_named = 0;
    for (std::uint16_t i = 0; i < *table_count; ++i) {
        VpcRouteTable t{};
        t.table = r.le16().value_or(0);
        const auto table_flags = r.u8().value_or(0);
        const auto pad1 = r.u8().value_or(0);
        const auto count = r.le16().value_or(0);
        const auto pad2 = r.le16().value_or(0);
        if ((table_flags & ~vpc_table_flag_main) != 0 || pad1 != 0 || pad2 != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        t.main = (table_flags & vpc_table_flag_main) != 0;
        routes_named += count;
        if (routes_named > *route_count) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
        t.routes.resize(count);  // filled below, bounded by route_count
        out.tables.push_back(std::move(t));
    }
    if (routes_named != *route_count) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    for (auto& t : out.tables) {
        for (auto& route : t.routes) {
            route.target_nic = r.le64().value_or(0);
            const auto kind = r.u8().value_or(0);
            const auto family = r.u8().value_or(0);
            route.length = r.u8().value_or(0);
            if (!detail::all_zero(r.bytes(5).value_or(std::span<const std::byte>{}))) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            take(route.prefix);
            if (kind != static_cast<std::uint8_t>(RouteKind::local) &&
                kind != static_cast<std::uint8_t>(RouteKind::nic)) {
                return std::unexpected(DecodeError::unknown_value);
            }
            if (family != static_cast<std::uint8_t>(RouteFamily::ipv4) &&
                family != static_cast<std::uint8_t>(RouteFamily::ipv6)) {
                return std::unexpected(DecodeError::unknown_value);
            }
            route.kind = static_cast<RouteKind>(kind);
            route.family = static_cast<RouteFamily>(family);
        }
    }
    auto domain = r.bytes(*domain_size).value_or(std::span<const std::byte>{});
    out.domain.assign(reinterpret_cast<const char*>(domain.data()), domain.size());
    take(out.signature);
    if (auto ok = detail::check_vpc_config(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a VpcConfig (with whatever is in `signature`), enforcing every
// rule decode_vpc_config checks.
[[nodiscard]] inline auto encode_vpc_config(const VpcConfigFrame& c)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_vpc_config(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::size_t routes = 0;
    for (const auto& t : c.tables) {
        routes += t.routes.size();
    }
    std::vector<std::byte> out;
    out.reserve(vpc_config_size(c.ipv4_blocks.size(), c.dns4.size(), c.dns6.size(),
                                c.subnets.size(), c.tables.size(), routes, c.domain.size()));
    wire::Writer w{out};
    w.le32(vpc_config_magic);
    w.le16(vpc_config_version);
    w.le16(c.key_id);
    w.le64(c.server_id);
    w.le32(c.vni);
    w.u8(static_cast<std::uint8_t>(c.ipv4_blocks.size()));
    w.u8(c.ipv6_block ? vpc_flag_ipv6 : std::uint8_t{0});
    w.u8(static_cast<std::uint8_t>(c.dns4.size()));
    w.u8(static_cast<std::uint8_t>(c.dns6.size()));
    w.le64(c.config_version);
    w.bytes(c.gateway_mac);
    w.u8(static_cast<std::uint8_t>(c.domain.size()));
    w.u8(0);
    w.le32(c.lease_seconds);
    w.le16(static_cast<std::uint16_t>(c.subnets.size()));
    w.le16(static_cast<std::uint16_t>(c.tables.size()));
    w.le16(static_cast<std::uint16_t>(routes));
    w.bytes(std::array<std::byte, 6>{});
    w.bytes(c.ipv6_block.value_or(Ipv6Address{}));
    for (const auto& b : c.ipv4_blocks) {
        w.bytes(b.prefix);
        w.u8(b.length);
        w.bytes(std::array<std::byte, 3>{});
    }
    for (const auto& a : c.dns4) {
        w.bytes(a);
    }
    for (const auto& a : c.dns6) {
        w.bytes(a);
    }
    for (const auto& s : c.subnets) {
        w.le64(s.subnet_id);
        w.le16(s.table);
        w.u8(s.ipv6_prefix ? vpc_subnet_flag_ipv6 : std::uint8_t{0});
        w.u8(s.ipv4_length);
        w.bytes(s.ipv4_prefix);
        w.bytes(s.ipv6_prefix.value_or(Ipv6Address{}));
    }
    for (const auto& t : c.tables) {
        w.le16(t.table);
        w.u8(t.main ? vpc_table_flag_main : std::uint8_t{0});
        w.u8(0);
        w.le16(static_cast<std::uint16_t>(t.routes.size()));
        w.le16(0);
    }
    for (const auto& t : c.tables) {
        for (const auto& route : t.routes) {
            w.le64(route.target_nic);
            w.u8(static_cast<std::uint8_t>(route.kind));
            w.u8(static_cast<std::uint8_t>(route.family));
            w.u8(route.length);
            w.bytes(std::array<std::byte, 5>{});
            w.bytes(route.prefix);
        }
    }
    w.bytes(std::as_bytes(std::span{c.domain}));
    w.bytes(c.signature);
    return out;
}

}  // namespace ak::proto
