// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VpcConfig: the controller's gateway and guest network configuration for
// one VPC, sent to every server hosting a NIC in it
// (.kiro/specs/controller-interface/ Requirement 10, design "VpcConfig";
// oar-net Requirement 12). helm forwards it unmodified to the network
// roles, which check the signature and apply it to the VSwitch
// (VSwitch::set_vpc_config).
//
// Like MapUpdate and GroupPolicy it is a full per-VNI snapshot at
// `config_version`, so applying it is idempotent and a server that missed
// versions catches up from the newest alone. Its server and key IDs are
// inside the signed bytes, so it cannot be replayed to another server.
//
// Layout (little-endian):
//   0x00  magic          u32  'AKVC'
//   0x04  version        u16  frame format version (1)
//   0x06  key_id         u16  controller key that signed it; non-zero
//   0x08  server_id      u64  target server; non-zero
//   0x10  vni            u32  VPC's 24-bit Geneve VNI; non-zero
//   0x14  flags          u8   bit 0: ipv6_prefix present; others zero
//   0x15  ipv4_length    u8   IPv4 prefix length, 8..30
//   0x16  dns4_count     u8   at most max_vpc_dns
//   0x17  dns6_count     u8   at most max_vpc_dns
//   0x18  config_version u64  per VPC, starts at 1, increases on every change
//   0x20  gateway_mac    [6]  locally administered unicast
//   0x26  domain_size    u8   at most max_vpc_domain_size
//   0x27  reserved       u8   zero
//   0x28  ipv4_prefix    [4]  network order, no host bits
//   0x2C  ipv4_gateway   [4]  inside the prefix, not its network or broadcast
//   0x30  ipv6_prefix    [16] a /64 (low 64 bits zero); all zero when absent
//   0x40  lease_seconds  u32  min_vpc_lease_seconds .. max_vpc_lease_seconds
//   0x44  route_count    u16  at most max_vpc_routes
//   0x46  reserved       u16  zero
//   0x48  dns4           dns4_count x [4]
//   then  dns6           dns6_count x [16]
//   then  routes         route_count x 32 bytes, strictly ascending by
//                        (family, prefix, length):
//           +0x00 target_nic u64 | +0x08 family u8 (4 or 6) | +0x09 length u8
//           +0x0A reserved [6] | +0x10 prefix [16] (IPv4 in the first 4 bytes,
//           the rest zero)
//   then  domain         domain_size bytes, RFC 1035 preferred name syntax
//   then  signature      64 bytes, Ed25519 over every byte before it
//
// Routes are the VPC's route table (oar-net Requirements 11.10 and 12.7, task 22):
// a packet a guest sends to the gateway MAC whose destination falls in a
// route's prefix goes to the route's target NIC, by longest prefix. A
// target names a NIC, never a VTEP or an address, because only a NIC with
// its source/destination check off may receive traffic not addressed to
// it; the receiver resolves the NIC through its own mapping. Prefixes
// carry no host bits (IPv4 0..32, IPv6 0..128, so a default route is
// allowed).
//
// The largest frame (max_vpc_dns of each family, max_vpc_routes and the
// longest domain) is max_vpc_config_size bytes, which fits one OarLink
// message, so helm forwards it without chunking.
//
// The value rules mirror oar-net's VSwitch::set_vpc_config (vswitch.hpp
// VpcConfig) so this header depends on nothing else; the network role
// checks them again when it applies the frame.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint32_t vpc_config_magic = 0x4356'4B41;  // "AKVC" as little-endian bytes
inline constexpr std::uint16_t vpc_config_version = 1;
inline constexpr std::size_t vpc_config_header_size = 0x48;
inline constexpr std::size_t vpc_route_size = 0x20;
inline constexpr std::size_t max_vpc_dns = 4;
inline constexpr std::size_t max_vpc_domain_size = 253;
inline constexpr std::size_t max_vpc_routes = 100;
inline constexpr std::uint32_t min_vpc_lease_seconds = 60;
inline constexpr std::uint32_t max_vpc_lease_seconds = 0x7FFF'FFFF;
inline constexpr std::uint8_t min_vpc_ipv4_length = 8;
inline constexpr std::uint8_t max_vpc_ipv4_length = 30;
inline constexpr std::uint8_t vpc_flag_ipv6 = 0x01;
inline constexpr std::uint64_t vpc_route_nic_broadcast = ~std::uint64_t{0};

// Values are part of the wire protocol: never renumber.
enum class RouteFamily : std::uint8_t {
    ipv4 = 4,
    ipv6 = 6,
};

struct VpcRoute {
    RouteFamily family{RouteFamily::ipv4};
    std::uint8_t length{0};
    Ipv6Address prefix{};  // IPv4 prefixes in the first four bytes, the rest zero
    std::uint64_t target_nic{0};

    friend auto operator==(const VpcRoute&, const VpcRoute&) -> bool = default;
};

struct VpcConfigFrame {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint32_t vni{0};
    std::uint64_t config_version{0};
    Mac gateway_mac{};
    Ipv4Address ipv4_prefix{};
    std::uint8_t ipv4_length{0};
    Ipv4Address ipv4_gateway{};
    bool has_ipv6{false};
    Ipv6Address ipv6_prefix{};  // all zero unless has_ipv6
    std::vector<Ipv4Address> dns4{};
    std::vector<Ipv6Address> dns6{};
    std::string domain{};
    std::uint32_t lease_seconds{0};
    std::vector<VpcRoute> routes{};  // strictly ascending (family, prefix, length)
    Ed25519Signature signature{};

    friend auto operator==(const VpcConfigFrame&, const VpcConfigFrame&) -> bool = default;
};

[[nodiscard]] inline constexpr auto vpc_config_size(std::size_t dns4, std::size_t dns6,
                                                    std::size_t routes, std::size_t domain) noexcept
    -> std::size_t {
    return vpc_config_header_size + (dns4 * ipv4_address_size) + (dns6 * ipv6_address_size) +
           (routes * vpc_route_size) + domain + ed25519_signature_size;
}

inline constexpr std::size_t min_vpc_config_size = vpc_config_size(0, 0, 0, 0);
inline constexpr std::size_t max_vpc_config_size =
    vpc_config_size(max_vpc_dns, max_vpc_dns, max_vpc_routes, max_vpc_domain_size);

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

// No bit set past `length` in the first `size` bytes of `prefix`.
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

[[nodiscard]] inline auto check_vpc_route(const VpcRoute& r) noexcept
    -> std::expected<void, DecodeError> {
    if (r.target_nic == 0 || r.target_nic == vpc_route_nic_broadcast) {
        return std::unexpected(DecodeError::bad_nic_id);
    }
    switch (r.family) {
        case RouteFamily::ipv4:
            if (r.length > 32 || !vpc_host_bits_clear(r.prefix, r.length)) {
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
    if (c.ipv4_length < min_vpc_ipv4_length || c.ipv4_length > max_vpc_ipv4_length) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    const std::uint32_t mask = vpc_mask4(c.ipv4_length);
    const std::uint32_t net = vpc_u32(c.ipv4_prefix);
    const std::uint32_t gw = vpc_u32(c.ipv4_gateway);
    if ((net & ~mask) != 0 || (gw & mask) != net || (gw & ~mask) == 0 || (gw & ~mask) == ~mask) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    if (c.has_ipv6) {
        const auto first = std::to_integer<std::uint8_t>(c.ipv6_prefix[0]);
        const auto second = std::to_integer<std::uint8_t>(c.ipv6_prefix[1]);
        const bool link_local = first == 0xFE && (second & 0xC0U) == 0x80;
        if (!vpc_host_bits_clear(c.ipv6_prefix, 64) || detail::all_zero(c.ipv6_prefix) ||
            first == ipv6_multicast_prefix || link_local) {
            return std::unexpected(DecodeError::bad_vpc_config);
        }
    } else if (!detail::all_zero(c.ipv6_prefix)) {
        return std::unexpected(DecodeError::bad_vpc_config);
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
        if (detail::all_zero(a) || std::to_integer<std::uint8_t>(a[0]) == ipv6_multicast_prefix) {
            return std::unexpected(DecodeError::bad_guest_address);
        }
    }
    if (!vpc_valid_domain(c.domain)) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    if (c.lease_seconds < min_vpc_lease_seconds || c.lease_seconds > max_vpc_lease_seconds) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    if (c.routes.size() > max_vpc_routes) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < c.routes.size(); ++i) {
        if (auto ok = check_vpc_route(c.routes[i]); !ok) {
            return ok;
        }
        if (i > 0 && !vpc_route_key_less(c.routes[i - 1], c.routes[i])) {
            return std::unexpected(DecodeError::not_ascending);
        }
    }
    return {};
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
    auto flags = r.u8();
    auto ipv4_length = r.u8();
    auto dns4_count = r.u8();
    auto dns6_count = r.u8();
    auto config_version = r.le64();
    auto gateway_mac = r.bytes(mac_size);
    auto domain_size = r.u8();
    auto reserved1 = r.u8();
    auto ipv4_prefix = r.bytes(ipv4_address_size);
    auto ipv4_gateway = r.bytes(ipv4_address_size);
    auto ipv6_prefix = r.bytes(ipv6_address_size);
    auto lease = r.le32();
    auto route_count = r.le16();
    auto reserved2 = r.le16();
    if (!magic || !version || !key_id || !server_id || !vni || !flags || !ipv4_length ||
        !dns4_count || !dns6_count || !config_version || !gateway_mac || !domain_size ||
        !reserved1 || !ipv4_prefix || !ipv4_gateway || !ipv6_prefix || !lease || !route_count ||
        !reserved2) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != vpc_config_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != vpc_config_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved1 != 0 || *reserved2 != 0 || (*flags & ~vpc_flag_ipv6) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*dns4_count > max_vpc_dns || *dns6_count > max_vpc_dns) {
        return std::unexpected(DecodeError::too_many_addresses);
    }
    if (*route_count > max_vpc_routes) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    if (*domain_size > max_vpc_domain_size) {
        return std::unexpected(DecodeError::bad_vpc_config);
    }
    VpcConfigFrame out{.server_id = *server_id,
                       .key_id = *key_id,
                       .vni = *vni,
                       .config_version = *config_version,
                       .ipv4_length = *ipv4_length,
                       .has_ipv6 = (*flags & vpc_flag_ipv6) != 0,
                       .lease_seconds = *lease};
    std::ranges::copy(*gateway_mac, out.gateway_mac.begin());
    std::ranges::copy(*ipv4_prefix, out.ipv4_prefix.begin());
    std::ranges::copy(*ipv4_gateway, out.ipv4_gateway.begin());
    std::ranges::copy(*ipv6_prefix, out.ipv6_prefix.begin());
    for (std::uint8_t i = 0; i < *dns4_count; ++i) {
        auto a = r.bytes(ipv4_address_size);
        if (!a) {
            return std::unexpected(DecodeError::truncated);
        }
        std::ranges::copy(*a, out.dns4.emplace_back().begin());
    }
    for (std::uint8_t i = 0; i < *dns6_count; ++i) {
        auto a = r.bytes(ipv6_address_size);
        if (!a) {
            return std::unexpected(DecodeError::truncated);
        }
        std::ranges::copy(*a, out.dns6.emplace_back().begin());
    }
    for (std::uint16_t i = 0; i < *route_count; ++i) {
        auto target = r.le64();
        auto family = r.u8();
        auto length = r.u8();
        auto reserved = r.bytes(6);
        auto prefix = r.bytes(ipv6_address_size);
        if (!target || !family || !length || !reserved || !prefix) {
            return std::unexpected(DecodeError::truncated);
        }
        if (!detail::all_zero(*reserved)) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        VpcRoute route{.family = static_cast<RouteFamily>(*family),
                       .length = *length,
                       .prefix = {},
                       .target_nic = *target};
        std::ranges::copy(*prefix, route.prefix.begin());
        if (route.family == RouteFamily::ipv4 &&
            !detail::all_zero(std::span{route.prefix}.subspan(ipv4_address_size))) {
            return std::unexpected(DecodeError::bad_route);
        }
        out.routes.push_back(route);
    }
    auto domain = r.bytes(*domain_size);
    auto signature = r.bytes(ed25519_signature_size);
    if (!domain || !signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    out.domain.assign(reinterpret_cast<const char*>(domain->data()), domain->size());
    std::ranges::copy(*signature, out.signature.begin());
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
    for (const auto& route : c.routes) {
        if (route.family == RouteFamily::ipv4 &&
            !detail::all_zero(std::span{route.prefix}.subspan(ipv4_address_size))) {
            return std::unexpected(DecodeError::bad_route);
        }
    }
    std::vector<std::byte> out;
    out.reserve(vpc_config_size(c.dns4.size(), c.dns6.size(), c.routes.size(), c.domain.size()));
    wire::Writer w{out};
    w.le32(vpc_config_magic);
    w.le16(vpc_config_version);
    w.le16(c.key_id);
    w.le64(c.server_id);
    w.le32(c.vni);
    w.u8(c.has_ipv6 ? vpc_flag_ipv6 : std::uint8_t{0});
    w.u8(c.ipv4_length);
    w.u8(static_cast<std::uint8_t>(c.dns4.size()));
    w.u8(static_cast<std::uint8_t>(c.dns6.size()));
    w.le64(c.config_version);
    w.bytes(c.gateway_mac);
    w.u8(static_cast<std::uint8_t>(c.domain.size()));
    w.u8(0);
    w.bytes(c.ipv4_prefix);
    w.bytes(c.ipv4_gateway);
    w.bytes(c.ipv6_prefix);
    w.le32(c.lease_seconds);
    w.le16(static_cast<std::uint16_t>(c.routes.size()));
    w.le16(0);
    for (const auto& a : c.dns4) {
        w.bytes(a);
    }
    for (const auto& a : c.dns6) {
        w.bytes(a);
    }
    for (const auto& route : c.routes) {
        w.le64(route.target_nic);
        w.u8(static_cast<std::uint8_t>(route.family));
        w.u8(route.length);
        w.bytes(std::array<std::byte, 6>{});
        w.bytes(route.prefix);
    }
    w.bytes(std::as_bytes(std::span{c.domain}));
    w.bytes(c.signature);
    return out;
}

}  // namespace ak::proto
