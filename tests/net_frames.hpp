// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Builders for the guest frames the oar-net tests send: Ethernet with IPv4
// or IPv6 and a UDP, TCP or ICMP/ICMPv6 header. Checksums are filled where
// a receiver would check them (IPv4 header, ICMPv6); UDP and TCP checksums
// are left zero, which nothing in oar-net looks at.

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/packet.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::test::frames {

namespace net = ak::oar::net;
namespace pk = ak::oar::net::packet;

inline constexpr std::uint8_t default_ttl = 64;
inline constexpr std::uint32_t ipv6_version_word = 0x6000'0000;
inline constexpr std::uint16_t ipv4_dont_fragment = 0x4000;
inline constexpr std::uint8_t ipv4_vihl = 0x45;
inline constexpr std::size_t ipv4_checksum_offset = 10;

inline auto ipv4_header_checksum(std::span<const std::byte> header) -> std::uint16_t {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < header.size(); i += 2) {
        sum += (std::to_integer<std::uint32_t>(header[i]) << CHAR_BIT) |
               std::to_integer<std::uint32_t>(header[i + 1]);
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

inline auto ethernet(ak::wire::Writer& w, const net::MacAddress& dst, const net::MacAddress& src,
                     std::uint16_t type) -> void {
    w.bytes(dst);
    w.bytes(src);
    w.be16(type);
}

// An IPv4 packet carrying `l4` (an L4 header and payload) as `protocol`.
// `fragment` is the raw flags/offset field (DF by default).
inline auto ipv4(const net::MacAddress& dst_mac, const net::MacAddress& src_mac,
                 const pk::Ipv4Address& src, const pk::Ipv4Address& dst, std::uint8_t protocol,
                 std::span<const std::byte> l4, std::uint16_t fragment = ipv4_dont_fragment)
    -> std::vector<std::byte> {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    ethernet(w, dst_mac, src_mac, net::neighbor::ethertype_ipv4);
    const std::size_t ip_at = f.size();
    w.u8(ipv4_vihl);
    w.u8(0);
    w.be16(static_cast<std::uint16_t>(pk::ipv4_min_header_size + l4.size()));
    w.be16(0);  // identification
    w.be16(fragment);
    w.u8(default_ttl);
    w.u8(protocol);
    w.be16(0);  // checksum, below
    w.bytes(src);
    w.bytes(dst);
    const std::uint16_t sum =
        ipv4_header_checksum(std::span{f}.subspan(ip_at, pk::ipv4_min_header_size));
    f[ip_at + ipv4_checksum_offset] = static_cast<std::byte>(sum >> CHAR_BIT);
    f[ip_at + ipv4_checksum_offset + 1] = static_cast<std::byte>(sum & UINT8_MAX);
    w.bytes(l4);
    return f;
}

// An IPv6 packet whose payload (extension headers included) is `payload`
// and whose first next header is `next`.
inline auto ipv6(const net::MacAddress& dst_mac, const net::MacAddress& src_mac,
                 const net::Ipv6Address& src, const net::Ipv6Address& dst, std::uint8_t next,
                 std::span<const std::byte> payload, std::uint8_t hop_limit = default_ttl)
    -> std::vector<std::byte> {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    ethernet(w, dst_mac, src_mac, net::neighbor::ethertype_ipv6);
    w.be32(ipv6_version_word);
    w.be16(static_cast<std::uint16_t>(payload.size()));
    w.u8(next);
    w.u8(hop_limit);
    w.bytes(src);
    w.bytes(dst);
    w.bytes(payload);
    return f;
}

// A UDP header plus `payload`, length filled, checksum zero.
inline auto udp(std::uint16_t src_port, std::uint16_t dst_port, std::span<const std::byte> payload)
    -> std::vector<std::byte> {
    std::vector<std::byte> u;
    ak::wire::Writer w{u};
    w.be16(src_port);
    w.be16(dst_port);
    w.be16(static_cast<std::uint16_t>(pk::udp_header_size + payload.size()));
    w.be16(0);
    w.bytes(payload);
    return u;
}

// A 20-byte TCP header (SYN) plus `payload`.
inline auto tcp(std::uint16_t src_port, std::uint16_t dst_port,
                std::span<const std::byte> payload = {}) -> std::vector<std::byte> {
    constexpr std::uint8_t data_offset_5 = 0x50;
    constexpr std::uint8_t syn = 0x02;
    constexpr std::uint16_t window = 0xFFFF;
    std::vector<std::byte> t;
    ak::wire::Writer w{t};
    w.be16(src_port);
    w.be16(dst_port);
    w.be32(0);
    w.be32(0);
    w.u8(data_offset_5);
    w.u8(syn);
    w.be16(window);
    w.be32(0);  // checksum, urgent pointer
    w.bytes(payload);
    return t;
}

// An ICMPv6 message with its checksum filled for src -> dst.
inline auto icmpv6(const net::Ipv6Address& src, const net::Ipv6Address& dst, std::uint8_t type,
                   std::uint8_t code, std::span<const std::byte> body) -> std::vector<std::byte> {
    std::vector<std::byte> m;
    ak::wire::Writer w{m};
    w.u8(type);
    w.u8(code);
    w.be16(0);
    w.bytes(body);
    const std::uint16_t sum = net::neighbor::icmpv6_checksum(src, dst, m);
    m[2] = static_cast<std::byte>(sum >> CHAR_BIT);
    m[3] = static_cast<std::byte>(sum & UINT8_MAX);
    return m;
}

}  // namespace ak::test::frames
