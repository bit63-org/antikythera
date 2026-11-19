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
#include <utility>
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

// A DHCPv4 client message (BOOTREQUEST) with `options` (code, value pairs,
// End appended) for `chaddr`.
struct DhcpOption {
    std::uint8_t code{0};
    std::vector<std::byte> value;
};

struct DhcpOption6 {
    std::uint16_t code{0};
    std::vector<std::byte> value;
};

inline auto dhcp4_request(std::uint8_t type, const net::MacAddress& chaddr, std::uint32_t xid,
                          std::vector<DhcpOption> options = {}, std::uint16_t flags = 0,
                          const pk::Ipv4Address& ciaddr = {}) -> std::vector<std::byte> {
    constexpr std::uint8_t op_request = 1;
    constexpr std::uint8_t htype_ethernet = 1;
    constexpr std::uint8_t hlen_ethernet = 6;
    constexpr std::size_t chaddr_pad = 10;
    constexpr std::size_t sname_file = 64 + 128;
    constexpr std::uint32_t magic_cookie = 0x6382'5363;
    constexpr std::uint8_t opt_message_type = 53;
    constexpr std::uint8_t opt_end = 255;
    std::vector<std::byte> m;
    ak::wire::Writer w{m};
    w.u8(op_request);
    w.u8(htype_ethernet);
    w.u8(hlen_ethernet);
    w.u8(0);
    w.be32(xid);
    w.be16(0);
    w.be16(flags);
    w.bytes(ciaddr);
    m.resize(m.size() + 12, std::byte{0});  // yiaddr, siaddr, giaddr
    w.bytes(chaddr);
    m.resize(m.size() + chaddr_pad + sname_file, std::byte{0});
    w.be32(magic_cookie);
    w.u8(opt_message_type);
    w.u8(1);
    w.u8(type);
    for (const auto& o : options) {
        w.u8(o.code);
        w.u8(static_cast<std::uint8_t>(o.value.size()));
        w.bytes(o.value);
    }
    w.u8(opt_end);
    return m;
}

// The options of a DHCPv4 server message, by code (first instance), after
// the 240-byte fixed part and cookie.
inline auto dhcp4_options(std::span<const std::byte> message)
    -> std::vector<std::pair<std::uint8_t, std::vector<std::byte>>> {
    constexpr std::size_t options_offset = 240;
    std::vector<std::pair<std::uint8_t, std::vector<std::byte>>> out;
    std::size_t i = options_offset;
    while (i < message.size()) {
        const auto code = std::to_integer<std::uint8_t>(message[i]);
        if (code == 255) {
            break;
        }
        if (code == 0) {
            ++i;
            continue;
        }
        if (i + 1 >= message.size()) {
            break;
        }
        const auto len = std::to_integer<std::size_t>(message[i + 1]);
        if (i + 2 + len > message.size()) {
            break;
        }
        out.emplace_back(code, std::vector<std::byte>(
                                   message.begin() + static_cast<std::ptrdiff_t>(i + 2),
                                   message.begin() + static_cast<std::ptrdiff_t>(i + 2 + len)));
        i += 2 + len;
    }
    return out;
}

// A DHCPv6 client message: type, transaction ID, then each option as given
// (code, value).
inline auto dhcp6_message(std::uint8_t type, std::uint32_t xid,
                          const std::vector<DhcpOption6>& options) -> std::vector<std::byte> {
    std::vector<std::byte> m;
    ak::wire::Writer w{m};
    w.be32((std::uint32_t{type} << 24U) | (xid & 0x00FF'FFFFU));
    for (const auto& o : options) {
        w.be16(o.code);
        w.be16(static_cast<std::uint16_t>(o.value.size()));
        w.bytes(o.value);
    }
    return m;
}

// An IA_NA option body: IAID, T1 and T2 zero, then IAADDR options.
inline auto ia_na(std::uint32_t iaid, const std::vector<net::Ipv6Address>& addresses = {})
    -> std::vector<std::byte> {
    std::vector<std::byte> v;
    ak::wire::Writer w{v};
    w.be32(iaid);
    w.be32(0);
    w.be32(0);
    for (const auto& a : addresses) {
        w.be16(5);
        w.be16(24);
        w.bytes(a);
        w.be32(0);
        w.be32(0);
    }
    return v;
}

// Top-level DHCPv6 options of a server message, in order.
inline auto dhcp6_options(std::span<const std::byte> message)
    -> std::vector<std::pair<std::uint16_t, std::vector<std::byte>>> {
    std::vector<std::pair<std::uint16_t, std::vector<std::byte>>> out;
    std::size_t i = 4;
    while (i + 4 <= message.size()) {
        const auto code = static_cast<std::uint16_t>((std::to_integer<unsigned>(message[i]) << 8U) |
                                                     std::to_integer<unsigned>(message[i + 1]));
        const auto len = (std::to_integer<std::size_t>(message[i + 2]) << 8U) |
                         std::to_integer<std::size_t>(message[i + 3]);
        if (i + 4 + len > message.size()) {
            break;
        }
        out.emplace_back(code, std::vector<std::byte>(
                                   message.begin() + static_cast<std::ptrdiff_t>(i + 4),
                                   message.begin() + static_cast<std::ptrdiff_t>(i + 4 + len)));
        i += 4 + len;
    }
    return out;
}

}  // namespace ak::test::frames
