// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The L3/L4 parser every guest IP frame goes through
// (.kiro/specs/oar-net-data-plane/ Requirement 11.2, design "IP awareness",
// task 15).
//
// Guests write these bytes, so the parser is bounds-checked through
// ak::wire and returns std::expected. It reads one untagged Ethernet frame
// carrying IPv4 or IPv6 and finds:
//   - the addresses, protocol and TTL/hop limit;
//   - whether the packet is a fragment, and whether it is the first one;
//   - the TCP or UDP ports, or the ICMP/ICMPv6 type and code, in an
//     unfragmented packet or a first fragment.
//
// IPv4: version 4, IHL >= 5, total length covering the header and within
// the frame; Ethernet padding past the total length is ignored. The header
// checksum is not verified: the receiving stack does that, and a packet
// with a bad checksum cannot pass the source check any more easily than a
// good one.
//
// IPv6: version 6, payload length within the frame. At most
// max_extension_headers extension headers are walked: hop-by-hop (only
// first), routing, fragment, destination options and AH. A fragment header
// with a non-zero offset ends the walk with no L4 header. ESP, "no next
// header" and every other value are the upper-layer protocol.
//
// L4 headers: TCP needs a data offset of at least 5 words, within the
// packet; UDP 8 bytes and, unfragmented, a length between 8 and the rest
// of the IP payload; ICMP and ICMPv6 four bytes. A first fragment too short
// to hold its L4 header is refused (RFC 1858: tiny fragments are how port
// filters are evaded).

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include "oar/net/neighbor.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net::packet {

using neighbor::Ipv4Address;

inline constexpr std::uint8_t ipproto_icmp = 1;
inline constexpr std::uint8_t ipproto_tcp = 6;
inline constexpr std::uint8_t ipproto_udp = 17;
inline constexpr std::uint8_t ipproto_icmpv6 = 58;
inline constexpr std::uint8_t ipproto_hop_by_hop = 0;
inline constexpr std::uint8_t ipproto_routing = 43;
inline constexpr std::uint8_t ipproto_fragment = 44;
inline constexpr std::uint8_t ipproto_esp = 50;
inline constexpr std::uint8_t ipproto_ah = 51;
inline constexpr std::uint8_t ipproto_none = 59;
inline constexpr std::uint8_t ipproto_destination_options = 60;

inline constexpr std::size_t ipv4_min_header_size = 20;
inline constexpr std::size_t ipv6_header_size = 40;
inline constexpr std::size_t tcp_min_header_size = 20;
inline constexpr std::size_t udp_header_size = 8;
inline constexpr std::size_t icmp_header_size = 4;
inline constexpr std::size_t max_extension_headers = 8;

enum class IpFamily : std::uint8_t {
    ipv4,
    ipv6,
};

enum class PacketError : std::uint8_t {
    not_ip,               // EtherType is neither IPv4 nor IPv6 (VLAN tags included)
    truncated,            // a header runs past the frame or the IP length
    bad_version,          // IP version does not match the EtherType
    bad_header_length,    // IPv4 IHL < 5, or past the total length
    bad_total_length,     // IPv4 total length < IHL, or past the frame
    bad_extension_order,  // IPv6 hop-by-hop header not first
    too_many_extensions,  // more than max_extension_headers
    bad_l4_header,        // TCP data offset < 5 or past the packet; UDP length wrong
    tiny_fragment,        // a first fragment without its whole L4 header
};

[[nodiscard]] auto to_string(PacketError e) noexcept -> const char*;

// Ports for TCP and UDP; type and code for ICMP and ICMPv6.
struct L4Header {
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    std::uint8_t icmp_type{0};
    std::uint8_t icmp_code{0};
};

struct ParsedPacket {
    IpFamily family{IpFamily::ipv4};
    // IPv4 addresses are in src4/dst4, IPv6 ones in src6/dst6; the other
    // pair is zero.
    Ipv4Address src4{};
    Ipv4Address dst4{};
    Ipv6Address src6{};
    Ipv6Address dst6{};
    std::uint8_t protocol{0};            // IPv4 protocol, or the IPv6 upper-layer next header
    std::uint8_t hop_limit{0};           // TTL for IPv4
    bool fragment{false};                // part of a fragmented packet
    bool first_fragment{false};          // fragment offset 0 (true for unfragmented packets)
    std::optional<L4Header> l4;          // TCP, UDP, ICMP or ICMPv6 when present
    std::span<const std::byte> ip;       // the IP header through the end of the IP packet
    std::span<const std::byte> l4_data;  // the L4 header onward (empty without one)
    std::span<const std::byte> payload;  // after the L4 header (UDP: bounded by its length)
};

// Parses an untagged Ethernet frame carrying IPv4 or IPv6.
[[nodiscard]] auto parse(std::span<const std::byte> frame)
    -> std::expected<ParsedPacket, PacketError>;

// The frame's EtherType (bytes 12-13); 0 for frames shorter than that.
[[nodiscard]] auto ethertype(std::span<const std::byte> frame) noexcept -> std::uint16_t;

[[nodiscard]] auto is_ipv4_multicast(const Ipv4Address& a) noexcept -> bool;   // 224/4
[[nodiscard]] auto is_ipv6_multicast(const Ipv6Address& a) noexcept -> bool;   // ff00::/8
[[nodiscard]] auto is_ipv6_link_local(const Ipv6Address& a) noexcept -> bool;  // fe80::/10
[[nodiscard]] auto is_unspecified(std::span<const std::byte> a) noexcept -> bool;

}  // namespace ak::oar::net::packet
