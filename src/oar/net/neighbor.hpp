// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ARP (RFC 826) and IPv6 neighbor solicitation (RFC 4861 4.3) parsing, and
// the replies the VSwitch's proxy builds (.kiro/specs/oar-net-data-plane/
// Requirement 2.6, task 8).
//
// Every frame parsed here was written by a guest, so the parsers are
// bounds-checked through ak::wire and return std::expected. They check
// structure and consistency with the Ethernet header (an ARP sender
// hardware address or an NS source link-layer option must equal the frame's
// source MAC); whether the addresses are believable for the sending NIC is
// the VSwitch's business.
//
// Only untagged frames are recognised: guest VLAN tags are payload
// (Requirement 2.2), so a tagged frame is just a frame and is forwarded.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net::neighbor {

using Ipv4Address = std::array<std::byte, 4>;

inline constexpr std::uint16_t ethertype_arp = 0x0806;
inline constexpr std::uint16_t ethertype_ipv4 = 0x0800;
inline constexpr std::uint16_t ethertype_ipv6 = 0x86DD;

inline constexpr std::uint16_t arp_op_request = 1;
inline constexpr std::uint16_t arp_op_reply = 2;
inline constexpr std::size_t arp_size = 28;  // Ethernet/IPv4 ARP body

inline constexpr std::uint8_t ipproto_icmpv6 = 58;
inline constexpr std::uint8_t nd_hop_limit = 255;
inline constexpr std::uint8_t icmpv6_neighbor_solicitation = 135;
inline constexpr std::uint8_t icmpv6_neighbor_advertisement = 136;
inline constexpr std::size_t ipv6_header_size = 40;
inline constexpr std::size_t nd_message_size = 24;  // type..target, before options

enum class ParseError : std::uint8_t {
    not_arp,           // Ethernet type is not ARP
    not_icmpv6,        // not IPv6, or the next header is not ICMPv6 (extension headers included)
    truncated,         // a header or option runs past the frame or the IPv6 payload
    bad_format,        // ARP: not Ethernet/IPv4 or bad lengths; IPv6: version != 6
    unknown_op,        // ARP opcode other than request or reply
    not_solicitation,  // ICMPv6 type other than 135, or code != 0
    bad_hop_limit,     // NS with hop limit != 255 (RFC 4861 7.1.1)
    bad_checksum,      // ICMPv6 checksum does not verify
    bad_option,        // an ND option with length 0
    bad_target,        // NS target is a multicast address
    sender_mismatch,   // ARP sender MAC or NS source link-layer option != frame source MAC
};

[[nodiscard]] auto to_string(ParseError e) noexcept -> const char*;

struct ArpPacket {
    std::uint16_t op{0};
    MacAddress sender_mac{};
    Ipv4Address sender_ip{};
    MacAddress target_mac{};
    Ipv4Address target_ip{};
};

// An Ethernet/IPv4 ARP request or reply. Trailing padding is ignored.
[[nodiscard]] auto parse_arp(std::span<const std::byte> frame)
    -> std::expected<ArpPacket, ParseError>;

struct NeighborSolicitation {
    MacAddress sender_mac{};  // the frame's source MAC
    Ipv6Address source_ip{};  // all-zero for duplicate address detection
    Ipv6Address target_ip{};
};

// An IPv6 neighbor solicitation with no extension headers.
[[nodiscard]] auto parse_neighbor_solicitation(std::span<const std::byte> frame)
    -> std::expected<NeighborSolicitation, ParseError>;

// The ARP reply a host owning `request.target_ip` at `target_mac` would
// send, addressed to the requester.
[[nodiscard]] auto build_arp_reply(const ArpPacket& request, const MacAddress& target_mac)
    -> std::vector<std::byte>;

// A solicited neighbor advertisement (S and O set, R clear) for
// `ns.target_ip` at `target_mac` with a target link-layer address option,
// addressed to the soliciting host. `ns` must not be a DAD probe.
[[nodiscard]] auto build_neighbor_advertisement(const NeighborSolicitation& ns,
                                                const MacAddress& target_mac)
    -> std::vector<std::byte>;

// The ICMPv6 checksum (RFC 4443 2.3) of `message` between the two
// addresses; 0 when `message` carries a correct checksum.
[[nodiscard]] auto icmpv6_checksum(const Ipv6Address& src, const Ipv6Address& dst,
                                   std::span<const std::byte> message) noexcept -> std::uint16_t;

}  // namespace ak::oar::net::neighbor
