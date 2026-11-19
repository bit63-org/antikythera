// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Guest MTU from the underlay MTU (.kiro/specs/oar-net-data-plane/
// Requirement 6, task 11).
//
// A guest frame crosses the underlay as
//
//   [tunnel overhead] outer IPv6 (40) | UDP (8) | Geneve (8) |
//   NIC-pair option (20) | inner Ethernet (14) | VLAN tag (4) | guest payload
//
// The guest's MTU counts only the payload, so the largest guest frame adds
// 94 bytes before any tunnel. The requirement's 90 leaves out the VLAN tag,
// but guest tags are payload (Requirement 2.2) and VirtioNetFunction admits
// one on top of the MTU, so a tagged full-size frame would not fit with 90.
//
// The tunnel (task 10) wraps the whole Geneve datagram. WireGuard over IPv6
// adds an outer IPv6 header, UDP and its 32 bytes of header and tag: 80,
// the same figure Linux uses for a wg device's default MTU. WireGuard pads
// the plaintext to a multiple of 16 but never past its own MTU, which this
// plan keeps every datagram under, so padding needs no allowance here.
//
// With a 9000-byte underlay and WireGuard a guest gets 8826; with 1500 and
// no tunnel, 1406 (Requirement 6.2 asks for at least 1500 from 9000).

#include <cstddef>
#include <cstdint>
#include <expected>

#include "oar/net/geneve.hpp"
#include "oar/net/virtio_net.hpp"

namespace ak::oar::net {

inline constexpr std::size_t ipv6_header_size = 40;
inline constexpr std::size_t udp_header_size = 8;
// IPv6's minimum link MTU (RFC 8200 section 5).
inline constexpr std::uint32_t min_underlay_mtu = 1280;
// Largest IPv6 packet without a jumbogram: payload length is 16 bits.
inline constexpr std::uint32_t max_underlay_mtu = 65535 + ipv6_header_size;
// virtio-net's mtu field is 16 bits.
inline constexpr std::uint32_t max_guest_mtu = 65535;

// Outer IPv6 and UDP headers around the Geneve datagram.
inline constexpr std::size_t outer_header_size = ipv6_header_size + udp_header_size;
// Geneve base header and the NIC-pair option in front of the inner frame.
inline constexpr std::size_t geneve_header_size =
    geneve::base_header_size + geneve::nic_pair_option_size;
// Inner Ethernet header and one guest VLAN tag around the guest payload.
inline constexpr std::size_t inner_frame_overhead = ethernet_header_size + vlan_tag_size;
// Everything a guest frame gains on the underlay, before any tunnel.
inline constexpr std::size_t encapsulation_overhead =
    outer_header_size + geneve_header_size + inner_frame_overhead;
static_assert(encapsulation_overhead == 94);
// So every guest MTU a valid underlay yields fits virtio-net's u16 field.
static_assert(max_underlay_mtu - encapsulation_overhead <= max_guest_mtu);

// WireGuard over IPv6: outer IPv6 (40), UDP (8), message header (16) and
// Poly1305 tag (16).
inline constexpr std::size_t wireguard_ipv6_overhead = ipv6_header_size + udp_header_size + 32;

struct MtuPlan {
    std::uint32_t underlay_mtu{0};
    std::uint32_t tunnel_overhead{0};
    // Largest Geneve UDP payload the Vtep may send (headers from the Geneve
    // base header on, no outer IPv6/UDP, no tunnel).
    std::uint32_t max_geneve_payload{0};
    // What VirtioNetFunction advertises through VIRTIO_NET_F_MTU.
    std::uint16_t guest_mtu{0};
};

enum class MtuError : std::uint8_t {
    underlay_too_small,  // below IPv6's 1280
    underlay_too_large,  // above an IPv6 packet without a jumbogram
    guest_too_small,     // the overheads leave the guest less than min_mtu
};

[[nodiscard]] auto to_string(MtuError e) noexcept -> const char*;

// The plan for an underlay of `underlay_mtu` bytes carrying a tunnel that
// adds `tunnel_overhead` (0 without one).
[[nodiscard]] auto plan_mtu(std::uint32_t underlay_mtu, std::uint32_t tunnel_overhead = 0)
    -> std::expected<MtuPlan, MtuError>;

}  // namespace ak::oar::net
