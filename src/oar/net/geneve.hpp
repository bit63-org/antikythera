// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Geneve (RFC 8926) encapsulation for VPC traffic between VTEPs.
//
// Wire format carried in the UDP payload (UDP destination port 6081, over
// IPv6; the outer IPv6/UDP headers are the socket's business, not ours):
//
//   Geneve base header   8 bytes   Ver=0, Opt Len=5, O, C=1,
//                                   Protocol Type=0x6558, VNI = global VPC ID
//   NIC-pair option     20 bytes   class=option_class, type=0x81 (critical),
//                                   len=4: source NIC ID (64), dest NIC ID (64)
//   Inner Ethernet frame
//
// decode() validates structure only. Whether the NIC IDs are believable for
// the sending VTEP is checked separately against controller-supplied
// mappings (vtep_policy.hpp).

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace ak::oar::net::geneve {

inline constexpr std::uint16_t udp_port = 6081;
inline constexpr std::uint16_t protocol_ethernet = 0x6558;  // Transparent Ethernet Bridging

// Placeholder taken from IANA's experimental range of the Geneve Option
// Class registry. Register a real class before using the format outside
// systems we control.
inline constexpr std::uint16_t option_class = 0xFF41;
inline constexpr std::uint8_t option_type_critical_bit = 0x80;
inline constexpr std::uint8_t option_type_nic_pair = option_type_critical_bit | 0x01;

inline constexpr std::size_t base_header_size = 8;
inline constexpr std::size_t nic_pair_option_size = 20;  // 4-byte option header + 16 bytes data
inline constexpr std::size_t ethernet_header_size = 14;
inline constexpr std::uint32_t vni_max = 0x00FF'FFFF;

// Controller-assigned 64-bit NIC identifier. 0 is invalid; all-ones as a
// destination means "broadcast within the VNI".
struct NicId {
    std::uint64_t value{0};
    friend constexpr auto operator<=>(NicId, NicId) = default;
};

inline constexpr NicId nic_invalid{0};
inline constexpr NicId nic_broadcast{~std::uint64_t{0}};

struct NicPair {
    NicId src;
    NicId dst;
    friend constexpr bool operator==(const NicPair&, const NicPair&) = default;
};

// A decoded packet. `inner` aliases the input buffer.
struct Packet {
    std::uint32_t vni{0};
    bool oam{false};
    std::uint16_t protocol{protocol_ethernet};
    std::optional<NicPair> nics;  // always present for non-OAM packets
    std::span<const std::byte> inner;
};

enum class DecodeError : std::uint8_t {
    truncated,                // shorter than the base header, or an option ran past Opt Len
    bad_version,              // Ver != 0
    options_overrun,          // Opt Len exceeds the packet
    bad_option_length,        // NIC-pair option with Length != 4
    unknown_critical_option,  // critical option we do not implement: must drop (RFC 8926 3.5.1)
    critical_flag_mismatch,   // critical option present but C bit clear
    missing_nic_pair,         // data packet without the NIC-pair option
    duplicate_nic_pair,       // more than one NIC-pair option
    invalid_nic_id,           // src is 0 or broadcast, or dst is 0
    bad_protocol,             // data packet that is not an Ethernet payload
    inner_frame_too_short,    // inner Ethernet frame shorter than its header
};

[[nodiscard]] const char* to_string(DecodeError e) noexcept;

// Structural decode of a Geneve UDP payload.
[[nodiscard]] std::expected<Packet, DecodeError> decode(std::span<const std::byte> udp_payload) noexcept;

// What a sending VTEP supplies. `src` must come from the VF the frame
// arrived on -- never from anything the guest wrote.
struct EncodeParams {
    std::uint32_t vni{0};
    NicPair nics;
    bool oam{false};
};

enum class EncodeError : std::uint8_t {
    vni_out_of_range,
    invalid_nic_id,
    inner_frame_too_short,
};

[[nodiscard]] const char* to_string(EncodeError e) noexcept;

// Builds a complete Geneve UDP payload: base header, NIC-pair option, frame.
[[nodiscard]] std::expected<std::vector<std::byte>, EncodeError> encode(
    const EncodeParams& params, std::span<const std::byte> inner_frame);

}  // namespace ak::oar::net::geneve
