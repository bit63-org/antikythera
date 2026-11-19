// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VTEP-to-VTEP OAM messages (.kiro/specs/oar-net-data-plane/ Requirement
// 3.6, design "Vtep", task 9).
//
// An OAM message is a Geneve packet with the O bit set, which the receiving
// VTEP consumes itself and never hands to the VSwitch:
//
//   Geneve base header   8 bytes   Ver=0, Opt Len=0, O=1, C=0,
//                                   Protocol Type=protocol, VNI=0
//   version              1 byte    1
//   type                 1 byte    1 = keepalive
//   reserved             2 bytes   sent as 0, ignored on receipt
//   sequence             8 bytes   per-sender counter, big-endian
//
// OAM is between VTEPs, not VPCs, so it carries no VNI and no NIC-pair
// option. The MTU probe (task 11) will be another type.
//
// Nothing here is authenticated: until the WireGuard tunnel (task 10) wraps
// the underlay, anyone who can reach the VTEP's port can forge a keepalive.
// The Vtep therefore accepts keepalives only from addresses that are peer
// VTEPs in the current mappings, and liveness is advisory.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "oar/net/geneve.hpp"

namespace ak::oar::net::oam {

// Geneve Protocol Type of OAM messages: IEEE 802 local experimental
// EtherType 2. Like geneve::option_class, a placeholder for systems we
// control.
inline constexpr std::uint16_t protocol = 0x88B6;
inline constexpr std::uint8_t version = 1;
inline constexpr std::size_t body_size = 12;
inline constexpr std::size_t message_size = geneve::base_header_size + body_size;

enum class Type : std::uint8_t {
    keepalive = 1,
};

struct Message {
    Type type{Type::keepalive};
    std::uint64_t sequence{0};
    friend constexpr auto operator==(const Message&, const Message&) -> bool = default;
};

enum class OamError : std::uint8_t {
    not_oam,         // the O bit is clear: a data packet
    bad_protocol,    // Protocol Type is not oam::protocol
    nonzero_vni,     // OAM belongs to no VPC
    truncated,       // shorter than the body
    bad_version,     // body version is not oam::version
    unknown_type,    // a type this VTEP does not implement
    trailing_bytes,  // bytes after the body
};

inline constexpr std::size_t oam_error_count =
    static_cast<std::size_t>(OamError::trailing_bytes) + 1;

[[nodiscard]] auto to_string(OamError e) noexcept -> const char*;

// The complete Geneve UDP payload for `message`.
[[nodiscard]] auto encode(const Message& message) -> std::vector<std::byte>;

// Parses an OAM packet that geneve::decode() accepted.
[[nodiscard]] auto parse(const geneve::Packet& packet) noexcept -> std::expected<Message, OamError>;

}  // namespace ak::oar::net::oam
