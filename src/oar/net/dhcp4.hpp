// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// DHCPv4 (RFC 2131, options RFC 2132) messages for oar-net's stateless
// server (.kiro/specs/oar-net-data-plane/ Requirement 12.3, design "VPC
// gateway", task 17).
//
// parse() reads a client message (the UDP payload): the fixed BOOTP header,
// the magic cookie and the options oar-net uses. Guests write these bytes,
// so it is bounds-checked through ak::wire and returns std::expected. Only
// Ethernet clients (htype 1, hlen 6) are accepted. Options are read until
// End or the end of the payload, at most max_options_size bytes; an option
// running past the end fails the parse. The first instance of an option
// wins; option overload (52) is not honoured, so sname and file stay
// opaque, and long-option concatenation (RFC 3396) is not needed for what
// is read here.
//
// build_reply() writes a server message: the reply to `request` that a
// server at `server` gives with `reply`. Replies are padded to the 300-byte
// BOOTP minimum that some older clients still expect.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "oar/net/neighbor.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net::dhcp4 {

using neighbor::Ipv4Address;

inline constexpr std::uint16_t server_port = 67;
inline constexpr std::uint16_t client_port = 68;
inline constexpr std::size_t fixed_size = 236;  // op .. file
inline constexpr std::size_t min_message_size = 300;
inline constexpr std::size_t max_options_size = 1500;
inline constexpr std::uint16_t flag_broadcast = 0x8000;

enum class MessageType : std::uint8_t {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

enum class ParseError : std::uint8_t {
    truncated,     // shorter than the fixed header and cookie, or an option runs past the end
    not_request,   // op is not BOOTREQUEST
    bad_hardware,  // not Ethernet (htype 1, hlen 6)
    bad_cookie,    // magic cookie is not 99.130.83.99
    options_too_long,
    missing_type,  // no option 53
    bad_option,    // a fixed-size option with the wrong length
    unknown_type,  // option 53 outside 1..8, or a server-only type
};

[[nodiscard]] auto to_string(ParseError e) noexcept -> const char*;

struct Message {
    MessageType type{MessageType::discover};
    std::uint32_t xid{0};
    std::uint16_t flags{0};
    Ipv4Address ciaddr{};
    MacAddress chaddr{};
    std::optional<Ipv4Address> requested_ip;  // option 50
    std::optional<Ipv4Address> server_id;     // option 54
};

[[nodiscard]] auto parse(std::span<const std::byte> payload) -> std::expected<Message, ParseError>;

struct Reply {
    MessageType type{MessageType::offer};  // offer, ack or nak
    Ipv4Address yiaddr{};                  // zero for nak and inform
    Ipv4Address server{};                  // server identifier (option 54)
    // The rest is omitted from a nak; lease options are omitted when
    // lease_seconds is zero (the ack to an inform).
    Ipv4Address subnet_mask{};
    Ipv4Address router{};
    std::vector<Ipv4Address> dns{};
    std::string domain{};
    std::uint16_t mtu{0};  // option 26 when non-zero
    std::uint32_t lease_seconds{0};
};

[[nodiscard]] auto build_reply(const Message& request, const Reply& reply)
    -> std::vector<std::byte>;

}  // namespace ak::oar::net::dhcp4
