// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// DHCPv6 (RFC 8415) messages for oar-net's stateless server, and the
// router advertisements the VPC gateway sends (.kiro/specs/
// oar-net-data-plane/ Requirements 12.4 and 12.5, design "VPC gateway",
// task 18).
//
// parse() reads a client message (the UDP payload): message type,
// transaction ID, and the options the server acts on: client and server
// identifiers, the first IA_NA (its IAID and any addresses in it, which a
// Confirm carries), and Rapid Commit. Guests write these bytes, so it is
// bounds-checked through ak::wire and returns std::expected. Options must
// lie inside the message, the message inside max_message_size, and DUIDs
// inside max_duid_size (RFC 8415 11.1). Options inside an IA_NA are
// walked one level deep, for IAADDR only.
//
// build_reply() writes an Advertise or Reply.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net::dhcp6 {

inline constexpr std::uint16_t client_port = 546;
inline constexpr std::uint16_t server_port = 547;
inline constexpr std::size_t max_message_size = 1500;
inline constexpr std::size_t max_duid_size = 130;  // 2-byte type + at most 128 bytes
inline constexpr std::size_t max_ia_addresses = 16;

// All_DHCP_Relay_Agents_and_Servers, ff02::1:2.
inline constexpr Ipv6Address all_servers{
    std::byte{0xff}, std::byte{0x02}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
    std::byte{0},    std::byte{0},    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
    std::byte{0},    std::byte{1},    std::byte{0}, std::byte{2}};

enum class MessageType : std::uint8_t {
    solicit = 1,
    advertise = 2,
    request = 3,
    confirm = 4,
    renew = 5,
    rebind = 6,
    reply = 7,
    release = 8,
    decline = 9,
    information_request = 11,
};

enum class StatusCode : std::uint16_t {
    success = 0,
    no_addrs_avail = 2,
    not_on_link = 4,
};

enum class ParseError : std::uint8_t {
    truncated,     // shorter than type + transaction ID, or an option runs past its parent
    too_long,      // over max_message_size
    unknown_type,  // not a client message type
    bad_duid,      // an empty or oversized client or server identifier
    bad_option,    // IA_NA, IAADDR or Rapid Commit with the wrong length
    too_many_addresses,
};

[[nodiscard]] auto to_string(ParseError e) noexcept -> const char*;

struct IaNa {
    std::uint32_t iaid{0};
    std::vector<Ipv6Address> addresses{};  // IAADDR options inside it
};

struct Message {
    MessageType type{MessageType::solicit};
    std::uint32_t xid{0};  // 24 bits
    std::vector<std::byte> client_id{};
    std::optional<std::vector<std::byte>> server_id{};
    std::optional<IaNa> ia_na{};  // the first one
    bool rapid_commit{false};
};

[[nodiscard]] auto parse(std::span<const std::byte> payload) -> std::expected<Message, ParseError>;

// The server's DUID-LL (RFC 8415 11.4): type 3, hardware type 1, the MAC.
[[nodiscard]] auto server_duid(const MacAddress& mac) -> std::vector<std::byte>;

struct Reply {
    MessageType type{MessageType::reply};  // advertise or reply
    std::vector<std::byte> server_id{};
    // An IA_NA echoing the request's IAID with these addresses, or the
    // status in it when empty; left out when the request had none.
    std::optional<std::uint32_t> iaid{};
    std::vector<Ipv6Address> addresses{};
    std::uint32_t lifetime{0};           // preferred = valid; T1 = 1/2, T2 = 7/8 of it
    std::optional<StatusCode> status{};  // a top-level Status Code option
    bool rapid_commit{false};
    std::vector<Ipv6Address> dns{};  // option 23
    std::string domain{};            // option 24, one name
};

[[nodiscard]] auto build_reply(const Message& request, const Reply& reply)
    -> std::vector<std::byte>;

// A router advertisement body (RFC 4861 4.2), after the ICMPv6 type, code
// and checksum: M and O set, the /64 on-link but not for autonomous
// configuration, the gateway MAC as source link-layer address, the MTU
// when non-zero, and RDNSS (RFC 8106) when there are DNS servers.
struct RouterAdvertisement {
    MacAddress gateway_mac{};
    Ipv6Address prefix{};  // a /64
    std::uint16_t mtu{0};
    std::vector<Ipv6Address> dns{};
    std::uint16_t router_lifetime{0};
    std::uint32_t dns_lifetime{0};
};

inline constexpr std::uint8_t icmpv6_router_solicitation = 133;
inline constexpr std::uint8_t icmpv6_router_advertisement = 134;

[[nodiscard]] auto build_router_advertisement_body(const RouterAdvertisement& ra)
    -> std::vector<std::byte>;

}  // namespace ak::oar::net::dhcp6
