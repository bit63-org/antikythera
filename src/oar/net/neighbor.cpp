// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/neighbor.hpp"

#include <algorithm>
#include <climits>

#include "common/wire.hpp"

namespace ak::oar::net::neighbor {

namespace {

constexpr std::uint16_t arp_htype_ethernet = 1;
constexpr std::uint8_t mac_size = 6;
constexpr std::uint8_t ipv4_size = 4;
constexpr std::size_t ipv6_size = 16;
constexpr unsigned ip_version_shift = 28;
constexpr std::uint32_t ip_version_6 = 6;
constexpr std::size_t icmpv6_checksum_offset = 2;
constexpr std::size_t nd_reserved_size = 4;
constexpr std::uint32_t na_flags_solicited_override = 0x6000'0000;  // S | O, R clear
constexpr std::uint8_t nd_option_source_lladdr = 1;
constexpr std::uint8_t nd_option_target_lladdr = 2;
constexpr std::uint8_t nd_option_unit = 8;  // option Length counts 8-byte units
constexpr std::uint8_t nd_lladdr_option_units = 1;
constexpr std::size_t nd_option_header_size = 2;
constexpr std::byte ipv6_multicast_prefix{0xff};
constexpr std::uint32_t low16 = 0xFFFF;
constexpr unsigned bits16 = 16;

template<std::size_t N>
auto to_array(std::span<const std::byte> s) noexcept -> std::array<std::byte, N> {
    std::array<std::byte, N> a{};
    std::copy_n(s.begin(), N, a.begin());
    return a;
}

auto map_wire(wire::WireError /*e*/) -> std::unexpected<ParseError> {
    return std::unexpected(ParseError::truncated);
}

// Reads the Ethernet header; returns the source MAC and leaves `r` at the
// payload, or fails if the type is not `want`.
auto read_ethernet(wire::Reader& r, std::uint16_t want, ParseError wrong_type)
    -> std::expected<MacAddress, ParseError> {
    if (!r.skip(mac_size)) {
        return std::unexpected(ParseError::truncated);
    }
    auto src = r.bytes(mac_size);
    if (!src) {
        return map_wire(src.error());
    }
    auto type = r.be16();
    if (!type) {
        return map_wire(type.error());
    }
    if (*type != want) {
        return std::unexpected(wrong_type);
    }
    return to_array<mac_size>(*src);
}

auto write_ethernet(wire::Writer& w, const MacAddress& dst, const MacAddress& src,
                    std::uint16_t type) -> void {
    w.bytes(dst);
    w.bytes(src);
    w.be16(type);
}

auto add_words(std::uint32_t sum, std::span<const std::byte> data) noexcept -> std::uint32_t {
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += (std::to_integer<std::uint32_t>(data[i]) << CHAR_BIT) |
               std::to_integer<std::uint32_t>(data[i + 1]);
    }
    if (i < data.size()) {
        sum += std::to_integer<std::uint32_t>(data[i]) << CHAR_BIT;
    }
    return sum;
}

}  // namespace

auto to_string(ParseError e) noexcept -> const char* {
    switch (e) {
        case ParseError::not_arp:
            return "not_arp";
        case ParseError::not_icmpv6:
            return "not_icmpv6";
        case ParseError::truncated:
            return "truncated";
        case ParseError::bad_format:
            return "bad_format";
        case ParseError::unknown_op:
            return "unknown_op";
        case ParseError::not_solicitation:
            return "not_solicitation";
        case ParseError::bad_hop_limit:
            return "bad_hop_limit";
        case ParseError::bad_checksum:
            return "bad_checksum";
        case ParseError::bad_option:
            return "bad_option";
        case ParseError::bad_target:
            return "bad_target";
        case ParseError::sender_mismatch:
            return "sender_mismatch";
    }
    return "unknown";
}

auto icmpv6_checksum(const Ipv6Address& src, const Ipv6Address& dst,
                     std::span<const std::byte> message) noexcept -> std::uint16_t {
    std::uint32_t sum = 0;
    sum = add_words(sum, src);
    sum = add_words(sum, dst);
    const auto length = static_cast<std::uint32_t>(message.size());
    sum += (length >> bits16) + (length & low16);
    sum += ipproto_icmpv6;
    sum = add_words(sum, message);
    while ((sum >> bits16) != 0) {
        sum = (sum & low16) + (sum >> bits16);
    }
    return static_cast<std::uint16_t>(~sum & low16);
}

auto parse_arp(std::span<const std::byte> frame) -> std::expected<ArpPacket, ParseError> {
    wire::Reader r{frame};
    const auto frame_src = read_ethernet(r, ethertype_arp, ParseError::not_arp);
    if (!frame_src) {
        return std::unexpected(frame_src.error());
    }
    if (r.remaining() < arp_size) {
        return std::unexpected(ParseError::truncated);
    }
    // The size check above covers every read below.
    const auto htype = r.be16().value_or(0);
    const auto ptype = r.be16().value_or(0);
    const auto hlen = r.u8().value_or(0);
    const auto plen = r.u8().value_or(0);
    if (htype != arp_htype_ethernet || ptype != ethertype_ipv4 || hlen != mac_size ||
        plen != ipv4_size) {
        return std::unexpected(ParseError::bad_format);
    }
    ArpPacket p{};
    p.op = r.be16().value_or(0);
    if (p.op != arp_op_request && p.op != arp_op_reply) {
        return std::unexpected(ParseError::unknown_op);
    }
    p.sender_mac = to_array<mac_size>(*r.bytes(mac_size));
    p.sender_ip = to_array<ipv4_size>(*r.bytes(ipv4_size));
    p.target_mac = to_array<mac_size>(*r.bytes(mac_size));
    p.target_ip = to_array<ipv4_size>(*r.bytes(ipv4_size));
    if (p.sender_mac != *frame_src) {
        return std::unexpected(ParseError::sender_mismatch);
    }
    return p;
}

auto parse_neighbor_solicitation(std::span<const std::byte> frame)
    -> std::expected<NeighborSolicitation, ParseError> {
    wire::Reader r{frame};
    const auto frame_src = read_ethernet(r, ethertype_ipv6, ParseError::not_icmpv6);
    if (!frame_src) {
        return std::unexpected(frame_src.error());
    }
    if (r.remaining() < ipv6_header_size) {
        return std::unexpected(ParseError::truncated);
    }
    // The size check above covers the fixed IPv6 header.
    const auto version = r.be32().value_or(0) >> ip_version_shift;
    const auto payload_length = r.be16().value_or(0);
    const auto next_header = r.u8().value_or(0);
    const auto hop_limit = r.u8().value_or(0);
    const auto src = to_array<ipv6_size>(*r.bytes(ipv6_size));
    const auto dst = to_array<ipv6_size>(*r.bytes(ipv6_size));
    if (version != ip_version_6) {
        return std::unexpected(ParseError::bad_format);
    }
    if (next_header != ipproto_icmpv6) {
        return std::unexpected(ParseError::not_icmpv6);
    }
    const auto payload = r.bytes(payload_length);
    if (!payload) {
        return map_wire(payload.error());
    }

    wire::Reader m{*payload};
    if (m.remaining() < nd_message_size) {
        return std::unexpected(ParseError::truncated);
    }
    const auto type = m.u8().value_or(0);
    const auto code = m.u8().value_or(0);
    if (type != icmpv6_neighbor_solicitation || code != 0) {
        return std::unexpected(ParseError::not_solicitation);
    }
    if (hop_limit != nd_hop_limit) {
        return std::unexpected(ParseError::bad_hop_limit);
    }
    if (icmpv6_checksum(src, dst, *payload) != 0) {
        return std::unexpected(ParseError::bad_checksum);
    }
    static_cast<void>(m.skip(icmpv6_checksum_offset + nd_reserved_size));
    NeighborSolicitation ns{};
    ns.sender_mac = *frame_src;
    ns.source_ip = src;
    ns.target_ip = to_array<ipv6_size>(*m.bytes(ipv6_size));
    if (ns.target_ip[0] == ipv6_multicast_prefix) {
        return std::unexpected(ParseError::bad_target);
    }
    const bool dad = std::ranges::all_of(src, [](std::byte b) { return b == std::byte{0}; });

    while (m.remaining() > 0) {
        const auto opt_type = m.u8();
        const auto opt_units = m.u8();
        if (!opt_type || !opt_units) {
            return std::unexpected(ParseError::truncated);
        }
        if (*opt_units == 0) {
            return std::unexpected(ParseError::bad_option);
        }
        const auto body = m.bytes((static_cast<std::size_t>(*opt_units) * nd_option_unit) -
                                  nd_option_header_size);
        if (!body) {
            return map_wire(body.error());
        }
        if (*opt_type == nd_option_source_lladdr) {
            // RFC 4861 7.1.1: a DAD probe must not carry one.
            if (dad || *opt_units != nd_lladdr_option_units) {
                return std::unexpected(ParseError::bad_option);
            }
            if (to_array<mac_size>(*body) != *frame_src) {
                return std::unexpected(ParseError::sender_mismatch);
            }
        }
    }
    return ns;
}

auto build_arp_reply(const ArpPacket& request, const MacAddress& target_mac)
    -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(geneve::ethernet_header_size + arp_size);
    wire::Writer w{out};
    write_ethernet(w, request.sender_mac, target_mac, ethertype_arp);
    w.be16(arp_htype_ethernet);
    w.be16(ethertype_ipv4);
    w.u8(mac_size);
    w.u8(ipv4_size);
    w.be16(arp_op_reply);
    w.bytes(target_mac);
    w.bytes(request.target_ip);
    w.bytes(request.sender_mac);
    w.bytes(request.sender_ip);
    return out;
}

auto build_neighbor_advertisement(const NeighborSolicitation& ns, const MacAddress& target_mac)
    -> std::vector<std::byte> {
    constexpr std::size_t message_size = nd_message_size + nd_option_unit;
    std::vector<std::byte> out;
    out.reserve(geneve::ethernet_header_size + ipv6_header_size + message_size);
    wire::Writer w{out};
    write_ethernet(w, ns.sender_mac, target_mac, ethertype_ipv6);
    w.be32(ip_version_6 << ip_version_shift);
    w.be16(static_cast<std::uint16_t>(message_size));
    w.u8(ipproto_icmpv6);
    w.u8(nd_hop_limit);
    w.bytes(ns.target_ip);
    w.bytes(ns.source_ip);
    const std::size_t message_at = out.size();
    w.u8(icmpv6_neighbor_advertisement);
    w.u8(0);
    w.be16(0);  // checksum, filled below
    w.be32(na_flags_solicited_override);
    w.bytes(ns.target_ip);
    w.u8(nd_option_target_lladdr);
    w.u8(nd_lladdr_option_units);
    w.bytes(target_mac);

    const auto message = std::span<const std::byte>{out}.subspan(message_at);
    const std::uint16_t sum = icmpv6_checksum(ns.target_ip, ns.source_ip, message);
    out[message_at + icmpv6_checksum_offset] = static_cast<std::byte>(sum >> CHAR_BIT);
    out[message_at + icmpv6_checksum_offset + 1] = static_cast<std::byte>(sum & UINT8_MAX);
    return out;
}

}  // namespace ak::oar::net::neighbor
