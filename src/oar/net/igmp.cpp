// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/igmp.hpp"

#include <algorithm>
#include <array>

#include "common/wire.hpp"
#include "proto/group_members.hpp"

namespace ak::oar::net::igmp {

namespace {

constexpr std::size_t igmp_min_size = 8;
constexpr std::size_t mld_v1_size = 24;
constexpr std::size_t report_head_size = 8;  // v3/v2 reports: type, rsvd, csum, rsvd, count
constexpr std::size_t record_head_size = 4;  // type, aux words, source count
constexpr std::size_t word = 4;

// Group record types (RFC 3376 4.2.12, RFC 3810 5.2.12).
constexpr std::uint8_t mode_is_include = 1;
constexpr std::uint8_t mode_is_exclude = 2;
constexpr std::uint8_t change_to_include = 3;
constexpr std::uint8_t change_to_exclude = 4;
constexpr std::uint8_t allow_new_sources = 5;
constexpr std::uint8_t block_old_sources = 6;

auto u8_at(std::span<const std::byte> b, std::size_t i) noexcept -> std::uint8_t {
    return std::to_integer<std::uint8_t>(b[i]);
}

auto be16_at(std::span<const std::byte> b, std::size_t i) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>((u8_at(b, i) << 8U) | u8_at(b, i + 1));
}

// One's-complement sum of `data` as 16-bit big-endian words, folded and
// complemented: 0 over a message that carries a correct checksum.
auto checksum(std::uint32_t sum, std::span<const std::byte> data) noexcept -> std::uint16_t {
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += be16_at(data, i);
    }
    if (i < data.size()) {
        sum += std::uint32_t{u8_at(data, i)} << 8U;
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

auto put16(std::vector<std::byte>& out, std::size_t at, std::uint16_t v) noexcept -> void {
    out[at] = static_cast<std::byte>(v >> 8U);
    out[at + 1] = static_cast<std::byte>(v & 0xFFU);
}

auto group_at(std::span<const std::byte> b, std::size_t at, bool ipv6) -> Group {
    Group g{.ipv6 = ipv6, .address = {}};
    const std::size_t n = ipv6 ? g.address.size() : neighbor::Ipv4Address{}.size();
    std::copy_n(b.begin() + static_cast<std::ptrdiff_t>(at), n, g.address.begin());
    return g;
}

// The IGMP message: the IPv4 payload (the parser finds L4 data only for
// TCP, UDP and ICMP).
auto igmp_bytes(const packet::ParsedPacket& p) noexcept -> std::span<const std::byte> {
    constexpr unsigned ihl_mask = 0x0F;
    if (p.ip.empty()) {
        return {};
    }
    const std::size_t header = (u8_at(p.ip, 0) & ihl_mask) * word;
    return header <= p.ip.size() ? p.ip.subspan(header) : std::span<const std::byte>{};
}

auto add(std::vector<Change>& out, const Group& g, bool join) -> void {
    if (replicable(g)) {
        out.push_back({.group = g, .join = join});
    }
}

// The group records of an IGMPv3 or MLDv2 report.
auto records(std::span<const std::byte> msg, bool ipv6)
    -> std::expected<std::vector<Change>, SnoopError> {
    const std::size_t group_size = ipv6 ? Ipv6Address{}.size() : neighbor::Ipv4Address{}.size();
    if (msg.size() < report_head_size) {
        return std::unexpected(SnoopError::malformed);
    }
    const std::size_t count = be16_at(msg, 6);
    std::size_t at = report_head_size;
    std::vector<Change> out;
    for (std::size_t i = 0; i < count; ++i) {
        if (msg.size() - at < record_head_size + group_size) {
            return std::unexpected(SnoopError::malformed);
        }
        const std::uint8_t type = u8_at(msg, at);
        const std::size_t aux = std::size_t{u8_at(msg, at + 1)} * word;
        const std::size_t sources = be16_at(msg, at + 2);
        const Group g = group_at(msg, at + record_head_size, ipv6);
        const std::size_t length = record_head_size + group_size + (sources * group_size) + aux;
        if (msg.size() - at < length) {
            return std::unexpected(SnoopError::malformed);
        }
        switch (type) {
            case mode_is_exclude:
            case change_to_exclude:
                add(out, g, true);
                break;
            case mode_is_include:
            case change_to_include:
            case allow_new_sources:
                if (sources != 0) {
                    add(out, g, true);
                } else if (type != allow_new_sources) {
                    add(out, g, false);
                }
                break;
            case block_old_sources:
                break;
            default:
                return std::unexpected(SnoopError::unknown_type);
        }
        at += length;
    }
    return out;
}

}  // namespace

auto to_string(SnoopError e) noexcept -> const char* {
    switch (e) {
        case SnoopError::malformed:
            return "malformed";
        case SnoopError::bad_checksum:
            return "bad_checksum";
        case SnoopError::unknown_type:
            return "unknown_type";
    }
    return "unknown";
}

auto classify(const packet::ParsedPacket& p) noexcept -> std::optional<Kind> {
    if (p.fragment) {
        return std::nullopt;
    }
    if (p.family == packet::IpFamily::ipv4) {
        if (p.protocol != ipproto_igmp) {
            return std::nullopt;
        }
        const auto msg = igmp_bytes(p);
        if (msg.empty()) {
            return Kind::other;
        }
        switch (u8_at(msg, 0)) {
            case igmp_query:
                return Kind::query;
            case igmp_v1_report:
            case igmp_v2_report:
            case igmp_v2_leave:
            case igmp_v3_report:
                return Kind::report;
            default:
                return Kind::other;
        }
    }
    if (p.protocol != packet::ipproto_icmpv6 || !p.l4) {
        return std::nullopt;
    }
    switch (p.l4->icmp_type) {
        case mld_query:
            return Kind::query;
        case mld_v1_report:
        case mld_v1_done:
        case mld_v2_report:
            return Kind::report;
        default:
            return std::nullopt;
    }
}

auto parse_report(const packet::ParsedPacket& p) -> std::expected<std::vector<Change>, SnoopError> {
    const bool ipv6 = p.family == packet::IpFamily::ipv6;
    const std::span<const std::byte> msg = ipv6 ? p.l4_data : igmp_bytes(p);
    if (msg.size() < igmp_min_size) {
        return std::unexpected(SnoopError::malformed);
    }
    if (ipv6 ? neighbor::icmpv6_checksum(p.src6, p.dst6, msg) != 0 : checksum(0, msg) != 0) {
        return std::unexpected(SnoopError::bad_checksum);
    }
    std::vector<Change> out;
    switch (u8_at(msg, 0)) {
        case igmp_v1_report:
        case igmp_v2_report:
            add(out, group_at(msg, 4, false), true);
            return out;
        case igmp_v2_leave:
            add(out, group_at(msg, 4, false), false);
            return out;
        case igmp_v3_report:
            return records(msg, false);
        case mld_v1_report:
        case mld_v1_done:
            if (msg.size() < mld_v1_size) {
                return std::unexpected(SnoopError::malformed);
            }
            add(out, group_at(msg, 8, true), u8_at(msg, 0) == mld_v1_report);
            return out;
        case mld_v2_report:
            return records(msg, true);
        default:
            return std::unexpected(SnoopError::malformed);
    }
}

auto replicable(const Group& g) noexcept -> bool {
    return proto::detail::valid_member_group(
        g.ipv6 ? proto::RouteFamily::ipv6 : proto::RouteFamily::ipv4, g.address);
}

auto destination_group(const packet::ParsedPacket& p) noexcept -> Group {
    Group g{.ipv6 = p.family == packet::IpFamily::ipv6, .address = {}};
    if (g.ipv6) {
        g.address = p.dst6;
    } else {
        std::ranges::copy(p.dst4, g.address.begin());
    }
    return g;
}

auto build_query4(const MacAddress& gateway_mac, const neighbor::Ipv4Address& gateway_ip)
    -> std::vector<std::byte> {
    constexpr std::size_t ip_header = 24;  // with the Router Alert option
    constexpr std::size_t query_size = 12;
    constexpr std::uint8_t vihl = 0x46;
    constexpr std::uint8_t tos_internetwork_control = 0xC0;
    constexpr std::uint8_t tenths = 10;
    constexpr std::size_t eth = 14;
    std::vector<std::byte> f;
    f.reserve(eth + ip_header + query_size);
    wire::Writer w{f};
    w.bytes(std::array<std::byte, 6>{std::byte{0x01}, std::byte{0x00}, std::byte{0x5E},
                                     std::byte{0x00}, std::byte{0x00}, std::byte{0x01}});
    w.bytes(gateway_mac);
    w.be16(neighbor::ethertype_ipv4);
    w.u8(vihl);
    w.u8(tos_internetwork_control);
    w.be16(static_cast<std::uint16_t>(ip_header + query_size));
    w.be16(0);  // identification
    w.be16(0);  // flags, fragment offset
    w.u8(1);    // TTL
    w.u8(ipproto_igmp);
    w.be16(0);  // checksum, below
    w.bytes(gateway_ip);
    w.bytes(neighbor::Ipv4Address{std::byte{224}, std::byte{0}, std::byte{0}, std::byte{1}});
    w.bytes(std::array<std::byte, 4>{std::byte{0x94}, std::byte{0x04}, std::byte{0}, std::byte{0}});
    put16(f, eth + 10, checksum(0, std::span{f}.subspan(eth, ip_header)));
    const std::size_t q = f.size();
    w.u8(igmp_query);
    w.u8(static_cast<std::uint8_t>(query_response_seconds * tenths));
    w.be16(0);  // checksum, below
    w.be32(0);  // group: a general query
    w.u8(static_cast<std::uint8_t>(robustness));
    w.u8(static_cast<std::uint8_t>(query_interval_seconds));
    w.be16(0);  // sources
    put16(f, q + 2, checksum(0, std::span{f}.subspan(q)));
    return f;
}

auto build_query6(const MacAddress& gateway_mac, const Ipv6Address& gateway_link_local)
    -> std::vector<std::byte> {
    constexpr std::size_t eth = 14;
    constexpr std::size_t ipv6_header = 40;
    constexpr std::size_t hop_by_hop = 8;
    constexpr std::size_t query_size = 28;
    constexpr std::uint16_t millis = 1000;
    Ipv6Address all_nodes{};
    all_nodes[0] = std::byte{0xFF};
    all_nodes[1] = std::byte{0x02};
    all_nodes[15] = std::byte{0x01};

    std::vector<std::byte> m;
    m.reserve(query_size);
    wire::Writer q{m};
    q.u8(mld_query);
    q.u8(0);
    q.be16(0);  // checksum, below
    q.be16(static_cast<std::uint16_t>(query_response_seconds * millis));
    q.be16(0);
    q.bytes(Ipv6Address{});  // a general query
    q.u8(static_cast<std::uint8_t>(robustness));
    q.u8(static_cast<std::uint8_t>(query_interval_seconds));
    q.be16(0);  // sources
    put16(m, 2, neighbor::icmpv6_checksum(gateway_link_local, all_nodes, m));

    std::vector<std::byte> f;
    f.reserve(eth + ipv6_header + hop_by_hop + query_size);
    wire::Writer w{f};
    w.bytes(std::array<std::byte, 6>{std::byte{0x33}, std::byte{0x33}, std::byte{0x00},
                                     std::byte{0x00}, std::byte{0x00}, std::byte{0x01}});
    w.bytes(gateway_mac);
    w.be16(neighbor::ethertype_ipv6);
    w.be32(0x6000'0000);
    w.be16(static_cast<std::uint16_t>(hop_by_hop + query_size));
    w.u8(packet::ipproto_hop_by_hop);
    w.u8(1);  // hop limit
    w.bytes(gateway_link_local);
    w.bytes(all_nodes);
    // Hop-by-hop: Router Alert (MLD), then PadN to eight bytes.
    w.u8(packet::ipproto_icmpv6);
    w.u8(0);
    w.bytes(std::array<std::byte, 6>{std::byte{0x05}, std::byte{0x02}, std::byte{0x00},
                                     std::byte{0x00}, std::byte{0x01}, std::byte{0x00}});
    w.bytes(m);
    return f;
}

}  // namespace ak::oar::net::igmp
