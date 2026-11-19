// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/packet.hpp"

#include <algorithm>

#include "common/wire.hpp"

namespace ak::oar::net::packet {

namespace {

constexpr std::size_t ethertype_offset = 12;
constexpr std::size_t ethernet_header_size = 14;
constexpr unsigned version_shift = 4;
constexpr std::uint8_t ihl_mask = 0x0F;
constexpr std::size_t word = 4;
constexpr std::uint16_t ipv4_more_fragments = 0x2000;
constexpr std::uint16_t ipv4_offset_mask = 0x1FFF;
constexpr std::size_t ipv6_address_size = 16;
constexpr std::size_t ipv4_address_size = 4;
constexpr std::uint8_t ip_version_4 = 4;
constexpr std::uint8_t ip_version_6 = 6;
constexpr std::size_t extension_unit = 8;  // hop-by-hop, routing, destination options
constexpr std::size_t ah_unit = 4;
constexpr std::size_t ah_length_bias = 2;
constexpr std::size_t fragment_header_size = 8;
constexpr std::uint16_t ipv6_offset_mask = 0xFFF8;
constexpr std::size_t tcp_data_offset_index = 12;
constexpr std::uint8_t tcp_min_data_offset = 5;
constexpr std::byte ipv4_multicast_mask{0xF0};
constexpr std::byte ipv4_multicast_bits{0xE0};
constexpr std::byte ipv6_multicast_prefix{0xFF};
constexpr std::byte ipv6_link_local_0{0xFE};
constexpr std::byte ipv6_link_local_1_mask{0xC0};
constexpr std::byte ipv6_link_local_1_bits{0x80};

auto u8_at(std::span<const std::byte> s, std::size_t i) noexcept -> std::uint8_t {
    return std::to_integer<std::uint8_t>(s[i]);
}

auto be16_at(std::span<const std::byte> s, std::size_t i) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>((u8_at(s, i) << 8U) | u8_at(s, i + 1));
}

template<std::size_t N>
auto array_at(std::span<const std::byte> s, std::size_t i) noexcept -> std::array<std::byte, N> {
    std::array<std::byte, N> a{};
    std::copy_n(s.begin() + static_cast<std::ptrdiff_t>(i), N, a.begin());
    return a;
}

// Reads the L4 header of `protocol` at the start of `rest`, the remainder
// of the IP packet. `fragmented` relaxes the UDP length check, since the
// datagram continues in later fragments.
auto parse_l4(ParsedPacket& p, std::span<const std::byte> rest, bool fragmented)
    -> std::expected<void, PacketError> {
    const auto short_header = fragmented ? PacketError::tiny_fragment : PacketError::truncated;
    switch (p.protocol) {
        case ipproto_tcp: {
            if (rest.size() < tcp_min_header_size) {
                return std::unexpected(short_header);
            }
            const std::size_t offset = (u8_at(rest, tcp_data_offset_index) >> version_shift);
            if (offset < tcp_min_data_offset) {
                return std::unexpected(PacketError::bad_l4_header);
            }
            if (offset * word > rest.size()) {
                return std::unexpected(fragmented ? PacketError::tiny_fragment
                                                  : PacketError::bad_l4_header);
            }
            p.l4 = L4Header{.src_port = be16_at(rest, 0), .dst_port = be16_at(rest, 2)};
            p.payload = rest.subspan(offset * word);
            break;
        }
        case ipproto_udp: {
            if (rest.size() < udp_header_size) {
                return std::unexpected(short_header);
            }
            const std::size_t length = be16_at(rest, word);
            std::size_t end = rest.size();
            if (!fragmented) {
                if (length < udp_header_size || length > rest.size()) {
                    return std::unexpected(PacketError::bad_l4_header);
                }
                end = length;
            }
            p.l4 = L4Header{.src_port = be16_at(rest, 0), .dst_port = be16_at(rest, 2)};
            p.payload = rest.subspan(udp_header_size, end - udp_header_size);
            break;
        }
        case ipproto_icmp:
        case ipproto_icmpv6: {
            const bool family_matches =
                (p.protocol == ipproto_icmp) == (p.family == IpFamily::ipv4);
            if (!family_matches) {
                return {};  // ICMP in IPv6 or ICMPv6 in IPv4: an opaque protocol number
            }
            if (rest.size() < icmp_header_size) {
                return std::unexpected(short_header);
            }
            p.l4 = L4Header{.icmp_type = u8_at(rest, 0), .icmp_code = u8_at(rest, 1)};
            p.payload = rest.subspan(icmp_header_size);
            break;
        }
        default:
            return {};
    }
    p.l4_data = rest;
    return {};
}

auto parse_ipv4(std::span<const std::byte> l3) -> std::expected<ParsedPacket, PacketError> {
    if (l3.size() < ipv4_min_header_size) {
        return std::unexpected(PacketError::truncated);
    }
    // The size check above covers every fixed-header read.
    wire::Reader r{l3};
    const std::uint8_t vihl = r.u8().value_or(0);
    if ((vihl >> version_shift) != ip_version_4) {
        return std::unexpected(PacketError::bad_version);
    }
    const std::size_t header = (vihl & ihl_mask) * word;
    if (header < ipv4_min_header_size) {
        return std::unexpected(PacketError::bad_header_length);
    }
    static_cast<void>(r.skip(1));  // DSCP/ECN
    const std::size_t total = r.be16().value_or(0);
    if (total > l3.size()) {
        return std::unexpected(PacketError::bad_total_length);
    }
    if (header > total) {
        return std::unexpected(PacketError::bad_header_length);
    }
    static_cast<void>(r.skip(2));  // identification
    const std::uint16_t frag = r.be16().value_or(0);
    const std::uint8_t ttl = r.u8().value_or(0);
    const std::uint8_t protocol = r.u8().value_or(0);
    static_cast<void>(r.skip(2));  // header checksum
    const auto src = r.bytes(ipv4_address_size).value_or(std::span<const std::byte>{});
    const auto dst = r.bytes(ipv4_address_size).value_or(std::span<const std::byte>{});
    const bool more = (frag & ipv4_more_fragments) != 0;
    const std::uint16_t offset = frag & ipv4_offset_mask;

    ParsedPacket p{
        .family = IpFamily::ipv4,
        .src4 = array_at<ipv4_address_size>(src, 0),
        .dst4 = array_at<ipv4_address_size>(dst, 0),
        .protocol = protocol,
        .hop_limit = ttl,
        .fragment = more || offset != 0,
        .first_fragment = offset == 0,
        .l4 = std::nullopt,
        .ip = l3.first(total),
        .l4_data = {},
        .payload = {},
    };
    if (p.first_fragment) {
        if (auto ok = parse_l4(p, p.ip.subspan(header), p.fragment); !ok) {
            return std::unexpected(ok.error());
        }
    }
    return p;
}

auto parse_ipv6(std::span<const std::byte> l3) -> std::expected<ParsedPacket, PacketError> {
    if (l3.size() < ipv6_header_size) {
        return std::unexpected(PacketError::truncated);
    }
    // The size check above covers every fixed-header read.
    wire::Reader r{l3};
    if ((r.u8().value_or(0) >> version_shift) != ip_version_6) {
        return std::unexpected(PacketError::bad_version);
    }
    static_cast<void>(r.skip(3));  // traffic class, flow label
    const std::size_t payload = r.be16().value_or(0);
    if (payload > l3.size() - ipv6_header_size) {
        return std::unexpected(PacketError::truncated);
    }
    std::uint8_t next = r.u8().value_or(0);
    const std::uint8_t hop_limit = r.u8().value_or(0);
    const auto src = r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{});
    const auto dst = r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{});
    ParsedPacket p{
        .family = IpFamily::ipv6,
        .src6 = array_at<ipv6_address_size>(src, 0),
        .dst6 = array_at<ipv6_address_size>(dst, 0),
        .hop_limit = hop_limit,
        .first_fragment = true,
        .l4 = std::nullopt,
        .ip = l3.first(ipv6_header_size + payload),
        .l4_data = {},
        .payload = {},
    };

    std::span<const std::byte> rest = p.ip.subspan(ipv6_header_size);
    for (std::size_t seen = 0;; ++seen) {
        std::size_t length = 0;
        switch (next) {
            case ipproto_hop_by_hop:
                if (seen != 0) {
                    return std::unexpected(PacketError::bad_extension_order);
                }
                [[fallthrough]];
            case ipproto_routing:
            case ipproto_destination_options:
                if (rest.size() < 2) {
                    return std::unexpected(PacketError::truncated);
                }
                length = (std::size_t{u8_at(rest, 1)} + 1) * extension_unit;
                break;
            case ipproto_ah:
                if (rest.size() < 2) {
                    return std::unexpected(PacketError::truncated);
                }
                length = (std::size_t{u8_at(rest, 1)} + ah_length_bias) * ah_unit;
                break;
            case ipproto_fragment: {
                if (rest.size() < fragment_header_size) {
                    return std::unexpected(PacketError::truncated);
                }
                // The M flag does not matter: with or without it this is a
                // fragment, and only the offset says whether L4 is here.
                p.fragment = true;
                p.first_fragment = (be16_at(rest, 2) & ipv6_offset_mask) == 0;
                length = fragment_header_size;
                break;
            }
            default:
                p.protocol = next;
                if (p.first_fragment) {
                    if (auto ok = parse_l4(p, rest, p.fragment); !ok) {
                        return std::unexpected(ok.error());
                    }
                }
                return p;
        }
        if (seen + 1 > max_extension_headers) {
            return std::unexpected(PacketError::too_many_extensions);
        }
        if (length > rest.size()) {
            return std::unexpected(PacketError::truncated);
        }
        next = u8_at(rest, 0);
        rest = rest.subspan(length);
        if (!p.first_fragment) {
            p.protocol = next;  // a later fragment: the rest is opaque
            return p;
        }
    }
}

}  // namespace

auto to_string(PacketError e) noexcept -> const char* {
    switch (e) {
        case PacketError::not_ip:
            return "not_ip";
        case PacketError::truncated:
            return "truncated";
        case PacketError::bad_version:
            return "bad_version";
        case PacketError::bad_header_length:
            return "bad_header_length";
        case PacketError::bad_total_length:
            return "bad_total_length";
        case PacketError::bad_extension_order:
            return "bad_extension_order";
        case PacketError::too_many_extensions:
            return "too_many_extensions";
        case PacketError::bad_l4_header:
            return "bad_l4_header";
        case PacketError::tiny_fragment:
            return "tiny_fragment";
    }
    return "unknown";
}

auto ethertype(std::span<const std::byte> frame) noexcept -> std::uint16_t {
    if (frame.size() < ethernet_header_size) {
        return 0;
    }
    return be16_at(frame, ethertype_offset);
}

auto parse(std::span<const std::byte> frame) -> std::expected<ParsedPacket, PacketError> {
    if (frame.size() < ethernet_header_size) {
        return std::unexpected(PacketError::truncated);
    }
    const auto l3 = frame.subspan(ethernet_header_size);
    switch (ethertype(frame)) {
        case neighbor::ethertype_ipv4:
            return parse_ipv4(l3);
        case neighbor::ethertype_ipv6:
            return parse_ipv6(l3);
        default:
            return std::unexpected(PacketError::not_ip);
    }
}

auto is_ipv4_multicast(const Ipv4Address& a) noexcept -> bool {
    return (a[0] & ipv4_multicast_mask) == ipv4_multicast_bits;
}

auto is_ipv6_multicast(const Ipv6Address& a) noexcept -> bool {
    return a[0] == ipv6_multicast_prefix;
}

auto is_ipv6_link_local(const Ipv6Address& a) noexcept -> bool {
    return a[0] == ipv6_link_local_0 && (a[1] & ipv6_link_local_1_mask) == ipv6_link_local_1_bits;
}

auto is_unspecified(std::span<const std::byte> a) noexcept -> bool {
    return std::ranges::all_of(a, [](std::byte b) { return b == std::byte{0}; });
}

}  // namespace ak::oar::net::packet
