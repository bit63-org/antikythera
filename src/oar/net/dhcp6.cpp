// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/dhcp6.hpp"

#include <algorithm>

#include "common/wire.hpp"

namespace ak::oar::net::dhcp6 {

namespace {

constexpr std::uint16_t opt_client_id = 1;
constexpr std::uint16_t opt_server_id = 2;
constexpr std::uint16_t opt_ia_na = 3;
constexpr std::uint16_t opt_iaaddr = 5;
constexpr std::uint16_t opt_status_code = 13;
constexpr std::uint16_t opt_rapid_commit = 14;
constexpr std::uint16_t opt_dns_servers = 23;
constexpr std::uint16_t opt_domain_list = 24;
constexpr std::size_t ia_na_fixed_size = 12;   // IAID, T1, T2
constexpr std::size_t iaaddr_fixed_size = 24;  // address, preferred, valid
constexpr std::size_t ipv6_size = 16;
constexpr std::uint16_t duid_type_ll = 3;
constexpr std::uint16_t hardware_ethernet = 1;
constexpr std::uint32_t xid_mask = 0x00FF'FFFF;
constexpr unsigned xid_shift = 8;
constexpr std::uint32_t rebind_eighths = 7;
constexpr std::uint32_t eighths = 8;

constexpr std::uint8_t ra_hop_limit = 64;
constexpr std::uint8_t ra_flags_managed_other = 0xC0;
constexpr std::uint8_t nd_opt_source_lladdr = 1;
constexpr std::uint8_t nd_opt_prefix_info = 3;
constexpr std::uint8_t nd_opt_mtu = 5;
constexpr std::uint8_t nd_opt_rdnss = 25;
constexpr std::uint8_t prefix_info_units = 4;
constexpr std::uint8_t prefix_length_64 = 64;
constexpr std::uint8_t prefix_flag_on_link = 0x80;  // L set, A clear
constexpr std::uint32_t infinite = 0xFFFF'FFFF;

auto client_type(std::uint8_t t) noexcept -> bool {
    switch (static_cast<MessageType>(t)) {
        case MessageType::solicit:
        case MessageType::request:
        case MessageType::confirm:
        case MessageType::renew:
        case MessageType::rebind:
        case MessageType::release:
        case MessageType::decline:
        case MessageType::information_request:
            return true;
        default:
            return false;
    }
}

auto to_ipv6(std::span<const std::byte> s) noexcept -> Ipv6Address {
    Ipv6Address a{};
    std::copy_n(s.begin(), a.size(), a.begin());
    return a;
}

auto parse_ia_na(std::span<const std::byte> value) -> std::expected<IaNa, ParseError> {
    wire::Reader r{value};
    if (r.remaining() < ia_na_fixed_size) {
        return std::unexpected(ParseError::bad_option);
    }
    IaNa ia{};
    ia.iaid = r.be32().value_or(0);
    static_cast<void>(r.skip(2 * sizeof(std::uint32_t)));  // T1, T2
    while (r.remaining() > 0) {
        const auto code = r.be16();
        const auto length = r.be16();
        if (!code || !length) {
            return std::unexpected(ParseError::truncated);
        }
        const auto body = r.bytes(*length);
        if (!body) {
            return std::unexpected(ParseError::truncated);
        }
        if (*code != opt_iaaddr) {
            continue;
        }
        if (body->size() < iaaddr_fixed_size) {
            return std::unexpected(ParseError::bad_option);
        }
        if (ia.addresses.size() == max_ia_addresses) {
            return std::unexpected(ParseError::too_many_addresses);
        }
        ia.addresses.push_back(to_ipv6(body->first(ipv6_size)));
    }
    return ia;
}

auto write_option(wire::Writer& w, std::uint16_t code, std::span<const std::byte> value) -> void {
    w.be16(code);
    w.be16(static_cast<std::uint16_t>(value.size()));
    w.bytes(value);
}

// One name in DNS wire format (RFC 1035 3.1): length-prefixed labels and a
// zero byte. The name was validated with the VpcConfig.
auto dns_name(const std::string& name) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    std::size_t start = 0;
    while (start < name.size()) {
        const std::size_t dot = std::min(name.find('.', start), name.size());
        out.push_back(static_cast<std::byte>(dot - start));
        for (std::size_t i = start; i < dot; ++i) {
            out.push_back(static_cast<std::byte>(name[i]));
        }
        start = dot + 1;
    }
    out.push_back(std::byte{0});
    return out;
}

}  // namespace

auto to_string(ParseError e) noexcept -> const char* {
    switch (e) {
        case ParseError::truncated:
            return "truncated";
        case ParseError::too_long:
            return "too_long";
        case ParseError::unknown_type:
            return "unknown_type";
        case ParseError::bad_duid:
            return "bad_duid";
        case ParseError::bad_option:
            return "bad_option";
        case ParseError::too_many_addresses:
            return "too_many_addresses";
    }
    return "unknown";
}

auto parse(std::span<const std::byte> payload) -> std::expected<Message, ParseError> {
    if (payload.size() > max_message_size) {
        return std::unexpected(ParseError::too_long);
    }
    wire::Reader r{payload};
    const auto header = r.be32();
    if (!header) {
        return std::unexpected(ParseError::truncated);
    }
    const auto type = static_cast<std::uint8_t>(*header >> (3 * xid_shift));
    if (!client_type(type)) {
        return std::unexpected(ParseError::unknown_type);
    }
    Message m{};
    m.type = static_cast<MessageType>(type);
    m.xid = *header & xid_mask;
    bool have_client = false;
    while (r.remaining() > 0) {
        const auto code = r.be16();
        const auto length = r.be16();
        if (!code || !length) {
            return std::unexpected(ParseError::truncated);
        }
        const auto value = r.bytes(*length);
        if (!value) {
            return std::unexpected(ParseError::truncated);
        }
        switch (*code) {
            case opt_client_id:
            case opt_server_id: {
                if (value->empty() || value->size() > max_duid_size) {
                    return std::unexpected(ParseError::bad_duid);
                }
                std::vector<std::byte> duid{value->begin(), value->end()};
                if (*code == opt_client_id && !have_client) {
                    m.client_id = std::move(duid);
                    have_client = true;
                } else if (*code == opt_server_id && !m.server_id) {
                    m.server_id = std::move(duid);
                }
                break;
            }
            case opt_ia_na: {
                auto ia = parse_ia_na(*value);
                if (!ia) {
                    return std::unexpected(ia.error());
                }
                if (!m.ia_na) {
                    m.ia_na = std::move(*ia);
                }
                break;
            }
            case opt_rapid_commit:
                if (!value->empty()) {
                    return std::unexpected(ParseError::bad_option);
                }
                m.rapid_commit = true;
                break;
            default:
                break;
        }
    }
    return m;
}

auto server_duid(const MacAddress& mac) -> std::vector<std::byte> {
    std::vector<std::byte> d;
    wire::Writer w{d};
    w.be16(duid_type_ll);
    w.be16(hardware_ethernet);
    w.bytes(mac);
    return d;
}

auto build_reply(const Message& request, const Reply& reply) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    wire::Writer w{out};
    w.be32((std::uint32_t{static_cast<std::uint8_t>(reply.type)} << (3 * xid_shift)) |
           (request.xid & xid_mask));
    write_option(w, opt_server_id, reply.server_id);
    if (!request.client_id.empty()) {
        write_option(w, opt_client_id, request.client_id);
    }
    if (reply.rapid_commit) {
        write_option(w, opt_rapid_commit, {});
    }
    if (reply.status) {
        std::vector<std::byte> s;
        wire::Writer sw{s};
        sw.be16(static_cast<std::uint16_t>(*reply.status));
        write_option(w, opt_status_code, s);
    }
    if (reply.iaid) {
        std::vector<std::byte> ia;
        wire::Writer iw{ia};
        iw.be32(*reply.iaid);
        iw.be32(reply.lifetime / 2);
        iw.be32(
            static_cast<std::uint32_t>(std::uint64_t{reply.lifetime} * rebind_eighths / eighths));
        if (reply.addresses.empty()) {
            std::vector<std::byte> s;
            wire::Writer sw{s};
            sw.be16(static_cast<std::uint16_t>(StatusCode::no_addrs_avail));
            write_option(iw, opt_status_code, s);
        }
        for (const auto& a : reply.addresses) {
            std::vector<std::byte> addr;
            wire::Writer aw{addr};
            aw.bytes(a);
            aw.be32(reply.lifetime);
            aw.be32(reply.lifetime);
            write_option(iw, opt_iaaddr, addr);
        }
        write_option(w, opt_ia_na, ia);
    }
    if (!reply.dns.empty()) {
        std::vector<std::byte> d;
        for (const auto& a : reply.dns) {
            d.insert(d.end(), a.begin(), a.end());
        }
        write_option(w, opt_dns_servers, d);
    }
    if (!reply.domain.empty()) {
        write_option(w, opt_domain_list, dns_name(reply.domain));
    }
    return out;
}

auto build_router_advertisement_body(const RouterAdvertisement& ra) -> std::vector<std::byte> {
    std::vector<std::byte> b;
    wire::Writer w{b};
    w.u8(ra_hop_limit);
    w.u8(ra_flags_managed_other);
    w.be16(ra.router_lifetime);
    w.be32(0);  // reachable time: unspecified
    w.be32(0);  // retransmit timer: unspecified
    w.u8(nd_opt_source_lladdr);
    w.u8(1);
    w.bytes(ra.gateway_mac);
    if (ra.mtu != 0) {
        w.u8(nd_opt_mtu);
        w.u8(1);
        w.be16(0);
        w.be32(ra.mtu);
    }
    w.u8(nd_opt_prefix_info);
    w.u8(prefix_info_units);
    w.u8(prefix_length_64);
    w.u8(prefix_flag_on_link);
    w.be32(infinite);  // valid lifetime
    w.be32(infinite);  // preferred lifetime
    w.be32(0);
    w.bytes(ra.prefix);
    if (!ra.dns.empty()) {
        w.u8(nd_opt_rdnss);
        w.u8(static_cast<std::uint8_t>(1 + (2 * ra.dns.size())));
        w.be16(0);
        w.be32(ra.dns_lifetime);
        for (const auto& a : ra.dns) {
            w.bytes(a);
        }
    }
    return b;
}

}  // namespace ak::oar::net::dhcp6
