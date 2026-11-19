// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/dhcp4.hpp"

#include <algorithm>

#include "common/wire.hpp"

namespace ak::oar::net::dhcp4 {

namespace {

constexpr std::uint8_t op_request = 1;
constexpr std::uint8_t op_reply = 2;
constexpr std::uint8_t htype_ethernet = 1;
constexpr std::uint8_t hlen_ethernet = 6;
constexpr std::uint32_t magic_cookie = 0x6382'5363;
constexpr std::size_t chaddr_size = 16;
constexpr std::size_t sname_size = 64;
constexpr std::size_t file_size = 128;
constexpr std::size_t ipv4_size = 4;

constexpr std::uint8_t opt_pad = 0;
constexpr std::uint8_t opt_subnet_mask = 1;
constexpr std::uint8_t opt_router = 3;
constexpr std::uint8_t opt_dns = 6;
constexpr std::uint8_t opt_domain = 15;
constexpr std::uint8_t opt_mtu = 26;
constexpr std::uint8_t opt_requested_ip = 50;
constexpr std::uint8_t opt_lease = 51;
constexpr std::uint8_t opt_message_type = 53;
constexpr std::uint8_t opt_server_id = 54;
constexpr std::uint8_t opt_renewal = 58;
constexpr std::uint8_t opt_rebinding = 59;
constexpr std::uint8_t opt_end = 255;
constexpr std::size_t max_option_length = 255;
constexpr std::uint32_t rebinding_eighths = 7;
constexpr std::uint32_t eighths = 8;

auto to_ipv4(std::span<const std::byte> s) noexcept -> Ipv4Address {
    Ipv4Address a{};
    std::copy_n(s.begin(), a.size(), a.begin());
    return a;
}

auto known_client_type(std::uint8_t t) noexcept -> bool {
    switch (static_cast<MessageType>(t)) {
        case MessageType::discover:
        case MessageType::request:
        case MessageType::decline:
        case MessageType::release:
        case MessageType::inform:
            return true;
        default:
            return false;
    }
}

auto option(wire::Writer& w, std::uint8_t code, std::span<const std::byte> value) -> void {
    w.u8(code);
    w.u8(static_cast<std::uint8_t>(value.size()));
    w.bytes(value);
}

auto option_u32(wire::Writer& w, std::uint8_t code, std::uint32_t value) -> void {
    w.u8(code);
    w.u8(sizeof(value));
    w.be32(value);
}

}  // namespace

auto to_string(ParseError e) noexcept -> const char* {
    switch (e) {
        case ParseError::truncated:
            return "truncated";
        case ParseError::not_request:
            return "not_request";
        case ParseError::bad_hardware:
            return "bad_hardware";
        case ParseError::bad_cookie:
            return "bad_cookie";
        case ParseError::options_too_long:
            return "options_too_long";
        case ParseError::missing_type:
            return "missing_type";
        case ParseError::bad_option:
            return "bad_option";
        case ParseError::unknown_type:
            return "unknown_type";
    }
    return "unknown";
}

auto parse(std::span<const std::byte> payload) -> std::expected<Message, ParseError> {
    wire::Reader r{payload};
    if (r.remaining() < fixed_size + sizeof(magic_cookie)) {
        return std::unexpected(ParseError::truncated);
    }
    // The size check above covers the fixed header and the cookie.
    const auto op = r.u8().value_or(0);
    const auto htype = r.u8().value_or(0);
    const auto hlen = r.u8().value_or(0);
    static_cast<void>(r.skip(1));  // hops
    Message m{};
    m.xid = r.be32().value_or(0);
    static_cast<void>(r.skip(2));  // secs
    m.flags = r.be16().value_or(0);
    m.ciaddr = to_ipv4(r.bytes(ipv4_size).value_or(std::span<const std::byte>{}));
    static_cast<void>(r.skip(3 * ipv4_size));  // yiaddr, siaddr, giaddr
    const auto chaddr = r.bytes(chaddr_size).value_or(std::span<const std::byte>{});
    std::copy_n(chaddr.begin(), m.chaddr.size(), m.chaddr.begin());
    static_cast<void>(r.skip(sname_size + file_size));
    const auto cookie = r.be32().value_or(0);
    if (op != op_request) {
        return std::unexpected(ParseError::not_request);
    }
    if (htype != htype_ethernet || hlen != hlen_ethernet) {
        return std::unexpected(ParseError::bad_hardware);
    }
    if (cookie != magic_cookie) {
        return std::unexpected(ParseError::bad_cookie);
    }
    if (r.remaining() > max_options_size) {
        return std::unexpected(ParseError::options_too_long);
    }

    std::optional<std::uint8_t> type;
    while (r.remaining() > 0) {
        const auto code = r.u8().value_or(opt_end);
        if (code == opt_end) {
            break;
        }
        if (code == opt_pad) {
            continue;
        }
        const auto length = r.u8();
        if (!length) {
            return std::unexpected(ParseError::truncated);
        }
        const auto value = r.bytes(*length);
        if (!value) {
            return std::unexpected(ParseError::truncated);
        }
        switch (code) {
            case opt_message_type:
                if (value->size() != 1) {
                    return std::unexpected(ParseError::bad_option);
                }
                if (!type) {
                    type = std::to_integer<std::uint8_t>((*value)[0]);
                }
                break;
            case opt_requested_ip:
            case opt_server_id: {
                if (value->size() != ipv4_size) {
                    return std::unexpected(ParseError::bad_option);
                }
                auto& slot = code == opt_requested_ip ? m.requested_ip : m.server_id;
                if (!slot) {
                    slot = to_ipv4(*value);
                }
                break;
            }
            default:
                break;
        }
    }
    if (!type) {
        return std::unexpected(ParseError::missing_type);
    }
    if (!known_client_type(*type)) {
        return std::unexpected(ParseError::unknown_type);
    }
    m.type = static_cast<MessageType>(*type);
    return m;
}

auto build_reply(const Message& request, const Reply& reply) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(min_message_size);
    wire::Writer w{out};
    w.u8(op_reply);
    w.u8(htype_ethernet);
    w.u8(hlen_ethernet);
    w.u8(0);  // hops
    w.be32(request.xid);
    w.be16(0);  // secs
    w.be16(request.flags);
    w.bytes(reply.type == MessageType::nak ? Ipv4Address{} : request.ciaddr);
    w.bytes(reply.yiaddr);
    w.bytes(Ipv4Address{});  // siaddr: no boot server
    w.bytes(Ipv4Address{});  // giaddr
    w.bytes(request.chaddr);
    out.resize(out.size() + (chaddr_size - request.chaddr.size()) + sname_size + file_size);
    w.be32(magic_cookie);

    w.u8(opt_message_type);
    w.u8(1);
    w.u8(static_cast<std::uint8_t>(reply.type));
    option(w, opt_server_id, reply.server);
    if (reply.type != MessageType::nak) {
        if (reply.lease_seconds != 0) {
            option_u32(w, opt_lease, reply.lease_seconds);
            option_u32(w, opt_renewal, reply.lease_seconds / 2);
            option_u32(w, opt_rebinding,
                       static_cast<std::uint32_t>(std::uint64_t{reply.lease_seconds} *
                                                  rebinding_eighths / eighths));
        }
        option(w, opt_subnet_mask, reply.subnet_mask);
        option(w, opt_router, reply.router);
        if (!reply.dns.empty()) {
            w.u8(opt_dns);
            w.u8(static_cast<std::uint8_t>(reply.dns.size() * ipv4_size));
            for (const auto& d : reply.dns) {
                w.bytes(d);
            }
        }
        if (!reply.domain.empty()) {
            const std::size_t n = std::min(reply.domain.size(), max_option_length);
            w.u8(opt_domain);
            w.u8(static_cast<std::uint8_t>(n));
            for (std::size_t i = 0; i < n; ++i) {
                w.u8(static_cast<std::uint8_t>(reply.domain[i]));
            }
        }
        if (reply.mtu != 0) {
            w.u8(opt_mtu);
            w.u8(sizeof(reply.mtu));
            w.be16(reply.mtu);
        }
    }
    w.u8(opt_end);
    if (out.size() < min_message_size) {
        out.resize(min_message_size, std::byte{0});
    }
    return out;
}

}  // namespace ak::oar::net::dhcp4
