// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// TCP/IP packets for the metadata service's tests (oar-net task 21.5):
// IPv4 and IPv6 TCP segments with correct checksums, and a check that a
// rewritten packet's checksums still hold.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace ak::test::metadata {

using Ipv4 = std::array<std::byte, 4>;
using Ipv6 = std::array<std::byte, 16>;

inline constexpr std::uint8_t tcp_syn = 0x02;
inline constexpr std::uint8_t tcp_ack = 0x10;

inline auto sum16(std::span<const std::byte> data, std::uint32_t sum = 0) -> std::uint32_t {
    for (std::size_t i = 0; i < data.size(); i += 2) {
        const auto hi = std::to_integer<std::uint32_t>(data[i]) << 8U;
        const auto lo = i + 1 < data.size() ? std::to_integer<std::uint32_t>(data[i + 1]) : 0U;
        sum += hi | lo;
    }
    return sum;
}

inline auto fold(std::uint32_t sum) -> std::uint16_t {
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

inline auto put16(std::vector<std::byte>& p, std::size_t at, std::uint16_t v) -> void {
    p[at] = static_cast<std::byte>(v >> 8U);
    p[at + 1] = static_cast<std::byte>(v & 0xFFU);
}

inline auto get16(std::span<const std::byte> p, std::size_t at) -> std::uint16_t {
    return static_cast<std::uint16_t>((std::to_integer<unsigned>(p[at]) << 8U) |
                                      std::to_integer<unsigned>(p[at + 1]));
}

// A TCP header (20 bytes) and payload, checksum zero.
inline auto tcp_segment(std::uint16_t sport, std::uint16_t dport, std::uint8_t flags,
                        std::string_view payload) -> std::vector<std::byte> {
    std::vector<std::byte> t(20);
    put16(t, 0, sport);
    put16(t, 2, dport);
    t[7] = std::byte{1};  // sequence 1
    t[12] = std::byte{0x50};
    t[13] = static_cast<std::byte>(flags);
    put16(t, 14, 0xFFFF);
    for (const char c : payload) {
        t.push_back(static_cast<std::byte>(c));
    }
    return t;
}

inline auto tcp4(const Ipv4& src, const Ipv4& dst, std::uint16_t sport, std::uint16_t dport,
                 std::uint8_t flags = tcp_syn, std::string_view payload = {})
    -> std::vector<std::byte> {
    auto tcp = tcp_segment(sport, dport, flags, payload);
    std::vector<std::byte> p(20);
    p[0] = std::byte{0x45};
    put16(p, 2, static_cast<std::uint16_t>(20 + tcp.size()));
    p[6] = std::byte{0x40};  // DF
    p[8] = std::byte{64};
    p[9] = std::byte{6};
    std::ranges::copy(src, p.begin() + 12);
    std::ranges::copy(dst, p.begin() + 16);
    put16(p, 10, fold(sum16(p)));
    std::uint32_t pseudo = sum16(src) + sum16(dst) + 6U + static_cast<std::uint32_t>(tcp.size());
    put16(tcp, 16, fold(sum16(tcp, pseudo)));
    p.insert(p.end(), tcp.begin(), tcp.end());
    return p;
}

inline auto tcp6(const Ipv6& src, const Ipv6& dst, std::uint16_t sport, std::uint16_t dport,
                 std::uint8_t flags = tcp_syn, std::string_view payload = {})
    -> std::vector<std::byte> {
    auto tcp = tcp_segment(sport, dport, flags, payload);
    std::vector<std::byte> p(40);
    p[0] = std::byte{0x60};
    put16(p, 4, static_cast<std::uint16_t>(tcp.size()));
    p[6] = std::byte{6};
    p[7] = std::byte{64};
    std::ranges::copy(src, p.begin() + 8);
    std::ranges::copy(dst, p.begin() + 24);
    std::uint32_t pseudo = sum16(src) + sum16(dst) + 6U + static_cast<std::uint32_t>(tcp.size());
    put16(tcp, 16, fold(sum16(tcp, pseudo)));
    p.insert(p.end(), tcp.begin(), tcp.end());
    return p;
}

// True when the packet's IPv4 header checksum (if IPv4) and TCP checksum hold.
inline auto checksums_ok(std::span<const std::byte> p) -> bool {
    if (p.empty()) {
        return false;
    }
    if ((std::to_integer<unsigned>(p[0]) >> 4U) == 4) {
        const std::size_t ihl = (std::to_integer<std::size_t>(p[0]) & 0x0FU) * 4U;
        const std::size_t total = get16(p, 2);
        if (fold(sum16(p.first(ihl))) != 0) {
            return false;
        }
        const auto tcp = p.subspan(ihl, total - ihl);
        const std::uint32_t pseudo = sum16(p.subspan(12, 4)) + sum16(p.subspan(16, 4)) + 6U +
                                     static_cast<std::uint32_t>(tcp.size());
        return fold(sum16(tcp, pseudo)) == 0;
    }
    const std::size_t length = get16(p, 4);
    const auto tcp = p.subspan(40, length);
    const std::uint32_t pseudo = sum16(p.subspan(8, 16)) + sum16(p.subspan(24, 16)) + 6U +
                                 static_cast<std::uint32_t>(tcp.size());
    return fold(sum16(tcp, pseudo)) == 0;
}

}  // namespace ak::test::metadata
