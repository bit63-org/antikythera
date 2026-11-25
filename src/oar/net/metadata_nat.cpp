// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/metadata_nat.hpp"

#include <algorithm>

#include "common/wire.hpp"
#include "oar/net/vswitch.hpp"

namespace ak::oar::net {

namespace {

// Probes per allocation before the pool counts as full: the pools hold
// millions of aliases and a role at most max_aliases_per_nic per function,
// so a long run of taken ones means something is wrong, not unlucky.
constexpr int max_probes = 4096;
constexpr std::uint32_t alias4_hosts = (1U << (32U - alias4_length)) - 2U;  // no .0, no broadcast
constexpr std::uint32_t alias6_hosts = 0xFFFF'FFFEU;

constexpr std::size_t ipv4_header = 20;
constexpr std::size_t ipv6_header = 40;
constexpr std::size_t tcp_header = 20;
constexpr std::uint8_t protocol_tcp = 6;

struct Layout {
    bool v6{false};
    std::size_t length{0};  // the packet's own length (trailing padding dropped)
    std::size_t src{0};     // address offsets
    std::size_t dst{0};
    std::size_t tcp{0};
};

auto parse(std::span<const std::byte> p) -> std::expected<Layout, NatDrop> {
    wire::Reader r{p};
    const auto first = r.u8();
    if (!first) {
        return std::unexpected{NatDrop::malformed};
    }
    const unsigned version = *first >> 4U;
    Layout out;
    std::size_t payload = 0;
    if (version == 4) {
        const std::size_t ihl = (*first & 0x0FU) * 4U;
        (void)r.u8();  // DSCP/ECN
        const auto total = r.be16();
        (void)r.be16();  // identification
        const auto fragment = r.be16();
        (void)r.u8();  // TTL
        const auto protocol = r.u8();
        if (!total || !fragment || !protocol || ihl < ipv4_header || *total < ihl ||
            *total > p.size()) {
            return std::unexpected{NatDrop::malformed};
        }
        if ((*fragment & 0x3FFFU) != 0) {
            return std::unexpected{NatDrop::fragment};  // MF set, or an offset
        }
        if (*protocol != protocol_tcp) {
            return std::unexpected{NatDrop::not_tcp};
        }
        out = Layout{.v6 = false, .length = *total, .src = 12, .dst = 16, .tcp = ihl};
        payload = *total - ihl;
    } else if (version == 6) {
        (void)r.skip(3);  // traffic class, flow label
        const auto length = r.be16();
        const auto next = r.u8();
        if (!length || !next || p.size() < ipv6_header || ipv6_header + *length > p.size()) {
            return std::unexpected{NatDrop::malformed};
        }
        if (*next != protocol_tcp) {
            return std::unexpected{NatDrop::not_tcp};  // extension headers too
        }
        out = Layout{
            .v6 = true, .length = ipv6_header + *length, .src = 8, .dst = 24, .tcp = ipv6_header};
        payload = *length;
    } else {
        return std::unexpected{NatDrop::malformed};
    }
    if (payload < tcp_header) {
        return std::unexpected{NatDrop::malformed};
    }
    const std::size_t data_offset = (std::to_integer<std::size_t>(p[out.tcp + 12]) >> 4U) * 4U;
    if (data_offset < tcp_header || data_offset > payload) {
        return std::unexpected{NatDrop::malformed};
    }
    return out;
}

auto address_at(std::span<const std::byte> p, const Layout& l, std::size_t offset) -> IpAddress {
    IpAddress a{.v6 = l.v6, .bytes = {}};
    std::copy_n(p.begin() + static_cast<std::ptrdiff_t>(offset), l.v6 ? 16 : 4, a.bytes.begin());
    return a;
}

auto port_at(std::span<const std::byte> p, std::size_t offset) -> std::uint16_t {
    return static_cast<std::uint16_t>((std::to_integer<unsigned>(p[offset]) << 8U) |
                                      std::to_integer<unsigned>(p[offset + 1]));
}

auto word_at(std::span<const std::byte> p, std::size_t offset) -> std::uint32_t {
    return port_at(p, offset);
}

// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m') over each 16-bit word changed.
auto adjust_checksum(std::span<std::byte> p, std::size_t checksum, std::span<const std::byte> old,
                     std::span<const std::byte> replacement) -> void {
    std::uint32_t sum = ~word_at(p, checksum) & 0xFFFFU;
    for (std::size_t i = 0; i + 1 < old.size(); i += 2) {
        sum += (~word_at(old, i) & 0xFFFFU) + word_at(replacement, i);
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    const auto result = static_cast<std::uint16_t>(~sum & 0xFFFFU);
    p[checksum] = static_cast<std::byte>(result >> 8U);
    p[checksum + 1] = static_cast<std::byte>(result & 0xFFU);
}

// Copies the packet and replaces the address at `offset` with `to`,
// fixing the IPv4 header checksum and the TCP checksum.
auto rewrite(std::span<const std::byte> in, const Layout& l, std::size_t offset,
             const IpAddress& to) -> std::vector<std::byte> {
    std::vector<std::byte> out(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(l.length));
    const std::size_t size = l.v6 ? 16 : 4;
    const auto old = std::span{in}.subspan(offset, size);
    const auto replacement = std::span{to.bytes}.first(size);
    if (!l.v6) {
        adjust_checksum(out, 10, old, replacement);
    }
    adjust_checksum(out, l.tcp + 16, old, replacement);
    std::ranges::copy(replacement, out.begin() + static_cast<std::ptrdiff_t>(offset));
    return out;
}

auto metadata_address(bool v6) -> IpAddress {
    return v6 ? IpAddress::from(metadata_ipv6) : IpAddress::from(metadata_ipv4);
}

}  // namespace

// ---- IpAddress ------------------------------------------------------------------

auto IpAddress::from(const neighbor::Ipv4Address& a) -> IpAddress {
    IpAddress out{.v6 = false, .bytes = {}};
    std::ranges::copy(a, out.bytes.begin());
    return out;
}

auto IpAddress::from(const Ipv6Address& a) -> IpAddress {
    return IpAddress{.v6 = true, .bytes = a};
}

auto IpAddress::v4() const -> neighbor::Ipv4Address {
    neighbor::Ipv4Address out{};
    std::copy_n(bytes.begin(), out.size(), out.begin());
    return out;
}

// ---- AliasTable -----------------------------------------------------------------

auto AliasTable::size(geneve::NicId nic) const -> std::size_t {
    std::size_t n = 0;
    for (auto it = _by_pair.lower_bound({nic.value, IpAddress{}});
         it != _by_pair.end() && it->first.first == nic.value; ++it) {
        ++n;
    }
    return n;
}

auto AliasTable::retire(const IpAddress& alias, Clock::time_point now) -> void {
    const auto it = _by_alias.find(alias);
    if (it == _by_alias.end()) {
        return;
    }
    _by_pair.erase({it->second.nic.value, it->second.guest});
    _by_alias.erase(it);
    _quarantine.insert(alias);
    _quarantine_order.emplace_back(now + alias_quarantine, alias);
}

auto AliasTable::allocate(bool v6, Clock::time_point now) -> std::optional<IpAddress> {
    while (!_quarantine_order.empty() && _quarantine_order.front().first <= now) {
        _quarantine.erase(_quarantine_order.front().second);
        _quarantine_order.pop_front();
    }
    for (int probe = 0; probe < max_probes; ++probe) {
        IpAddress a{.v6 = v6, .bytes = v6 ? alias6_prefix : Ipv6Address{}};
        if (v6) {
            const std::uint32_t host = (_next6++ % alias6_hosts) + 1U;
            for (std::size_t i = 0; i < 4; ++i) {
                a.bytes[12 + i] = static_cast<std::byte>(host >> (8U * (3U - i)));
            }
        } else {
            const std::uint32_t host = (_next4++ % alias4_hosts) + 1U;
            std::uint32_t v = 0;
            for (std::size_t i = 0; i < 4; ++i) {
                v = (v << 8U) | std::to_integer<std::uint32_t>(alias4_prefix[i]);
            }
            v |= host;
            for (std::size_t i = 0; i < 4; ++i) {
                a.bytes[i] = static_cast<std::byte>(v >> (8U * (3U - i)));
            }
        }
        if (!_by_alias.contains(a) && !_quarantine.contains(a)) {
            return a;
        }
    }
    return std::nullopt;
}

auto AliasTable::alias(geneve::NicId nic, const IpAddress& guest, Clock::time_point now)
    -> std::optional<IpAddress> {
    if (const auto it = _by_pair.find({nic.value, guest}); it != _by_pair.end()) {
        _by_alias.at(it->second).used = now;
        return it->second;
    }
    if (size(nic) >= max_aliases_per_nic) {
        // Replace the NIC's least recently used alias.
        std::optional<IpAddress> oldest;
        Clock::time_point when = Clock::time_point::max();
        for (auto it = _by_pair.lower_bound({nic.value, IpAddress{}});
             it != _by_pair.end() && it->first.first == nic.value; ++it) {
            const auto used = _by_alias.at(it->second).used;
            if (used < when) {
                when = used;
                oldest = it->second;
            }
        }
        if (oldest) {
            retire(*oldest, now);
        }
    }
    const auto a = allocate(guest.v6, now);
    if (!a) {
        return std::nullopt;
    }
    _by_alias.emplace(*a, Entry{.nic = nic, .guest = guest, .used = now});
    _by_pair.emplace(std::pair{nic.value, guest}, *a);
    return a;
}

auto AliasTable::lookup(const IpAddress& alias) const
    -> std::optional<std::pair<geneve::NicId, IpAddress>> {
    const auto it = _by_alias.find(alias);
    if (it == _by_alias.end()) {
        return std::nullopt;
    }
    return std::pair{it->second.nic, it->second.guest};
}

auto AliasTable::release(geneve::NicId nic, Clock::time_point now) -> void {
    std::vector<IpAddress> aliases;
    for (auto it = _by_pair.lower_bound({nic.value, IpAddress{}});
         it != _by_pair.end() && it->first.first == nic.value; ++it) {
        aliases.push_back(it->second);
    }
    for (const auto& a : aliases) {
        retire(a, now);
    }
}

// ---- translation ----------------------------------------------------------------

auto to_string(NatDrop d) noexcept -> const char* {
    switch (d) {
        case NatDrop::malformed:
            return "malformed";
        case NatDrop::fragment:
            return "fragment";
        case NatDrop::not_tcp:
            return "not_tcp";
        case NatDrop::wrong_address:
            return "wrong_address";
        case NatDrop::wrong_port:
            return "wrong_port";
        case NatDrop::no_alias:
            return "no_alias";
        case NatDrop::unknown_alias:
            return "unknown_alias";
    }
    return "unknown";
}

auto to_kernel(geneve::NicId nic, std::span<const std::byte> ip_packet, AliasTable& aliases,
               AliasTable::Clock::time_point now)
    -> std::expected<std::vector<std::byte>, NatDrop> {
    const auto l = parse(ip_packet);
    if (!l) {
        return std::unexpected{l.error()};
    }
    if (address_at(ip_packet, *l, l->dst) != metadata_address(l->v6)) {
        return std::unexpected{NatDrop::wrong_address};
    }
    if (port_at(ip_packet, l->tcp + 2) != metadata_port) {
        return std::unexpected{NatDrop::wrong_port};
    }
    const auto alias = aliases.alias(nic, address_at(ip_packet, *l, l->src), now);
    if (!alias) {
        return std::unexpected{NatDrop::no_alias};
    }
    return rewrite(ip_packet, *l, l->src, *alias);
}

auto to_guest(std::span<const std::byte> ip_packet, const AliasTable& aliases)
    -> std::expected<ToGuest, NatDrop> {
    const auto l = parse(ip_packet);
    if (!l) {
        return std::unexpected{l.error()};
    }
    if (address_at(ip_packet, *l, l->src) != metadata_address(l->v6)) {
        return std::unexpected{NatDrop::wrong_address};
    }
    if (port_at(ip_packet, l->tcp) != metadata_port) {
        return std::unexpected{NatDrop::wrong_port};
    }
    const auto pair = aliases.lookup(address_at(ip_packet, *l, l->dst));
    if (!pair) {
        return std::unexpected{NatDrop::unknown_alias};
    }
    return ToGuest{.nic = pair->first, .packet = rewrite(ip_packet, *l, l->dst, pair->second)};
}

}  // namespace ak::oar::net
