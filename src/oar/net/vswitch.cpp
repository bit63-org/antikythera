// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/vswitch.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <set>
#include <string_view>

#include "oar/net/dhcp4.hpp"
#include "oar/net/dhcp6.hpp"

namespace ak::oar::net {

namespace {

constexpr std::size_t dst_mac_offset = 0;
constexpr std::size_t src_mac_offset = 6;
constexpr std::byte group_bit{0x01};
constexpr std::byte ipv4_first_multicast{224};  // 224.0.0.0 and up: multicast, reserved, broadcast
constexpr std::byte ipv6_multicast_prefix{0xff};

constexpr std::uint64_t nano = 1'000'000'000;
constexpr std::byte ipv4_multicast_mac_0{0x01};
constexpr std::byte ipv4_multicast_mac_1{0x00};
constexpr std::byte ipv4_multicast_mac_2{0x5e};
constexpr std::byte ipv4_multicast_mac_3_reserved{0x80};
constexpr std::byte ipv6_multicast_mac_0{0x33};
constexpr std::byte ipv6_solicited_node_mac_2{0xff};

// Requirement 10.2: IPv4 multicast (01:00:5e, low half) and IPv6 multicast
// (33:33) other than solicited-node groups (33:33:ff), which belong to ND.
auto ip_multicast(const MacAddress& dst) noexcept -> bool {
    if (dst[0] == ipv4_multicast_mac_0 && dst[1] == ipv4_multicast_mac_1 &&
        dst[2] == ipv4_multicast_mac_2) {
        return (dst[3] & ipv4_multicast_mac_3_reserved) == std::byte{0};
    }
    return dst[0] == ipv6_multicast_mac_0 && dst[1] == ipv6_multicast_mac_0 &&
           dst[2] != ipv6_solicited_node_mac_2;
}

auto admits(const GroupPolicy& policy, const MacAddress& dst) noexcept -> bool {
    return policy.mode == GroupMode::multicast && ip_multicast(dst);
}

// Adds rate x elapsed to `tokens`, capped at burst (all scaled by `nano`).
// Elapsed is capped first, at the time a refill from empty takes, so the
// product cannot overflow: rate x cap <= burst x nano, which the policy
// bounds keep under 2^63.
auto refill(std::uint64_t tokens, std::uint64_t rate, std::uint64_t burst,
            std::uint64_t elapsed_ns) noexcept -> std::uint64_t {
    const std::uint64_t cap = burst * nano;
    const std::uint64_t full_ns = (cap + rate - 1) / rate;
    const std::uint64_t add = std::min(elapsed_ns, full_ns) * rate;
    return std::min(cap, tokens + add);
}

auto mac_at(std::span<const std::byte> frame, std::size_t offset) noexcept -> MacAddress {
    MacAddress mac{};
    std::copy_n(frame.begin() + static_cast<std::ptrdiff_t>(offset), mac.size(), mac.begin());
    return mac;
}

template<typename A> auto all_zero(const A& a) noexcept -> bool {
    return std::ranges::all_of(a, [](std::byte b) { return b == std::byte{0}; });
}

constexpr std::uint8_t icmp_redirect = 5;
constexpr std::uint8_t icmpv6_router_advertisement = 134;
constexpr std::uint8_t icmpv6_redirect = 137;
constexpr std::uint16_t dhcp4_server_port = 67;
constexpr std::uint16_t dhcp4_client_port = 68;
constexpr std::uint16_t dhcp6_server_port = 547;
constexpr std::size_t nd_target_offset = 8;  // in an NS or NA: type, code, checksum, flags

auto is_ipv6(const packet::ParsedPacket& p) noexcept -> bool {
    return p.family == packet::IpFamily::ipv6;
}

auto icmpv6_type(const packet::ParsedPacket& p) noexcept -> std::optional<std::uint8_t> {
    if (!is_ipv6(p) || p.protocol != packet::ipproto_icmpv6 || !p.l4) {
        return std::nullopt;
    }
    return p.l4->icmp_type;
}

auto udp_ports(const packet::ParsedPacket& p, std::uint16_t src, std::uint16_t dst) noexcept
    -> bool {
    return p.protocol == packet::ipproto_udp && p.l4 && p.l4->src_port == src &&
           p.l4->dst_port == dst;
}

// Requirement 11.7: messages only a router or an address server sends.
auto router_message(const packet::ParsedPacket& p) noexcept -> bool {
    if (!p.l4) {
        return false;
    }
    if (is_ipv6(p)) {
        const auto type = icmpv6_type(p);
        if (type == icmpv6_router_advertisement || type == icmpv6_redirect) {
            return true;
        }
        return p.protocol == packet::ipproto_udp && p.l4->src_port == dhcp6_server_port;
    }
    if (p.protocol == packet::ipproto_icmp && p.l4->icmp_type == icmp_redirect) {
        return true;
    }
    return p.protocol == packet::ipproto_udp && p.l4->src_port == dhcp4_server_port;
}

// Requirement 11.4: sources allowed only for traffic oar-net consumes. The
// responders that consume them come with the VPC gateway (tasks 17-18);
// until then these packets end at tx_drop_local_only unless the ND proxy
// answers them.
auto local_only_source(const packet::ParsedPacket& p) noexcept -> bool {
    if (is_ipv6(p)) {
        return packet::is_unspecified(p.src6) || packet::is_ipv6_link_local(p.src6);
    }
    return packet::is_unspecified(p.src4) && udp_ports(p, dhcp4_client_port, dhcp4_server_port);
}

auto ip_multicast_destination(const packet::ParsedPacket& p) noexcept -> bool {
    return is_ipv6(p) ? packet::is_ipv6_multicast(p.dst6) : packet::is_ipv4_multicast(p.dst4);
}

auto to_u32(const neighbor::Ipv4Address& a) noexcept -> std::uint32_t {
    std::uint32_t v = 0;
    for (const std::byte b : a) {
        v = (v << 8U) | std::to_integer<std::uint32_t>(b);
    }
    return v;
}

auto from_u32(std::uint32_t v) noexcept -> neighbor::Ipv4Address {
    neighbor::Ipv4Address a{};
    for (std::size_t i = a.size(); i-- > 0;) {
        a.at(i) = static_cast<std::byte>(v & 0xFFU);
        v >>= 8U;
    }
    return a;
}

auto prefix_mask(std::uint8_t length) noexcept -> std::uint32_t {
    return length == 0 ? 0 : ~std::uint32_t{0} << (32U - length);
}

auto in_prefix(const Ipv4Prefix& prefix, const neighbor::Ipv4Address& a) noexcept -> bool {
    return (to_u32(a) & prefix_mask(prefix.length)) == to_u32(prefix.address);
}

constexpr neighbor::Ipv4Address ipv4_broadcast{std::byte{255}, std::byte{255}, std::byte{255},
                                               std::byte{255}};
constexpr std::size_t max_label_size = 63;
constexpr std::size_t ipv6_interface_id_offset = 8;
constexpr std::byte mac_local_bit{0x02};

// RFC 1035 preferred name syntax (letters, digits, hyphens; labels of 1-63
// bytes not starting or ending with a hyphen), as DHCP option 15 carries it.
auto valid_domain(const std::string& name) -> bool {
    if (name.empty()) {
        return true;
    }
    if (name.size() > max_domain_size) {
        return false;
    }
    std::size_t start = 0;
    while (start <= name.size()) {
        const std::size_t dot = std::min(name.find('.', start), name.size());
        const std::string_view label{name.data() + start, dot - start};
        if (label.empty() || label.size() > max_label_size || label.front() == '-' ||
            label.back() == '-') {
            return false;
        }
        for (const char c : label) {
            if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '-') {
                return false;
            }
        }
        start = dot + 1;
    }
    return true;
}

auto valid_dns4(const neighbor::Ipv4Address& a) noexcept -> bool {
    return !all_zero(a) && !packet::is_ipv4_multicast(a) && a != ipv4_broadcast;
}

auto valid_dns6(const Ipv6Address& a) noexcept -> bool {
    return !packet::is_unspecified(a) && !packet::is_ipv6_multicast(a);
}

// No bit set past `length` in `prefix` (whose first `bytes` bytes are the
// address; the rest must be zero too).
auto host_bits_clear(const Ipv6Address& prefix, std::size_t length) noexcept -> bool {
    constexpr std::size_t byte_bits = 8;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const auto b = std::to_integer<unsigned>(prefix.at(i));
        const std::size_t first = i * byte_bits;
        const unsigned keep = first >= length ? 0U
                              : first + byte_bits <= length
                                  ? 0xFFU
                                  : (0xFFU << (byte_bits - (length - first))) & 0xFFU;
        if ((b & ~keep) != 0) {
            return false;
        }
    }
    return true;
}

auto valid_route(const VpcRoute& r) noexcept -> bool {
    constexpr std::size_t ipv4_bits = 32;
    constexpr std::size_t ipv6_bits = 128;
    if (r.target == geneve::nic_invalid || r.target == geneve::nic_broadcast) {
        return false;
    }
    return r.length <= (r.ipv6 ? ipv6_bits : ipv4_bits) && host_bits_clear(r.prefix, r.length);
}

// Whether the first `length` bits of `a` equal `prefix`'s.
auto matches(std::span<const std::byte> a, const Ipv6Address& prefix, std::size_t length) noexcept
    -> bool {
    constexpr std::size_t byte_bits = 8;
    for (std::size_t i = 0; i * byte_bits < length; ++i) {
        const std::size_t bits = std::min(byte_bits, length - (i * byte_bits));
        const unsigned mask = (0xFFU << (byte_bits - bits)) & 0xFFU;
        if (((std::to_integer<unsigned>(a[i]) ^ std::to_integer<unsigned>(prefix.at(i))) & mask) !=
            0) {
            return false;
        }
    }
    return true;
}

auto validate(const VpcConfig& c) -> std::expected<void, VpcConfigError> {
    const MacAddress& m = c.gateway_mac;
    if (all_zero(m) || (m[0] & group_bit) == group_bit || (m[0] & mac_local_bit) != mac_local_bit) {
        return std::unexpected(VpcConfigError::bad_gateway_mac);
    }
    if (c.ipv4.length < min_ipv4_prefix || c.ipv4.length > max_ipv4_prefix ||
        (to_u32(c.ipv4.address) & ~prefix_mask(c.ipv4.length)) != 0) {
        return std::unexpected(VpcConfigError::bad_ipv4_prefix);
    }
    const std::uint32_t host_mask = ~prefix_mask(c.ipv4.length);
    const std::uint32_t host = to_u32(c.ipv4_gateway) & host_mask;
    if (!in_prefix(c.ipv4, c.ipv4_gateway) || host == 0 || host == host_mask) {
        return std::unexpected(VpcConfigError::bad_ipv4_gateway);
    }
    if (c.ipv6_prefix) {
        const Ipv6Address& p = *c.ipv6_prefix;
        const bool low_clear = std::all_of(p.begin() + ipv6_interface_id_offset, p.end(),
                                           [](std::byte b) { return b == std::byte{0}; });
        if (!low_clear || packet::is_unspecified(p) || packet::is_ipv6_multicast(p) ||
            packet::is_ipv6_link_local(p)) {
            return std::unexpected(VpcConfigError::bad_ipv6_prefix);
        }
    }
    if (c.dns4.size() > max_dns_servers || c.dns6.size() > max_dns_servers) {
        return std::unexpected(VpcConfigError::too_many_dns);
    }
    if (!std::ranges::all_of(c.dns4, valid_dns4) || !std::ranges::all_of(c.dns6, valid_dns6)) {
        return std::unexpected(VpcConfigError::bad_dns);
    }
    if (!valid_domain(c.domain)) {
        return std::unexpected(VpcConfigError::bad_domain);
    }
    if (c.lease_seconds < min_lease_seconds || c.lease_seconds > max_lease_seconds) {
        return std::unexpected(VpcConfigError::bad_lease);
    }
    if (c.routes.size() > max_vpc_routes) {
        return std::unexpected(VpcConfigError::too_many_routes);
    }
    for (auto it = c.routes.begin(); it != c.routes.end(); ++it) {
        const bool twice = std::any_of(c.routes.begin(), it, [&](const VpcRoute& r) {
            return r.ipv6 == it->ipv6 && r.length == it->length && r.prefix == it->prefix;
        });
        if (!valid_route(*it) || twice) {
            return std::unexpected(VpcConfigError::bad_route);
        }
    }
    return {};
}

// The longest-prefix route for a packet's destination, if any.
auto lookup_route(const VpcConfig& cfg, const packet::ParsedPacket& p) noexcept -> const VpcRoute* {
    const bool v6 = p.family == packet::IpFamily::ipv6;
    const std::span<const std::byte> dst =
        v6 ? std::span<const std::byte>{p.dst6} : std::span<const std::byte>{p.dst4};
    const VpcRoute* best = nullptr;
    for (const VpcRoute& r : cfg.routes) {
        if (r.ipv6 == v6 && (best == nullptr || r.length > best->length) &&
            matches(dst, r.prefix, r.length)) {
            best = &r;
        }
    }
    return best;
}

// A DHCPv4 client message for this VNI's server (Requirement 12.3): UDP
// 68 -> 67, unfragmented, from 0.0.0.0 or to the broadcast address or the
// gateway. A client talking to some other host's port 67 is forwarded.
auto dhcp4_client_message(const packet::ParsedPacket& p, const VpcConfig* cfg) noexcept -> bool {
    if (is_ipv6(p) || p.fragment || !udp_ports(p, dhcp4_client_port, dhcp4_server_port)) {
        return false;
    }
    return packet::is_unspecified(p.src4) || p.dst4 == ipv4_broadcast ||
           (cfg != nullptr && p.dst4 == cfg->ipv4_gateway);
}

constexpr Ipv6Address all_nodes{std::byte{0xff}, std::byte{0x02}, std::byte{0}, std::byte{0},
                                std::byte{0},    std::byte{0},    std::byte{0}, std::byte{0},
                                std::byte{0},    std::byte{0},    std::byte{0}, std::byte{0},
                                std::byte{0},    std::byte{0},    std::byte{0}, std::byte{1}};

// A DHCPv6 client message for this VNI's server (Requirement 12.5): UDP
// 546 -> 547, unfragmented, to All_DHCP_Relay_Agents_and_Servers or the
// gateway's link-local address.
auto dhcp6_client_message(const packet::ParsedPacket& p, const VpcConfig* cfg) -> bool {
    if (!is_ipv6(p) || p.fragment || !udp_ports(p, dhcp6::client_port, dhcp6::server_port)) {
        return false;
    }
    return p.dst6 == dhcp6::all_servers ||
           (cfg != nullptr && p.dst6 == gateway_link_local(cfg->gateway_mac));
}

auto metadata_destination(const packet::ParsedPacket& p) noexcept -> bool {
    return is_ipv6(p) ? p.dst6 == metadata_ipv6 : p.dst4 == metadata_ipv4;
}

auto valid_nic(geneve::NicId id) noexcept -> bool {
    return id != geneve::nic_invalid && id != geneve::nic_broadcast;
}

// The NIC registered for `ip`, if it is still mapped in `vni`.
template<typename Map, typename Ip>
auto resolve(const MappingSnapshot& snap, std::uint32_t vni, const Map& map, const Ip& ip)
    -> std::optional<std::pair<geneve::NicId, NicBinding>> {
    const auto it = map.find(ip);
    if (it == map.end()) {
        return std::nullopt;
    }
    const auto binding = snap.lookup(it->second);
    if (!binding || binding->vni != vni) {
        return std::nullopt;
    }
    return std::pair{it->second, *binding};
}

template<typename List, typename Valid>
auto check_neighbors(const List& list, Valid valid) -> std::expected<void, NeighborError> {
    std::set<decltype(list.front().ip)> seen;
    for (const auto& n : list) {
        if (!valid_nic(n.nic)) {
            return std::unexpected(NeighborError::invalid_nic_id);
        }
        if (!valid(n.ip)) {
            return std::unexpected(NeighborError::invalid_address);
        }
        if (!seen.insert(n.ip).second) {
            return std::unexpected(NeighborError::duplicate_address);
        }
    }
    return {};
}

}  // namespace

auto to_string(NeighborError e) noexcept -> const char* {
    switch (e) {
        case NeighborError::vni_out_of_range:
            return "vni_out_of_range";
        case NeighborError::invalid_nic_id:
            return "invalid_nic_id";
        case NeighborError::invalid_address:
            return "invalid_address";
        case NeighborError::duplicate_address:
            return "duplicate_address";
    }
    return "unknown";
}

auto to_string(AttachError e) noexcept -> const char* {
    switch (e) {
        case AttachError::invalid_nic_id:
            return "invalid_nic_id";
        case AttachError::already_attached:
            return "already_attached";
    }
    return "unknown";
}

auto to_string(GroupPolicyError e) noexcept -> const char* {
    switch (e) {
        case GroupPolicyError::vni_out_of_range:
            return "vni_out_of_range";
        case GroupPolicyError::unknown_mode:
            return "unknown_mode";
        case GroupPolicyError::missing_limit:
            return "missing_limit";
        case GroupPolicyError::limit_too_large:
            return "limit_too_large";
        case GroupPolicyError::nonzero_limits:
            return "nonzero_limits";
    }
    return "unknown";
}

auto to_string(VpcConfigError e) noexcept -> const char* {
    switch (e) {
        case VpcConfigError::vni_out_of_range:
            return "vni_out_of_range";
        case VpcConfigError::bad_gateway_mac:
            return "bad_gateway_mac";
        case VpcConfigError::bad_ipv4_prefix:
            return "bad_ipv4_prefix";
        case VpcConfigError::bad_ipv4_gateway:
            return "bad_ipv4_gateway";
        case VpcConfigError::bad_ipv6_prefix:
            return "bad_ipv6_prefix";
        case VpcConfigError::too_many_dns:
            return "too_many_dns";
        case VpcConfigError::bad_dns:
            return "bad_dns";
        case VpcConfigError::bad_domain:
            return "bad_domain";
        case VpcConfigError::bad_lease:
            return "bad_lease";
        case VpcConfigError::too_many_routes:
            return "too_many_routes";
        case VpcConfigError::bad_route:
            return "bad_route";
    }
    return "unknown";
}

auto gateway_link_local(const MacAddress& gateway_mac) noexcept -> Ipv6Address {
    Ipv6Address a{};
    a[0] = std::byte{0xfe};
    a[1] = std::byte{0x80};
    a[8] = gateway_mac[0] ^ mac_local_bit;  // RFC 4291: the universal/local bit, inverted
    a[9] = gateway_mac[1];
    a[10] = gateway_mac[2];
    a[11] = std::byte{0xff};
    a[12] = std::byte{0xfe};
    a[13] = gateway_mac[3];
    a[14] = gateway_mac[4];
    a[15] = gateway_mac[5];
    return a;
}

auto VSwitch::set_vpc_config(std::uint32_t vni, const VpcConfig& config)
    -> std::expected<void, VpcConfigError> {
    if (vni == 0 || vni > geneve::vni_max) {
        return std::unexpected(VpcConfigError::vni_out_of_range);
    }
    if (auto ok = validate(config); !ok) {
        return ok;
    }
    _vpc_configs.insert_or_assign(vni, config);
    return {};
}

auto VSwitch::clear_vpc_config(std::uint32_t vni) -> void {
    _vpc_configs.erase(vni);
}

auto VSwitch::vpc_config(std::uint32_t vni) const -> const VpcConfig* {
    const auto it = _vpc_configs.find(vni);
    return it == _vpc_configs.end() ? nullptr : &it->second;
}

auto VSwitch::dhcp4_address(std::uint32_t vni, geneve::NicId nic, const Ipv4Prefix& prefix) const
    -> std::optional<neighbor::Ipv4Address> {
    const VpcNeighbors* const table = neighbors(vni);
    if (table == nullptr) {
        return std::nullopt;
    }
    // The map is ordered by address, so the first match is the lowest.
    for (const auto& [ip, owner] : table->ipv4) {
        if (owner == nic && in_prefix(prefix, ip)) {
            return ip;
        }
    }
    return std::nullopt;
}

auto VSwitch::handle_gateway_arp(geneve::NicId src, const NicBinding& binding,
                                 const neighbor::ArpPacket& arp, const MacAddress& dst_mac)
    -> bool {
    const VpcConfig* const cfg = vpc_config(binding.vni);
    if (cfg == nullptr || arp.op != neighbor::arp_op_request) {
        return false;
    }
    const bool to_gateway = (dst_mac[0] & group_bit) == group_bit || dst_mac == cfg->gateway_mac;
    if (!to_gateway || (arp.target_ip != cfg->ipv4_gateway && arp.target_ip != metadata_ipv4)) {
        return false;
    }
    if (deliver(src, neighbor::build_arp_reply(arp, cfg->gateway_mac))) {
        ++_counters.arp_replies;
    }
    return true;
}

auto VSwitch::handle_gateway_nd(geneve::NicId src, const NicBinding& binding,
                                std::span<const std::byte> frame, const MacAddress& dst_mac)
    -> bool {
    const VpcConfig* const cfg = vpc_config(binding.vni);
    if (cfg == nullptr || !cfg->ipv6_prefix) {
        return false;
    }
    const bool to_gateway = (dst_mac[0] & group_bit) == group_bit || dst_mac == cfg->gateway_mac;
    if (!to_gateway) {
        return false;
    }
    const auto ns = neighbor::parse_neighbor_solicitation(frame);
    if (!ns || all_zero(ns->source_ip)) {
        return false;  // the proxy path counts spoofing; DAD is never answered
    }
    if (ns->target_ip != gateway_link_local(cfg->gateway_mac) && ns->target_ip != metadata_ipv6) {
        return false;
    }
    // The gateway's own address is a router's; the metadata address is not.
    const bool router = ns->target_ip != metadata_ipv6;
    if (deliver(src, neighbor::build_neighbor_advertisement(*ns, cfg->gateway_mac, router))) {
        ++_counters.nd_replies;
    }
    return true;
}

auto VSwitch::handle_dhcp4(geneve::NicId src, const NicBinding& binding,
                           const packet::ParsedPacket& p) -> bool {
    const VpcConfig* const cfg = vpc_config(binding.vni);
    if (cfg == nullptr) {
        ++_counters.dhcp4_no_config;
        return true;
    }
    const auto msg = dhcp4::parse(p.payload);
    if (!msg || msg->chaddr != binding.mac) {
        ++_counters.dhcp4_bad;
        return true;
    }
    if (msg->type == dhcp4::MessageType::release || msg->type == dhcp4::MessageType::decline ||
        (msg->server_id && *msg->server_id != cfg->ipv4_gateway)) {
        ++_counters.dhcp4_ignored;
        return true;
    }
    const auto mtu_it = _mtus.find(src);
    dhcp4::Reply reply{
        .type = dhcp4::MessageType::ack,
        .yiaddr = {},
        .server = cfg->ipv4_gateway,
        .subnet_mask = from_u32(prefix_mask(cfg->ipv4.length)),
        .router = cfg->ipv4_gateway,
        .dns = cfg->dns4,
        .domain = cfg->domain,
        .mtu = mtu_it == _mtus.end() ? std::uint16_t{0} : mtu_it->second,
        .lease_seconds = cfg->lease_seconds,
    };
    if (msg->type == dhcp4::MessageType::inform) {
        reply.lease_seconds = 0;  // RFC 2131 3.4: no lease, no yiaddr
    } else {
        const auto address = dhcp4_address(binding.vni, src, cfg->ipv4);
        if (!address) {
            ++_counters.dhcp4_no_address;
            return true;
        }
        if (msg->type == dhcp4::MessageType::discover) {
            reply.type = dhcp4::MessageType::offer;
            reply.yiaddr = *address;
        } else if (msg->requested_ip.value_or(msg->ciaddr) == *address) {  // request
            reply.yiaddr = *address;
        } else {
            reply.type = dhcp4::MessageType::nak;
        }
    }
    // RFC 2131 4.1: a NAK is broadcast; otherwise unicast to ciaddr if the
    // client has one, broadcast if it asked, else to the offered address.
    // The Ethernet destination is always the NIC, and only it gets a copy.
    const bool unicast_ciaddr = reply.type != dhcp4::MessageType::nak && !all_zero(msg->ciaddr);
    const bool broadcast =
        reply.type == dhcp4::MessageType::nak ||
        (!unicast_ciaddr && ((msg->flags & dhcp4::flag_broadcast) != 0 || all_zero(reply.yiaddr)));
    const neighbor::Ipv4Address dst = broadcast        ? ipv4_broadcast
                                      : unicast_ciaddr ? msg->ciaddr
                                                       : reply.yiaddr;
    const auto payload = dhcp4::build_reply(*msg, reply);
    const auto frame = packet::build_ipv4_udp(binding.mac, cfg->gateway_mac, cfg->ipv4_gateway, dst,
                                              dhcp4::server_port, dhcp4::client_port, payload);
    if (deliver(src, frame)) {
        ++_counters.dhcp4_replies;
    }
    return true;
}

auto VSwitch::send_ra(geneve::NicId nic, const NicBinding& binding, const VpcConfig& cfg,
                      const Ipv6Address& dst) -> void {
    const auto mtu_it = _mtus.find(nic);
    const auto body = dhcp6::build_router_advertisement_body({
        .gateway_mac = cfg.gateway_mac,
        .prefix = cfg.ipv6_prefix.value_or(Ipv6Address{}),
        .mtu = mtu_it == _mtus.end() ? std::uint16_t{0} : mtu_it->second,
        .dns = cfg.dns6,
        .router_lifetime = ra_router_lifetime_seconds,
        .dns_lifetime = static_cast<std::uint32_t>(3 * ra_interval.count()),
    });
    const auto frame =
        packet::build_icmpv6(binding.mac, cfg.gateway_mac, gateway_link_local(cfg.gateway_mac), dst,
                             dhcp6::icmpv6_router_advertisement, 0, body, neighbor::nd_hop_limit);
    if (deliver(nic, frame)) {
        ++_counters.ra_sent;
    }
}

auto VSwitch::handle_rs(geneve::NicId src, const NicBinding& binding, const packet::ParsedPacket& p)
    -> void {
    const VpcConfig* const cfg = vpc_config(binding.vni);
    if (cfg == nullptr || !cfg->ipv6_prefix || p.hop_limit != neighbor::nd_hop_limit) {
        ++_counters.rs_dropped;
        return;
    }
    // RFC 4861 6.2.6: to the solicitor's address, or all-nodes from ::.
    send_ra(src, binding, *cfg, packet::is_unspecified(p.src6) ? all_nodes : p.src6);
}

auto VSwitch::poll() -> void {
    const Clock::time_point now = _now();
    const auto snap = _mappings->snapshot();
    for (const auto& [nic, port] : _ports) {
        const auto binding = snap->lookup(nic);
        if (!binding || !snap->is_local(nic)) {
            continue;
        }
        const VpcConfig* const cfg = vpc_config(binding->vni);
        if (cfg == nullptr || !cfg->ipv6_prefix) {
            continue;
        }
        const auto last = _last_ra.find(nic);
        if (last != _last_ra.end() && now - last->second < ra_interval) {
            continue;
        }
        send_ra(nic, *binding, *cfg, all_nodes);
        _last_ra.insert_or_assign(nic, now);
    }
}

auto VSwitch::handle_dhcp6(geneve::NicId src, const NicBinding& binding,
                           const packet::ParsedPacket& p) -> void {
    using dhcp6::MessageType;
    const VpcConfig* const cfg = vpc_config(binding.vni);
    if (cfg == nullptr || !cfg->ipv6_prefix) {
        ++_counters.dhcp6_no_config;
        return;
    }
    const auto msg = dhcp6::parse(p.payload);
    if (!msg || packet::is_unspecified(p.src6) ||
        (msg->client_id.empty() && msg->type != MessageType::information_request)) {
        ++_counters.dhcp6_bad;
        return;
    }
    const auto ours = dhcp6::server_duid(cfg->gateway_mac);
    // RFC 8415 16: which messages must, may or must not name a server.
    bool wrong_server = false;
    switch (msg->type) {
        case MessageType::solicit:
        case MessageType::confirm:
        case MessageType::rebind:
            wrong_server = msg->server_id.has_value();
            break;
        case MessageType::request:
        case MessageType::renew:
        case MessageType::release:
        case MessageType::decline:
            wrong_server = msg->server_id != ours;
            break;
        default:  // information-request
            wrong_server = msg->server_id && *msg->server_id != ours;
            break;
    }
    if (wrong_server) {
        ++_counters.dhcp6_ignored;
        return;
    }

    const Ipv6Address& prefix = *cfg->ipv6_prefix;
    const auto in_prefix6 = [&prefix](const Ipv6Address& a) {
        return std::equal(prefix.begin(), prefix.begin() + ipv6_interface_id_offset, a.begin());
    };
    dhcp6::Reply reply{.type = MessageType::reply,
                       .server_id = ours,
                       .iaid = std::nullopt,
                       .addresses = {},
                       .lifetime = cfg->lease_seconds,
                       .status = std::nullopt,
                       .rapid_commit = false,
                       .dns = cfg->dns6,
                       .domain = cfg->domain};
    switch (msg->type) {
        case MessageType::solicit:
        case MessageType::request:
        case MessageType::renew:
        case MessageType::rebind:
            if (msg->type == MessageType::solicit) {
                reply.rapid_commit = msg->rapid_commit;
                reply.type = msg->rapid_commit ? MessageType::reply : MessageType::advertise;
            }
            if (msg->ia_na) {
                reply.iaid = msg->ia_na->iaid;
                if (const VpcNeighbors* const table = neighbors(binding.vni); table != nullptr) {
                    for (const auto& [ip, owner] : table->ipv6) {
                        if (owner == src && in_prefix6(ip)) {
                            reply.addresses.push_back(ip);
                        }
                    }
                }
            }
            break;
        case MessageType::confirm:
            if (!msg->ia_na || msg->ia_na->addresses.empty()) {
                ++_counters.dhcp6_ignored;  // RFC 8415 18.3.3: nothing to confirm
                return;
            }
            reply.status = std::ranges::all_of(msg->ia_na->addresses, in_prefix6)
                               ? dhcp6::StatusCode::success
                               : dhcp6::StatusCode::not_on_link;
            break;
        case MessageType::release:
        case MessageType::decline:
            reply.status = dhcp6::StatusCode::success;
            break;
        default:  // information-request: configuration only
            break;
    }
    const auto payload = dhcp6::build_reply(*msg, reply);
    const auto frame =
        packet::build_ipv6_udp(binding.mac, cfg->gateway_mac, gateway_link_local(cfg->gateway_mac),
                               p.src6, dhcp6::server_port, dhcp6::client_port, payload);
    if (deliver(src, frame)) {
        ++_counters.dhcp6_replies;
    }
}

auto VSwitch::take_metadata_token(Bucket& bucket) -> bool {
    const Clock::time_point now = _now();
    const std::uint64_t cap = std::uint64_t{metadata_burst} * nano;
    if (!bucket.primed) {
        bucket = {.frames = cap, .bytes = 0, .last = now, .primed = true};
    } else {
        const auto elapsed = now > bucket.last ? now - bucket.last : Clock::duration::zero();
        const auto ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
        bucket.frames = refill(bucket.frames, metadata_rate_pps, metadata_burst, ns);
        bucket.last = std::max(bucket.last, now);
    }
    if (bucket.frames < nano) {
        return false;
    }
    bucket.frames -= nano;
    return true;
}

auto VSwitch::handle_metadata(geneve::NicId src, const packet::ParsedPacket& p) -> void {
    if (_metadata == nullptr) {
        ++_counters.metadata_no_endpoint;
        return;
    }
    if (!take_metadata_token(_metadata_buckets[src])) {
        ++_counters.metadata_drop_rate;
        return;
    }
    _metadata->deliver(src, p.ip);
    ++_counters.metadata_tx;
}

auto VSwitch::inject_metadata(geneve::NicId nic, std::span<const std::byte> ip_packet) -> bool {
    const auto snap = _mappings->snapshot();
    const auto binding = snap->lookup(nic);
    const VpcConfig* const cfg = binding ? vpc_config(binding->vni) : nullptr;
    if (!binding || !snap->is_local(nic) || !attached(nic) || cfg == nullptr) {
        ++_counters.metadata_inject_refused;
        return false;
    }
    const auto frame = packet::build_ethernet(binding->mac, cfg->gateway_mac, ip_packet);
    const auto p = packet::parse(frame);
    const bool from_metadata =
        p && (is_ipv6(*p) ? p->src6 == metadata_ipv6 : p->src4 == metadata_ipv4);
    if (!from_metadata || owner(binding->vni, *p, false) != nic) {
        ++_counters.metadata_inject_refused;
        return false;
    }
    if (!deliver(nic, frame)) {
        return false;
    }
    ++_counters.metadata_rx;
    return true;
}

auto VSwitch::NicIdHash::operator()(geneve::NicId id) const noexcept -> std::size_t {
    return std::hash<std::uint64_t>{}(id.value);
}

VSwitch::VSwitch(const MappingTable& mappings, Underlay& underlay, Now now)
    : _mappings{&mappings}, _underlay{&underlay}, _now{std::move(now)} {}

auto VSwitch::attach(geneve::NicId nic, RxPort& port, std::uint16_t mtu)
    -> std::expected<void, AttachError> {
    if (!valid_nic(nic)) {
        return std::unexpected(AttachError::invalid_nic_id);
    }
    if (!_ports.try_emplace(nic, &port).second) {
        return std::unexpected(AttachError::already_attached);
    }
    _mtus.insert_or_assign(nic, mtu);
    _group.insert_or_assign(nic, NicGroupState{.attachment = ++_attachments});
    return {};
}

auto VSwitch::detach(geneve::NicId nic) -> bool {
    if (_ports.erase(nic) == 0) {
        return false;
    }
    _mtus.erase(nic);
    _last_ra.erase(nic);
    _metadata_buckets.erase(nic);
    const auto it = _group.find(nic);
    if (it != _group.end()) {
        _retired.push_back({.nic = nic,
                            .attachment = it->second.attachment,
                            .detached = true,
                            .meter = it->second.meter});
        _group.erase(it);
    }
    return true;
}

auto VSwitch::set_group_policy(std::uint32_t vni, const GroupPolicy& policy)
    -> std::expected<void, GroupPolicyError> {
    if (vni == 0 || vni > geneve::vni_max) {
        return std::unexpected(GroupPolicyError::vni_out_of_range);
    }
    switch (policy.mode) {
        case GroupMode::drop:
            if (policy.rate_frames != 0 || policy.burst_frames != 0 || policy.rate_bytes != 0 ||
                policy.burst_bytes != 0 || policy.max_remote_vteps != 0) {
                return std::unexpected(GroupPolicyError::nonzero_limits);
            }
            _group_policies.erase(vni);
            return {};
        case GroupMode::multicast:
            break;
        default:
            return std::unexpected(GroupPolicyError::unknown_mode);
    }
    if (policy.rate_frames == 0 || policy.burst_frames == 0 || policy.rate_bytes == 0 ||
        policy.burst_bytes == 0 || policy.max_remote_vteps == 0) {
        return std::unexpected(GroupPolicyError::missing_limit);
    }
    if (policy.rate_frames > group_rate_frames_max ||
        policy.burst_frames > group_burst_frames_max || policy.rate_bytes > group_rate_bytes_max ||
        policy.burst_bytes > group_burst_bytes_max ||
        policy.max_remote_vteps > group_max_remote_vteps_max) {
        return std::unexpected(GroupPolicyError::limit_too_large);
    }
    _group_policies.insert_or_assign(vni, policy);
    return {};
}

auto VSwitch::group_policy(std::uint32_t vni) const -> GroupPolicy {
    const auto it = _group_policies.find(vni);
    return it == _group_policies.end() ? GroupPolicy{} : it->second;
}

auto VSwitch::group_meter(geneve::NicId nic) const -> std::optional<GroupMeter> {
    const auto it = _group.find(nic);
    if (it == _group.end()) {
        return std::nullopt;
    }
    return it->second.meter;
}

auto VSwitch::group_usage() -> std::vector<GroupUsage> {
    std::vector<GroupUsage> out;
    out.reserve(_group.size() + _retired.size());
    for (const auto& [nic, state] : _group) {
        out.push_back({.nic = nic, .attachment = state.attachment, .meter = state.meter});
    }
    std::ranges::sort(out, {}, [](const GroupUsage& u) { return u.nic.value; });
    out.insert(out.end(), _retired.begin(), _retired.end());
    _retired.clear();
    return out;
}

auto VSwitch::take_tokens(Bucket& bucket, const GroupPolicy& policy, std::size_t bytes) -> bool {
    const Clock::time_point now = _now();
    const std::uint64_t frame_cap = std::uint64_t{policy.burst_frames} * nano;
    const std::uint64_t byte_cap = policy.burst_bytes * nano;
    if (!bucket.primed) {
        bucket = {.frames = frame_cap, .bytes = byte_cap, .last = now, .primed = true};
    } else {
        const auto elapsed = now > bucket.last ? now - bucket.last : Clock::duration::zero();
        const auto ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
        // min() also clamps to a burst lowered by a policy change.
        bucket.frames =
            refill(std::min(bucket.frames, frame_cap), policy.rate_frames, policy.burst_frames, ns);
        bucket.bytes =
            refill(std::min(bucket.bytes, byte_cap), policy.rate_bytes, policy.burst_bytes, ns);
        bucket.last = std::max(bucket.last, now);
    }
    const std::uint64_t need_bytes = static_cast<std::uint64_t>(bytes) * nano;
    if (bucket.frames < nano || bucket.bytes < need_bytes) {
        return false;
    }
    bucket.frames -= nano;
    bucket.bytes -= need_bytes;
    return true;
}

auto VSwitch::attached(geneve::NicId nic) const -> bool {
    return _ports.contains(nic);
}

auto VSwitch::port(geneve::NicId nic) const -> RxPort* {
    const auto it = _ports.find(nic);
    return it == _ports.end() ? nullptr : it->second;
}

auto VSwitch::neighbors(std::uint32_t vni) const -> const VpcNeighbors* {
    const auto it = _neighbors.find(vni);
    return it == _neighbors.end() ? nullptr : &it->second;
}

auto VSwitch::set_neighbors(const NeighborUpdate& update) -> std::expected<void, NeighborError> {
    if (update.vni == 0 || update.vni > geneve::vni_max) {
        return std::unexpected(NeighborError::vni_out_of_range);
    }
    if (auto ok = check_neighbors(update.ipv4,
                                  [](const neighbor::Ipv4Address& ip) {
                                      return !all_zero(ip) && ip[0] < ipv4_first_multicast;
                                  });
        !ok) {
        return ok;
    }
    if (auto ok = check_neighbors(
            update.ipv6,
            [](const Ipv6Address& ip) { return !all_zero(ip) && ip[0] != ipv6_multicast_prefix; });
        !ok) {
        return ok;
    }
    if (update.ipv4.empty() && update.ipv6.empty()) {
        _neighbors.erase(update.vni);
        return {};
    }
    VpcNeighbors next;
    for (const auto& n : update.ipv4) {
        next.ipv4.emplace(n.ip, n.nic);
    }
    for (const auto& n : update.ipv6) {
        next.ipv6.emplace(n.ip, n.nic);
    }
    _neighbors.insert_or_assign(update.vni, std::move(next));
    return {};
}

auto VSwitch::deliver_to(RxPort& port, std::span<const std::byte> frame) -> bool {
    if (port.deliver(frame) != RxResult::delivered) {
        ++_counters.deliver_failed;
        return false;
    }
    return true;
}

auto VSwitch::deliver(geneve::NicId nic, std::span<const std::byte> frame) -> bool {
    RxPort* const p = port(nic);
    return p != nullptr && deliver_to(*p, frame);
}

auto VSwitch::transmit(const TxFrame& tx) -> void {
    ++_counters.tx_frames;
    const auto snap = _mappings->snapshot();
    const auto binding = snap->lookup(tx.source);
    if (!binding || !snap->is_local(tx.source) || !attached(tx.source)) {
        ++_counters.tx_drop_dead_vpc;
        return;
    }
    if (tx.frame.size() < geneve::ethernet_header_size) {
        ++_counters.tx_drop_short;
        return;
    }
    if (mac_at(tx.frame, src_mac_offset) != binding->mac) {
        ++_counters.tx_drop_spoofed;
        return;
    }

    const MacAddress dst_mac = mac_at(tx.frame, dst_mac_offset);
    const bool group = (dst_mac[0] & group_bit) == group_bit;

    const std::uint16_t type = packet::ethertype(tx.frame);
    if (type == neighbor::ethertype_arp) {
        if (!handle_arp(*snap, tx.source, *binding, tx.frame, group)) {
            forward(*snap, tx.source, *binding, tx.frame, nullptr);
        }
        return;
    }
    if (type != neighbor::ethertype_ipv4 && type != neighbor::ethertype_ipv6) {
        ++_counters.tx_drop_ethertype;
        return;
    }
    const auto pkt = packet::parse(tx.frame);
    if (!pkt) {
        ++_counters.tx_drop_malformed;
        return;
    }
    const bool local_only = local_only_source(*pkt);
    if (!local_only && binding->source_dest_check && owner(binding->vni, *pkt, true) != tx.source) {
        ++_counters.tx_drop_ip_spoofed;
        return;
    }
    if (router_message(*pkt)) {
        ++_counters.tx_drop_router_msg;
        return;
    }
    if (const auto icmp = icmpv6_type(*pkt); icmp) {
        if (*icmp == neighbor::icmpv6_neighbor_advertisement &&
            !own_na_target(*pkt, tx.source, binding->vni)) {
            ++_counters.tx_drop_neighbor_spoofed;
            return;
        }
        if (*icmp == dhcp6::icmpv6_router_solicitation) {
            handle_rs(tx.source, *binding, *pkt);
            return;
        }
        if (*icmp == neighbor::icmpv6_neighbor_solicitation &&
            (handle_gateway_nd(tx.source, *binding, tx.frame, dst_mac) ||
             (group && handle_nd(*snap, tx.source, *binding, tx.frame)))) {
            return;
        }
    }
    if (dhcp4_client_message(*pkt, vpc_config(binding->vni)) &&
        handle_dhcp4(tx.source, *binding, *pkt)) {
        return;
    }
    if (dhcp6_client_message(*pkt, vpc_config(binding->vni))) {
        handle_dhcp6(tx.source, *binding, *pkt);
        return;
    }
    if (local_only) {
        ++_counters.tx_drop_local_only;
        return;
    }
    if (const VpcConfig* const cfg = vpc_config(binding->vni);
        cfg != nullptr && dst_mac == cfg->gateway_mac) {
        if (metadata_destination(*pkt)) {
            handle_metadata(tx.source, *pkt);
        } else {
            route(*snap, tx.source, *binding, *cfg, tx.frame, *pkt);
        }
        return;
    }
    forward(*snap, tx.source, *binding, tx.frame, &*pkt);
}

auto VSwitch::owner(std::uint32_t vni, const packet::ParsedPacket& p, bool source) const
    -> std::optional<geneve::NicId> {
    const VpcNeighbors* const table = neighbors(vni);
    if (table == nullptr) {
        return std::nullopt;
    }
    if (is_ipv6(p)) {
        const auto it = table->ipv6.find(source ? p.src6 : p.dst6);
        return it == table->ipv6.end() ? std::nullopt : std::optional{it->second};
    }
    const auto it = table->ipv4.find(source ? p.src4 : p.dst4);
    return it == table->ipv4.end() ? std::nullopt : std::optional{it->second};
}

auto VSwitch::own_na_target(const packet::ParsedPacket& p, geneve::NicId src,
                            std::uint32_t vni) const -> bool {
    if (p.l4_data.size() < nd_target_offset + Ipv6Address{}.size()) {
        return false;
    }
    Ipv6Address target{};
    std::copy_n(p.l4_data.begin() + static_cast<std::ptrdiff_t>(nd_target_offset), target.size(),
                target.begin());
    const VpcNeighbors* const table = neighbors(vni);
    if (table == nullptr) {
        return false;
    }
    const auto it = table->ipv6.find(target);
    return it != table->ipv6.end() && it->second == src;
}

auto VSwitch::forward(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                      std::span<const std::byte> frame, const packet::ParsedPacket* ip) -> void {
    const MacAddress dst_mac = mac_at(frame, dst_mac_offset);
    if ((dst_mac[0] & group_bit) == group_bit) {
        replicate(snap, src, binding.vni, frame, ip == nullptr || ip_multicast_destination(*ip));
        return;
    }
    const auto dst = snap.find_by_mac(binding.vni, dst_mac);
    if (!dst) {
        ++_counters.tx_drop_unknown_unicast;
        return;
    }
    if (*dst == src) {
        ++_counters.tx_drop_hairpin;
        return;
    }
    // find_by_mac only returns mapped NICs. A NIC with its check off takes
    // packets for any destination (Requirement 11.10).
    if (ip != nullptr && snap.lookup(*dst)->source_dest_check &&
        owner(binding.vni, *ip, false) != *dst) {
        ++_counters.tx_drop_ip_dst;
        return;
    }
    static_cast<void>(send_unicast(snap, src, binding.vni, *dst, frame));
}

auto VSwitch::send_unicast(const MappingSnapshot& snap, geneve::NicId src, std::uint32_t vni,
                           geneve::NicId dst, std::span<const std::byte> frame) -> bool {
    if (snap.is_local(dst)) {
        RxPort* const p = port(dst);
        if (p == nullptr) {
            ++_counters.tx_drop_unattached;
            return false;
        }
        if (!deliver_to(*p, frame)) {
            return false;
        }
        ++_counters.tx_local;
        return true;
    }
    const auto remote = snap.lookup(dst);
    _underlay->send(
        {.vtep = remote->owner_vtep, .vni = vni, .nics = {.src = src, .dst = dst}, .frame = frame});
    ++_counters.tx_remote;
    return true;
}

auto VSwitch::route(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                    const VpcConfig& cfg, std::span<const std::byte> frame,
                    const packet::ParsedPacket& p) -> void {
    constexpr std::size_t ipv4_ttl_offset = 8;
    constexpr std::size_t ipv4_checksum_offset = 10;
    constexpr std::size_t ipv6_hop_limit_offset = 7;
    constexpr neighbor::Ipv4Address broadcast{std::byte{255}, std::byte{255}, std::byte{255},
                                              std::byte{255}};
    const bool v6 = is_ipv6(p);
    const VpcRoute* const r = ip_multicast_destination(p) || (!v6 && p.dst4 == broadcast)
                                  ? nullptr
                                  : lookup_route(cfg, p);
    if (r == nullptr) {
        ++_counters.tx_drop_no_route;
        return;
    }
    const auto target = snap.lookup(r->target);
    if (!target || target->vni != binding.vni) {
        ++_counters.tx_drop_route_target;
        return;
    }
    if (r->target == src) {
        ++_counters.tx_drop_hairpin;
        return;
    }
    if (target->source_dest_check && owner(binding.vni, p, false) != r->target) {
        ++_counters.tx_drop_ip_dst;
        return;
    }
    if (p.hop_limit <= 1) {
        ++_counters.tx_drop_ttl;
        return;
    }
    // A router's rewrite: the target's MAC, one hop fewer. The source MAC
    // stays the sender's (see the header).
    std::vector<std::byte> out{frame.begin(), frame.end()};
    std::copy(target->mac.begin(), target->mac.end(), out.begin());
    const auto ip_at = static_cast<std::size_t>(p.ip.data() - frame.data());
    if (v6) {
        out[ip_at + ipv6_hop_limit_offset] = std::byte(p.hop_limit - 1);
    } else {
        // RFC 1624 incremental update: TTL is the high byte of its 16-bit word.
        out[ip_at + ipv4_ttl_offset] = std::byte(p.hop_limit - 1);
        const std::size_t c = ip_at + ipv4_checksum_offset;
        std::uint32_t sum = (std::to_integer<std::uint32_t>(out[c]) << 8U) |
                            std::to_integer<std::uint32_t>(out[c + 1]);
        sum = (~sum & 0xFFFFU) + (~0x0100U & 0xFFFFU);  // HC' = ~(~HC + ~m + m'), m - m' = 0x0100
        sum = (sum & 0xFFFFU) + (sum >> 16U);
        sum = (sum & 0xFFFFU) + (sum >> 16U);
        const auto updated = static_cast<std::uint16_t>(~sum);
        out[c] = std::byte(updated >> 8U);
        out[c + 1] = std::byte(updated & 0xFFU);
    }
    if (send_unicast(snap, src, binding.vni, r->target, out)) {
        ++_counters.tx_routed;
    }
}

auto VSwitch::handle_arp(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                         std::span<const std::byte> frame, bool group) -> bool {
    const auto arp = neighbor::parse_arp(frame);
    if (!arp) {
        if (arp.error() == neighbor::ParseError::sender_mismatch) {
            ++_counters.tx_drop_neighbor_spoofed;
            return true;
        }
        return false;  // not ARP, or malformed: forwarded as a plain frame
    }
    // Requirement 11.6: the sender IP is the NIC's own, or 0.0.0.0 (a probe).
    const VpcNeighbors* const table = neighbors(binding.vni);
    if (!all_zero(arp->sender_ip)) {
        const bool own = table != nullptr && [&] {
            const auto it = table->ipv4.find(arp->sender_ip);
            return it != table->ipv4.end() && it->second == src;
        }();
        if (!own) {
            ++_counters.tx_drop_neighbor_spoofed;
            return true;
        }
    }
    if (handle_gateway_arp(src, binding, *arp, mac_at(frame, dst_mac_offset))) {
        return true;
    }
    if (!group || arp->op != neighbor::arp_op_request || table == nullptr) {
        return false;
    }
    const auto target = resolve(snap, binding.vni, table->ipv4, arp->target_ip);
    if (!target || target->first == src) {
        return false;  // unknown, or the sender's own address (gratuitous ARP)
    }
    const auto reply = neighbor::build_arp_reply(*arp, target->second.mac);
    if (deliver(src, reply)) {
        ++_counters.arp_replies;
    }
    return true;
}

auto VSwitch::handle_nd(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                        std::span<const std::byte> frame) -> bool {
    const auto ns = neighbor::parse_neighbor_solicitation(frame);
    if (!ns) {
        if (ns.error() == neighbor::ParseError::sender_mismatch) {
            ++_counters.tx_drop_neighbor_spoofed;
            return true;
        }
        return false;
    }
    if (all_zero(ns->source_ip)) {
        return false;  // DAD probe: answering would make the guest give up its address
    }
    const VpcNeighbors* const table = neighbors(binding.vni);
    if (table == nullptr) {
        return false;
    }
    const auto target = resolve(snap, binding.vni, table->ipv6, ns->target_ip);
    if (!target || target->first == src) {
        return false;
    }
    const auto reply = neighbor::build_neighbor_advertisement(*ns, target->second.mac);
    if (deliver(src, reply)) {
        ++_counters.nd_replies;
    }
    return true;
}

auto VSwitch::replicate(const MappingSnapshot& snap, geneve::NicId src, std::uint32_t vni,
                        std::span<const std::byte> frame, bool ip_ok) -> void {
    NicGroupState& state = _group[src];  // attached senders always have one
    GroupMeter& meter = state.meter;
    const auto policy_it = _group_policies.find(vni);
    if (policy_it == _group_policies.end() ||
        !admits(policy_it->second, mac_at(frame, dst_mac_offset))) {
        ++meter.drop_policy;
        ++_counters.tx_drop_group;
        return;
    }
    if (!ip_ok) {  // Requirement 11.5: a multicast MAC with a unicast IP destination
        ++meter.drop_policy;
        ++_counters.tx_drop_ip_dst;
        return;
    }
    const GroupPolicy& policy = policy_it->second;

    std::vector<geneve::NicId> locals;
    std::vector<Ipv6Address> vteps;
    for (const MapEntry& e : snap.entries(vni)) {
        if (e.nic_id == src) {
            continue;
        }
        if (snap.is_local(e.nic_id)) {
            locals.push_back(e.nic_id);
        } else if (std::ranges::find(vteps, e.owner_vtep) == vteps.end()) {
            vteps.push_back(e.owner_vtep);
        }
    }
    if (vteps.size() > policy.max_remote_vteps) {
        ++meter.drop_fanout;
        ++_counters.tx_drop_group;
        return;
    }
    if (!take_tokens(state.bucket, policy, frame.size())) {
        ++meter.drop_rate;
        ++_counters.tx_drop_group;
        return;
    }

    ++_counters.tx_flooded;
    ++meter.frames;
    meter.bytes += frame.size();
    for (const geneve::NicId nic : locals) {
        if (deliver(nic, frame)) {
            ++_counters.tx_replicas_local;
            ++meter.replicas_local;
            meter.replica_bytes_local += frame.size();
        }
    }
    for (const Ipv6Address& vtep : vteps) {
        _underlay->send({.vtep = vtep,
                         .vni = vni,
                         .nics = {.src = src, .dst = geneve::nic_broadcast},
                         .frame = frame});
        ++_counters.tx_replicas_remote;
        ++meter.replicas_remote;
        meter.replica_bytes_remote += frame.size();
    }
}

auto VSwitch::receive(const geneve::Packet& packet, const Ipv6Address& outer_src)
    -> std::expected<geneve::NicId, PolicyError> {
    ++_counters.rx_frames;
    const auto snap = _mappings->snapshot();
    const auto dst = check_ingress(packet, outer_src, *snap);
    if (!dst) {
        ++_counters.rx_drop_policy.at(static_cast<std::size_t>(dst.error()));
        return dst;
    }
    if (*dst == geneve::nic_broadcast) {
        const auto policy_it = _group_policies.find(packet.vni);
        if (policy_it == _group_policies.end() ||
            !admits(policy_it->second, mac_at(packet.inner, dst_mac_offset))) {
            ++_counters.rx_drop_group;
            return dst;
        }
        if (!inner_allowed(packet, *dst)) {
            return dst;
        }
        for (const MapEntry& e : snap->entries(packet.vni)) {
            if (snap->is_local(e.nic_id) && deliver(e.nic_id, packet.inner)) {
                ++_counters.rx_delivered;
            }
        }
        return dst;
    }
    if (!inner_allowed(packet, *dst)) {
        return dst;
    }
    RxPort* const p = port(*dst);
    if (p == nullptr) {
        ++_counters.rx_drop_unattached;
    } else if (deliver_to(*p, packet.inner)) {
        ++_counters.rx_delivered;
    }
    return dst;
}

auto VSwitch::inner_allowed(const geneve::Packet& packet, geneve::NicId dst) -> bool {
    const std::uint16_t type = packet::ethertype(packet.inner);
    if (type == neighbor::ethertype_arp) {
        return true;
    }
    if (type != neighbor::ethertype_ipv4 && type != neighbor::ethertype_ipv6) {
        ++_counters.rx_drop_ethertype;
        return false;
    }
    const auto pkt = packet::parse(packet.inner);
    if (!pkt) {
        ++_counters.rx_drop_malformed;
        return false;
    }
    // No local-only sources here: link-local and unspecified sources are
    // never forwarded (Requirement 11.4), so a peer sending one is wrong.
    // A NIC whose mapping turns its check off may send from, and receive
    // for, addresses it does not own (Requirement 11.10); judged by this
    // VTEP's own mapping, like everything else here.
    const auto snap = _mappings->snapshot();
    const auto src_binding = snap->lookup(packet.nics->src);
    const bool src_checked = !src_binding || src_binding->source_dest_check;
    if (src_checked && owner(packet.vni, *pkt, true) != packet.nics->src) {
        ++_counters.rx_drop_ip_spoofed;
        return false;
    }
    const auto dst_binding = dst == geneve::nic_broadcast ? std::nullopt : snap->lookup(dst);
    const bool dst_ok = dst == geneve::nic_broadcast ? ip_multicast_destination(*pkt)
                        : dst_binding && !dst_binding->source_dest_check
                            ? true
                            : owner(packet.vni, *pkt, false) == dst;
    if (!dst_ok) {
        ++_counters.rx_drop_ip_dst;
        return false;
    }
    return true;
}

}  // namespace ak::oar::net
