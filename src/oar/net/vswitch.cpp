// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/vswitch.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <iterator>
#include <tuple>
#include <set>
#include <string_view>

#include "oar/net/dhcp4.hpp"
#include "oar/net/dhcp6.hpp"
#include "proto/group_members.hpp"

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
    // An IGMP report before the guest has an address comes from 0.0.0.0
    // (RFC 3376 4.2.13); snooping consumes it.
    return packet::is_unspecified(p.src4) &&
           (udp_ports(p, dhcp4_client_port, dhcp4_server_port) || p.protocol == igmp::ipproto_igmp);
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
    const bool target_ok =
        r.local ? r.target == geneve::nic_invalid
                : r.target != geneve::nic_invalid && r.target != geneve::nic_broadcast;
    if (!target_ok) {
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

auto valid_ipv4_prefix(const Ipv4Prefix& p) noexcept -> bool {
    return p.length >= min_ipv4_prefix && p.length <= max_ipv4_prefix &&
           (to_u32(p.address) & ~prefix_mask(p.length)) == 0;
}

auto overlap(const Ipv4Prefix& a, const Ipv4Prefix& b) noexcept -> bool {
    const std::uint32_t mask = prefix_mask(std::min(a.length, b.length));
    return (to_u32(a.address) & mask) == (to_u32(b.address) & mask);
}

// A global or unique-local IPv6 prefix of `length` bits, no host bits.
auto valid_ipv6_prefix(const Ipv6Address& p, std::size_t length) noexcept -> bool {
    return host_bits_clear(p, length) && !packet::is_unspecified(p) &&
           !packet::is_ipv6_multicast(p) && !packet::is_ipv6_link_local(p);
}

auto validate_blocks(const VpcConfig& c) -> std::expected<void, VpcConfigError> {
    if (c.ipv4_blocks.empty() || c.ipv4_blocks.size() > max_vpc_ipv4_blocks) {
        return std::unexpected(VpcConfigError::bad_ipv4_prefix);
    }
    for (auto it = c.ipv4_blocks.begin(); it != c.ipv4_blocks.end(); ++it) {
        if (!valid_ipv4_prefix(*it) || std::any_of(c.ipv4_blocks.begin(), it, [&](const auto& b) {
                return overlap(b, *it);
            })) {
            return std::unexpected(VpcConfigError::bad_ipv4_prefix);
        }
    }
    if (c.ipv6_block && !valid_ipv6_prefix(*c.ipv6_block, ipv6_block_length)) {
        return std::unexpected(VpcConfigError::bad_ipv6_prefix);
    }
    return {};
}

auto validate_subnets(const VpcConfig& c) -> std::expected<void, VpcConfigError> {
    constexpr std::size_t ipv6_subnet_length = 64;
    if (c.subnets.empty() || c.subnets.size() > max_vpc_subnets) {
        return std::unexpected(VpcConfigError::bad_subnet);
    }
    for (auto it = c.subnets.begin(); it != c.subnets.end(); ++it) {
        const VpcSubnet& s = *it;
        const bool ordered = it == c.subnets.begin() || std::prev(it)->id < s.id;
        if (s.id == 0 || !ordered || !valid_ipv4_prefix(s.ipv4) ||
            std::ranges::none_of(c.ipv4_blocks,
                                 [&](const Ipv4Prefix& b) {
                                     return b.length <= s.ipv4.length && overlap(b, s.ipv4);
                                 }) ||
            std::any_of(c.subnets.begin(), it,
                        [&](const VpcSubnet& o) { return overlap(o.ipv4, s.ipv4); })) {
            return std::unexpected(VpcConfigError::bad_subnet);
        }
        const std::uint32_t host_mask = ~prefix_mask(s.ipv4.length);
        const std::uint32_t host = to_u32(s.gateway) & host_mask;
        if (!in_prefix(s.ipv4, s.gateway) || host == 0 || host == host_mask) {
            return std::unexpected(VpcConfigError::bad_ipv4_gateway);
        }
        if (s.ipv6_prefix &&
            (!c.ipv6_block || !valid_ipv6_prefix(*s.ipv6_prefix, ipv6_subnet_length) ||
             !matches(*s.ipv6_prefix, *c.ipv6_block, ipv6_block_length) ||
             std::any_of(c.subnets.begin(), it,
                         [&](const VpcSubnet& o) { return o.ipv6_prefix == s.ipv6_prefix; }))) {
            return std::unexpected(VpcConfigError::bad_ipv6_prefix);
        }
    }
    return {};
}

auto validate_tables(const VpcConfig& c) -> std::expected<void, VpcConfigError> {
    if (c.tables.empty() || c.tables.size() > max_vpc_tables ||
        std::ranges::count_if(c.tables, &VpcRouteTable::main) != 1 ||
        std::ranges::adjacent_find(c.tables, std::ranges::greater_equal{}, &VpcRouteTable::table) !=
            c.tables.end()) {
        return std::unexpected(VpcConfigError::bad_table);
    }
    std::size_t total = 0;
    for (const VpcRouteTable& t : c.tables) {
        total += t.routes.size();
        if (total > max_vpc_routes ||
            static_cast<std::size_t>(std::ranges::count_if(
                t.routes, [](const VpcRoute& r) { return !r.local; })) > max_vpc_nic_routes) {
            return std::unexpected(VpcConfigError::too_many_routes);
        }
        for (auto it = t.routes.begin(); it != t.routes.end(); ++it) {
            const bool twice = std::any_of(t.routes.begin(), it, [&](const VpcRoute& r) {
                return r.ipv6 == it->ipv6 && r.length == it->length && r.prefix == it->prefix;
            });
            if (!valid_route(*it) || twice) {
                return std::unexpected(VpcConfigError::bad_route);
            }
        }
    }
    for (const VpcSubnet& s : c.subnets) {
        if (!std::ranges::binary_search(c.tables, s.table, {}, &VpcRouteTable::table)) {
            return std::unexpected(VpcConfigError::bad_subnet);
        }
    }
    return {};
}

auto validate(const VpcConfig& c) -> std::expected<void, VpcConfigError> {
    const MacAddress& m = c.gateway_mac;
    if (all_zero(m) || (m[0] & group_bit) == group_bit || (m[0] & mac_local_bit) != mac_local_bit) {
        return std::unexpected(VpcConfigError::bad_gateway_mac);
    }
    if (auto ok = validate_blocks(c); !ok) {
        return ok;
    }
    if (auto ok = validate_subnets(c); !ok) {
        return ok;
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
    return validate_tables(c);
}

// A DHCPv4 client message for this VNI's server (Requirement 12.3): UDP
// 68 -> 67, unfragmented, from 0.0.0.0 or to the broadcast address or the
// gateway. A client talking to some other host's port 67 is forwarded.
auto dhcp4_client_message(const packet::ParsedPacket& p, const VpcSubnet* subnet) noexcept -> bool {
    if (is_ipv6(p) || p.fragment || !udp_ports(p, dhcp4_client_port, dhcp4_server_port)) {
        return false;
    }
    return packet::is_unspecified(p.src4) || p.dst4 == ipv4_broadcast ||
           (subnet != nullptr && p.dst4 == subnet->gateway);
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

// The mapping as check_ingress sees it on receive: the snapshot, plus the
// VNI's gateway MAC when this VTEP holds a config for it, so a routed
// frame's source passes (vpc-subnets-routing design "Receive").
class GatewayView final : public MappingView {
public:
    GatewayView(const MappingSnapshot& snap, std::uint32_t vni, const VpcConfig* cfg)
        : _snap{&snap}, _vni{vni}, _cfg{cfg} {}

    [[nodiscard]] auto lookup(geneve::NicId id) const -> std::optional<NicBinding> override {
        return _snap->lookup(id);
    }
    [[nodiscard]] auto is_local(geneve::NicId id) const -> bool override {
        return _snap->is_local(id);
    }
    [[nodiscard]] auto gateway_mac(std::uint32_t vni) const -> std::optional<MacAddress> override {
        if (_cfg == nullptr || vni != _vni) {
            return std::nullopt;
        }
        return _cfg->gateway_mac;
    }

private:
    const MappingSnapshot* _snap;
    std::uint32_t _vni;
    const VpcConfig* _cfg;
};

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

auto in_prefix(const Ipv4Prefix& prefix, const neighbor::Ipv4Address& address) noexcept -> bool {
    return (to_u32(address) & prefix_mask(prefix.length)) == to_u32(prefix.address);
}

auto in_prefix64(const Ipv6Address& prefix, const Ipv6Address& address) noexcept -> bool {
    return std::equal(prefix.begin(), prefix.begin() + ipv6_interface_id_offset, address.begin());
}

auto find_subnet(const VpcConfig& config, std::uint64_t id) noexcept -> const VpcSubnet* {
    const auto it = std::ranges::lower_bound(config.subnets, id, {}, &VpcSubnet::id);
    return it != config.subnets.end() && it->id == id && id != 0 ? &*it : nullptr;
}

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

auto to_string(GroupMembersError e) noexcept -> const char* {
    switch (e) {
        case GroupMembersError::vni_out_of_range:
            return "vni_out_of_range";
        case GroupMembersError::too_many_groups:
            return "too_many_groups";
        case GroupMembersError::bad_group:
            return "bad_group";
        case GroupMembersError::bad_vteps:
            return "bad_vteps";
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
        case VpcConfigError::bad_subnet:
            return "bad_subnet";
        case VpcConfigError::bad_table:
            return "bad_table";
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
    // validate() refused duplicate prefixes, so every insert succeeds.
    VpcState state{.config = config, .tables = {}};
    state.tables.reserve(config.tables.size());
    for (const VpcRouteTable& t : config.tables) {
        CompiledTable& compiled = state.tables.emplace_back();
        compiled.table = t.table;
        for (const VpcRoute& r : t.routes) {
            const RouteTrie::Target target{.local = r.local, .nic = r.target};
            static_cast<void>(r.ipv6 ? compiled.ipv6.insert(r.prefix, r.length, target)
                                     : compiled.ipv4.insert(r.prefix, r.length, target));
        }
    }
    _vpc_configs.insert_or_assign(vni, std::move(state));
    return {};
}

auto VSwitch::clear_vpc_config(std::uint32_t vni) -> void {
    _vpc_configs.erase(vni);
}

auto VSwitch::vpc_config(std::uint32_t vni) const -> const VpcConfig* {
    const VpcState* const state = vpc_state(vni);
    return state == nullptr ? nullptr : &state->config;
}

auto VSwitch::vpc_state(std::uint32_t vni) const -> const VpcState* {
    const auto it = _vpc_configs.find(vni);
    return it == _vpc_configs.end() ? nullptr : &it->second;
}

auto VSwitch::nic_addresses(std::uint32_t vni, geneve::NicId nic) const
    -> std::pair<std::vector<neighbor::Ipv4Address>, std::vector<Ipv6Address>> {
    std::pair<std::vector<neighbor::Ipv4Address>, std::vector<Ipv6Address>> out;
    const VpcNeighbors* const table = neighbors(vni);
    if (table == nullptr) {
        return out;
    }
    for (const auto& [ip, owner] : table->ipv4) {
        if (owner == nic) {
            out.first.push_back(ip);
        }
    }
    for (const auto& [ip, owner] : table->ipv6) {
        if (owner == nic) {
            out.second.push_back(ip);
        }
    }
    return out;
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
    if (!to_gateway) {
        return false;
    }
    // transmit() already dropped a NIC without a subnet in this VPC.
    const VpcSubnet* const subnet = find_subnet(*cfg, binding.subnet_id);
    if (arp.target_ip != metadata_ipv4 && (subnet == nullptr || arp.target_ip != subnet->gateway)) {
        // Another subnet's gateway is not on this NIC's link (Requirement 3).
        if (std::ranges::any_of(cfg->subnets,
                                [&](const VpcSubnet& o) { return o.gateway == arp.target_ip; })) {
            ++_counters.tx_drop_arp_other_subnet;
            return true;
        }
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
    const VpcSubnet* const subnet = subnet_of(binding);
    if (cfg == nullptr || subnet == nullptr || !subnet->ipv6_prefix) {
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
    const VpcSubnet* const subnet = find_subnet(*cfg, binding.subnet_id);
    if (subnet == nullptr) {
        ++_counters.dhcp4_no_address;  // unreachable: transmit() drops NICs without a subnet
        return true;
    }
    const auto msg = dhcp4::parse(p.payload);
    if (!msg || msg->chaddr != binding.mac) {
        ++_counters.dhcp4_bad;
        return true;
    }
    if (msg->type == dhcp4::MessageType::release || msg->type == dhcp4::MessageType::decline ||
        (msg->server_id && *msg->server_id != subnet->gateway)) {
        ++_counters.dhcp4_ignored;
        return true;
    }
    const auto mtu_it = _mtus.find(src);
    dhcp4::Reply reply{
        .type = dhcp4::MessageType::ack,
        .yiaddr = {},
        .server = subnet->gateway,
        .subnet_mask = from_u32(prefix_mask(subnet->ipv4.length)),
        .router = subnet->gateway,
        .dns = cfg->dns4,
        .domain = cfg->domain,
        .mtu = mtu_it == _mtus.end() ? std::uint16_t{0} : mtu_it->second,
        .lease_seconds = cfg->lease_seconds,
    };
    if (msg->type == dhcp4::MessageType::inform) {
        reply.lease_seconds = 0;  // RFC 2131 3.4: no lease, no yiaddr
    } else {
        const auto address = dhcp4_address(binding.vni, src, subnet->ipv4);
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
    const auto frame = packet::build_ipv4_udp(binding.mac, cfg->gateway_mac, subnet->gateway, dst,
                                              dhcp4::server_port, dhcp4::client_port, payload);
    if (deliver(src, frame)) {
        ++_counters.dhcp4_replies;
    }
    return true;
}

auto VSwitch::send_ra(geneve::NicId nic, const NicBinding& binding, const VpcConfig& cfg,
                      const Ipv6Address& prefix, const Ipv6Address& dst) -> void {
    const auto mtu_it = _mtus.find(nic);
    const auto body = dhcp6::build_router_advertisement_body({
        .gateway_mac = cfg.gateway_mac,
        .prefix = prefix,
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
    const VpcSubnet* const subnet = subnet_of(binding);
    if (cfg == nullptr || subnet == nullptr || !subnet->ipv6_prefix ||
        p.hop_limit != neighbor::nd_hop_limit) {
        ++_counters.rs_dropped;
        return;
    }
    // RFC 4861 6.2.6: to the solicitor's address, or all-nodes from ::.
    send_ra(src, binding, *cfg, *subnet->ipv6_prefix,
            packet::is_unspecified(p.src6) ? all_nodes : p.src6);
}

auto VSwitch::poll() -> void {
    const Clock::time_point now = _now();
    const auto snap = _mappings->snapshot();
    for (auto& [nic, state] : _group) {
        const auto erased =
            std::erase_if(state.groups, [now](const auto& g) { return g.second <= now; });
        if (erased != 0) {
            _membership_count -= erased;
            _counters.snoop_expired += erased;
            ++_membership_changes;
        }
        const auto binding = snap->lookup(nic);
        if (!binding || !snap->is_local(nic) || !_group_policies.contains(binding->vni)) {
            continue;
        }
        const VpcConfig* const cfg = vpc_config(binding->vni);
        const VpcSubnet* const subnet = subnet_of(*binding);
        if (cfg != nullptr && subnet != nullptr &&
            (!state.last_query ||
             now - *state.last_query >= std::chrono::seconds{igmp::query_interval_seconds})) {
            send_queries(nic, *cfg, *subnet);
            state.last_query = now;
        }
    }
    for (const auto& [nic, port] : _ports) {
        const auto binding = snap->lookup(nic);
        if (!binding || !snap->is_local(nic)) {
            continue;
        }
        const VpcConfig* const cfg = vpc_config(binding->vni);
        const VpcSubnet* const subnet = subnet_of(*binding);
        if (cfg == nullptr || subnet == nullptr || !subnet->ipv6_prefix) {
            continue;
        }
        const auto last = _last_ra.find(nic);
        if (last != _last_ra.end() && now - last->second < ra_interval) {
            continue;
        }
        send_ra(nic, *binding, *cfg, *subnet->ipv6_prefix, all_nodes);
        _last_ra.insert_or_assign(nic, now);
    }
}

auto VSwitch::handle_dhcp6(geneve::NicId src, const NicBinding& binding,
                           const packet::ParsedPacket& p) -> void {
    using dhcp6::MessageType;
    const VpcConfig* const cfg = vpc_config(binding.vni);
    const VpcSubnet* const subnet = subnet_of(binding);
    if (cfg == nullptr || subnet == nullptr || !subnet->ipv6_prefix) {
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

    const Ipv6Address& prefix = *subnet->ipv6_prefix;
    const auto in_prefix6 = [&prefix](const Ipv6Address& a) { return in_prefix64(prefix, a); };
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

auto VSwitch::send_queries(geneve::NicId nic, const VpcConfig& cfg, const VpcSubnet& subnet)
    -> void {
    if (deliver(nic, igmp::build_query4(cfg.gateway_mac, subnet.gateway))) {
        ++_counters.queries_sent;
    }
    if (subnet.ipv6_prefix &&
        deliver(nic, igmp::build_query6(cfg.gateway_mac, gateway_link_local(cfg.gateway_mac)))) {
        ++_counters.queries_sent;
    }
}

auto VSwitch::snoop(geneve::NicId src, const NicBinding& binding, const packet::ParsedPacket& p,
                    igmp::Kind kind) -> void {
    if (kind != igmp::Kind::report) {
        ++_counters.tx_drop_router_msg;  // only the gateway queries
        return;
    }
    ++_counters.snoop_reports;
    const auto changes = igmp::parse_report(p);
    if (!changes) {
        ++_counters.snoop_malformed;
        return;
    }
    const auto policy = _group_policies.find(binding.vni);
    if (policy == _group_policies.end()) {
        ++_counters.snoop_ignored;
        return;
    }
    NicGroupState& state = _group[src];  // attached senders always have one
    const Clock::time_point expiry = _now() + std::chrono::seconds{igmp::membership_seconds};
    for (const igmp::Change& c : *changes) {
        const auto it = state.groups.find(c.group);
        if (!c.join) {
            if (it != state.groups.end()) {
                state.groups.erase(it);
                --_membership_count;
                ++_membership_changes;
                ++_counters.snoop_leaves;
            }
        } else if (it != state.groups.end()) {
            it->second = expiry;
        } else if (state.groups.size() >= policy->second.max_groups_per_nic ||
                   _membership_count >= max_role_memberships) {
            ++_counters.snoop_drop_cap;
        } else {
            state.groups.emplace(c.group, expiry);
            ++_membership_count;
            ++_membership_changes;
            ++_counters.snoop_joins;
        }
    }
}

auto VSwitch::trim_memberships(std::uint32_t vni, std::size_t cap) -> void {
    const auto snap = _mappings->snapshot();
    for (auto& [nic, state] : _group) {
        const auto binding = snap->lookup(nic);
        if (!binding || binding->vni != vni || state.groups.size() <= cap) {
            continue;
        }
        const std::size_t extra = state.groups.size() - cap;
        state.groups.erase(std::next(state.groups.begin(), static_cast<std::ptrdiff_t>(cap)),
                           state.groups.end());
        _membership_count -= extra;
        ++_membership_changes;
    }
}

auto VSwitch::set_group_members(std::uint32_t vni, const GroupMembers& members)
    -> std::expected<void, GroupMembersError> {
    if (vni == 0 || vni > geneve::vni_max) {
        return std::unexpected(GroupMembersError::vni_out_of_range);
    }
    if (members.size() > proto::max_member_groups) {
        return std::unexpected(GroupMembersError::too_many_groups);
    }
    std::size_t total = 0;
    for (const auto& [group, vteps] : members) {
        if (!igmp::replicable(group)) {
            return std::unexpected(GroupMembersError::bad_group);
        }
        total += vteps.size();
        const bool bad = std::ranges::any_of(vteps, [](const Ipv6Address& v) {
            return packet::is_unspecified(v) || packet::is_ipv6_multicast(v);
        });
        if (vteps.empty() || vteps.size() > proto::max_group_vteps ||
            total > proto::max_member_vteps || bad || !std::ranges::is_sorted(vteps) ||
            std::ranges::adjacent_find(vteps) != vteps.end()) {
            return std::unexpected(GroupMembersError::bad_vteps);
        }
    }
    if (members.empty()) {
        _group_members.erase(vni);
    } else {
        _group_members.insert_or_assign(vni, members);
    }
    return {};
}

auto VSwitch::group_members(std::uint32_t vni) const -> const GroupMembers* {
    const auto it = _group_members.find(vni);
    return it == _group_members.end() ? nullptr : &it->second;
}

auto VSwitch::memberships() const -> std::vector<Membership> {
    const auto snap = _mappings->snapshot();
    std::vector<Membership> out;
    out.reserve(_membership_count);
    for (const auto& [nic, state] : _group) {
        const auto binding = snap->lookup(nic);
        if (!binding) {
            continue;
        }
        for (const auto& entry : state.groups) {
            out.push_back({.nic = nic, .vni = binding->vni, .group = entry.first});
        }
    }
    std::ranges::sort(out, [](const Membership& a, const Membership& b) {
        return std::tie(a.nic, a.group) < std::tie(b.nic, b.group);
    });
    return out;
}

auto VSwitch::listed_vteps(std::uint32_t vni, const packet::ParsedPacket* ip) const
    -> const std::vector<Ipv6Address>* {
    if (ip == nullptr) {
        return nullptr;
    }
    const auto lists = _group_members.find(vni);
    if (lists == _group_members.end()) {
        return nullptr;
    }
    const auto it = lists->second.find(igmp::destination_group(*ip));
    return it == lists->second.end() ? nullptr : &it->second;
}

auto VSwitch::joined(geneve::NicId nic, const igmp::Group& g) const -> bool {
    const auto it = _group.find(nic);
    return it != _group.end() && it->second.groups.contains(g);
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
        if (!it->second.groups.empty()) {
            _membership_count -= it->second.groups.size();
            ++_membership_changes;
        }
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
                policy.burst_bytes != 0 || policy.max_remote_vteps != 0 ||
                policy.max_groups_per_nic != 0) {
                return std::unexpected(GroupPolicyError::nonzero_limits);
            }
            _group_policies.erase(vni);
            trim_memberships(vni, 0);
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
        policy.max_remote_vteps > group_max_remote_vteps_max ||
        policy.max_groups_per_nic > group_max_groups_per_nic_max) {
        return std::unexpected(GroupPolicyError::limit_too_large);
    }
    _group_policies.insert_or_assign(vni, policy);
    trim_memberships(vni, policy.max_groups_per_nic);
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

auto VSwitch::subnet_of(const NicBinding& binding) const -> const VpcSubnet* {
    const VpcConfig* const cfg = vpc_config(binding.vni);
    return cfg == nullptr ? nullptr : find_subnet(*cfg, binding.subnet_id);
}

auto VSwitch::same_subnet(const NicBinding& a, const NicBinding& b) const -> bool {
    return a.vni == b.vni && (vpc_config(a.vni) == nullptr || a.subnet_id == b.subnet_id);
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
    // In a VPC with a config a NIC carries traffic only inside its subnet;
    // one the mapping does not place in a known subnet carries none
    // (vpc-subnets-routing Requirement 2.6).
    const VpcSubnet* const subnet = subnet_of(*binding);
    if (subnet == nullptr && vpc_config(binding->vni) != nullptr) {
        ++_counters.tx_drop_no_subnet;
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
    if (const auto kind = igmp::classify(*pkt); kind) {
        snoop(tx.source, *binding, *pkt, *kind);
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
    if (dhcp4_client_message(*pkt, subnet) && handle_dhcp4(tx.source, *binding, *pkt)) {
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
    if (const VpcState* const state = vpc_state(binding->vni);
        state != nullptr && dst_mac == state->config.gateway_mac) {
        if (metadata_destination(*pkt)) {
            handle_metadata(tx.source, *pkt);
        } else {
            // subnet is set: a NIC without one was dropped above.
            route(*snap, tx.source, *binding, *state, *subnet, tx.frame, *pkt);
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
        replicate(snap, src, binding.vni, frame, ip);
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
    // find_by_mac only returns mapped NICs. Another subnet is reached only
    // through the router, at the gateway MAC (Requirement 6.4).
    const auto dst_binding = snap.lookup(*dst);
    if (!same_subnet(binding, *dst_binding)) {
        ++_counters.tx_drop_cross_subnet;
        return;
    }
    // A NIC with its check off takes packets for any destination
    // (Requirement 11.10).
    if (ip != nullptr && dst_binding->source_dest_check && owner(binding.vni, *ip, false) != *dst) {
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

auto VSwitch::route_target(const MappingSnapshot& snap, std::uint32_t vni, const VpcState& state,
                           const VpcSubnet& subnet, const packet::ParsedPacket& p) const
    -> std::expected<std::pair<geneve::NicId, NicBinding>, RouteDrop> {
    constexpr neighbor::Ipv4Address broadcast{std::byte{255}, std::byte{255}, std::byte{255},
                                              std::byte{255}};
    const bool v6 = is_ipv6(p);
    if (ip_multicast_destination(p) || (!v6 && p.dst4 == broadcast)) {
        return std::unexpected(RouteDrop::no_route);  // never routed
    }
    // validate() made every subnet's table exist.
    const auto table =
        std::ranges::lower_bound(state.tables, subnet.table, {}, &CompiledTable::table);
    const auto target = v6 ? table->ipv6.lookup(p.dst6) : table->ipv4.lookup(p.dst4);
    if (!target) {
        return std::unexpected(RouteDrop::no_route);
    }
    if (target->local) {
        // The NIC owning the destination, in any subnet of the VPC.
        const auto nic = owner(vni, p, false);
        const auto binding = nic ? snap.lookup(*nic) : std::nullopt;
        if (!binding || binding->vni != vni) {
            return std::unexpected(RouteDrop::no_neighbor);
        }
        return std::pair{*nic, *binding};
    }
    // A NIC route whose target is not mapped here matches nothing: EC2's
    // blackhole (Requirement 4.5).
    const auto binding = snap.lookup(target->nic);
    if (!binding || binding->vni != vni) {
        return std::unexpected(RouteDrop::route_target);
    }
    return std::pair{target->nic, *binding};
}

auto VSwitch::route(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                    const VpcState& state, const VpcSubnet& subnet,
                    std::span<const std::byte> frame, const packet::ParsedPacket& p) -> void {
    constexpr std::size_t ipv4_ttl_offset = 8;
    constexpr std::size_t ipv4_checksum_offset = 10;
    constexpr std::size_t ipv6_hop_limit_offset = 7;
    const auto target = route_target(snap, binding.vni, state, subnet, p);
    if (!target) {
        switch (target.error()) {
            case RouteDrop::no_route:
                ++_counters.tx_drop_no_route;
                break;
            case RouteDrop::no_neighbor:
                ++_counters.tx_drop_no_neighbor;
                break;
            case RouteDrop::route_target:
                ++_counters.tx_drop_route_target;
                break;
        }
        return;
    }
    const auto& [dst, dst_binding] = *target;
    if (dst == src) {
        ++_counters.tx_drop_hairpin;
        return;
    }
    // Requirement 12.7: a route leads only to a NIC that owns the
    // destination or has turned its check off.
    if (dst_binding.source_dest_check && owner(binding.vni, p, false) != dst) {
        ++_counters.tx_drop_ip_dst;
        return;
    }
    if (p.hop_limit <= 1) {
        ++_counters.tx_drop_ttl;
        return;
    }
    // A router's rewrite: the target's MAC from the gateway's, one hop
    // fewer. The gateway source MAC tells the receiving VTEP the frame was
    // routed (vpc-subnets-routing design "Decisions").
    std::vector<std::byte> out{frame.begin(), frame.end()};
    std::copy(dst_binding.mac.begin(), dst_binding.mac.end(), out.begin());
    std::copy(state.config.gateway_mac.begin(), state.config.gateway_mac.end(),
              out.begin() + static_cast<std::ptrdiff_t>(src_mac_offset));
    const auto ip_at = static_cast<std::size_t>(p.ip.data() - frame.data());
    if (is_ipv6(p)) {
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
    if (send_unicast(snap, src, binding.vni, dst, out)) {
        ++_counters.tx_routed;
    }
}

auto VSwitch::routed_to(const MappingSnapshot& snap, const geneve::Packet& packet,
                        const NicBinding& src, geneve::NicId dst) const -> bool {
    const VpcState* const state = vpc_state(packet.vni);
    const VpcSubnet* const subnet = subnet_of(src);
    if (state == nullptr || subnet == nullptr ||
        packet::ethertype(packet.inner) == neighbor::ethertype_arp) {
        return false;  // the router forwards only IP
    }
    const auto p = packet::parse(packet.inner);
    if (!p) {
        return false;
    }
    const auto target = route_target(snap, packet.vni, *state, *subnet, *p);
    return target && target->first == dst;
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
    if (!target || target->first == src || !same_subnet(binding, target->second)) {
        return false;  // unknown, the sender's own address (gratuitous ARP), or off-link
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
    if (!target || target->first == src || !same_subnet(binding, target->second)) {
        return false;
    }
    const auto reply = neighbor::build_neighbor_advertisement(*ns, target->second.mac);
    if (deliver(src, reply)) {
        ++_counters.nd_replies;
    }
    return true;
}

auto VSwitch::replicate(const MappingSnapshot& snap, geneve::NicId src, std::uint32_t vni,
                        std::span<const std::byte> frame, const packet::ParsedPacket* ip) -> void {
    const bool ip_ok = ip == nullptr || ip_multicast_destination(*ip);
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

    // A listed group goes to its VTEPs and the local NICs that joined it;
    // any other group to the whole VNI.
    const std::vector<Ipv6Address>* const listed = listed_vteps(vni, ip);
    const igmp::Group group = ip == nullptr ? igmp::Group{} : igmp::destination_group(*ip);
    // In a VPC with a config the frame stays inside the sender's subnet:
    // only its NICs get local copies, and only VTEPs hosting one of them
    // are on the flood list (vpc-subnets-routing Requirement 6.7).
    const bool subnets = vpc_config(vni) != nullptr;
    const std::uint64_t subnet = subnets ? snap.lookup(src)->subnet_id : 0;
    std::vector<geneve::NicId> locals;
    std::vector<Ipv6Address> reach;  // remote VTEPs hosting a NIC the frame may reach
    for (const MapEntry& e : snap.entries(vni)) {
        if (e.nic_id == src || (subnets && e.subnet_id != subnet)) {
            continue;
        }
        if (snap.is_local(e.nic_id)) {
            if (listed == nullptr || joined(e.nic_id, group)) {
                locals.push_back(e.nic_id);
            }
        } else if (std::ranges::find(reach, e.owner_vtep) == reach.end()) {
            reach.push_back(e.owner_vtep);
        }
    }
    std::vector<Ipv6Address> vteps;
    if (listed == nullptr) {
        vteps = std::move(reach);
    } else {
        // A listed group's VTEPs; with subnets only those the subnet reaches.
        std::ranges::copy_if(*listed, std::back_inserter(vteps), [&](const Ipv6Address& v) {
            return v != snap.local_vtep() &&
                   (!subnets || std::ranges::find(reach, v) != reach.end());
        });
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
    if (listed != nullptr) {
        ++_counters.tx_replicas_pruned;
    }
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
    const VpcConfig* const cfg = vpc_config(packet.vni);
    const GatewayView view{*snap, packet.vni, cfg};
    const auto dst = check_ingress(packet, outer_src, view);
    if (!dst) {
        ++_counters.rx_drop_policy.at(static_cast<std::size_t>(dst.error()));
        return dst;
    }
    // In a VPC with a config, judged by this VTEP's own mapping and config:
    // the source NIC must be in a known subnet, and a switched frame stays
    // inside it (vpc-subnets-routing Requirements 2.6 and 6.4).
    const bool subnets = cfg != nullptr;
    std::optional<NicBinding> src_binding;
    if (subnets) {
        src_binding = snap->lookup(packet.nics->src);
        if (!src_binding || subnet_of(*src_binding) == nullptr) {
            ++_counters.rx_drop_no_subnet;
            return dst;
        }
    }
    const std::uint64_t subnet = src_binding ? src_binding->subnet_id : 0;
    // A routed frame: check_ingress accepted the gateway MAC as its source
    // only because this VTEP holds a config with that MAC (Requirement
    // 6.5). The router never replicates, and this VTEP's own lookup must
    // lead to the same NIC.
    const bool routed = subnets && mac_at(packet.inner, src_mac_offset) == cfg->gateway_mac;
    if (routed &&
        (*dst == geneve::nic_broadcast || !routed_to(*snap, packet, *src_binding, *dst))) {
        ++_counters.rx_drop_route_mismatch;
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
        // A listed group reaches only the local NICs that joined it.
        std::optional<packet::ParsedPacket> ip;
        if (_group_members.contains(packet.vni)) {
            if (auto parsed = packet::parse(packet.inner); parsed) {
                ip = *parsed;
            }
        }
        const bool listed = listed_vteps(packet.vni, ip ? &*ip : nullptr) != nullptr;
        const igmp::Group group = ip ? igmp::destination_group(*ip) : igmp::Group{};
        for (const MapEntry& e : snap->entries(packet.vni)) {
            if (snap->is_local(e.nic_id) && (!subnets || e.subnet_id == subnet) &&
                (!listed || joined(e.nic_id, group)) && deliver(e.nic_id, packet.inner)) {
                ++_counters.rx_delivered;
            }
        }
        return dst;
    }
    if (subnets && !routed && snap->lookup(*dst)->subnet_id != subnet) {
        ++_counters.rx_drop_cross_subnet;
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
