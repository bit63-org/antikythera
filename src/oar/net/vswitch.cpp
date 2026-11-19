// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/vswitch.hpp"

#include <algorithm>
#include <functional>
#include <set>

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

auto VSwitch::NicIdHash::operator()(geneve::NicId id) const noexcept -> std::size_t {
    return std::hash<std::uint64_t>{}(id.value);
}

VSwitch::VSwitch(const MappingTable& mappings, Underlay& underlay, Now now)
    : _mappings{&mappings}, _underlay{&underlay}, _now{std::move(now)} {}

auto VSwitch::attach(geneve::NicId nic, RxPort& port) -> std::expected<void, AttachError> {
    if (!valid_nic(nic)) {
        return std::unexpected(AttachError::invalid_nic_id);
    }
    if (!_ports.try_emplace(nic, &port).second) {
        return std::unexpected(AttachError::already_attached);
    }
    _group.insert_or_assign(nic, NicGroupState{.attachment = ++_attachments});
    return {};
}

auto VSwitch::detach(geneve::NicId nic) -> bool {
    if (_ports.erase(nic) == 0) {
        return false;
    }
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
    if (!local_only && owner(binding->vni, *pkt, true) != tx.source) {
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
        if (*icmp == neighbor::icmpv6_neighbor_solicitation && group &&
            handle_nd(*snap, tx.source, *binding, tx.frame)) {
            return;
        }
    }
    if (local_only) {
        ++_counters.tx_drop_local_only;
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
    if (ip != nullptr && owner(binding.vni, *ip, false) != *dst) {
        ++_counters.tx_drop_ip_dst;
        return;
    }
    if (snap.is_local(*dst)) {
        RxPort* const p = port(*dst);
        if (p == nullptr) {
            ++_counters.tx_drop_unattached;
            return;
        }
        if (deliver_to(*p, frame)) {
            ++_counters.tx_local;
        }
        return;
    }
    const auto remote = snap.lookup(*dst);  // find_by_mac only returns mapped NICs
    _underlay->send({.vtep = remote->owner_vtep,
                     .vni = binding.vni,
                     .nics = {.src = src, .dst = *dst},
                     .frame = frame});
    ++_counters.tx_remote;
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
    if (owner(packet.vni, *pkt, true) != packet.nics->src) {
        ++_counters.rx_drop_ip_spoofed;
        return false;
    }
    const bool dst_ok = dst == geneve::nic_broadcast ? ip_multicast_destination(*pkt)
                                                     : owner(packet.vni, *pkt, false) == dst;
    if (!dst_ok) {
        ++_counters.rx_drop_ip_dst;
        return false;
    }
    return true;
}

}  // namespace ak::oar::net
