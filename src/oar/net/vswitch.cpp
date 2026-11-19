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

auto mac_at(std::span<const std::byte> frame, std::size_t offset) noexcept -> MacAddress {
    MacAddress mac{};
    std::copy_n(frame.begin() + static_cast<std::ptrdiff_t>(offset), mac.size(), mac.begin());
    return mac;
}

template<typename A> auto all_zero(const A& a) noexcept -> bool {
    return std::ranges::all_of(a, [](std::byte b) { return b == std::byte{0}; });
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

auto VSwitch::NicIdHash::operator()(geneve::NicId id) const noexcept -> std::size_t {
    return std::hash<std::uint64_t>{}(id.value);
}

VSwitch::VSwitch(const MappingTable& mappings, Underlay& underlay)
    : _mappings{&mappings}, _underlay{&underlay} {}

auto VSwitch::attach(geneve::NicId nic, RxPort& port) -> std::expected<void, AttachError> {
    if (!valid_nic(nic)) {
        return std::unexpected(AttachError::invalid_nic_id);
    }
    if (!_ports.try_emplace(nic, &port).second) {
        return std::unexpected(AttachError::already_attached);
    }
    return {};
}

auto VSwitch::detach(geneve::NicId nic) -> bool {
    return _ports.erase(nic) != 0;
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

    if (handle_arp(*snap, tx.source, *binding, tx.frame, group)) {
        return;
    }
    if (group) {
        if (handle_nd(*snap, tx.source, *binding, tx.frame)) {
            return;
        }
        flood(*snap, tx.source, binding->vni, tx.frame);
        return;
    }

    const auto dst = snap->find_by_mac(binding->vni, dst_mac);
    if (!dst) {
        ++_counters.tx_drop_unknown_unicast;
        return;
    }
    if (*dst == tx.source) {
        ++_counters.tx_drop_hairpin;
        return;
    }
    if (snap->is_local(*dst)) {
        RxPort* const p = port(*dst);
        if (p == nullptr) {
            ++_counters.tx_drop_unattached;
            return;
        }
        if (deliver_to(*p, tx.frame)) {
            ++_counters.tx_local;
        }
        return;
    }
    const auto remote = snap->lookup(*dst);  // find_by_mac only returns mapped NICs
    _underlay->send({.vtep = remote->owner_vtep,
                     .vni = binding->vni,
                     .nics = {.src = tx.source, .dst = *dst},
                     .frame = tx.frame});
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
    const VpcNeighbors* const table = neighbors(binding.vni);
    if (table != nullptr && !all_zero(arp->sender_ip)) {
        const auto owner = table->ipv4.find(arp->sender_ip);
        if (owner != table->ipv4.end() && owner->second != src) {
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

auto VSwitch::flood(const MappingSnapshot& snap, geneve::NicId src, std::uint32_t vni,
                    std::span<const std::byte> frame) -> void {
    ++_counters.tx_flooded;
    std::vector<Ipv6Address> vteps;
    for (const MapEntry& e : snap.entries(vni)) {
        if (e.nic_id == src) {
            continue;
        }
        if (snap.is_local(e.nic_id)) {
            if (deliver(e.nic_id, frame)) {
                ++_counters.tx_replicas_local;
            }
        } else if (std::ranges::find(vteps, e.owner_vtep) == vteps.end()) {
            vteps.push_back(e.owner_vtep);
        }
    }
    for (const Ipv6Address& vtep : vteps) {
        _underlay->send({.vtep = vtep,
                         .vni = vni,
                         .nics = {.src = src, .dst = geneve::nic_broadcast},
                         .frame = frame});
        ++_counters.tx_replicas_remote;
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
        for (const MapEntry& e : snap->entries(packet.vni)) {
            if (snap->is_local(e.nic_id) && deliver(e.nic_id, packet.inner)) {
                ++_counters.rx_delivered;
            }
        }
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

}  // namespace ak::oar::net
