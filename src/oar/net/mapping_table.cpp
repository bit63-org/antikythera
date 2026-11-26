// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/mapping_table.hpp"

#include <algorithm>
#include <climits>
#include <functional>
#include <unordered_set>
#include <utility>

namespace ak::oar::net {

namespace {

constexpr std::byte group_bit{0x01};

struct MacHash {
    auto operator()(const MacAddress& mac) const noexcept -> std::size_t {
        std::uint64_t v = 0;
        for (const std::byte b : mac) {
            v = (v << CHAR_BIT) | std::to_integer<std::uint64_t>(b);
        }
        return std::hash<std::uint64_t>{}(v);
    }
};

template<typename A> auto all_zero(const A& a) noexcept -> bool {
    return std::ranges::all_of(a, [](std::byte b) { return b == std::byte{0}; });
}

auto validate(const MapUpdate& update, const MappingSnapshot& current)
    -> std::expected<void, MapUpdateError> {
    if (update.vni == 0 || update.vni > geneve::vni_max) {
        return std::unexpected(MapUpdateError::vni_out_of_range);
    }
    if (update.version <= current.version(update.vni)) {
        return std::unexpected(MapUpdateError::stale_version);
    }

    struct IdHash {
        auto operator()(geneve::NicId id) const noexcept -> std::size_t {
            return std::hash<std::uint64_t>{}(id.value);
        }
    };
    std::unordered_set<geneve::NicId, IdHash> ids;
    std::unordered_set<MacAddress, MacHash> macs;
    ids.reserve(update.entries.size());
    macs.reserve(update.entries.size());

    for (const MapEntry& e : update.entries) {
        if (e.nic_id == geneve::nic_invalid || e.nic_id == geneve::nic_broadcast) {
            return std::unexpected(MapUpdateError::invalid_nic_id);
        }
        if (!ids.insert(e.nic_id).second) {
            return std::unexpected(MapUpdateError::duplicate_nic_id);
        }
        if (const auto existing = current.lookup(e.nic_id);
            existing && existing->vni != update.vni) {
            return std::unexpected(MapUpdateError::nic_in_other_vni);
        }
        if (all_zero(e.mac) || (e.mac[0] & group_bit) == group_bit) {
            return std::unexpected(MapUpdateError::invalid_mac);
        }
        if (!macs.insert(e.mac).second) {
            return std::unexpected(MapUpdateError::duplicate_mac);
        }
        if (all_zero(e.owner_vtep)) {
            return std::unexpected(MapUpdateError::invalid_vtep);
        }
    }
    return {};
}

}  // namespace

auto to_string(MapUpdateError e) noexcept -> const char* {
    switch (e) {
        case MapUpdateError::vni_out_of_range:
            return "vni_out_of_range";
        case MapUpdateError::stale_version:
            return "stale_version";
        case MapUpdateError::invalid_nic_id:
            return "invalid_nic_id";
        case MapUpdateError::duplicate_nic_id:
            return "duplicate_nic_id";
        case MapUpdateError::nic_in_other_vni:
            return "nic_in_other_vni";
        case MapUpdateError::invalid_mac:
            return "invalid_mac";
        case MapUpdateError::duplicate_mac:
            return "duplicate_mac";
        case MapUpdateError::invalid_vtep:
            return "invalid_vtep";
    }
    return "unknown";
}

auto MappingSnapshot::lookup(geneve::NicId id) const -> std::optional<NicBinding> {
    if (const auto it = _nics.find(id); it != _nics.end()) {
        return it->second;
    }
    return std::nullopt;
}

auto MappingSnapshot::is_local(geneve::NicId id) const -> bool {
    const auto it = _nics.find(id);
    return it != _nics.end() && it->second.owner_vtep == _local_vtep;
}

auto MappingSnapshot::find_by_mac(std::uint32_t vni, const MacAddress& mac) const
    -> std::optional<geneve::NicId> {
    for (const MapEntry& e : entries(vni)) {
        if (e.mac == mac) {
            return e.nic_id;
        }
    }
    return std::nullopt;
}

auto MappingSnapshot::version(std::uint32_t vni) const -> std::uint64_t {
    const auto it = _vpcs.find(vni);
    return it == _vpcs.end() ? 0 : it->second.version;
}

auto MappingSnapshot::entries(std::uint32_t vni) const -> std::span<const MapEntry> {
    const auto it = _vpcs.find(vni);
    if (it == _vpcs.end()) {
        return {};
    }
    return it->second.entries;
}

auto MappingSnapshot::peer_vteps() const -> std::vector<Ipv6Address> {
    std::vector<Ipv6Address> peers;
    for (const auto& [vni, vpc] : _vpcs) {
        const bool here = std::ranges::any_of(
            vpc.entries, [this](const MapEntry& e) { return e.owner_vtep == _local_vtep; });
        if (!here) {
            continue;
        }
        for (const MapEntry& e : vpc.entries) {
            if (e.owner_vtep != _local_vtep) {
                peers.push_back(e.owner_vtep);
            }
        }
    }
    std::ranges::sort(peers);
    const auto dup = std::ranges::unique(peers);
    peers.erase(dup.begin(), dup.end());
    return peers;
}

auto MappingSnapshot::vni_count() const noexcept -> std::size_t {
    return static_cast<std::size_t>(
        std::ranges::count_if(_vpcs, [](const auto& kv) { return !kv.second.entries.empty(); }));
}

MappingTable::MappingTable(const Ipv6Address& local_vtep)
    : _current(std::make_shared<const MappingSnapshot>(local_vtep)) {}

auto MappingTable::snapshot() const -> std::shared_ptr<const MappingSnapshot> {
    return _current.load(std::memory_order_acquire);
}

auto MappingTable::apply(const MapUpdate& update) -> std::expected<std::uint64_t, MapUpdateError> {
    const std::scoped_lock lock(_writer);
    const auto current = _current.load(std::memory_order_acquire);
    if (auto ok = validate(update, *current); !ok) {
        return std::unexpected(ok.error());
    }

    auto next = std::make_shared<MappingSnapshot>(*current);
    auto& vpc = next->_vpcs[update.vni];
    for (const MapEntry& old : vpc.entries) {
        next->_nics.erase(old.nic_id);
    }
    vpc.version = update.version;
    vpc.entries = update.entries;
    for (const MapEntry& e : update.entries) {
        next->_nics.emplace(e.nic_id, NicBinding{update.vni, e.mac, e.owner_vtep,
                                                 e.source_dest_check, e.subnet_id});
    }

    _current.store(std::move(next), std::memory_order_release);
    return update.version;
}

auto MappingTable::lookup(geneve::NicId id) const -> std::optional<NicBinding> {
    return snapshot()->lookup(id);
}

auto MappingTable::is_local(geneve::NicId id) const -> bool {
    return snapshot()->is_local(id);
}

}  // namespace ak::oar::net
