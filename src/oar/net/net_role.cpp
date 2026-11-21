// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/net_role.hpp"

#include <algorithm>
#include <format>
#include <limits>
#include <utility>
#include <variant>

#include "proto/map_update.hpp"

namespace ak::oar::net {

namespace {

namespace oar = helm::oar;

// Placeholder NIC IDs: a block at the top of the space, below the broadcast
// ID, one per function number. The controller allocates NIC IDs from the
// bottom, and a placeholder is never connected anyway; the range only keeps
// the IDs valid and distinct.
constexpr std::uint64_t placeholder_nic_base = 0xFFFF'FFFE'0000'0000;
constexpr std::byte placeholder_mac_head{0x02};  // locally administered unicast
constexpr std::byte placeholder_mac_fill{0xFF};
constexpr unsigned byte_bits = 8;
constexpr std::size_t mac_fn_high = 4;
constexpr std::size_t mac_fn_low = 5;

auto to_map_update(const proto::MapUpdate& u) -> MapUpdate {
    MapUpdate out{.vni = u.vni, .version = u.map_version, .entries = {}};
    out.entries.reserve(u.entries.size());
    for (const auto& e : u.entries) {
        out.entries.push_back(
            {.nic_id = geneve::NicId{e.nic_id}, .mac = e.mac, .owner_vtep = e.owner_vtep});
    }
    return out;
}

// The proxy addresses carried by the same frame (format v2). decode
// guarantees what set_neighbors() checks: unicast, unique, and every NIC
// listed in the frame.
auto to_neighbors(const proto::MapUpdate& u) -> NeighborUpdate {
    NeighborUpdate out{.vni = u.vni, .ipv4 = {}, .ipv6 = {}};
    out.ipv4.reserve(u.ipv4.size());
    for (const auto& g : u.ipv4) {
        out.ipv4.push_back({.ip = g.address, .nic = geneve::NicId{g.nic_id}});
    }
    out.ipv6.reserve(u.ipv6.size());
    for (const auto& g : u.ipv6) {
        out.ipv6.push_back({.ip = g.address, .nic = geneve::NicId{g.nic_id}});
    }
    return out;
}

}  // namespace

auto placeholder_identity(oar::FunctionNumber fn, std::uint16_t mtu) -> NicIdentity {
    MacAddress mac{};
    mac.fill(placeholder_mac_fill);
    mac[0] = placeholder_mac_head;
    mac[mac_fn_high] = static_cast<std::byte>(fn >> byte_bits);
    mac[mac_fn_low] = static_cast<std::byte>(fn & 0xFFU);
    return {.nic_id = geneve::NicId{placeholder_nic_base | fn}, .mac = mac, .mtu = mtu};
}

NetRole::NetRole(NetRoleConfig config, MapVerifier verifier)
    : _config{std::move(config)}, _verifier{std::move(verifier)}, _mappings{_config.vtep} {}

NetRole::~NetRole() = default;

auto NetRole::create(NetRoleConfig config, const std::vector<NetTransport*>& transports,
                     MapVerifier verifier, DatagramSender& sender, PeerObserver* observer)
    -> std::expected<std::unique_ptr<NetRole>, std::string> {
    if (transports.empty() || transports.size() > std::numeric_limits<oar::FunctionNumber>::max()) {
        return std::unexpected("need between 1 and 65535 functions");
    }
    if (!verifier) {
        return std::unexpected("no map_update verifier");
    }
    if (config.server_id == 0) {
        return std::unexpected("server ID must be non-zero");
    }
    if (std::ranges::all_of(config.vtep, [](std::byte b) { return b == std::byte{0}; })) {
        return std::unexpected("VTEP address must be set");
    }
    if (config.mtu.guest_mtu < min_mtu || config.mtu.max_geneve_payload == 0) {
        return std::unexpected("MTU plan not set (plan_mtu)");
    }
    if (!config.clock) {
        config.clock = [] { return NetRoleConfig::Clock::now(); };
    }
    config.vtep_config.max_payload = config.mtu.max_geneve_payload;

    std::unique_ptr<NetRole> role{new NetRole{std::move(config), std::move(verifier)}};
    auto vtep = Vtep::create(role->_mappings, sender, observer, role->_config.vtep_config);
    if (!vtep) {
        return std::unexpected(std::format("vtep: {}", to_string(vtep.error())));
    }
    role->_vtep = std::move(*vtep);
    role->_vswitch = std::make_unique<VSwitch>(role->_mappings, *role->_vtep);
    role->_started = role->_config.clock();
    role->_slots.resize(transports.size());
    for (std::size_t i = 0; i < transports.size(); ++i) {
        NetTransport* t = transports[i];
        if (t == nullptr) {
            return std::unexpected(std::format("function {}: no transport", i));
        }
        const auto fn = static_cast<oar::FunctionNumber>(i);
        auto f = VirtioNetFunction::create(
            {.identity = placeholder_identity(fn, role->_config.mtu.guest_mtu),
             .queue_size = role->_config.queue_size,
             .tx_budget = role->_config.tx_budget},
            t->memory(), t->interrupts(), *role->_vswitch);
        if (!f) {
            return std::unexpected(std::format("function {}: {}", i, to_string(f.error())));
        }
        role->_slots[i].function = std::move(*f);
        if (auto ok = t->bind(role->_slots[i].function->pci()); !ok) {
            return std::unexpected(std::format("function {}: {}", i, ok.error()));
        }
    }
    return role;
}

auto NetRole::slot(oar::FunctionNumber fn) -> Slot* {
    return fn < _slots.size() ? &_slots[fn] : nullptr;
}

auto NetRole::attached(oar::FunctionNumber fn) const -> std::optional<geneve::NicId> {
    return fn < _slots.size() ? _slots[fn].nic : std::nullopt;
}

auto NetRole::function(oar::FunctionNumber fn) -> VirtioNetFunction* {
    Slot* s = slot(fn);
    return s == nullptr ? nullptr : s->function.get();
}

auto NetRole::function_inventory() -> std::expected<oar::Inventory, oar::Status> {
    oar::Inventory inv{.role = oar::Role::net, .vtep = _config.vtep, .functions = {}};
    inv.functions.reserve(_slots.size());
    for (std::size_t i = 0; i < _slots.size(); ++i) {
        inv.functions.push_back(
            {.fn = static_cast<oar::FunctionNumber>(i), .type = helm::FunctionType::nic_vf});
    }
    return inv;
}

auto NetRole::prepare_function(const oar::PrepareFunction& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    const auto* cfg = std::get_if<oar::NicConfig>(&request.config);
    if (request.type != helm::FunctionType::nic_vf || cfg == nullptr) {
        return oar::Status::wrong_type;
    }
    if (s->nic) {
        return oar::Status::busy;  // helm cleans a function before preparing it again
    }
    const geneve::NicId nic{cfg->nic_id};
    if (_vswitch->attached(nic)) {
        return oar::Status::busy;  // that NIC is already on another function here
    }
    const NicIdentity identity{.nic_id = nic, .mac = cfg->mac, .mtu = _config.mtu.guest_mtu};
    if (!validate(identity)) {
        return oar::Status::bad_request;
    }
    if (!s->function->reassign(identity)) {
        return oar::Status::failed;
    }
    if (!_vswitch->attach(nic, *s->function, _config.mtu.guest_mtu)) {
        static_cast<void>(
            s->function->reassign(placeholder_identity(request.fn, _config.mtu.guest_mtu)));
        return oar::Status::failed;
    }
    s->nic = nic;
    return oar::Status::ok;
}

auto NetRole::release(oar::FunctionNumber fn, Slot& s) -> bool {
    if (s.nic) {
        static_cast<void>(_vswitch->detach(*s.nic));
        s.nic.reset();
    }
    // Resets the function (queues, interrupts, driver state) even if it was
    // never attached: cleaning is how helm gets a known-empty function.
    return s.function->reassign(placeholder_identity(fn, _config.mtu.guest_mtu)).has_value();
}

auto NetRole::clean_function(const oar::CleanFunction& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (request.action != helm::CleaningAction::reset_nic_vf) {
        return oar::Status::wrong_type;
    }
    return release(request.fn, *s) ? oar::Status::ok : oar::Status::failed;
}

auto NetRole::deliver_key(const oar::DeliverKey& /*request*/) -> oar::Status {
    return oar::Status::unsupported;
}

auto NetRole::drop_key(const oar::DropKey& /*request*/) -> oar::Status {
    return oar::Status::unsupported;
}

auto NetRole::map_update(std::span<const std::byte> frame) -> oar::Status {
    auto update = proto::decode_map_update(frame);
    if (!update) {
        ++_counters.map_undecodable;
        return oar::Status::failed;
    }
    if (update->server_id != _config.server_id) {
        ++_counters.map_wrong_server;
        return oar::Status::failed;
    }
    if (!_verifier(proto::map_update_signed_bytes(frame), update->signature, update->key_id)) {
        ++_counters.map_bad_signature;
        return oar::Status::failed;
    }
    // Checked after the signature, so an unsigned frame cannot probe which
    // versions are applied.
    if (_mappings.snapshot()->version(update->vni) == update->map_version) {
        ++_counters.map_redelivered;
        return oar::Status::ok;
    }
    if (!_mappings.apply(to_map_update(*update))) {
        ++_counters.map_rejected;
        return oar::Status::failed;
    }
    // The proxy follows the mapping. Its answers resolve each address
    // through the current snapshot, so the moment between the two calls
    // cannot answer for a NIC the new mapping dropped. If the addresses are
    // refused (decode makes that unreachable), fail closed: no proxy answers
    // for the VNI rather than stale ones.
    if (!_vswitch->set_neighbors(to_neighbors(*update))) {
        static_cast<void>(_vswitch->set_neighbors({.vni = update->vni, .ipv4 = {}, .ipv6 = {}}));
        ++_counters.map_neighbors_rejected;
        return oar::Status::failed;
    }
    ++_counters.map_applied;
    return oar::Status::ok;
}

auto NetRole::health() -> std::expected<oar::Health, oar::Status> {
    const auto up = std::chrono::duration_cast<std::chrono::seconds>(_config.clock() - _started);
    const auto secs = static_cast<std::uint64_t>(std::max<std::int64_t>(0, up.count()));
    const auto peers = _vtep->peers();
    const bool any_down =
        std::ranges::any_of(peers, [](const PeerStatus& p) { return p.state == PeerState::down; });
    return oar::Health{.state = any_down ? oar::HealthState::degraded : oar::HealthState::ok,
                       .fault_code = 0,
                       .uptime_seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                           secs, std::numeric_limits<std::uint32_t>::max()))};
}

auto NetRole::poll() -> bool {
    bool more = false;
    for (auto& s : _slots) {
        more = s.function->pci().poll() || more;
    }
    return more;
}

auto NetRole::tick(VtepClock::time_point now) -> VtepClock::time_point {
    return _vtep->tick(now);
}

}  // namespace ak::oar::net
