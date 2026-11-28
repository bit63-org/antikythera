// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/net_role.hpp"

#include <algorithm>
#include <format>
#include <limits>
#include <utility>
#include <variant>

#include <poll.h>
#include <unistd.h>

#include "proto/group_members.hpp"
#include "proto/group_policy.hpp"
#include "proto/map_update.hpp"
#include "proto/vpc_config.hpp"

namespace ak::oar::net {

namespace {

namespace oar = helm::oar;

// Placeholder NIC IDs: a block at the top of the space, below the broadcast
// ID, one per function number. The controller allocates NIC IDs from the
// bottom, and a placeholder is never connected anyway; the range only keeps
// the IDs valid and distinct.
constexpr std::uint64_t placeholder_nic_base = 0xFFFF'FFFE'0000'0000;
// Metadata packets read from the TUN per poll().
constexpr std::size_t metadata_budget = 64;

constexpr std::byte placeholder_mac_head{0x02};  // locally administered unicast
constexpr std::byte placeholder_mac_fill{0xFF};
constexpr unsigned byte_bits = 8;
constexpr std::size_t mac_fn_high = 4;
constexpr std::size_t mac_fn_low = 5;

// The VSwitch's config from a decoded VpcConfig version 2 frame.
// decode_vpc_config already checked every value; the VSwitch checks the
// result again.
auto to_vpc_config(const proto::VpcConfigFrame& f) -> VpcConfig {
    VpcConfig c{.gateway_mac = f.gateway_mac,
                .ipv4_blocks = {},
                .ipv6_block = f.ipv6_block,
                .subnets = {},
                .dns4 = f.dns4,
                .dns6 = f.dns6,
                .domain = f.domain,
                .lease_seconds = f.lease_seconds,
                .tables = {}};
    for (const auto& b : f.ipv4_blocks) {
        c.ipv4_blocks.push_back({.address = b.prefix, .length = b.length});
    }
    for (const auto& s : f.subnets) {
        c.subnets.push_back({.id = s.subnet_id,
                             .ipv4 = {.address = s.ipv4_prefix, .length = s.ipv4_length},
                             .gateway = proto::vpc_subnet_gateway(s),
                             .ipv6_prefix = s.ipv6_prefix,
                             .table = s.table});
    }
    for (const auto& t : f.tables) {
        VpcRouteTable& table = c.tables.emplace_back();
        table.table = t.table;
        table.main = t.main;
        for (const auto& r : t.routes) {
            const bool local = r.kind == proto::RouteKind::local;
            table.routes.push_back(
                {.ipv6 = r.family == proto::RouteFamily::ipv6,
                 .prefix = r.prefix,
                 .length = r.length,
                 .target = local ? geneve::nic_invalid : geneve::NicId{r.target_nic},
                 .local = local});
        }
    }
    return c;
}

auto to_map_update(const proto::MapUpdate& u) -> MapUpdate {
    MapUpdate out{.vni = u.vni, .version = u.map_version, .entries = {}};
    out.entries.reserve(u.entries.size());
    for (const auto& e : u.entries) {
        out.entries.push_back({.nic_id = geneve::NicId{e.nic_id},
                               .mac = e.mac,
                               .owner_vtep = e.owner_vtep,
                               .source_dest_check = e.source_dest_check,
                               .subnet_id = e.subnet_id});
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

static_assert(proto::max_group_groups_per_nic == group_max_groups_per_nic_max);

// The VSwitch's policy from a decoded frame. decode_group_policy already
// checked the mode and limits against the same bounds; the VSwitch checks
// them again.
auto to_group_policy(const proto::GroupPolicy& p) -> GroupPolicy {
    return {.mode = p.mode == proto::GroupMode::multicast ? GroupMode::multicast : GroupMode::drop,
            .rate_frames = p.rate_frames,
            .burst_frames = p.burst_frames,
            .rate_bytes = p.rate_bytes,
            .burst_bytes = p.burst_bytes,
            .max_remote_vteps = p.max_remote_vteps,
            .max_groups_per_nic = p.max_groups_per_nic};
}

// A version 2 frame's per-subnet policies (vpc-subnets-routing task 12).
auto to_subnet_policies(const proto::GroupPolicy& p) -> std::vector<SubnetGroupPolicy> {
    std::vector<SubnetGroupPolicy> out;
    out.reserve(p.subnets.size());
    for (const proto::GroupSubnetLimits& s : p.subnets) {
        out.push_back({.subnet = s.subnet_id,
                       .policy = {.mode = GroupMode::multicast,
                                  .rate_frames = s.rate_frames,
                                  .burst_frames = s.burst_frames,
                                  .rate_bytes = s.rate_bytes,
                                  .burst_bytes = s.burst_bytes,
                                  .max_remote_vteps = s.max_remote_vteps,
                                  .max_groups_per_nic = s.max_groups_per_nic}});
    }
    return out;
}

// The VSwitch's lists from a decoded frame.
auto to_group_members(const proto::GroupMembers& m) -> GroupMembers {
    GroupMembers out;
    for (const auto& g : m.groups) {
        out.emplace(igmp::Group{.ipv6 = g.family == proto::RouteFamily::ipv6, .address = g.group},
                    g.vteps);
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
    if (config.tunnel && config.mtu.tunnel_overhead < wireguard_overhead) {
        return std::unexpected(
            std::format("MTU plan reserves {} bytes for the tunnel, WireGuard needs {}",
                        config.mtu.tunnel_overhead, wireguard_overhead));
    }
    if (config.mtu_grace < std::chrono::milliseconds::zero()) {
        return std::unexpected("negative MTU grace");
    }
    if (config.mtu_grace == std::chrono::milliseconds::zero()) {
        config.mtu_grace = 2 * config.vtep_config.probe_interval;
    }
    if (!config.clock) {
        config.clock = [] { return NetRoleConfig::Clock::now(); };
    }
    config.vtep_config.max_payload = config.mtu.max_geneve_payload;

    std::unique_ptr<NetRole> role{new NetRole{std::move(config), std::move(verifier)}};
    DatagramSender* underlay = &sender;
    if (role->_config.tunnel) {
        auto tc = *role->_config.tunnel;
        tc.peer_port = role->_config.vtep_config.peer_port;
        auto tunnel = Tunnel::create(sender, std::move(tc));
        if (!tunnel) {
            return std::unexpected(std::format("tunnel: {}", to_string(tunnel.error())));
        }
        role->_tunnel = std::move(*tunnel);
        // The same controller keys sign MapUpdates and TunnelPeers frames.
        role->_peer_set = std::make_unique<TunnelPeerSet>(*role->_tunnel, role->_config.server_id,
                                                          role->_config.vtep, role->_verifier);
        underlay = role->_tunnel.get();
    }
    auto vtep = Vtep::create(role->_mappings, *underlay, observer, role->_config.vtep_config);
    if (!vtep) {
        return std::unexpected(std::format("vtep: {}", to_string(vtep.error())));
    }
    role->_vtep = std::move(*vtep);
    role->_vswitch = std::make_unique<VSwitch>(role->_mappings, *role->_vtep);
    role->_started = role->_config.clock();
    role->_slots.resize(transports.size());
    // One record per NIC the role can host; the same controller keys sign
    // MapUpdates and InstanceMetadata frames.
    role->_metadata = std::make_unique<MetadataStore>(role->_config.server_id, transports.size(),
                                                      role->_verifier);
    if (role->_config.metadata) {
        if (auto r = role->start_metadata(); !r) {
            return std::unexpected(std::format("metadata: {}", r.error()));
        }
    }
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
    _nic_vnis.insert_or_assign(cfg->nic_id, cfg->vni);
    return oar::Status::ok;
}

auto NetRole::start_metadata() -> std::expected<void, std::string> {
    const auto plumbing = *_config.metadata;
    _config.metadata->tun_fd = -1;  // owned below, or closed on failure
    _config.metadata->listen_fd = -1;
    auto key = TokenKey::generate();
    if (!key || plumbing.tun_fd < 0) {
        if (plumbing.tun_fd >= 0) {
            ::close(plumbing.tun_fd);
        }
        if (plumbing.listen_fd >= 0) {
            ::close(plumbing.listen_fd);
        }
        return std::unexpected(key ? "no TUN" : "token key: RNG failed");
    }
    _aliases = std::make_unique<AliasTable>();
    _md_server = std::make_unique<MetadataServer>(
        std::move(*key), [this](std::uint64_t nic) { return metadata_view(nic); });
    if (plumbing.listen_fd >= 0) {
        _md_server->listen(plumbing.listen_fd,
                           [this](const sockaddr_storage& peer, socklen_t length) {
                               return resolve_peer(*_aliases, peer, length);
                           });
    }
    _md_tap = std::make_unique<MetadataTap>(
        plumbing.tun_fd, *_aliases,
        [this](geneve::NicId nic) {
            const auto* r = _metadata->find(nic.value);
            return r != nullptr && r->http_endpoint == proto::MetadataEndpoint::enabled;
        },
        [this](geneve::NicId nic, std::span<const std::byte> packet) {
            return _vswitch->inject_metadata(nic, packet);
        },
        _config.clock);
    _vswitch->set_metadata_endpoint(_md_tap.get());
    return {};
}

auto NetRole::metadata_view(std::uint64_t nic_id) const -> MetadataView {
    MetadataView view;
    view.record = _metadata->find(nic_id);
    if (view.record == nullptr) {
        return view;
    }
    const geneve::NicId nic{nic_id};
    const auto binding = _mappings.snapshot()->lookup(nic);
    if (!binding) {
        return view;
    }
    view.network.mac = binding->mac;
    auto [ipv4, ipv6] = _vswitch->nic_addresses(binding->vni, nic);
    if (const VpcConfig* cfg = _vswitch->vpc_config(binding->vni); cfg != nullptr) {
        for (const auto& b : cfg->ipv4_blocks) {
            view.network.vpc4.push_back({.address = b.address, .length = b.length});
        }
        view.network.vpc6 = cfg->ipv6_block;
        if (const VpcSubnet* subnet = find_subnet(*cfg, binding->subnet_id); subnet != nullptr) {
            view.network.subnet_id = subnet->id;
            view.network.subnet4 = subnet->ipv4.address;
            view.network.subnet4_length = subnet->ipv4.length;
            view.network.subnet6 = subnet->ipv6_prefix;
            // local-ipv4 is the address DHCP hands out: the lowest in the
            // subnet (the table holds only addresses inside it).
            const auto inside = std::ranges::find_if(
                ipv4, [&](const neighbor::Ipv4Address& a) { return in_prefix(subnet->ipv4, a); });
            if (inside != ipv4.end()) {
                std::rotate(ipv4.begin(), inside, inside + 1);
            }
        }
    }
    view.network.ipv4 = std::move(ipv4);
    view.network.ipv6 = std::move(ipv6);
    return view;
}

auto NetRole::metadata_poll_fds(std::vector<pollfd>& out) const -> void {
    if (_md_tap) {
        out.push_back({.fd = _md_tap->fd(), .events = POLLIN, .revents = 0});
        _md_server->append_poll_fds(out);
    }
}

auto NetRole::release(oar::FunctionNumber fn, Slot& s) -> bool {
    if (s.nic) {
        static_cast<void>(_vswitch->detach(*s.nic));
        static_cast<void>(_metadata->drop(s.nic->value));
        if (_md_server) {
            _md_server->reset_nic(s.nic->value);
            _aliases->release(*s.nic, _config.clock());
        }
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

auto NetRole::vpc_config(std::span<const std::byte> frame) -> oar::Status {
    auto config = proto::decode_vpc_config(frame);
    if (!config) {
        ++_counters.vpc_undecodable;
        return oar::Status::failed;
    }
    if (config->server_id != _config.server_id) {
        ++_counters.vpc_wrong_server;
        return oar::Status::failed;
    }
    if (!_verifier(proto::vpc_config_signed_bytes(frame), config->signature, config->key_id)) {
        ++_counters.vpc_bad_signature;
        return oar::Status::failed;
    }
    // Versions are looked at only after the signature, as for map_update.
    const auto applied = _vpc_versions.find(config->vni);
    if (applied != _vpc_versions.end()) {
        if (applied->second == config->config_version) {
            ++_counters.vpc_redelivered;
            return oar::Status::ok;
        }
        if (applied->second > config->config_version) {
            ++_counters.vpc_stale;
            return oar::Status::failed;
        }
    }
    if (!_vswitch->set_vpc_config(config->vni, to_vpc_config(*config))) {
        ++_counters.vpc_rejected;
        return oar::Status::failed;
    }
    _vpc_versions.insert_or_assign(config->vni, config->config_version);
    ++_counters.vpc_applied;
    // The subnets decide which guest addresses count (Requirement 2.6).
    if (!refresh_neighbors(config->vni)) {
        ++_counters.map_neighbors_rejected;
    }
    return oar::Status::ok;
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
    // cannot answer for a NIC the new mapping dropped.
    _guest_addresses.insert_or_assign(update->vni, to_neighbors(*update));
    if (!refresh_neighbors(update->vni)) {
        ++_counters.map_neighbors_rejected;
        return oar::Status::failed;
    }
    ++_counters.map_applied;
    return oar::Status::ok;
}

auto NetRole::refresh_neighbors(std::uint32_t vni) -> bool {
    const auto it = _guest_addresses.find(vni);
    if (it == _guest_addresses.end()) {
        return true;  // no map_update yet: nothing to filter
    }
    const NeighborUpdate& all = it->second;
    const VpcConfig* const cfg = _vswitch->vpc_config(vni);
    NeighborUpdate next{.vni = vni, .ipv4 = {}, .ipv6 = {}};
    if (cfg == nullptr) {
        next = all;  // one L2 segment: every address counts
    } else {
        const auto snap = _mappings.snapshot();
        const auto subnet_of = [&](geneve::NicId nic) -> const VpcSubnet* {
            const auto binding = snap->lookup(nic);
            return binding ? find_subnet(*cfg, binding->subnet_id) : nullptr;
        };
        for (const auto& n : all.ipv4) {
            const VpcSubnet* const s = subnet_of(n.nic);
            if (s != nullptr && in_prefix(s->ipv4, n.ip)) {
                next.ipv4.push_back(n);
            } else {
                ++_counters.map_addr_outside_subnet;
            }
        }
        for (const auto& n : all.ipv6) {
            const VpcSubnet* const s = subnet_of(n.nic);
            if (s != nullptr && s->ipv6_prefix && in_prefix64(*s->ipv6_prefix, n.ip)) {
                next.ipv6.push_back(n);
            } else {
                ++_counters.map_addr_outside_subnet;
            }
        }
    }
    // Fail closed if refused (decode makes that unreachable): no proxy
    // answers or source matches for the VNI rather than stale ones.
    if (!_vswitch->set_neighbors(next)) {
        static_cast<void>(_vswitch->set_neighbors({.vni = vni, .ipv4 = {}, .ipv6 = {}}));
        return false;
    }
    return true;
}

auto NetRole::group_policy(std::span<const std::byte> frame) -> oar::Status {
    auto policy = proto::decode_group_policy(frame);
    if (!policy) {
        ++_counters.group_undecodable;
        return oar::Status::failed;
    }
    if (policy->server_id != _config.server_id) {
        ++_counters.group_wrong_server;
        return oar::Status::failed;
    }
    if (!_verifier(proto::group_policy_signed_bytes(frame), policy->signature, policy->key_id)) {
        ++_counters.group_bad_signature;
        return oar::Status::failed;
    }
    // Versions are looked at only after the signature, as for map_update.
    const auto applied = _group_versions.find(policy->vni);
    if (applied != _group_versions.end()) {
        if (applied->second == policy->policy_version) {
            ++_counters.group_redelivered;
            return oar::Status::ok;
        }
        if (applied->second > policy->policy_version) {
            ++_counters.group_stale;
            return oar::Status::failed;
        }
    }
    const bool set =
        policy->format == proto::group_policy_version_subnets
            ? _vswitch->set_subnet_group_policies(policy->vni, to_subnet_policies(*policy))
                  .has_value()
            : _vswitch->set_group_policy(policy->vni, to_group_policy(*policy)).has_value();
    if (!set) {
        ++_counters.group_rejected;
        return oar::Status::failed;
    }
    _group_versions.insert_or_assign(policy->vni, policy->policy_version);
    ++_counters.group_applied;
    return oar::Status::ok;
}

auto NetRole::usage_snapshot() -> oar::UsagePager::Snapshot {
    oar::UsagePager::Snapshot out;
    for (const auto& u : _vswitch->group_usage()) {
        const auto vni = _nic_vnis.find(u.nic.value);
        if (vni == _nic_vnis.end()) {
            ++_counters.usage_unknown_vni;  // unreachable: every attach goes through prepare
            continue;
        }
        out.push_back({.nic_id = u.nic.value,
                       .vni = vni->second,
                       .detached = u.detached,
                       .attachment = u.attachment,
                       .frames = u.meter.frames,
                       .bytes = u.meter.bytes,
                       .replicas_remote = u.meter.replicas_remote,
                       .replica_bytes_remote = u.meter.replica_bytes_remote,
                       .replicas_local = u.meter.replicas_local,
                       .replica_bytes_local = u.meter.replica_bytes_local,
                       .drop_policy = u.meter.drop_policy,
                       .drop_rate = u.meter.drop_rate,
                       .drop_fanout = u.meter.drop_fanout});
    }
    // Every final reading is in `out` now (the VSwitch hands each out once),
    // so the VNIs of NICs no longer attached are not needed again.
    std::erase_if(_nic_vnis,
                  [this](const auto& kv) { return !_vswitch->attached(geneve::NicId{kv.first}); });
    return out;
}

auto NetRole::group_usage(std::uint16_t cursor) -> std::expected<oar::UsagePage, oar::Status> {
    return _usage.page(cursor, [this] { return usage_snapshot(); });
}

auto NetRole::group_members(std::span<const std::byte> frame) -> oar::Status {
    auto members = proto::decode_group_members(frame);
    if (!members) {
        ++_counters.members_undecodable;
        return oar::Status::failed;
    }
    if (members->server_id != _config.server_id) {
        ++_counters.members_wrong_server;
        return oar::Status::failed;
    }
    if (!_verifier(proto::group_members_signed_bytes(frame), members->signature, members->key_id)) {
        ++_counters.members_bad_signature;
        return oar::Status::failed;
    }
    const auto applied = _members_versions.find(members->vni);
    if (applied != _members_versions.end()) {
        if (applied->second == members->members_version) {
            ++_counters.members_redelivered;
            return oar::Status::ok;
        }
        if (applied->second > members->members_version) {
            ++_counters.members_stale;
            return oar::Status::failed;
        }
    }
    if (!_vswitch->set_group_members(members->vni, to_group_members(*members))) {
        ++_counters.members_rejected;
        return oar::Status::failed;
    }
    _members_versions.insert_or_assign(members->vni, members->members_version);
    ++_counters.members_applied;
    return oar::Status::ok;
}

auto NetRole::instance_metadata(std::span<const std::byte> frame) -> oar::Status {
    return accepted(_metadata->put(frame)) ? oar::Status::ok : oar::Status::failed;
}

auto NetRole::group_membership(const oar::MembershipRequest& request)
    -> std::expected<oar::MembershipPage, oar::Status> {
    const auto generation = static_cast<std::uint32_t>(_vswitch->membership_changes());
    return _membership.page(request, generation, [this] {
        oar::MembershipPager::Snapshot out;
        for (const auto& m : _vswitch->memberships()) {
            out.push_back({.nic_id = m.nic.value,
                           .vni = m.vni,
                           .ipv6 = m.group.ipv6,
                           .group = m.group.address});
        }
        return out;
    });
}

auto NetRole::health() -> std::expected<oar::Health, oar::Status> {
    const auto up = std::chrono::duration_cast<std::chrono::seconds>(_config.clock() - _started);
    const auto secs = static_cast<std::uint64_t>(std::max<std::int64_t>(0, up.count()));
    const auto peers = _vtep->peers();
    std::uint16_t faults = 0;
    if (std::ranges::any_of(peers,
                            [](const PeerStatus& p) { return p.state == PeerState::down; })) {
        faults |= net_fault_peer_down;
    }
    // A peer counts while it is still up without mtu_ok and tick() has seen
    // it so for the whole grace; a probe that arrived since the last tick
    // clears it at once.
    if (std::ranges::any_of(peers, [this](const PeerStatus& p) {
            if (p.state != PeerState::up || p.mtu_ok) {
                return false;
            }
            const auto it = _mtu_unproven.find(p.vtep);
            return it != _mtu_unproven.end() && _last_tick - it->second >= _config.mtu_grace;
        })) {
        faults |= net_fault_mtu;
    }
    if (_tunnel && !_tunnel->public_key()) {
        faults |= net_fault_no_tunnel_key;
    }
    return oar::Health{.state = faults != 0 ? oar::HealthState::degraded : oar::HealthState::ok,
                       .fault_code = faults,
                       .uptime_seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                           secs, std::numeric_limits<std::uint32_t>::max()))};
}

auto NetRole::set_tunnel_key(const oar::SetTunnelKey& request) -> oar::Status {
    if (!_tunnel) {
        return oar::Status::unsupported;
    }
    // A grace makes it a rotation (fleet-scale-networking Requirement 1.3):
    // sessions under the old key run on until the grace ends.
    const auto done = request.grace_seconds != 0
                          ? _tunnel->rotate_private_key(request.private_key,
                                                        std::chrono::seconds{request.grace_seconds})
                          : _tunnel->set_private_key(request.private_key);
    if (!done) {
        ++_counters.tunnel_keys_refused;
        return oar::Status::failed;
    }
    return oar::Status::ok;
}

auto NetRole::set_tunnel_peer(const oar::SetTunnelPeer& request) -> oar::Status {
    if (!_tunnel) {
        return oar::Status::unsupported;
    }
    if (request.vtep == _config.vtep) {
        return oar::Status::bad_request;  // a VTEP is never its own peer
    }
    if (!_tunnel->set_peer(request.vtep, request.public_key, request.psk)) {
        ++_counters.tunnel_keys_refused;
        return oar::Status::failed;
    }
    return oar::Status::ok;
}

auto NetRole::remove_tunnel_peer(const oar::RemoveTunnelPeer& request) -> oar::Status {
    if (!_tunnel) {
        return oar::Status::unsupported;
    }
    return _tunnel->remove_peer(request.vtep) ? oar::Status::ok : oar::Status::failed;
}

auto NetRole::tunnel_peers(std::span<const std::byte> frame) -> oar::Status {
    if (!_peer_set) {
        return oar::Status::unsupported;
    }
    const auto r = _peer_set->apply(frame);
    if (accepted(r)) {
        return oar::Status::ok;
    }
    return r == PeersResult::unsupported ? oar::Status::unsupported : oar::Status::failed;
}

auto NetRole::receive(std::span<const std::byte> datagram, const Ipv6Address& outer_src,
                      VtepClock::time_point now) -> bool {
    Ipv6Address src = outer_src;
    if (_tunnel) {
        auto opened = _tunnel->receive(datagram, outer_src);
        if (!opened) {
            return false;  // a handshake message, a keepalive, or dropped and counted
        }
        datagram = opened->payload;
        src = opened->peer;
    }
    auto packet = _vtep->receive(datagram, src, now);
    if (!packet) {
        return false;
    }
    static_cast<void>(_vswitch->receive(*packet, src));
    return true;
}

auto NetRole::pump(UdpEndpoint& endpoint, std::span<std::byte> buffer, std::size_t budget,
                   VtepClock::time_point now) -> std::size_t {
    return _tunnel ? net::pump(endpoint, *_tunnel, *_vtep, *_vswitch, buffer, budget, now)
                   : net::pump(endpoint, *_vtep, *_vswitch, buffer, budget, now);
}

auto NetRole::poll() -> bool {
    bool more = false;
    for (auto& s : _slots) {
        more = s.function->pci().poll() || more;
    }
    if (_md_tap) {
        // The kernel's replies first, then the connections they feed.
        more = _md_tap->poll(metadata_budget) || more;
        _md_server->run_once(_config.clock(), std::chrono::milliseconds::zero());
    }
    return more;
}

auto NetRole::tick(VtepClock::time_point now) -> VtepClock::time_point {
    auto next = _vtep->tick(now);
    if (_tunnel) {
        next = std::min(next, _tunnel->tick());
    }
    track_mtu(now);
    return next;
}

auto NetRole::track_mtu(VtepClock::time_point now) -> void {
    _last_tick = now;
    std::map<Ipv6Address, VtepClock::time_point> unproven;
    for (const auto& p : _vtep->peers()) {
        if (p.state == PeerState::up && !p.mtu_ok) {
            const auto it = _mtu_unproven.find(p.vtep);
            unproven.emplace(p.vtep, it == _mtu_unproven.end() ? now : it->second);
        }
    }
    _mtu_unproven = std::move(unproven);
}

}  // namespace ak::oar::net
