// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/helm_daemon.hpp"

#include <algorithm>
#include <utility>

namespace ak::helm {

namespace {

auto sequencer_config(const DaemonConfig& config) -> SequencerConfig {
    auto seq = config.sequencer;
    seq.slots.clear();
    for (const auto& s : config.slots) {
        seq.slots.push_back(s.slot);
    }
    return seq;
}

auto disconnected() -> std::unexpected<LinkError> {
    return std::unexpected(LinkError{.code = LinkErrc::disconnected});
}

[[nodiscard]] auto nonzero(const oar::Vtep& v) -> bool {
    return std::ranges::any_of(v, [](std::byte b) { return b != std::byte{0}; });
}

// The reports a hold role may send.
[[nodiscard]] auto hold_kind(const proto::ReportBody& body) -> bool {
    return std::holds_alternative<proto::ReplicaStatus>(body) ||
           std::holds_alternative<proto::VolumeFault>(body) ||
           std::holds_alternative<proto::DemotionConfirmed>(body) ||
           std::holds_alternative<proto::OpOutcome>(body) ||
           std::holds_alternative<proto::SnapshotProgress>(body);
}

// Reports taken from one role per pass, so a chatty role cannot hold the loop.
constexpr std::size_t max_reports_per_pass = 64;

}  // namespace

// ---- SlotPort ---------------------------------------------------------------

auto HelmDaemon::SlotPort::prepare_function(const oar::PrepareFunction& request)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->prepare_function(request);
}

auto HelmDaemon::SlotPort::clean_function(const oar::CleanFunction& request)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->clean_function(request);
}

auto HelmDaemon::SlotPort::deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                                       std::optional<ScopedKey> image_key)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();  // the keys are wiped as they go out of scope
    }
    return _slot->link->deliver_key(fn, volume, std::move(key), std::move(image_key));
}

auto HelmDaemon::SlotPort::drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->drop_key(request);
}

auto HelmDaemon::SlotPort::create_volume(const oar::CreateVolume& request)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->create_volume(request);
}

auto HelmDaemon::SlotPort::delete_volume(const oar::DeleteVolume& request)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->delete_volume(request);
}

auto HelmDaemon::SlotPort::rewrap_volume(const oar::RewrapVolume& request)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->rewrap_volume(request);
}

auto HelmDaemon::SlotPort::replica_config(std::span<const std::byte> frame)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();
    }
    return _slot->link->replica_config(frame);
}

// ---- HelmDaemon ---------------------------------------------------------------

HelmDaemon::HelmDaemon(DaemonConfig config, KeyStore& keys, AuditLog& audit, HostPort& host,
                       Backplane& backplane, SidebandConnector connect, ReportOut reports)
    : _config{std::move(config)},
      _keys{&keys},
      _connect{std::move(connect)},
      _reports{std::move(reports)},
      _router{_config.router, _pool, keys, host, *this, audit},
      _sequencer{sequencer_config(_config), backplane, *this} {
    for (const auto& s : _config.slots) {
        _slots.try_emplace(s.slot, std::make_unique<SlotState>(s.slot, s.link));
    }
    _next_check = now() + _config.check_interval;
    _next_reports = now();
    _next_identity = now();
    _snapshot = _router.inventory();
}

HelmDaemon::~HelmDaemon() = default;

auto HelmDaemon::now() const -> Clock::time_point {
    return _config.clock ? _config.clock() : Clock::now();
}

auto HelmDaemon::boot() -> BootResult {
    auto result = _sequencer.boot();
    publish();
    return result;
}

auto HelmDaemon::run(const std::stop_token& stop) -> void {
    // Wake the loop promptly when stop is requested.
    const std::stop_callback wake{stop, [this] {
                                      const std::scoped_lock lock{_inbox_mutex};
                                      _inbox_ready.notify_all();
                                  }};
    while (!stop.stop_requested()) {
        run_once(_config.tick);
    }
}

auto HelmDaemon::run_once(std::chrono::milliseconds wait) -> void {
    std::vector<Item> items;
    {
        std::unique_lock lock{_inbox_mutex};
        if (_inbox.empty() && wait.count() > 0) {
            _inbox_ready.wait_for(lock, wait);
        }
        items.swap(_inbox);
    }
    for (auto& item : items) {
        handle(item);
    }
    _router.poll();
    if (now() >= _next_check) {
        check();
        _next_check = now() + _config.check_interval;
    }
    if (now() >= _next_reports) {
        take_hold_reports();
        _next_reports = now() + _config.report_interval;
    }
    if (now() >= _next_identity) {
        for (auto& [n, slot] : _slots) {
            poll_identity(*slot);
        }
        _next_identity = now() + _config.identity_interval;
    }
    publish();
}

auto HelmDaemon::shutdown() -> void {
    _sequencer.shutdown();
    for (auto& [n, slot] : _slots) {
        detach(*slot);
        slot->pending = false;
    }
    publish();
}

auto HelmDaemon::attached(SlotNumber slot) const -> bool {
    const auto it = _slots.find(slot);
    return it != _slots.end() && it->second->link != nullptr;
}

auto HelmDaemon::stats() const -> DaemonStats {
    const std::scoped_lock lock{_inbox_mutex};
    return _stats;
}

auto HelmDaemon::role_health(SlotNumber slot) const -> std::optional<oar::Health> {
    const auto it = _slots.find(slot);
    return it == _slots.end() ? std::nullopt : it->second->health;
}

// ---- inbound, any thread ------------------------------------------------------

auto HelmDaemon::enqueue(Item item) -> void {
    const std::scoped_lock lock{_inbox_mutex};
    if (_inbox.size() >= _config.max_inbox) {
        ++_stats.inbox_dropped;
        return;
    }
    _inbox.push_back(std::move(item));
    _inbox_ready.notify_one();
}

auto HelmDaemon::on_envelope(const proto::Envelope& envelope) -> void {
    enqueue(envelope);
}

auto HelmDaemon::on_map_update(const proto::MapUpdate& update, std::span<const std::byte> frame)
    -> void {
    enqueue(MapFrame{.vni = update.vni,
                     .map_version = update.map_version,
                     .frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::on_replica_config(const proto::ReplicaConfig& config,
                                   std::span<const std::byte> frame) -> void {
    enqueue(ConfigFrame{.volume_id = config.volume_id,
                        .epoch = config.epoch,
                        .frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::on_volume_op(const proto::VolumeOp& /*op*/, std::span<const std::byte> frame)
    -> void {
    enqueue(OpFrame{.frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::on_lease_grant(const proto::LeaseGrant& grant) -> void {
    enqueue(grant);
}

auto HelmDaemon::on_role_certificate(const proto::RoleCertificate& certificate) -> void {
    enqueue(certificate);
}

auto HelmDaemon::on_volume_key(const proto::VolumeKey& /*key*/, std::span<const std::byte> frame)
    -> void {
    enqueue(KeyFrame{.frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::on_tunnel_peers(const proto::TunnelPeers& peers, std::span<const std::byte> frame)
    -> void {
    enqueue(PeersFrame{.peers = peers, .frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::on_image_key(const proto::ImageKey& /*key*/, std::span<const std::byte> frame)
    -> void {
    enqueue(ImageKeyFrame{.frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::on_vpc_config(const proto::VpcConfigFrame& config,
                               std::span<const std::byte> frame) -> void {
    enqueue(VpcFrame{.vni = config.vni,
                     .config_version = config.config_version,
                     .frame = {frame.begin(), frame.end()}});
}

auto HelmDaemon::post_host_slot(const mailbox::Slot& slot) -> void {
    enqueue(slot);
}

auto HelmDaemon::inventory() const -> proto::Inventory {
    const std::scoped_lock lock{_snapshot_mutex};
    return _snapshot;
}

// ---- loop thread --------------------------------------------------------------

auto HelmDaemon::handle(Item& item) -> void {
    if (const auto* env = std::get_if<proto::Envelope>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.envelopes;
        }
        _router.on_envelope(*env);
    } else if (auto* map = std::get_if<MapFrame>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.map_updates;
        }
        apply_map(*map);
    } else if (const auto* slot = std::get_if<mailbox::Slot>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.host_slots;
        }
        _router.on_host_slot(*slot);
    } else if (auto* config = std::get_if<ConfigFrame>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.replica_configs;
        }
        forward_config(*config);
    } else if (const auto* op = std::get_if<OpFrame>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.volume_ops;
        }
        forward_op(*op);
    } else if (const auto* grant = std::get_if<proto::LeaseGrant>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.lease_grants;
        }
        forward_grant(*grant);
    } else if (const auto* key = std::get_if<KeyFrame>(&item)) {
        // Opened in the secure element and kept wrapped, per attachment,
        // for the attach that delivers it (KeyStore).
        const auto kept = _keys->put_attachment_key(key->frame);
        const std::scoped_lock lock{_inbox_mutex};
        ++(kept ? _stats.volume_keys : _stats.volume_keys_refused);
    } else if (const auto* image = std::get_if<ImageKeyFrame>(&item)) {
        // Opened in the secure element and kept wrapped until the
        // CREATE_VOLUME of the image volume it names (KeyStore).
        const auto kept = _keys->put_image_key(image->frame);
        const std::scoped_lock lock{_inbox_mutex};
        ++(kept ? _stats.image_keys : _stats.image_keys_refused);
    } else if (const auto* cert = std::get_if<proto::RoleCertificate>(&item)) {
        deliver_certificate(*cert);
    } else if (const auto* peers = std::get_if<PeersFrame>(&item)) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.tunnel_peer_sets;
        }
        forward_peers(*peers);
    } else if (auto* vpc = std::get_if<VpcFrame>(&item)) {
        forward_vpc_config(*vpc);
    }
}

// ---- VPC configuration ----------------------------------------------------------

auto HelmDaemon::is_net_role(const SlotState& slot) -> bool {
    return slot.link && slot.inventory && slot.inventory->role == oar::Role::net;
}

auto HelmDaemon::count_vpc_refusal(const std::expected<void, LinkError>& r) -> void {
    if (!r) {
        const std::scoped_lock lock{_inbox_mutex};
        ++_stats.vpc_configs_refused;
    }
}

auto HelmDaemon::forward_vpc_config(VpcFrame& config) -> void {
    const auto kept = _vpc_configs.find(config.vni);
    if (kept != _vpc_configs.end() && config.config_version <= kept->second.config_version) {
        const std::scoped_lock lock{_inbox_mutex};
        ++_stats.vpc_configs_stale;
        return;
    }
    {
        const std::scoped_lock lock{_inbox_mutex};
        ++_stats.vpc_configs;
    }
    auto& frame = _vpc_configs.insert_or_assign(config.vni, std::move(config)).first->second;
    for (auto& [n, slot] : _slots) {
        if (is_net_role(*slot)) {
            count_vpc_refusal(slot->link->vpc_config(frame.frame));
        }
    }
}

auto HelmDaemon::replay_vpc_configs(SlotState& slot) -> void {
    if (!is_net_role(slot)) {
        return;
    }
    for (const auto& [vni, config] : _vpc_configs) {
        count_vpc_refusal(slot.link->vpc_config(config.frame));
    }
}

// ---- tunnel keys and network health -------------------------------------------

auto HelmDaemon::is_net(const SlotState& slot) -> bool {
    return slot.link && slot.inventory && slot.inventory->role == oar::Role::net &&
           nonzero(slot.inventory->vtep);
}

auto HelmDaemon::provision_tunnel(SlotState& slot) -> void {
    slot.keys_pending = false;
    if (!is_net(slot)) {
        return;
    }
    const auto& vtep = slot.inventory->vtep;
    std::expected<void, LinkError> done = std::unexpected(LinkError{.code = LinkErrc::bad_request});
    if (_keyring.ensure(vtep)) {  // fails only if OpenSSL cannot make a key pair
        done = _keyring.provision(*slot.link, vtep);
    }
    if (!done && done.error().code == LinkErrc::refused &&
        done.error().status == oar::Status::unsupported) {
        // A role run without a tunnel (ak-oar-net --tunnel-overhead 0): it
        // has no use for a key, and the inventory must not offer one.
        static_cast<void>(_keyring.forget(vtep));
        return;
    }
    slot.keys_pending = !done;
    const std::scoped_lock lock{_inbox_mutex};
    ++(done ? _stats.tunnel_provisioned : _stats.tunnel_provision_failed);
}

auto HelmDaemon::forward_peers(const PeersFrame& peers) -> void {
    // Kept even with no role for the VTEP attached yet: provision() hands
    // it over when the role's sideband opens.
    bool forwarded = false;
    bool refused = false;
    if (_keyring.store_peers(peers.peers, peers.frame) == PeersOutcome::stored) {
        for (auto& [n, slot] : _slots) {
            if (!is_net(*slot) || slot->keys_pending ||
                !std::ranges::equal(slot->inventory->vtep, peers.peers.vtep)) {
                continue;  // a role still waiting for its key gets the set with it
            }
            if (slot->link->tunnel_peers(peers.frame)) {
                forwarded = true;
            } else {
                refused = true;
            }
        }
    }
    const std::scoped_lock lock{_inbox_mutex};
    if (refused) {
        ++_stats.tunnel_peer_sets_refused;
    } else if (forwarded) {
        ++_stats.tunnel_peer_sets_forwarded;
    } else {
        ++_stats.tunnel_peer_sets_held;
    }
}

auto HelmDaemon::poll_health(SlotState& slot) -> void {
    if (!is_net(slot)) {
        slot.health.reset();
        return;
    }
    auto h = slot.link->health();
    if (h) {
        slot.health = *h;
    }
    // A failed request leaves the last answer: the sequencer, not this
    // poll, decides when a board is lost.
}

// ---- enrollment ---------------------------------------------------------------

auto HelmDaemon::is_storage(const SlotState& slot) -> bool {
    return is_blk(slot) || is_hold(slot);
}

auto HelmDaemon::poll_identity(SlotState& slot) -> void {
    if (!is_storage(slot)) {
        return;
    }
    auto asked = slot.link->cert_request();
    if (!asked || asked->csr.empty() || asked->role != slot.inventory->role) {
        return;  // unsupported, nothing wanted, or a role that changed its story
    }
    if (asked->csr == slot.reported_csr && now() < slot.reported_at + _config.identity_retry) {
        return;  // already with the controller
    }
    proto::CertRequest request{.slot = slot.number,
                               .role = asked->role == oar::Role::hold
                                           ? proto::StorageRole::hold
                                           : proto::StorageRole::initiator,
                               .csr = std::move(asked->csr)};
    if (!proto::detail::check_body(request)) {
        return;  // not a DER request: the controller would refuse the report
    }
    slot.reported_csr = request.csr;
    slot.reported_at = now();
    {
        const std::scoped_lock lock{_inbox_mutex};
        ++_stats.cert_requests;
    }
    report(std::move(request));
}

auto HelmDaemon::deliver_certificate(const proto::RoleCertificate& certificate) -> void {
    auto* slot = slot_state(certificate.slot);
    const bool taken =
        slot != nullptr && is_storage(*slot) && slot->link->role_certificate(certificate.chain);
    if (taken) {
        slot->reported_csr.clear();  // a later request is a renewal: report it
    }
    const std::scoped_lock lock{_inbox_mutex};
    ++(taken ? _stats.role_certificates : _stats.role_certificates_refused);
}

// ---- block volumes ------------------------------------------------------------

auto HelmDaemon::is_hold(const SlotState& slot) -> bool {
    return slot.link && slot.inventory && slot.inventory->role == oar::Role::hold;
}

auto HelmDaemon::count_refusal(const std::expected<void, LinkError>& r) -> void {
    if (!r) {
        const std::scoped_lock lock{_inbox_mutex};
        ++_stats.hold_refused;
    }
}

auto HelmDaemon::forward_config(ConfigFrame& config) -> void {
    // The roles refuse an older epoch themselves; keeping only the newest
    // bounds the replay.
    auto [it, added] = _volume_configs.try_emplace(config.volume_id);
    if (!added && it->second.epoch > config.epoch) {
        return;
    }
    it->second = std::move(config);
    // A network volume attached (or attachable) here goes to the storage
    // roles too, so a live attachment follows its epochs.
    const bool attached_here = _router.on_replica_config(it->second.frame);
    for (auto& [n, slot] : _slots) {
        if (is_hold(*slot)) {
            count_refusal(slot->link->replica_config(it->second.frame));
        } else if (attached_here && is_blk(*slot)) {
            count_blk_refusal(slot->link->replica_config(it->second.frame));
        }
    }
}

auto HelmDaemon::is_blk(const SlotState& slot) -> bool {
    return slot.link && slot.inventory && slot.inventory->role == oar::Role::blk;
}

auto HelmDaemon::count_blk_refusal(const std::expected<void, LinkError>& r) -> void {
    if (!r) {
        const std::scoped_lock lock{_inbox_mutex};
        ++_stats.blk_configs_refused;
    }
}

auto HelmDaemon::forward_op(const OpFrame& op) -> void {
    for (auto& [n, slot] : _slots) {
        if (is_hold(*slot)) {
            count_refusal(slot->link->volume_op(op.frame));
        }
    }
}

auto HelmDaemon::forward_grant(const proto::LeaseGrant& grant) -> void {
    for (auto& [n, slot] : _slots) {
        if (is_hold(*slot)) {
            count_refusal(
                slot->link->lease_grant({.volume_id = grant.volume_id, .epoch = grant.epoch}));
        }
    }
}

auto HelmDaemon::replay_configs(SlotState& slot) -> void {
    if (!is_hold(slot)) {
        return;
    }
    for (const auto& [volume, config] : _volume_configs) {
        count_refusal(slot.link->replica_config(config.frame));
    }
}

auto HelmDaemon::take_hold_reports() -> void {
    for (auto& [n, slot] : _slots) {
        if (!is_hold(*slot)) {
            continue;
        }
        auto taken = slot->link->hold_reports(max_reports_per_pass);
        if (!taken) {
            continue;  // tried again next pass; the role keeps them
        }
        for (const auto& bytes : *taken) {
            auto rep = proto::decode_report(bytes);
            if (!rep || !hold_kind(rep->body)) {
                const std::scoped_lock lock{_inbox_mutex};
                ++_stats.hold_reports_dropped;
                continue;
            }
            {
                const std::scoped_lock lock{_inbox_mutex};
                ++_stats.hold_reports;
            }
            report(std::move(rep->body));  // renumbered by the controller session
        }
    }
}

auto HelmDaemon::apply_map(MapFrame& map) -> void {
    bool any = false;
    bool all_ok = true;
    for (auto& [n, slot] : _slots) {
        if (!slot->link || !slot->inventory || slot->inventory->role != oar::Role::net) {
            continue;
        }
        any = true;
        if (!slot->link->map_update(map.frame)) {
            all_ok = false;
        }
    }
    const bool applied = any && all_ok;
    {
        const std::scoped_lock lock{_inbox_mutex};
        ++(applied ? _stats.maps_applied : _stats.maps_refused);
    }
    if (applied) {
        _router.on_map_applied(map.vni, map.map_version);
    }
}

auto HelmDaemon::report(proto::ReportBody body) -> void {
    if (_reports) {
        _reports(std::move(body));
    }
}

auto HelmDaemon::slot_state(SlotNumber slot) -> SlotState* {
    const auto it = _slots.find(slot);
    return it == _slots.end() ? nullptr : it->second.get();
}

auto HelmDaemon::attach(SlotState& slot) -> bool {
    detach(slot);
    auto binding = _connect ? _connect(slot.number) : std::unexpected(BindingError::disconnected);
    std::expected<oar::Inventory, LinkError> inv = std::unexpected(LinkError{});
    if (binding) {
        slot.binding = std::move(*binding);
        slot.link = std::make_unique<OarLink>(*slot.binding, slot.config);
        inv = slot.link->function_inventory();
    }
    if (!inv) {
        detach(slot);
        // Reported once per failure streak, retried on every check.
        if (!slot.pending) {
            report(proto::HostFaultReport{
                .code = proto::FaultCode::device_lost, .slot = slot.number, .detail = 0});
        }
        slot.pending = true;
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.sideband_failures;
        }
        return false;
    }
    slot.pending = false;
    slot.inventory = *inv;
    slot.reported_csr.clear();  // a restarted role's request is reported afresh
    slot.health.reset();
    provision_tunnel(slot);  // network roles: before any NIC is prepared on it
    poll_identity(slot);
    if (inv->role == oar::Role::hold) {
        replay_configs(slot);  // a hold role has no functions for the router
        return true;
    }
    replay_vpc_configs(slot);  // before the router can prepare a NIC here
    _router.add_slot(slot.number, slot.port, *inv);
    if (is_blk(slot)) {
        for (const auto frame : _router.network_configs()) {
            count_blk_refusal(slot.link->replica_config(frame));
        }
    }
    return true;
}

auto HelmDaemon::detach(SlotState& slot) noexcept -> void {
    slot.link.reset();
    slot.binding.reset();
    slot.keys_pending = false;
    slot.health.reset();
}

auto HelmDaemon::on_slot_ready(SlotNumber slot) -> void {
    if (auto* state = slot_state(slot)) {
        (void)attach(*state);
    }
}

auto HelmDaemon::on_slot_recovered(SlotNumber slot) -> void {
    auto* state = slot_state(slot);
    if (state == nullptr) {
        return;
    }
    // The role restarted: its old sideband is gone. Functions the router
    // already knows keep their state; slot_power_cycled cleans the faulted
    // ones once the sideband is back.
    if (attach(*state)) {
        _router.slot_power_cycled(slot);
    }
}

auto HelmDaemon::on_slot_faulted(SlotNumber slot) -> void {
    auto* state = slot_state(slot);
    if (state == nullptr) {
        return;
    }
    detach(*state);
    state->pending = false;  // powered off: nothing to retry until it recovers
    report(
        proto::HostFaultReport{.code = proto::FaultCode::device_lost, .slot = slot, .detail = 0});
}

auto HelmDaemon::check() -> void {
    _sequencer.check();
    for (auto& [n, slot] : _slots) {
        // A slot attached late may hold functions that faulted while its
        // sideband was unreachable; clean them now that it answers.
        if (slot->pending && _sequencer.health(n) == SlotHealth::ready && attach(*slot)) {
            _router.slot_power_cycled(n);
        }
        if (slot->keys_pending) {
            provision_tunnel(*slot);
        }
        poll_health(*slot);
    }
}

auto HelmDaemon::publish() -> void {
    auto inv = _router.inventory();
    for (const auto& [n, slot] : _slots) {
        if (is_net(*slot)) {
            proto::VtepAddress v{};
            std::ranges::copy(slot->inventory->vtep, v.begin());
            if (std::ranges::find(inv.vteps, v) == inv.vteps.end()) {
                inv.vteps.push_back(v);
            }
            // A network role that cannot carry traffic as planned degrades
            // the host; the router's own verdict (faulted functions) stands
            // if it is worse.
            if (slot->health && slot->health->state != oar::HealthState::ok &&
                inv.health == proto::Health::ok) {
                inv.health = proto::Health::degraded;
            }
        }
    }
    _keyring.fill(inv);
    bool changed = false;
    {
        const std::scoped_lock lock{_snapshot_mutex};
        changed = inv.vteps != _snapshot.vteps || inv.tunnels != _snapshot.tunnels ||
                  inv.health != _snapshot.health;
        _snapshot = inv;
    }
    if (changed) {
        {
            const std::scoped_lock lock{_inbox_mutex};
            ++_stats.inventory_reports;
        }
        report(std::move(inv));
    }
}

}  // namespace ak::helm
