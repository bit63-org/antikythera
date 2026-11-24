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

auto HelmDaemon::SlotPort::deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
    -> std::expected<void, LinkError> {
    if (!_slot->link) {
        return disconnected();  // `key` is wiped as it goes out of scope
    }
    return _slot->link->deliver_key(fn, volume, std::move(key));
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

auto HelmDaemon::on_volume_key(const proto::VolumeKey& /*key*/, std::span<const std::byte> frame)
    -> void {
    enqueue(KeyFrame{.frame = {frame.begin(), frame.end()}});
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
    }
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
    for (auto& [n, slot] : _slots) {
        if (is_hold(*slot)) {
            count_refusal(slot->link->replica_config(it->second.frame));
        }
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
    if (inv->role == oar::Role::hold) {
        replay_configs(slot);  // a hold role has no functions for the router
        return true;
    }
    _router.add_slot(slot.number, slot.port, *inv);
    return true;
}

auto HelmDaemon::detach(SlotState& slot) noexcept -> void {
    slot.link.reset();
    slot.binding.reset();
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
    }
}

auto HelmDaemon::publish() -> void {
    auto inv = _router.inventory();
    for (const auto& [n, slot] : _slots) {
        if (slot->link && slot->inventory && slot->inventory->role == oar::Role::net &&
            nonzero(slot->inventory->vtep)) {
            proto::VtepAddress v{};
            std::ranges::copy(slot->inventory->vtep, v.begin());
            if (std::ranges::find(inv.vteps, v) == inv.vteps.end()) {
                inv.vteps.push_back(v);
            }
        }
    }
    const std::scoped_lock lock{_snapshot_mutex};
    _snapshot = std::move(inv);
}

}  // namespace ak::helm
