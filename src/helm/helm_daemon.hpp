// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// HelmDaemon: helm's event loop, wiring the ControllerLink, the
// CommandRouter, the PowerSequencer, the mailbox and one OarLink per slot
// into the running daemon (.kiro/specs/helm-control-plane/ design
// "Overview": an event loop around the device pool, the key store, the
// mapping table and the slot table, driven by the controller, mailbox and
// sideband channels).
//
// Threads. Everything that changes helm's state runs on the loop thread,
// the one that calls boot() and run(): the router, the device pool, the key
// store, the sequencer and every OarLink. Three things arrive from other
// threads and are queued for it:
//
//   on_envelope, on_map_update   ControllerLink's thread (ControllerSink).
//                                They run with the link's lock held, so
//                                they only copy and queue.
//   post_host_slot               the MailboxDevice's thread: a response or
//                                event slot hull wrote.
//
// and one thing is read from other threads: inventory(), the snapshot the
// ControllerSession sends on every connection. The loop republishes it after
// each pass, so the link never touches the router.
//
// Slots. When the sequencer reports a slot link-ready (on_slot_ready) the
// daemon opens its sideband (the SidebandConnector: a SocketBinding to the
// board process in harbor), reads the role's function inventory and
// registers it with the router (add_slot), which cleans every function
// before it joins the pool. A slot whose sideband cannot be opened, or
// whose inventory cannot be read, is reported as a host fault and retried
// on every check. A power-cycled slot (on_slot_recovered) restarted its
// role, so the sideband is reopened and the inventory re-read before the
// router cleans the slot's faulted functions (slot_power_cycled). A faulted
// slot's sideband is closed: requests for it fail as disconnected, which
// fails the commands and cleaning that need it.
//
// Mapping updates. helm verifies no signatures (controller-interface design
// "ControllerLink"): a MapUpdate frame goes unmodified to every net role,
// which verifies it before applying it. It is reported applied
// (CommandRouter::on_map_applied) once every connected net role accepted it.
//
// The daemon never powers anything off by itself: losing the controller
// leaves running VMs alone (Requirement 2.3), and stopping run() leaves the
// slots and the host as they are. shutdown() is the explicit power-off.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stop_token>
#include <variant>
#include <vector>

#include "helm/audit_log.hpp"
#include "helm/command_router.hpp"
#include "helm/controller_link.hpp"
#include "helm/device_pool.hpp"
#include "helm/key_store.hpp"
#include "helm/mailbox.hpp"
#include "helm/oar_link.hpp"
#include "helm/power_sequencer.hpp"
#include "helm/sideband_binding.hpp"
#include "proto/envelope.hpp"
#include "proto/report.hpp"

namespace ak::helm {

// One slot's sideband segment, as helm sees it.
struct SlotSideband {
    SlotNumber slot{0};
    LinkConfig link;
};

struct DaemonConfig {
    using Clock = std::chrono::steady_clock;

    std::vector<SlotSideband> slots;
    RouterConfig router;
    SequencerConfig sequencer;  // `slots` is filled from DaemonConfig::slots
    // Longest the loop sleeps between router polls.
    std::chrono::milliseconds tick{std::chrono::milliseconds{50}};
    // How often the sequencer looks for lost links and unattached slots
    // are retried.
    std::chrono::milliseconds check_interval{std::chrono::seconds{1}};
    // Items waiting for the loop; more are dropped and counted. Only a loop
    // stuck far longer than any timeout fills it.
    std::size_t max_inbox{4096};
    // Empty: steady_clock::now.
    std::function<Clock::time_point()> clock;
};

struct DaemonStats {
    std::uint64_t envelopes{0};
    std::uint64_t host_slots{0};
    std::uint64_t map_updates{0};
    std::uint64_t maps_applied{0};
    std::uint64_t maps_refused{0};  // a net role refused it, or no net role is attached
    std::uint64_t inbox_dropped{0};
    std::uint64_t sideband_failures{0};  // a slot's sideband or inventory could not be read
};

class HelmDaemon final : public ControllerSink, public ReportSink, public SequencerObserver {
public:
    using Clock = DaemonConfig::Clock;
    // Opens the sideband to the role on `slot` (called once it is link-ready).
    using SidebandConnector =
        std::function<std::expected<std::unique_ptr<Binding>, BindingError>(SlotNumber)>;
    // Where reports go: ControllerLink::report, which is thread-safe.
    using ReportOut = std::function<void(proto::ReportBody)>;

    // Every reference must outlive the daemon.
    HelmDaemon(DaemonConfig config, KeyStore& keys, AuditLog& audit, HostPort& host,
               Backplane& backplane, SidebandConnector connect, ReportOut reports);

    HelmDaemon(const HelmDaemon&) = delete;
    auto operator=(const HelmDaemon&) -> HelmDaemon& = delete;
    HelmDaemon(HelmDaemon&&) = delete;
    auto operator=(HelmDaemon&&) -> HelmDaemon& = delete;
    ~HelmDaemon() override;

    // ---- loop thread --------------------------------------------------------

    // Powers the slots, attaches every one that comes up, releases the host
    // (PowerSequencer::boot) and publishes the first inventory.
    auto boot() -> BootResult;
    // Serves queued traffic, router deadlines and sequencer checks until
    // stop is requested.
    auto run(const std::stop_token& stop) -> void;
    // One pass: waits up to `wait` for queued traffic, handles it, polls
    // the router, runs a due check and republishes the inventory.
    auto run_once(std::chrono::milliseconds wait) -> void;
    // Holds the host and powers every slot off.
    auto shutdown() -> void;

    [[nodiscard]] auto router() const noexcept -> const CommandRouter& { return _router; }
    [[nodiscard]] auto pool() const noexcept -> const DevicePool& { return _pool; }
    [[nodiscard]] auto sequencer() const noexcept -> const PowerSequencer& { return _sequencer; }
    [[nodiscard]] auto attached(SlotNumber slot) const -> bool;
    [[nodiscard]] auto stats() const -> DaemonStats;

    // ---- any thread ---------------------------------------------------------

    auto on_envelope(const proto::Envelope& envelope) -> void override;
    auto on_map_update(const proto::MapUpdate& update, std::span<const std::byte> frame)
        -> void override;
    // A slot hull wrote (RSP_SLOT or EVT_SLOT), from the MailboxDevice.
    auto post_host_slot(const mailbox::Slot& slot) -> void;
    // The newest published snapshot (ControllerSession's InventorySource).
    [[nodiscard]] auto inventory() const -> proto::Inventory;

    // ---- callbacks on the loop thread (router and sequencer) ----------------

    auto report(proto::ReportBody body) -> void override;
    auto on_slot_ready(SlotNumber slot) -> void override;
    auto on_slot_recovered(SlotNumber slot) -> void override;
    auto on_slot_faulted(SlotNumber slot) -> void override;

private:
    struct MapFrame {
        std::uint32_t vni{0};
        std::uint64_t map_version{0};
        std::vector<std::byte> frame;
    };
    using Item = std::variant<proto::Envelope, MapFrame, mailbox::Slot>;

    struct SlotState;

    // The router's OarPort for a slot: forwards to the slot's current link,
    // which is replaced when the role restarts and absent while it is down.
    class SlotPort final : public OarPort {
    public:
        explicit SlotPort(SlotState& slot) noexcept : _slot{&slot} {}

        auto prepare_function(const oar::PrepareFunction& request)
            -> std::expected<void, LinkError> override;
        auto clean_function(const oar::CleanFunction& request)
            -> std::expected<void, LinkError> override;
        auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
            -> std::expected<void, LinkError> override;
        auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> override;
        auto create_volume(const oar::CreateVolume& request)
            -> std::expected<void, LinkError> override;
        auto delete_volume(const oar::DeleteVolume& request)
            -> std::expected<void, LinkError> override;
        auto rewrap_volume(const oar::RewrapVolume& request)
            -> std::expected<void, LinkError> override;

    private:
        SlotState* _slot;
    };

    struct SlotState {
        SlotNumber number{0};
        LinkConfig config;
        std::unique_ptr<Binding> binding;
        std::unique_ptr<OarLink> link;  // set while attached
        std::optional<oar::Inventory> inventory;
        bool pending{false};  // link-ready, attach failed: retried on check
        SlotPort port;

        SlotState(SlotNumber n, LinkConfig c) : number{n}, config{c}, port{*this} {}
    };

    [[nodiscard]] auto now() const -> Clock::time_point;
    auto enqueue(Item item) -> void;
    auto handle(Item& item) -> void;
    auto apply_map(MapFrame& map) -> void;
    // Opens the sideband, reads the inventory, registers with the router.
    auto attach(SlotState& slot) -> bool;
    auto detach(SlotState& slot) noexcept -> void;
    auto check() -> void;
    auto publish() -> void;
    auto slot_state(SlotNumber slot) -> SlotState*;

    DaemonConfig _config;
    SidebandConnector _connect;
    ReportOut _reports;
    DevicePool _pool;
    CommandRouter _router;
    PowerSequencer _sequencer;
    std::map<SlotNumber, std::unique_ptr<SlotState>> _slots;
    Clock::time_point _next_check;

    mutable std::mutex _inbox_mutex;
    std::condition_variable _inbox_ready;
    std::vector<Item> _inbox;
    DaemonStats _stats;  // guarded by _inbox_mutex

    mutable std::mutex _snapshot_mutex;
    proto::Inventory _snapshot;
};

}  // namespace ak::helm
