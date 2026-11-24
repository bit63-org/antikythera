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
// Tunnel keys (oar-net Requirement 5.2, helm design "Tunnel keys"). helm's
// TunnelKeyring holds one WireGuard key pair per VTEP. When a network
// role's sideband opens, helm makes its VTEP's pair (the first time) and
// provisions the role: the private key, then the newest controller peer
// set for the VTEP, so a restarted role gets both back. A role that
// cannot be provisioned is retried on every check; one that answers
// unsupported runs without a tunnel, and its VTEP's key pair is dropped so
// the inventory advertises no key for it. The public keys go into the
// inventory (TunnelKeyring::fill). A TunnelPeers frame from the controller
// is kept if it is newer than the one held for its VTEP and forwarded
// unmodified to that VTEP's role, which verifies it.
//
// Network health (oar-net Requirement 6, task 11). Every check helm asks
// each network role for its health; a degraded role (a peer VTEP down, a
// path that does not carry full-size frames, an unkeyed tunnel: the
// fault_code bits in net_role.hpp) makes the inventory's health degraded.
// Whenever the inventory's VTEPs, tunnel keys or health change, helm sends
// the controller a fresh inventory report, so a role that attaches or
// degrades after registration is not invisible until the next connection.
//
// Block volumes (.kiro/specs/block-volume-service/ task 12). ReplicaConfig
// and VolumeOp frames go unmodified to every hold role, which verifies
// them, and so do the controller's lease acknowledgements. helm keeps the
// newest config of each volume and hands them all again to a hold role
// whose sideband it (re)opens, so a restarted role catches up without the
// controller. Every report_interval it takes each hold role's queued
// reports and relays those of the kinds a hold role sends (replica
// status, volume faults, demotions, op outcomes, snapshot progress) to the
// controller; anything else is dropped and counted. A VolumeKey goes to
// the KeyStore, which opens it in the secure element and keeps it wrapped
// for the attachment it names (KeyStore::put_attachment_key); an ImageKey
// likewise, for the image volume it names (KeyStore::put_image_key, oar-blk
// task 15), until that volume's CREATE_VOLUME re-wraps it. A config
// whose attachments name this server also goes to the CommandRouter (which
// attaches the volume on ATTACH_VOLUME) and to every storage (blk) role,
// and again to a storage role whose sideband (re)opens.
//
// Enrollment. Every identity_interval, and as soon as its sideband opens,
// helm asks each storage role (blk, hold) for its certificate request.
// A request it has not reported for that slot (or reported more than
// identity_retry ago) goes to the controller as a cert_request report; a
// role that wants nothing answers with none, and one that does not take
// part answers unsupported. The controller's role_certificate for a slot
// goes to that slot's role unmodified (the role checks it); once a role
// takes one, a later request from it (a renewal, the same bytes) is
// reported again.
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
#include "helm/tunnel_keyring.hpp"
#include "proto/envelope.hpp"
#include "proto/report.hpp"
#include "proto/tunnel_peers.hpp"

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
    // How often hold roles' reports are taken (their lease requests ride
    // them, every lease_ms / 4).
    std::chrono::milliseconds report_interval{std::chrono::milliseconds{100}};
    // How often storage roles are asked for a certificate request, and
    // how long an unanswered one waits before it is reported again.
    std::chrono::milliseconds identity_interval{std::chrono::seconds{10}};
    std::chrono::milliseconds identity_retry{std::chrono::minutes{10}};
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
    // Block volumes.
    std::uint64_t replica_configs{0};  // received from the controller
    std::uint64_t volume_ops{0};
    std::uint64_t lease_grants{0};
    std::uint64_t hold_refused{0};          // a hold role refused or missed a frame or grant
    std::uint64_t hold_reports{0};          // relayed to the controller
    std::uint64_t hold_reports_dropped{0};  // undecodable, or of a kind a hold role never sends
    std::uint64_t volume_keys{0};           // opened and kept (KeyStore::put_attachment_key)
    std::uint64_t volume_keys_refused{0};   // did not open, stale, or too many
    std::uint64_t image_keys{0};            // opened and kept (KeyStore::put_image_key)
    std::uint64_t image_keys_refused{0};    // did not open, or too many
    std::uint64_t blk_configs_refused{0};   // a storage role refused a network volume's config
    std::uint64_t cert_requests{0};         // storage role requests reported to the controller
    std::uint64_t role_certificates{0};     // certificates a storage role took
    std::uint64_t role_certificates_refused{0};  // refused, or for a slot with no storage role
    // Tunnel keys.
    std::uint64_t tunnel_provisioned{0};          // network roles given their key (and peers)
    std::uint64_t tunnel_provision_failed{0};     // could not be keyed: retried on check
    std::uint64_t tunnel_peer_sets{0};            // TunnelPeers frames from the controller
    std::uint64_t tunnel_peer_sets_forwarded{0};  // accepted by the VTEP's role
    std::uint64_t tunnel_peer_sets_refused{0};    // the role refused it, or its link failed
    std::uint64_t tunnel_peer_sets_held{0};       // stale or duplicate, or no role for the VTEP yet
    std::uint64_t inventory_reports{0};           // sent because VTEPs, keys or health changed
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
    [[nodiscard]] auto keyring() const noexcept -> const TunnelKeyring& { return _keyring; }
    // The health a network role last reported (loop thread); empty for
    // other roles, or before the first answer.
    [[nodiscard]] auto role_health(SlotNumber slot) const -> std::optional<oar::Health>;

    // ---- any thread ---------------------------------------------------------

    auto on_envelope(const proto::Envelope& envelope) -> void override;
    auto on_map_update(const proto::MapUpdate& update, std::span<const std::byte> frame)
        -> void override;
    auto on_replica_config(const proto::ReplicaConfig& config, std::span<const std::byte> frame)
        -> void override;
    auto on_volume_op(const proto::VolumeOp& op, std::span<const std::byte> frame) -> void override;
    auto on_lease_grant(const proto::LeaseGrant& grant) -> void override;
    auto on_role_certificate(const proto::RoleCertificate& certificate) -> void override;
    auto on_volume_key(const proto::VolumeKey& key, std::span<const std::byte> frame)
        -> void override;
    auto on_tunnel_peers(const proto::TunnelPeers& peers, std::span<const std::byte> frame)
        -> void override;
    auto on_image_key(const proto::ImageKey& key, std::span<const std::byte> frame)
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
    struct ConfigFrame {
        std::uint64_t volume_id{0};
        std::uint64_t epoch{0};
        std::vector<std::byte> frame;
    };
    struct OpFrame {
        std::vector<std::byte> frame;
    };
    struct KeyFrame {
        std::vector<std::byte> frame;
    };
    struct PeersFrame {
        proto::TunnelPeers peers;
        std::vector<std::byte> frame;
    };
    struct ImageKeyFrame {
        std::vector<std::byte> frame;
    };
    using Item = std::variant<proto::Envelope, MapFrame, mailbox::Slot, ConfigFrame, OpFrame,
                              proto::LeaseGrant, KeyFrame, proto::RoleCertificate, PeersFrame,
                              ImageKeyFrame>;

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
        auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                         std::optional<ScopedKey> image_key)
            -> std::expected<void, LinkError> override;
        auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> override;
        auto create_volume(const oar::CreateVolume& request)
            -> std::expected<void, LinkError> override;
        auto delete_volume(const oar::DeleteVolume& request)
            -> std::expected<void, LinkError> override;
        auto rewrap_volume(const oar::RewrapVolume& request)
            -> std::expected<void, LinkError> override;
        auto replica_config(std::span<const std::byte> frame)
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
        // The certificate request last reported for this slot, and when.
        std::vector<std::byte> reported_csr;
        Clock::time_point reported_at{};
        // A network role not yet given its tunnel key: retried on check.
        bool keys_pending{false};
        std::optional<oar::Health> health;  // network roles: the last answer
        SlotPort port;

        SlotState(SlotNumber n, LinkConfig c) : number{n}, config{c}, port{*this} {}
    };

    [[nodiscard]] auto now() const -> Clock::time_point;
    auto enqueue(Item item) -> void;
    auto handle(Item& item) -> void;
    auto apply_map(MapFrame& map) -> void;
    // Block volumes: to every attached hold role.
    [[nodiscard]] static auto is_hold(const SlotState& slot) -> bool;
    [[nodiscard]] static auto is_blk(const SlotState& slot) -> bool;
    auto count_blk_refusal(const std::expected<void, LinkError>& r) -> void;
    auto forward_config(ConfigFrame& config) -> void;
    auto forward_op(const OpFrame& op) -> void;
    auto forward_grant(const proto::LeaseGrant& grant) -> void;
    auto replay_configs(SlotState& slot) -> void;
    auto take_hold_reports() -> void;
    [[nodiscard]] static auto is_storage(const SlotState& slot) -> bool;
    auto poll_identity(SlotState& slot) -> void;
    auto deliver_certificate(const proto::RoleCertificate& certificate) -> void;
    auto count_refusal(const std::expected<void, LinkError>& r) -> void;
    // Tunnel keys and network health.
    [[nodiscard]] static auto is_net(const SlotState& slot) -> bool;
    auto provision_tunnel(SlotState& slot) -> void;
    auto forward_peers(const PeersFrame& peers) -> void;
    auto poll_health(SlotState& slot) -> void;
    // Opens the sideband, reads the inventory, registers with the router.
    auto attach(SlotState& slot) -> bool;
    auto detach(SlotState& slot) noexcept -> void;
    auto check() -> void;
    auto publish() -> void;
    auto slot_state(SlotNumber slot) -> SlotState*;

    DaemonConfig _config;
    KeyStore* _keys;
    SidebandConnector _connect;
    ReportOut _reports;
    DevicePool _pool;
    CommandRouter _router;
    PowerSequencer _sequencer;
    std::map<SlotNumber, std::unique_ptr<SlotState>> _slots;
    Clock::time_point _next_check;
    Clock::time_point _next_reports;
    Clock::time_point _next_identity;
    std::map<std::uint64_t, ConfigFrame> _volume_configs;  // the newest, by volume
    TunnelKeyring _keyring;

    mutable std::mutex _inbox_mutex;
    std::condition_variable _inbox_ready;
    std::vector<Item> _inbox;
    DaemonStats _stats;  // guarded by _inbox_mutex

    mutable std::mutex _snapshot_mutex;
    proto::Inventory _snapshot;
};

}  // namespace ak::helm
