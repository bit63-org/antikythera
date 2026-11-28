// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ControllerLink: helm's connection to the controller
// (.kiro/specs/controller-interface/ Requirements 2 and 3, design
// "ControllerLink"; helm-control-plane design "ControllerLink").
//
// Two layers:
//
//   ControllerSession  the protocol, with no I/O: it turns received bytes
//                      into envelopes and mapping updates for helm, and
//                      helm's reports into bytes to send. Unit-testable
//                      byte by byte.
//   ControllerLink     drives a session over mutually authenticated TLS
//                      (ak::tls): connects to the controller, reconnects
//                      with capped exponential backoff, and lets other
//                      helm threads queue reports.
//
// What a session does:
//   - On every connection it sends hello (server and boot ID), then every
//     report the controller has not yet acknowledged, in order and with
//     their original sequence numbers, then a fresh inventory
//     (registration, Requirement 3.1) with the highest sequence number.
//     Nothing reported while the link was down is lost, the controller
//     drops duplicates by (boot ID, sequence), and it ends up holding the
//     newest snapshot (Requirement 3.3, reconcile after reconnect). An
//     unacknowledged older inventory is superseded and not replayed.
//   - It checks each envelope's shape (strict decode) and that it names
//     this server, then hands the slot to helm unmodified (Requirement
//     1.4). It never verifies signatures: hull does, and helm is not
//     trusted to (helm-control-plane design).
//   - It checks each MapUpdate's and TunnelPeers frame's shape and target
//     the same way and hands it, with its exact signed bytes, to helm,
//     which forwards it to oar-net to verify and apply. ReplicaConfig,
//     VolumeOp, VolumeKey and LeaseGrant records are checked and handed
//     over the same way (block volumes), as are RoleCertificate records
//     (enrollment of the storage roles). After the inventory it sends
//     helm's enrollment (the secure element's transport key), when set,
//     which an older unacknowledged one never outlives either.
//   - Any protocol violation (a malformed record, a record that only helm
//     sends, an envelope for another server, an ack for a report never
//     sent) ends the connection; the link reconnects and re-registers.
//
// Losing the link never touches running VMs (Requirement 2.3): nothing
// here reaches the mailbox except envelopes the controller sent. Commands
// resume when the controller sends the next sequence number, which it
// learns from the inventory's last_command_seq.
//
// Unacknowledged reports are bounded (max_pending_reports). When the
// controller is unreachable for long enough to overflow it, the oldest
// are dropped and counted; the inventory sent on reconnect restates the
// state they described.
//
// The process must ignore SIGPIPE (helm's main does): writing to a socket
// the controller closed would otherwise kill it.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <expected>
#include <functional>
#include <mutex>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

#include "proto/envelope.hpp"
#include "proto/link.hpp"
#include "proto/group_policy.hpp"
#include "proto/map_update.hpp"
#include "proto/report.hpp"
#include "proto/tunnel_peers.hpp"
#include "proto/group_members.hpp"
#include "proto/instance_metadata.hpp"
#include "proto/vpc_config.hpp"
#include "tls/tls.hpp"

namespace ak::helm {

// Where verified-shape controller traffic goes.
class ControllerSink {
public:
    ControllerSink() = default;
    ControllerSink(const ControllerSink&) = delete;
    auto operator=(const ControllerSink&) -> ControllerSink& = delete;
    ControllerSink(ControllerSink&&) = delete;
    auto operator=(ControllerSink&&) -> ControllerSink& = delete;
    virtual ~ControllerSink() = default;

    // A command for this server, to relay into the mailbox unmodified.
    virtual auto on_envelope(const proto::Envelope& envelope) -> void = 0;
    // A mapping update for this server; `frame` is its exact encoding, so
    // the receiver verifies map_update_signed_bytes(frame).
    virtual auto on_map_update(const proto::MapUpdate& update, std::span<const std::byte> frame)
        -> void = 0;
    // A VPC's broadcast/multicast policy for this server; `frame` is its
    // exact encoding, which helm forwards to the network roles unmodified
    // (GroupPolicyFanout). Ignored by sinks that predate it.
    virtual auto on_group_policy(const proto::GroupPolicy& /*policy*/,
                                 std::span<const std::byte> /*frame*/) -> void {}
    // A VTEP's tunnel peer set for this server; `frame` is its exact
    // encoding, which the VTEP's network role verifies. The default drops
    // it, for sinks that run no network role.
    virtual auto on_tunnel_peers(const proto::TunnelPeers& /*peers*/,
                                 std::span<const std::byte> /*frame*/) -> void {}
    // A VPC's gateway and guest network configuration for this server;
    // `frame` is its exact encoding, which helm forwards to the network
    // roles unmodified. The default drops it, for sinks that run no
    // network role.
    virtual auto on_vpc_config(const proto::VpcConfigFrame& /*config*/,
                               std::span<const std::byte> /*frame*/) -> void {}
    // A multicast VPC's per-group VTEP lists for this server; `frame` is
    // its exact encoding, which helm forwards to the network roles
    // unmodified. The default drops it, for sinks that run no network role.
    virtual auto on_group_members(const proto::GroupMembers& /*members*/,
                                  std::span<const std::byte> /*frame*/) -> void {}
    // A NIC's instance metadata record for this server; `frame` is its
    // exact encoding, which helm forwards unmodified to the NIC's network
    // role (oar-net task 21). The default drops it.
    virtual auto on_instance_metadata(const proto::InstanceMetadata& /*metadata*/,
                                      std::span<const std::byte> /*frame*/) -> void {}
    // Block volumes (.kiro/specs/block-volume-service/ task 12). A volume's
    // replica set and attachments at one epoch; `frame` is its exact
    // encoding, which the storage roles verify.
    virtual auto on_replica_config(const proto::ReplicaConfig& /*config*/,
                                   std::span<const std::byte> /*frame*/) -> void {}
    // A one-shot operation on a replica, verified by the role like a config.
    virtual auto on_volume_op(const proto::VolumeOp& /*op*/, std::span<const std::byte> /*frame*/)
        -> void {}
    // A network volume's key, wrapped to this helm's secure element;
    // `frame` carries the HPKE AAD (proto::volume_key_aad).
    virtual auto on_volume_key(const proto::VolumeKey& /*key*/,
                               std::span<const std::byte> /*frame*/) -> void {}
    // An encrypted image's key for an image volume about to be created
    // (oar-blk task 15), wrapped to this helm's secure element; `frame`
    // carries the HPKE AAD (proto::image_key_aad).
    virtual auto on_image_key(const proto::ImageKey& /*key*/, std::span<const std::byte> /*frame*/)
        -> void {}
    // The controller acknowledged a storage role's lease request.
    virtual auto on_lease_grant(const proto::LeaseGrant& /*grant*/) -> void {}
    // A storage role's certificate, for the role in `certificate.slot`.
    virtual auto on_role_certificate(const proto::RoleCertificate& /*certificate*/) -> void {}
    // khold (kythira khold-block-service task 17). A khold volume's layout
    // at one epoch for this server; `frame` is its exact encoding, which
    // the khold or blk role verifies.
    virtual auto on_volume_layout(const proto::VolumeLayout& /*layout*/,
                                  std::span<const std::byte> /*frame*/) -> void {}
    // Run the storage self-test on one khold role or all of them.
    virtual auto on_self_test(const proto::SelfTest& /*request*/) -> void {}
    // AZ cold start (.kiro/specs/cold-start/). A standing set or power-on
    // policy for this server, strictly decoded but not yet verified;
    // `frame` is its exact encoding, which helm verifies and keeps in its
    // sealed store.
    virtual auto on_standing_set(const proto::StandingSet& /*set*/,
                                 std::span<const std::byte> /*frame*/) -> void {}
    virtual auto on_power_policy(const proto::PowerPolicy& /*policy*/,
                                 std::span<const std::byte> /*frame*/) -> void {}
};

enum class SessionError : std::uint8_t {
    bad_record,       // the stream or a payload failed strict decoding
    wrong_direction,  // a record type only helm sends
    wrong_server,     // an envelope or mapping update for another server
    bad_ack,          // an ack for another server or for a report never sent
    not_connected,    // bytes arrived with no connection open
};

[[nodiscard]] auto to_string(SessionError e) noexcept -> const char*;

inline constexpr std::size_t max_pending_reports = 4096;

class ControllerSession {
public:
    using InventorySource = std::function<proto::Inventory()>;
    // The boot cache's state (.kiro/specs/cold-start/ Requirement 8.2), or
    // nothing to send yet. Called whenever an inventory is queued, with the
    // link's lock held, so it must not block or call back into the link.
    using BootCacheSource = std::function<std::optional<proto::BootCache>()>;

    // `boot_id` is fresh for every helm boot (non-zero). `inventory` is
    // called at every (re)connection for a fresh snapshot; the session
    // sets its boot ID.
    ControllerSession(std::uint64_t server_id, std::uint64_t boot_id, InventorySource inventory,
                      ControllerSink& sink);

    // A new connection: queues the replay, then the registration
    // inventory and the enrollment.
    auto on_connected() -> void;

    // helm's secure-element transport key (block volumes, enrollment):
    // sent after the inventory on every connection, and now if connected.
    auto set_enrollment(const proto::Enrollment& enrollment) -> void;
    // Every inventory, at a connection or a later change, is followed by a
    // boot_cache report from `source` (cold-start Requirement 8.2). Set it
    // before the link runs.
    auto set_boot_cache_source(BootCacheSource source) -> void { _boot_cache = std::move(source); }
    auto on_disconnected() noexcept -> void;
    [[nodiscard]] auto connected() const noexcept -> bool { return _connected; }

    // Bytes from the controller. An error means: close the connection.
    [[nodiscard]] auto on_bytes(std::span<const std::byte> bytes)
        -> std::expected<void, SessionError>;

    // Queues a report (assigning its sequence number); it is sent now if
    // connected, else at the next connection. Returns the sequence number.
    auto report(proto::ReportBody body) -> std::uint64_t;

    // Bytes waiting to be written to the controller; clears them.
    [[nodiscard]] auto take_outbound() -> std::vector<std::byte>;

    [[nodiscard]] auto pending_reports() const noexcept -> std::size_t { return _pending.size(); }
    [[nodiscard]] auto dropped_reports() const noexcept -> std::uint64_t { return _dropped; }
    [[nodiscard]] auto last_acked() const noexcept -> std::uint64_t { return _acked; }

private:
    struct Pending {
        std::uint64_t seq;
        bool snapshot;  // an inventory or boot cache: restated at every connection
        bool enrollment;
        std::vector<std::byte> record;  // the framed report, ready to send
    };

    auto queue(proto::ReportBody body) -> std::uint64_t;
    auto handle(const proto::Record& rec) -> std::expected<void, SessionError>;

    std::uint64_t _server_id;
    std::uint64_t _boot_id;
    InventorySource _inventory;
    BootCacheSource _boot_cache;
    ControllerSink* _sink;
    std::uint64_t _next_seq{1};
    std::uint64_t _acked{0};
    std::uint64_t _dropped{0};
    bool _connected{false};
    std::deque<Pending> _pending;
    std::optional<proto::Enrollment> _enrollment;
    std::vector<std::byte> _outbound;
    proto::RecordDecoder _decoder;
};

struct LinkOptions {
    std::string host;  // the controller, reached over helm's management NIC
    std::uint16_t port{0};
    tls::Config tls;  // role client; peer_name is the controller's name
    std::chrono::milliseconds min_backoff{std::chrono::seconds{1}};
    std::chrono::milliseconds max_backoff{std::chrono::seconds{60}};
    std::chrono::milliseconds io_timeout{std::chrono::seconds{30}};
};

struct ControllerLinkStats {
    std::uint64_t connects{0};  // completed handshakes
    std::uint64_t failures{0};  // failed connects and broken connections
    std::uint64_t protocol_errors{0};
};

class ControllerLink {
public:
    // Fails if the TLS configuration does not load.
    [[nodiscard]] static auto create(LinkOptions options, ControllerSession& session)
        -> std::expected<std::unique_ptr<ControllerLink>, tls::Error>;

    ControllerLink(const ControllerLink&) = delete;
    auto operator=(const ControllerLink&) -> ControllerLink& = delete;
    ControllerLink(ControllerLink&&) = delete;
    auto operator=(ControllerLink&&) -> ControllerLink& = delete;
    ~ControllerLink();

    // Connects, serves and reconnects until stop is requested. Run it on
    // its own thread (std::jthread passes the token).
    auto run(const std::stop_token& stop) -> void;

    // Thread-safe: queue a report from any helm thread.
    auto report(proto::ReportBody body) -> std::uint64_t;

    [[nodiscard]] auto stats() const -> ControllerLinkStats;

private:
    ControllerLink(LinkOptions options, ControllerSession& session, tls::Context ctx, int wake_fd);

    auto serve(tls::Stream& stream, const std::stop_token& stop) -> void;
    auto flush(tls::Stream& stream) -> bool;
    auto sleep_backoff(std::chrono::milliseconds delay, const std::stop_token& stop) -> void;
    auto wake() noexcept -> void;
    auto drain_wake() noexcept -> void;

    LinkOptions _options;
    ControllerSession* _session;
    tls::Context _ctx;
    int _wake_fd{-1};  // eventfd: report() and stop requests interrupt poll()
    // Guards _session and _stats. Recursive so a sink callback, which runs
    // with it held, may queue a report through report().
    mutable std::recursive_mutex _mutex;
    ControllerLinkStats _stats;
};

}  // namespace ak::helm
