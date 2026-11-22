// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The hold role's request handling for one storage server
// (.kiro/specs/block-volume-service/ task 6): the volumes it holds a
// replica of, the sessions initiators and peers open to it, and the
// queue between them. Transport-free: the node (node.hpp) feeds it
// decoded frames from TLS sessions whose peer certificate named a server
// ID, and it answers through a SessionSink. Single-threaded.
//
// Volumes. apply_config() takes each ReplicaConfig helm hands down (helm
// has verified the controller's signature). A config for another server
// or an epoch below the newest applied is refused; the same epoch again
// is a no-op. While this server is a member, it holds the member's
// replica (vol-<id>.<replica_gen> under the data directory, created or
// opened as needed) and records each new epoch and role in it.
//
// Sessions (Requirement 13.2). A session starts with HELLO for one volume:
//   - from an initiator, naming an attachment and its generation that the
//     current config lists for the peer's own server, at the current
//     epoch, to the primary (else REDIRECT to the one the config names);
//   - from a peer, naming the replica_gen the config lists for the peer's
//     server as a member, while this server is a member too.
// Everything after HELLO must name the same volume and attachment.
//
// Fencing, checked when a request is queued and again when it runs, so a
// config applied in between takes effect (Requirements 6.2, 6.4):
//   epoch below the config's            stale_epoch
//   epoch above it (helm is behind)     REDIRECT, status not_primary
//   attachment or member gone, or its
//     generation / replica_gen retired  fenced
//   not the primary (initiators)        REDIRECT, status not_primary
//   io_suspended                        io_suspended
//   a write from an ro attachment       read_only
//   past capacity, wrong block size     range, bad_request
//   a block whose CRC32C is wrong       checksum
//
// READ, WRITE (and WRITE with the hydrate flag: fill only blocks still
// unhydrated) and FLUSH (a barrier: an acknowledged write is already
// durable) run in order per volume. Consecutive writes are group-committed
// as one ReplicaStore batch. A read that finds a block whose checksum
// does not match fails with io_error (a single replica has no copy to
// repair from; task 8 adds repair). PING is answered at once.
//
// Single replica only (task 6): a primary with other members refuses
// writes with io_suspended until replication (task 8) exists, and the
// lease (task 10) does not yet gate reads.
//
// QoS (Requirement 10.2): each volume's requests wait in its queue until
// its limiter (qos.hpp) admits them; run() serves the volumes round-robin,
// at most `quantum` requests each per pass, so a busy volume cannot starve
// a quiet one. A volume whose queue is full answers throttled.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "hold/server/qos.hpp"
#include "hold/store/file_layer.hpp"
#include "hold/store/replica_store.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"

namespace ak::hold {

using Clock = std::chrono::steady_clock;
using SessionId = std::uint64_t;

class SessionSink {
public:
    SessionSink() = default;
    SessionSink(const SessionSink&) = delete;
    auto operator=(const SessionSink&) -> SessionSink& = delete;
    SessionSink(SessionSink&&) = delete;
    auto operator=(SessionSink&&) -> SessionSink& = delete;
    virtual ~SessionSink() = default;

    // One encoded frame for the session's peer.
    virtual auto send(SessionId session, std::vector<std::byte> frame) -> void = 0;
};

struct ServerConfig {
    std::uint64_t server_id{0};
    std::filesystem::path data_dir;
    std::uint8_t chunk_shift{20};
    std::size_t max_queue{256};                    // requests waiting per volume
    std::size_t quantum{32};                       // requests per volume per pass
    std::size_t max_batch_writes{64};              // writes per group commit
    std::size_t max_batch_bytes{8 * 1024 * 1024};  // bytes per group commit
};

enum class ConfigError : std::uint8_t {
    wrong_server,  // the config names another server
    stale,         // an epoch below the newest applied
    mismatch,      // block size, capacity or lineage differ from the replica's
    store,         // the replica could not be created, opened or updated
};

[[nodiscard]] auto to_string(ConfigError e) noexcept -> const char*;

struct ServerStats {
    std::uint64_t requests{0};
    std::uint64_t refused{0};  // any status other than ok
    std::uint64_t throttled{0};
    std::uint64_t checksum{0};  // blocks read whose data did not match
    std::uint64_t io_errors{0};
    std::uint64_t batches{0};  // group commits
    std::uint64_t writes{0};   // writes in them
};

class HoldServer {
public:
    HoldServer(store::FileLayer& files, ServerConfig config, SessionSink& sink);

    [[nodiscard]] auto apply_config(const proto::ReplicaConfig& c, Clock::time_point now)
        -> std::expected<void, ConfigError>;

    // A session from the server the peer's certificate names.
    [[nodiscard]] auto open_session(std::uint64_t peer_server_id) -> SessionId;
    // Its queued requests are dropped.
    auto close_session(SessionId id) -> void;
    // A frame decoded from the session (block data is copied).
    auto on_frame(SessionId id, const proto::HoldFrame& frame, Clock::time_point now) -> void;

    // Serves queued requests the limits allow.
    auto run(Clock::time_point now) -> void;
    // When run() next has work: now, a later time (a limiter), or never.
    [[nodiscard]] auto next_wake(Clock::time_point now) const -> std::optional<Clock::time_point>;

    [[nodiscard]] auto stats() const noexcept -> const ServerStats& { return _stats; }
    [[nodiscard]] auto epoch(std::uint64_t volume_id) const -> std::optional<std::uint64_t>;
    [[nodiscard]] auto replica(std::uint64_t volume_id) -> store::ReplicaStore*;
    [[nodiscard]] auto queued(std::uint64_t volume_id) const -> std::size_t;

private:
    struct Session {
        std::uint64_t peer{0};
        bool open{false};  // HELLO accepted
        proto::HoldPeerRole role{proto::HoldPeerRole::initiator};
        std::uint64_t volume_id{0};
        std::uint64_t attachment_id{0};
        std::uint32_t generation{0};  // the attachment's, or the peer's replica_gen
    };
    struct Request {
        SessionId session{0};
        proto::HoldHeader header;
        std::vector<std::byte> data;
        std::vector<std::uint32_t> crcs;
        std::uint32_t block_size{0};
    };
    struct Volume {
        proto::ReplicaConfig config;
        std::unique_ptr<store::ReplicaStore> store;
        VolumeLimiter limiter;
        std::deque<Request> queue;
    };
    // The outcome of the fencing checks.
    struct Verdict {
        proto::HoldStatus status{proto::HoldStatus::ok};
        bool redirect{false};
    };

    [[nodiscard]] auto ensure_replica(Volume& v, const proto::ReplicaMember& me)
        -> std::expected<void, ConfigError>;
    [[nodiscard]] auto check(const Session& s, const proto::HoldHeader& h) const -> Verdict;
    [[nodiscard]] auto check_hello(const Session& s, const proto::HoldHeader& h,
                                   const proto::HoldHello& hello) const -> Verdict;
    [[nodiscard]] auto single_replica_primary(const Volume& v) const -> bool;
    auto hello(SessionId id, Session& s, const proto::HoldFrame& f) -> void;
    auto serve(Volume& v, std::size_t budget, Clock::time_point now) -> std::size_t;
    auto commit(Volume& v, std::vector<Request>& batch) -> void;
    auto execute(Volume& v, Request& r) -> void;

    auto respond(SessionId id, const proto::HoldHeader& req, proto::HoldStatus status,
                 proto::HoldPayload payload = {}) -> void;
    auto refuse(SessionId id, const proto::HoldHeader& req, Verdict v) -> void;

    store::FileLayer* _files;
    ServerConfig _config;
    SessionSink* _sink;
    std::map<std::uint64_t, Volume> _volumes;
    std::map<SessionId, Session> _sessions;
    SessionId _next_session{1};
    std::uint64_t _rr{0};  // the volume run() starts from
    ServerStats _stats;
};

}  // namespace ak::hold
