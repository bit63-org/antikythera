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
// as one ReplicaStore batch. PING is answered at once.
//
// Replication (task 8, design "Write and read paths"). A primary with
// other members opens one session to each (SessionSink::dial, then
// connected(); HELLO as a peer naming its own replica_gen) and assigns
// every write the next seq. After the local group commit, each write goes
// to every member as REPL_WRITE(seq, commit_seq) on that member's ordered
// stream, and the initiator is answered once every member has sent
// REPL_ACK; commit_seq, the highest seq answered, then moves (Requirements
// 1.5, 1.6). Joining members are awaited too until rebuild (task 11) gives
// them a stream of their own. A member applies REPL_WRITEs in seq order
// from the primary of its own epoch only (a deposed primary gets
// stale_epoch, Requirement 6.2), acknowledges a seq it already holds
// without writing it again, and refuses a gap unless it is joining. A
// lost member session is redialled after redial_backoff and everything it
// has not acknowledged is sent again in order. Members are awaited until
// the controller removes them at a new epoch (reporting is task 10).
//
// The primary holds back a read that overlaps a write not yet answered,
// so a read never returns data that might still be rolled back, and stops
// taking writes while max_replicating are unanswered. A read that finds a
// block whose checksum does not match is repaired (Requirement 5.4): the
// primary reads the range from an in-sync member over its peer session,
// writes the good blocks back (ReplicaStore::repair) and answers with
// them; writes that overlap a repair wait for it. With no member to ask,
// or no good copy there, the read fails with io_error.
//
// Single replica (task 6): a lone primary commits locally and answers at
// once. The lease (task 10) does not yet gate reads.
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
    // Replication: open `session` to another hold role at endpoint:port,
    // whose certificate must name `server_id`. The node answers with
    // HoldServer::connected() or close_session(). A sink without outbound
    // connections ignores it (and replicated writes then wait).
    virtual auto dial(SessionId session, std::uint64_t server_id,
                      const proto::StorageEndpoint& endpoint, std::uint16_t port) -> void {
        static_cast<void>(session);
        static_cast<void>(server_id);
        static_cast<void>(endpoint);
        static_cast<void>(port);
    }
    // Ends a session (either direction); the node then calls close_session().
    virtual auto hang_up(SessionId session) -> void { static_cast<void>(session); }
};

struct ServerConfig {
    std::uint64_t server_id{0};
    std::filesystem::path data_dir;
    std::uint8_t chunk_shift{20};
    std::size_t max_queue{256};                    // requests waiting per volume
    std::size_t quantum{32};                       // requests per volume per pass
    std::size_t max_batch_writes{64};              // writes per group commit
    std::size_t max_batch_bytes{8 * 1024 * 1024};  // bytes per group commit
    std::size_t max_replicating{1024};             // writes awaiting members per volume
    std::chrono::milliseconds redial_backoff{250};
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
    std::uint64_t batches{0};       // group commits
    std::uint64_t writes{0};        // writes in them
    std::uint64_t replicated{0};    // writes every member acknowledged
    std::uint64_t repaired{0};      // blocks rewritten from a member's copy
    std::uint64_t unrepairable{0};  // bad blocks with no good copy to be had
};

class HoldServer {
public:
    HoldServer(store::FileLayer& files, ServerConfig config, SessionSink& sink);

    [[nodiscard]] auto apply_config(const proto::ReplicaConfig& c, Clock::time_point now)
        -> std::expected<void, ConfigError>;

    // A session from the server the peer's certificate names.
    [[nodiscard]] auto open_session(std::uint64_t peer_server_id) -> SessionId;
    // A session dialled for replication is up (the certificate named the
    // server asked for).
    auto connected(SessionId id, Clock::time_point now) -> void;
    // Its queued requests are dropped; a dialled one is redialled later.
    auto close_session(SessionId id) -> void;
    // A frame decoded from the session (block data is copied).
    auto on_frame(SessionId id, const proto::HoldFrame& frame, Clock::time_point now) -> void;

    // Serves queued requests the limits allow, and dials members.
    auto run(Clock::time_point now) -> void;
    // When run() next has work: now, a later time (a limiter or a redial),
    // or never.
    [[nodiscard]] auto next_wake(Clock::time_point now) const -> std::optional<Clock::time_point>;

    [[nodiscard]] auto stats() const noexcept -> const ServerStats& { return _stats; }
    [[nodiscard]] auto epoch(std::uint64_t volume_id) const -> std::optional<std::uint64_t>;
    [[nodiscard]] auto replica(std::uint64_t volume_id) -> store::ReplicaStore*;
    [[nodiscard]] auto queued(std::uint64_t volume_id) const -> std::size_t;
    // Writes committed here and still awaiting a member's REPL_ACK.
    [[nodiscard]] auto replicating(std::uint64_t volume_id) const -> std::size_t;

private:
    struct Session {
        std::uint64_t peer{0};
        bool open{false};  // HELLO accepted
        proto::HoldPeerRole role{proto::HoldPeerRole::initiator};
        std::uint64_t volume_id{0};
        std::uint64_t attachment_id{0};
        std::uint32_t generation{0};  // the attachment's, or the peer's replica_gen
        bool outbound{false};         // dialled by this server to a member
    };
    struct Request {
        SessionId session{0};
        proto::HoldHeader header;
        std::vector<std::byte> data;
        std::vector<std::uint32_t> crcs;
        std::uint32_t block_size{0};
        std::uint64_t seq{0};         // REPL_WRITE
        std::uint64_t commit_seq{0};  // REPL_WRITE
    };
    // The primary's session to one member.
    struct Link {
        enum class State : std::uint8_t {
            down,
            dialing,
            hello,
            open
        };
        proto::ReplicaMember member;
        State state{State::down};
        SessionId session{0};
        Clock::time_point redial_at{};
        std::uint64_t acked{0};  // every seq up to here is durable there
        bool backoff{false};     // lost: redial_at is set by the next run()
    };
    // A write committed here, awaiting the members.
    struct Replicating {
        Request request;
        std::uint64_t seq{0};
    };
    // A read waiting for a member's copy of its bad blocks.
    struct Repair {
        Request request;
        std::vector<std::uint64_t> bad;  // LBAs
        std::uint64_t member{0};         // server asked
    };
    struct Volume {
        proto::ReplicaConfig config;
        std::unique_ptr<store::ReplicaStore> store;
        VolumeLimiter limiter;
        std::deque<Request> queue;
        std::deque<Request> parked;               // reads held back behind writes or repairs
        std::map<std::uint64_t, Link> links;      // primary: by member server ID
        std::deque<Replicating> replicating;      // by seq
        std::map<std::uint64_t, Repair> repairs;  // by request ID to the member
        std::uint64_t next_request{1};
        bool held{false};  // serving waits for a member, not for time
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
    [[nodiscard]] auto is_primary(const Volume& v) const -> bool;
    [[nodiscard]] auto held_back(const Volume& v, const Request& r) const -> bool;
    auto sync_links(Volume& v, Clock::time_point now) -> void;
    auto drop_link(Volume& v, Link& l, Clock::time_point now) -> void;
    auto send_link(Volume& v, Link& l, proto::HoldFrame f) -> void;
    auto send_repl(Volume& v, Link& l, const Replicating& w) -> void;
    auto on_link_frame(Session& s, SessionId id, const proto::HoldFrame& f, Clock::time_point now)
        -> void;
    auto advance(Volume& v) -> void;
    auto unpark(Volume& v) -> void;
    auto abandon(Volume& v) -> void;
    auto start_repair(Volume& v, Request& r, std::vector<std::uint64_t> bad) -> bool;
    auto finish_repair(Volume& v, Repair& rep, const proto::HoldFrame* f) -> void;
    auto commit_replicas(Volume& v, std::vector<Request>& batch) -> void;
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
