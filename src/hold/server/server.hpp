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
// Volumes. apply_config() takes each ReplicaConfig helm hands down (the
// caller, HoldRole, has verified the controller's signature). A config for another server
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
// without writing it again, and refuses a gap unless it is joining or the
// gap opens a session (a new primary's first write, see Promotion). A
// lost member session is redialled after redial_backoff and everything it
// has not acknowledged is sent again in order. Members are awaited until
// the controller removes them at a new epoch (see Failover).
//
// The primary holds back a read that overlaps a write not yet answered,
// so a read never returns data that might still be rolled back, and stops
// taking writes while max_replicating are unanswered. A read that finds a
// block whose checksum does not match is repaired (Requirement 5.4): the
// primary reads the bad blocks' span from an in-sync member over its peer
// session (the member answers with its copy as it holds it, checksums
// included, and needs no lease to), checks each bad block against its
// checksum, writes the good ones back (ReplicaStore::repair) and answers
// with its own copy, mended; writes that overlap a repair wait for it.
// With no member to ask, or no good copy there of a block, the read fails
// with io_error.
//
// Single replica (task 6): a lone primary commits locally and answers at
// once.
//
// Failover (task 10, design "Epochs, leases and fencing" and "Failure
// detection and failover"). take_reports() hands helm what goes up its
// report path: a ReplicaStatus every status_interval (at most lease_ms / 4
// apart while this server is a primary), which is also each primary's
// lease request, and faults and demotions as they happen; also at once
// after a config this server is a member of is applied (so a new primary
// asks for its lease without waiting) and when a joining copy completes. grant_lease()
// takes the controller's acknowledgement; the lease runs lease_ms from
// when the first unanswered request was sent, and a primary serves reads
// only while it holds one (writes are fenced by epochs instead). Faults:
//   member_timeout   a member left a write unacknowledged, or a promotion's
//                    INTENTS unanswered, for member_timeout
//   primary_timeout  a member heard nothing from its primary (which pings
//                    every ping_interval) for primary_timeout
// each at most once per epoch and suspect. Applying a config that ends
// this server's primary role reports demotion_confirmed.
//
// Promotion (Requirement 6.6). A server that becomes primary of a
// replicated volume reconciles before it serves: it asks every member for
// its uncommitted intent extents (INTENTS), and once all have answered it
// writes its own copy of the union of theirs and its own to every member,
// as ordinary replicated writes numbered above every seq any of them
// holds (a member takes the jump on a session's first REPL_WRITE).
// Writes no one acknowledged may thus be kept or lost, but every replica
// ends up with the same copy. Its own blocks there are taken as they are,
// with fresh checksums: a block a crash left half written belongs to a
// write never acknowledged, which a disk may also leave torn at sectors.
// The commit point it starts from is the highest any member reported in
// HELLO_OK; commit_seq claims stay truthful, so a member's uncommitted
// extents survive until every member holds the reconciled copy.
//
// Resync and rebuild (task 11, design "Resync and rebuild"). A joining
// member gets every new write at once, and a copy of what it lacks as
// SYNC_DATA regions on the same ordered stream, so a region's copy,
// read when it is sent, never overwrites a later write (the region lock
// of the design, free in a single-threaded server). What it lacks: when
// the controller removed it from this primary's set within the config's
// resync window, the regions written since it last acknowledged (kept in
// this primary's memory: a restart or a new primary means a full copy);
// otherwise every region ever written. Either way also the extents its
// own INTENTS reports. The copy goes copy_window regions at a time, paced
// by a byte budget for the role and one per volume, and only while the
// volume has no tenant request waiting. After the last region comes a
// SYNC_DATA with the `last` flag; once the member has applied it on its
// current session from the primary, it reports in_sync, and the
// controller makes it a secondary. A joining member takes up the stream
// wherever it is: on a session's first REPL_WRITE it rebases its replica
// onto that seq. Blocks awaiting hydration are not copied (hydration
// reaches members with the snapshot task).
//
// Scrubbing (task 24, Requirement 5.5). start_scrub() takes the
// controller's scrub VolumeOp: this server reads its replica in full,
// region by region, paced by the op's MiB/s and a budget for the role,
// only while the volume has no tenant request waiting, skipping regions
// never written and blocks still awaiting hydration. A bad block on the
// primary is repaired as a read's would be (from an in-sync member);
// one that a write still awaiting the members overlaps is looked at
// again later. A secondary asks its primary for the good copy with a
// READ over the session the primary opened to it; the primary serves it
// like an initiator's read (held back behind overlapping writes not yet
// answered, so the copy is never older than what the member holds, and
// repaired itself first if its own copy is bad), and the member writes
// it back (ReplicaStore::repair) only if it comes on the primary's
// newest session at the current epoch. An op_id runs once: a resend of
// the running one is ignored, of a finished one answered again. The
// op's outcome reports the bad blocks found as `detail`, status ok, or
// io_error if any stayed bad: no good copy, or none within
// scrub_timeout of the walk's end. Each of those is also a
// checksum_unrepairable fault naming this server, so the controller
// replaces the replica. A scrub ends early (unknown_volume) when this
// server stops being a member, its replica is replaced, or it starts
// joining; a later op starts over.
//
// Deleting replicas (task 17, Requirements 8.4-8.5). delete_replica()
// takes the controller's op for a replica that left the set: a move's
// source, a drained or long-gone replica, a deleted volume. The replica's
// directory goes (and the directory entry is synced) unless the newest
// config this server holds still names it as a member with that
// replica_gen, which can only mean this server has not yet applied the
// epoch that removed it: stale_epoch, and the controller resends. A
// replica already gone, or never here, is ok, so a resend is harmless.
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
#include <set>
#include <span>
#include <utility>
#include <vector>

#include "common/token_bucket.hpp"
#include "hold/server/qos.hpp"
#include "hold/store/file_layer.hpp"
#include "hold/store/replica_store.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"

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
    // Task 10. Without leases (no controller to grant them, as with
    // ak-hold's --configs stand-in for helm) a primary serves reads
    // regardless.
    bool leases{true};
    std::chrono::milliseconds member_timeout{2000};
    std::chrono::milliseconds primary_timeout{2000};
    std::chrono::milliseconds ping_interval{1000};
    std::chrono::milliseconds status_interval{1000};
    // Task 11.
    std::size_t copy_window{4};                           // SYNC_DATA regions in flight per member
    double copy_bytes_per_s{400.0 * 1024 * 1024};         // all copies of the role
    double copy_volume_bytes_per_s{200.0 * 1024 * 1024};  // each volume's copies
    // Task 24.
    double scrub_bytes_per_s{200.0 * 1024 * 1024};   // all scrubs of the role
    std::chrono::milliseconds scrub_timeout{60000};  // repairs after the walk ends
    std::chrono::milliseconds scrub_retry{1000};     // a secondary asks again
    std::size_t scrub_asks{8};                       // a secondary's asks in flight
};

enum class ConfigError : std::uint8_t {
    wrong_server,  // the config names another server
    stale,         // an epoch below the newest applied
    mismatch,      // block size or lineage differ, or the capacity shrank
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
    std::uint64_t reconciled{0};    // extents rewritten by promotions
    std::uint64_t copied{0};        // SYNC_DATA regions sent
    std::uint64_t scrubbed{0};      // blocks read by scrubs
    std::uint64_t deleted{0};       // replica directories removed by delete_replica
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

    // What goes up helm's report path now (see above).
    [[nodiscard]] auto take_reports(Clock::time_point now) -> std::vector<proto::ReportBody>;
    // The controller acknowledged this server's lease request for the
    // volume at `epoch`.
    auto grant_lease(std::uint64_t volume_id, std::uint64_t epoch, Clock::time_point now) -> void;
    [[nodiscard]] auto has_lease(std::uint64_t volume_id, Clock::time_point now) const -> bool;
    // A promotion is still collecting INTENTS.
    [[nodiscard]] auto reconciling(std::uint64_t volume_id) const -> bool;

    // The controller's scrub VolumeOp (see above); the outcome goes up
    // with take_reports(). mib_per_s 0: the default pace.
    auto start_scrub(std::uint64_t volume_id, std::uint64_t op_id, std::uint64_t epoch,
                     std::uint32_t mib_per_s, Clock::time_point now) -> void;
    [[nodiscard]] auto scrubbing(std::uint64_t volume_id) const -> bool;
    // The controller's delete_replica VolumeOp (see above); the outcome
    // goes up with take_reports().
    auto delete_replica(std::uint64_t volume_id, std::uint64_t op_id, std::uint64_t epoch,
                        std::uint32_t replica_gen, Clock::time_point now) -> void;
    // Replica directories this server holds for `volume_id`, any generation.
    [[nodiscard]] auto replica_on_disk(std::uint64_t volume_id, std::uint32_t replica_gen) const
        -> bool;

private:
    struct Session {
        std::uint64_t peer{0};
        bool open{false};  // HELLO accepted
        proto::HoldPeerRole role{proto::HoldPeerRole::initiator};
        std::uint64_t volume_id{0};
        std::uint64_t attachment_id{0};
        std::uint32_t generation{0};  // the attachment's, or the peer's replica_gen
        bool outbound{false};         // dialled by this server to a member
        bool replicated{false};       // a REPL_WRITE was taken from it
    };
    struct Request {
        SessionId session{0};  // 0: the server's own (a reconcile write)
        proto::HoldHeader header;
        std::vector<std::byte> data;
        std::vector<std::uint32_t> crcs;
        std::uint32_t block_size{0};
        std::uint64_t seq{0};         // REPL_WRITE
        std::uint64_t commit_seq{0};  // REPL_WRITE
        bool member{false};           // a member's READ to the primary (a scrub's)
        bool scrub{false};            // session 0: the primary's own scrub repair
    };
    // A joining member's copy.
    struct Copy {
        bool planned{false};                // `todo` and `scan` are set
        std::set<std::uint64_t> todo;       // regions to send
        std::optional<std::uint64_t> scan;  // full: the next region to look at
        std::set<std::uint64_t> holes;  // full: regions its intents name, sent even if unwritten
        std::map<std::uint64_t, std::uint64_t> sent;  // request ID -> region
        std::uint64_t marker{0};                      // the `last` SYNC_DATA's request ID
        std::uint64_t tail{0};                        // a block already sent: the marker's
        bool finished{false};                         // and the member has it
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
        Clock::time_point next_ping{};
        std::uint64_t commit_seen{0};    // the member's commit point in HELLO_OK
        std::uint64_t intents_asked{0};  // the INTENTS request ID
        bool intents_answered{false};    // reconcile: this member has answered
        std::optional<Copy> copy;
    };
    // A write committed here, awaiting the members.
    struct Replicating {
        Request request;
        std::uint64_t seq{0};
        Clock::time_point at{};  // committed here
    };
    // A promotion collecting its members' uncommitted extents.
    struct Reconcile {
        Clock::time_point started{};
        std::vector<proto::HoldIntent> extents;
        std::uint64_t base{0};    // the highest seq any replica holds
        std::uint64_t commit{0};  // the highest commit point reported
    };
    // A read waiting for a member's copy of its bad blocks.
    struct Repair {
        Request request;
        std::vector<std::uint64_t> bad;  // LBAs, ascending
        std::uint64_t member{0};         // server asked
        std::uint64_t lba{0};            // the span asked for: the bad blocks'
        std::uint32_t blocks{0};
        std::vector<std::byte> data;  // the read's own copy, mended blocks put in
        std::vector<std::uint32_t> crcs;
    };
    // A scrub VolumeOp running on this server's replica.
    struct Scrub {
        std::uint64_t op_id{0};
        std::uint64_t epoch{0};  // the op's
        std::uint32_t replica_gen{0};
        TokenBucket budget;
        std::uint64_t next{0};                        // the next region to read
        std::optional<Clock::time_point> walked;      // every region read
        bool blocked{false};                          // primary: behind an unanswered write
        std::set<std::uint64_t> bad;                  // LBAs to repair
        std::map<std::uint64_t, std::uint64_t> asks;  // secondary: request ID -> LBA
        SessionId asked_on{0};                        // the session the asks went on
        Clock::time_point ask_at{};                   // secondary: asking again
        std::size_t repairing{0};                     // primary: repairs in flight
        std::uint64_t found{0};
        std::uint64_t unrepairable{0};
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
        // Task 10.
        std::uint64_t committed{0};  // primary: the highest seq every member holds
        std::uint64_t seq_floor{0};  // primary: writes are numbered above this
        std::optional<Reconcile> reconcile;
        std::optional<Clock::time_point> lease_asked;  // the first status since a grant
        Clock::time_point lease_until{};
        Clock::time_point heard{};  // member: the primary's last frame
        bool primary_reported{false};
        std::vector<std::uint64_t> timeout_reported;  // members, this epoch
        // Task 11.
        struct Dirty {
            std::set<std::uint64_t> chunks;
            Clock::time_point since{};
        };
        std::map<std::pair<std::uint64_t, std::uint32_t>, Dirty> dirty;  // by (server, gen)
        TokenBucket copy_budget;  // primary: this volume's copies
        SessionId synced{0};      // joining member: the primary session that completed its copy
        // Task 24.
        SessionId from_primary{0};  // member: the newest session the primary opened
        std::optional<Scrub> scrub;
        std::deque<proto::OpOutcome> scrubs_done;  // the latest outcomes, for resends
        std::uint64_t checksum_errors{0};          // bad blocks found here (replica_status)
        std::uint64_t checksum_repairs{0};         // and rewritten from a good copy
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
    [[nodiscard]] auto held_back(const Volume& v, const Request& r, Clock::time_point now) const
        -> bool;
    [[nodiscard]] auto lease_valid(const Volume& v, Clock::time_point now) const -> bool;
    auto start_reconcile(Volume& v, Clock::time_point now) -> void;
    auto ask_intents(Volume& v, Link& l) -> void;
    auto finish_reconcile(Volume& v) -> void;
    auto watch(Volume& v, Clock::time_point now) -> void;
    auto report_timeout(Volume& v, proto::VolumeFaultKind kind, std::uint64_t suspect) -> void;
    [[nodiscard]] auto region_blocks(const Volume& v) const -> std::uint64_t;
    auto mark_regions(const Volume& v, std::set<std::uint64_t>& regions, std::uint64_t lba,
                      std::uint64_t blocks) const -> void;
    auto record_dirty(Volume& v, const Link& l, Clock::time_point now) -> void;
    auto plan_copy(Volume& v, Link& l, const proto::HoldIntents& theirs) -> void;
    auto pump_copies(Volume& v, Clock::time_point now) -> void;
    // Frames sent; the store failed if v.store is gone.
    auto send_copy(Volume& v, Link& l, std::uint64_t lba, std::uint64_t blocks, bool last)
        -> std::size_t;
    [[nodiscard]] auto copy_ready(const Volume& v, const Link& l) const -> bool;
    auto sync_links(Volume& v, Clock::time_point now) -> void;
    auto drop_link(Volume& v, Link& l, Clock::time_point now) -> void;
    auto send_link(Volume& v, Link& l, proto::HoldFrame f) -> void;
    auto send_repl(Volume& v, Link& l, const Replicating& w) -> void;
    auto on_link_frame(Session& s, SessionId id, const proto::HoldFrame& f, Clock::time_point now)
        -> void;
    auto advance(Volume& v) -> void;
    auto unpark(Volume& v) -> void;
    auto abandon(Volume& v) -> void;
    // Asks an open in-sync member other than `except` for good copies.
    // `data` and `crcs`: the read's own copy, answered with the mended
    // blocks put in.
    auto start_repair(Volume& v, Request& r, std::vector<std::uint64_t> bad,
                      std::uint64_t except = 0, std::vector<std::byte> data = {},
                      std::vector<std::uint32_t> crcs = {}) -> bool;
    auto finish_repair(Volume& v, Repair& rep, const proto::HoldFrame* f) -> void;
    auto commit_replicas(Volume& v, std::vector<Request>& batch) -> void;
    auto hello(SessionId id, Session& s, const proto::HoldFrame& f) -> void;
    auto serve(Volume& v, std::size_t budget, Clock::time_point now) -> std::size_t;
    auto commit(Volume& v, std::vector<Request>& batch) -> void;
    auto execute(Volume& v, Request& r) -> void;
    // Task 24.
    auto pump_scrub(Volume& v, Clock::time_point now) -> void;
    // Reads blocks [lba, lba + blocks) for a scrub; false if the store failed.
    auto scrub_range(Volume& v, std::uint64_t lba, std::uint64_t blocks) -> bool;
    auto scrub_repair(Volume& v, Clock::time_point now) -> void;
    auto scrub_ask(Volume& v, Clock::time_point now) -> void;
    auto on_fill(Volume& v, const Session& s, SessionId id, const proto::HoldFrame& f) -> void;
    auto member_read(Session& s, SessionId id, const proto::HoldFrame& f) -> void;
    auto end_scrub(Volume& v, proto::OpStatus status) -> void;
    [[nodiscard]] auto scrub_due(const Volume& v) const -> std::optional<Clock::time_point>;

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
    std::vector<proto::ReportBody> _reports;
    TokenBucket _copy_budget;
    TokenBucket _scrub_budget;
    Clock::time_point _now{};  // the latest time a caller gave
    std::optional<Clock::time_point> _next_status;
};

}  // namespace ak::hold
