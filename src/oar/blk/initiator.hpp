// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The initiator's protocol logic for one network volume attachment
// (.kiro/specs/block-volume-service/ task 7, design "Write and read
// paths", "Failure detection and failover"). No I/O and no threads: the
// NetworkVolumeBackend (network_volume_backend.hpp) carries its frames
// over TLS, and the tests drive it against an in-process hold server.
//
// Route (Requirement 2.2). Until set_route() delivers the volume's
// ReplicaConfig, requests are held, not failed, however long that takes
// (the route's counterpart of VirtioBlkFunction::await_key); their
// deadlines start when it arrives. Each later config moves
// the epoch; a new primary, or a session the hold refused as stale, makes
// target() name the session to open next. A config may raise the
// capacity (an online grow, Requirement 10.3) and change the QoS limits
// (10.4); capacity_bytes() follows at once, and the caller then grows the
// VirtioBlkFunction in front (VirtioBlkFunction::grow). A smaller capacity
// or another block size is refused.
//
// Requests. A read or write becomes one or more parts of at most
// max_hold_blocks blocks and max_hold_data_bytes, each a hold request
// carrying the epoch, attachment and generation. Writes carry a CRC32C per
// block over their ciphertext; reads are checked against the CRC32Cs the
// primary returns (a block never written comes back as zeros with CRC 0)
// and are retried once on a mismatch. Parts go out in submit order, at
// most max_in_flight at a time, shaped by the volume's QoS limits (two
// token buckets: I/Os in 256 KiB units and MiB, refilled at the baseline,
// as deep as the burst). A write never goes out while an earlier write to
// an overlapping range is unacknowledged, so a resent write is idempotent.
// FLUSH completes at once: every completed write is already durable on
// every in-sync replica (Requirement 1.5).
//
// Failures. Unacknowledged parts are resent, in order, on the next
// session. The primary is presumed lost when nothing comes back within
// primary_timeout while a request or PING is outstanding (a PING goes out
// every ping_interval on an idle session); the core reports
// primary_timeout and opens a new session after retry_backoff. Replies:
//   ok                          done (reads checked)
//   stale_epoch, REDIRECT to a
//     newer epoch               wait for the next config (Requirement 6.6)
//   REDIRECT, not newer         new session after retry_backoff
//   throttled, io_suspended     resent after retry_backoff (x4 suspended)
//   checksum (write)            resent up to twice, then io
//   fenced                      every request fails; the attachment is over
//   not_hydrated (read)         not_hydrated: a range of a volume restored
//                               from an image that oar-blk must hydrate
//                               first (HydratingBackend)
//   range                       out_of_range;  anything else  io
// A routed request still not done at its deadline (request_timeout after
// submit, or after the route arrived) fails with io, so the guest never
// hangs, even with no reachable primary or with I/O suspended.
//
// Completions run on the caller's thread, after the core's state is
// consistent, so a completion may submit again.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "common/token_bucket.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"

namespace ak::oar::blk {

struct InitiatorConfig {
    std::uint64_t attachment_id{0};
    std::chrono::milliseconds request_timeout{30000};
    std::chrono::milliseconds primary_timeout{2000};
    std::chrono::milliseconds ping_interval{1000};
    std::chrono::milliseconds retry_backoff{250};
    std::size_t max_in_flight{64};
};

enum class InitiatorFault : std::uint8_t {
    primary_timeout,  // the primary (khold: a group leader) stopped answering
    fenced,           // the attachment's generation was retired
    checksum,         // a block read back did not match its CRC32C
    media_error,      // the server answered io_error: a media error it could not repair
};

[[nodiscard]] auto to_string(InitiatorFault f) noexcept -> const char*;

// One fault, for helm's report path (BlkRole turns it into a volume_fault
// or attachment_status report): the server it is about (0 for fenced) and
// the epoch the initiator held.
struct FaultEvent {
    InitiatorFault kind{InitiatorFault::primary_timeout};
    std::uint64_t server{0};
    std::uint64_t epoch{0};
    friend auto operator==(const FaultEvent&, const FaultEvent&) -> bool = default;
};

enum class RouteError : std::uint8_t {
    wrong_volume,  // a config for another volume than the first
    stale,         // an epoch below the newest applied
    mismatch,      // block size changed, or capacity shrank
};

[[nodiscard]] auto to_string(RouteError e) noexcept -> const char*;

// Where the next session goes. `session` changes whenever the core wants
// a new session, even to the same server.
struct HoldTarget {
    std::uint64_t server_id{0};
    proto::StorageEndpoint endpoint{};
    std::uint16_t port{0};
    std::uint64_t session{0};
    friend auto operator==(const HoldTarget&, const HoldTarget&) -> bool = default;
};

class InitiatorCore {
public:
    using Clock = std::chrono::steady_clock;

    explicit InitiatorCore(InitiatorConfig config) noexcept;

    [[nodiscard]] auto set_route(const proto::ReplicaConfig& c, Clock::time_point now)
        -> std::expected<void, RouteError>;
    [[nodiscard]] auto routed() const noexcept -> bool { return _route.has_value(); }
    [[nodiscard]] auto fenced() const noexcept -> bool { return _fenced; }
    [[nodiscard]] auto capacity_bytes() const noexcept -> std::uint64_t;

    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done,
                     Clock::time_point now) -> void;
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done,
                      Clock::time_point now) -> void;
    auto submit_flush(BackendCompletion done) -> void;
    // A WRITE with the hydrate flag (block-volume task 23): the hold stores
    // only the blocks still awaiting hydration. Ordered and resent like a
    // write; allowed on a read-only attachment, since it only fills in
    // what the volume already holds.
    auto submit_hydrate(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done,
                        Clock::time_point now) -> void;

    // The session the transport should have open, if any.
    [[nodiscard]] auto target(Clock::time_point now) const -> std::optional<HoldTarget>;
    // The transport opened (TLS, server identity checked) or lost `session`.
    auto connected(std::uint64_t session, Clock::time_point now) -> void;
    auto disconnected(std::uint64_t session, Clock::time_point now) -> void;
    auto on_frame(std::uint64_t session, const proto::HoldFrame& f, Clock::time_point now) -> void;

    // Frames for the current session, in order.
    [[nodiscard]] auto take_output() -> std::vector<std::vector<std::byte>>;
    [[nodiscard]] auto take_faults() -> std::vector<FaultEvent>;

    auto tick(Clock::time_point now) -> void;
    [[nodiscard]] auto next_wake(Clock::time_point now) const -> std::optional<Clock::time_point>;

    [[nodiscard]] auto pending() const noexcept -> std::size_t { return _ops.size(); }
    [[nodiscard]] auto session_open() const noexcept -> bool { return _state == State::open; }

private:
    enum class State : std::uint8_t {
        down,
        hello,
        open
    };
    enum class Kind : std::uint8_t {
        read,
        write,
        hydrate  // a write with the hydrate flag
    };

    struct Route {
        proto::ReplicaConfig config;
        std::uint32_t generation{0};
        proto::AttachMode mode{proto::AttachMode::rw};
    };
    struct Op {
        Kind kind{Kind::read};
        std::uint64_t offset{0};
        std::span<std::byte> out;
        std::span<const std::byte> in;
        std::vector<std::byte> crcs;  // writes: one le32 per block
        BackendCompletion done;
        Clock::time_point deadline;
        std::size_t parts_left{0};
        bool split{false};
    };
    struct Part {
        std::uint64_t op{0};
        std::uint64_t request_id{0};
        Kind kind{Kind::read};
        std::uint64_t lba{0};
        std::uint32_t blocks{0};
        std::size_t first_block{0};  // within the op
        bool sent{false};
        int retries{0};
        Clock::time_point not_before{};
    };

    auto submit(Kind kind, std::uint64_t offset, std::span<std::byte> out,
                std::span<const std::byte> in, BackendCompletion done, Clock::time_point now)
        -> void;
    auto split(std::uint64_t id, Op& op) -> void;
    auto pump(Clock::time_point now) -> void;
    auto send_hello() -> void;
    auto drop_session(Clock::time_point retry_at) -> void;
    auto complete(std::uint64_t id, BackendResult r) -> void;
    auto fail_all(BackendError e) -> void;
    auto fence() -> void;
    auto fault(InitiatorFault kind) -> void;
    auto part_done(std::deque<Part>::iterator it) -> void;
    auto on_reply(std::deque<Part>::iterator it, const proto::HoldFrame& f, Clock::time_point now)
        -> void;
    auto on_redirect(const proto::HoldFrame& f, Clock::time_point now) -> void;
    [[nodiscard]] auto admit(std::uint64_t bytes, Clock::time_point now) -> bool;
    [[nodiscard]] auto qos_wait() const -> Clock::duration;
    [[nodiscard]] auto blocked(std::deque<Part>::const_iterator it) const -> bool;
    [[nodiscard]] auto header(proto::HoldOpcode op) const -> proto::HoldHeader;
    [[nodiscard]] auto outstanding() const -> bool;
    auto run_completions() -> void;

    InitiatorConfig _config;
    std::optional<Route> _route;
    bool _fenced{false};
    bool _stale{false};  // the hold knows a newer epoch: wait for the config
    State _state{State::down};
    std::uint64_t _session{1};
    Clock::time_point _reconnect_at{};
    Clock::time_point _last_heard{};  // the last frame, or when waiting began
    Clock::time_point _last_sent{};
    bool _ping_out{false};
    TokenBucket _ios;
    TokenBucket _mib;
    std::map<std::uint64_t, Op> _ops;
    std::deque<Part> _parts;  // submit order
    std::uint64_t _next_op{1};
    std::uint64_t _next_request{1};
    std::vector<std::vector<std::byte>> _out;
    std::vector<FaultEvent> _faults;
    std::vector<std::pair<BackendCompletion, BackendResult>> _ready;
    bool _running_completions{false};
};

}  // namespace ak::oar::blk
