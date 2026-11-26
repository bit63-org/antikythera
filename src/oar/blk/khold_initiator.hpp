// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The initiator's protocol logic for one khold volume attachment: hold
// wire version 2 over a striped volume (kythira
// .kiro/specs/khold-block-service/ task 16, design "Striping", "Layouts,
// authority and fencing", "Hold wire protocol version 2", "Error
// handling"; Requirements 3.3, 3.4, 4.2, 9.1, 9.9, 11.3, 11.4). No I/O and
// no threads: KholdVolumeBackend (khold_volume_backend.hpp) carries the
// frames over TLS, one session per server, and the tests drive the core
// against in-process khold nodes. InitiatorCore (initiator.hpp) is the
// version 1 counterpart for hold volumes; the two share their request,
// QoS and completion rules.
//
// Layout. Until set_layout() delivers the volume's signed VolumeLayout,
// requests are held, not failed (their deadlines start when it arrives).
// Each later layout moves the epoch; it may grow the capacity and change
// the QoS limits and the members, but not the block size or the striping
// (re-striping is a mirror migration, Requirement 3.5).
//
// Striping. Block b of the volume is in stripe unit u = b / (SU / bs) and
// belongs to group u mod G. A request is split at every stripe unit
// boundary and every max_hold_blocks / max_hold_data_bytes, and each part
// goes to its group (Requirement 3.3); a part names its first block
// volume-relative, its group ID and the term the initiator last saw for
// that group.
//
// Leaders. The core keeps, per group, the server it believes leads it and
// that leader's term. The first guess is the group's data members in turn
// (group i starts at data member i mod n, so leaders spread). A REDIRECT
// (status not_leader) naming a data member of the group in the current
// layout, at a term no older than the one known, moves the guess there
// and the part is resent at once; a redirect naming nobody, a server
// outside the layout or an older term moves the guess to the next data
// member and the part waits retry_backoff (an election is under way).
// unknown_group does the same. So a compromised node can delay requests
// but never steer them outside the group (Requirement 11.3).
//
// Sessions. Co-located (no gateways in the layout), the core keeps one
// session per server that leads a group it has parts for; split, one per
// gateway, each group using gateway (i + k) mod the gateway count, where k
// moves on whenever that gateway fails. At most max_sessions sessions are
// open: an idle one (nothing in flight, no part waiting for it) is closed
// to make room, otherwise parts wait. A session is HELLO (initiator role,
// attachment and generation) and then requests; hello_ok must agree with
// the layout's block size and striping. An idle session is PINGed every
// ping_interval; a session that answers nothing for leader_timeout while
// something is outstanding is presumed lost: the core reports
// primary_timeout for that server, drops the session (its unacknowledged
// parts are resent, in order, elsewhere) and moves every group it led to
// the next data member (Requirement 9.1). A refused or lost connection
// moves them too. A server just dropped is not tried again for
// retry_backoff.
//
// Requests. As in version 1: parts go out in submit order, at most
// max_in_flight at a time across the volume, shaped by the two QoS token
// buckets; a write, discard or write-zeroes never goes out while an
// earlier overlapping one is unacknowledged, so resends are idempotent
// (Requirement 3.4); writes carry a CRC32C per block over their
// ciphertext and reads are checked (a block never written, or freed, is
// zeros with CRC 0) and retried once on a mismatch. FLUSH completes at
// once: every completed write is durable on the group's in-sync replicas.
// DISCARD and WRITE_ZEROES (Requirement 4.2) are parts without data.
//
// Replies:
//   ok                        done (reads checked; a newer term recorded)
//   not_leader + REDIRECT,
//     unknown_group           as above
//   stale_epoch, newer        wait for the next layout (every session closes)
//   stale_epoch, not newer    resent
//   throttled, repairing      resent after retry_backoff
//   io_suspended              resent after 4 x retry_backoff
//   checksum (write)          resent up to twice, then io
//   fenced                    every request fails; the attachment is over
//   no_space, read_only       io for that request only (Requirement 4.5)
//   io_error                  io, and a media_error fault for that server
//   range                     out_of_range;  anything else  io
// A request still not done at its deadline (request_timeout after submit,
// or after the layout arrived) fails with io, so the guest never hangs.
// A layout with io_suspended set holds every request until its deadline.
//
// Faults (take_faults) name the server they are about and the epoch held:
// primary_timeout for a leader (or gateway) that stopped answering,
// checksum for every read mismatch, media_error for io_error, and fenced.
// BlkRole forwards them to helm (Requirement 9.9).
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
#include <utility>
#include <vector>

#include "common/token_bucket.hpp"
#include "oar/blk/initiator.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "proto/hold_wire_v2.hpp"
#include "proto/volume_layout.hpp"

namespace ak::oar::blk {

struct KholdInitiatorConfig {
    std::uint64_t attachment_id{0};
    std::chrono::milliseconds request_timeout{30000};
    std::chrono::milliseconds leader_timeout{2000};
    std::chrono::milliseconds ping_interval{1000};
    std::chrono::milliseconds retry_backoff{250};
    std::size_t max_in_flight{64};  // parts in flight across the volume
    std::size_t max_sessions{16};
};

// One frame for one session.
struct SessionFrame {
    std::uint64_t session{0};
    std::vector<std::byte> frame;
};

class KholdInitiatorCore {
public:
    using Clock = std::chrono::steady_clock;

    explicit KholdInitiatorCore(KholdInitiatorConfig config) noexcept;

    // The layout must already be verified (signature, recipient) by the
    // caller. wrong_volume, stale and mismatch as for InitiatorCore.
    [[nodiscard]] auto set_layout(const proto::VolumeLayout& l, Clock::time_point now)
        -> std::expected<void, RouteError>;
    [[nodiscard]] auto routed() const noexcept -> bool { return _layout.has_value(); }
    [[nodiscard]] auto fenced() const noexcept -> bool { return _fenced; }
    [[nodiscard]] auto capacity_bytes() const noexcept -> std::uint64_t;

    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done,
                     Clock::time_point now) -> void;
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done,
                      Clock::time_point now) -> void;
    auto submit_discard(std::uint64_t offset, std::uint64_t length, BackendCompletion done,
                        Clock::time_point now) -> void;
    auto submit_write_zeroes(std::uint64_t offset, std::uint64_t length, BackendCompletion done,
                             Clock::time_point now) -> void;
    auto submit_flush(BackendCompletion done) -> void;

    // The sessions the transport should have open, each with its own
    // session number (a new number for every new session, even to the same
    // server). A session left out should be closed.
    [[nodiscard]] auto targets(Clock::time_point now) const -> std::vector<HoldTarget>;
    // The transport opened (TLS, server identity checked) or lost `session`.
    auto connected(std::uint64_t session, Clock::time_point now) -> void;
    auto disconnected(std::uint64_t session, Clock::time_point now) -> void;
    auto on_frame(std::uint64_t session, const proto::HoldV2Frame& f, Clock::time_point now)
        -> void;

    // Frames for open sessions, in order per session.
    [[nodiscard]] auto take_output() -> std::vector<SessionFrame>;
    [[nodiscard]] auto take_faults() -> std::vector<FaultEvent>;

    auto tick(Clock::time_point now) -> void;
    [[nodiscard]] auto next_wake(Clock::time_point now) const -> std::optional<Clock::time_point>;

    [[nodiscard]] auto pending() const noexcept -> std::size_t { return _ops.size(); }
    [[nodiscard]] auto sessions_open() const noexcept -> std::size_t;
    // The server the core believes leads stripe group `index` (0: none).
    [[nodiscard]] auto leader_of(std::size_t index) const noexcept -> std::uint64_t;

private:
    enum class State : std::uint8_t {
        down,
        hello,
        open
    };
    enum class Kind : std::uint8_t {
        read,
        write,
        discard,
        write_zeroes
    };

    struct Group {
        std::uint64_t group_id{0};
        std::uint64_t leader{0};  // the server believed to lead it
        std::uint64_t term{0};    // that leader's term, 0: unknown
        std::size_t gateway{0};   // split layouts: index into the gateways
    };
    struct Session {
        std::uint64_t id{0};
        std::uint64_t server{0};
        proto::StorageEndpoint endpoint{};
        std::uint16_t port{0};
        State state{State::down};
        Clock::time_point connect_at{};  // down: when to ask for it
        Clock::time_point last_heard{};
        Clock::time_point last_sent{};
        bool ping_out{false};
    };
    struct Op {
        Kind kind{Kind::read};
        std::uint64_t offset{0};
        std::uint64_t length{0};
        std::span<std::byte> out;
        std::span<const std::byte> in;
        std::vector<std::byte> crcs;  // writes: one le32 per block
        BackendCompletion done;
        Clock::time_point deadline;
        std::size_t parts_left{0};
    };
    struct Part {
        std::uint64_t op{0};
        std::uint64_t request_id{0};
        Kind kind{Kind::read};
        std::size_t group{0};  // stripe order index
        std::uint64_t lba{0};
        std::uint32_t blocks{0};
        std::size_t first_block{0};  // within the op
        std::uint64_t sent_on{0};    // session ID; 0: not sent
        int retries{0};
        Clock::time_point not_before{};
    };

    auto submit(Kind kind, std::uint64_t offset, std::uint64_t length, std::span<std::byte> out,
                std::span<const std::byte> in, BackendCompletion done, Clock::time_point now)
        -> void;
    auto split(std::uint64_t id, Op& op) -> void;
    auto seed_groups() -> void;
    auto pump(Clock::time_point now) -> void;
    auto plan_sessions(Clock::time_point now) -> void;
    [[nodiscard]] auto destination(std::size_t group) const -> std::uint64_t;
    [[nodiscard]] auto endpoint_of(std::uint64_t server) const
        -> std::optional<std::pair<proto::StorageEndpoint, std::uint16_t>>;
    [[nodiscard]] auto session_of(std::uint64_t id) -> Session*;
    [[nodiscard]] auto in_flight_on(const Session& s) const -> bool;
    auto drop_session(Session& s, Clock::time_point now) -> void;
    auto drop_all(Clock::time_point now) -> void;
    // Moves every group whose destination is `server` to its next candidate.
    auto rotate_from(std::uint64_t server) -> void;
    auto rotate(Group& g, std::size_t index) -> void;
    auto send_hello(Session& s) -> void;
    auto complete(std::uint64_t id, BackendResult r) -> void;
    auto fail_all(BackendError e) -> void;
    auto fence() -> void;
    auto fault(InitiatorFault kind, std::uint64_t server) -> void;
    auto part_done(std::deque<Part>::iterator it) -> void;
    auto on_reply(std::deque<Part>::iterator it, Session& s, const proto::HoldV2Frame& f,
                  Clock::time_point now) -> void;
    auto on_redirect(Session& s, const proto::HoldV2Frame& f, Clock::time_point now) -> void;
    auto on_hello(Session& s, const proto::HoldV2Frame& f, Clock::time_point now) -> void;
    auto resend_group_on(std::size_t group, const Session& s, Clock::time_point not_before) -> void;
    [[nodiscard]] auto admit(std::uint64_t bytes, Clock::time_point now) -> bool;
    [[nodiscard]] auto qos_wait() const -> Clock::duration;
    [[nodiscard]] auto blocked(std::deque<Part>::const_iterator it) const -> bool;
    [[nodiscard]] auto header(proto::HoldV2Opcode op) const -> proto::HoldV2Header;
    [[nodiscard]] auto group_index(std::uint64_t group_id) const -> std::optional<std::size_t>;
    [[nodiscard]] auto suspended() const noexcept -> bool;
    auto run_completions() -> void;

    KholdInitiatorConfig _config;
    std::optional<proto::VolumeLayout> _layout;
    std::uint32_t _generation{0};
    proto::AttachMode _mode{proto::AttachMode::rw};
    bool _fenced{false};
    bool _stale{false};  // a node knows a newer epoch: wait for the layout
    std::vector<Group> _groups;
    std::map<std::uint64_t, Session> _sessions;            // by server
    std::map<std::uint64_t, Clock::time_point> _cooldown;  // server -> not before
    std::uint64_t _next_session{1};
    TokenBucket _ios;
    TokenBucket _mib;
    std::map<std::uint64_t, Op> _ops;
    std::deque<Part> _parts;  // submit order
    std::uint64_t _next_op{1};
    std::uint64_t _next_request{1};
    std::vector<SessionFrame> _out;
    std::vector<FaultEvent> _faults;
    std::vector<std::pair<BackendCompletion, BackendResult>> _ready;
    bool _running_completions{false};
};

}  // namespace ak::oar::blk
