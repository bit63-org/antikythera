// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The connections of one network volume attachment: hold wire sessions
// over mutually authenticated TLS 1.3 on the storage segment, for an
// initiator core that does no I/O (InitiatorCore for hold, one session;
// KholdInitiatorCore for khold, one per leader or gateway). Shared by
// NetworkVolumeBackend and KholdVolumeBackend.
//
// Threads. The role thread calls sync(), take_events() and arm(); each
// session has its own I/O thread, so a connect that hangs on one server
// (up to connect_timeout) never holds up the sessions to the others. They
// share a mailbox: the sessions wanted and the frames for each one way,
// connection events and received frames the other. The inbox's eventfd
// and a timerfd armed for the core's next wake sit in one epoll
// descriptor, wake_fd().
//
// Sessions. Every session the core names (HoldTarget, with its own
// session number) gets one connection attempt: connected, then frames,
// then disconnected when it ends; or disconnected at once when the
// connect fails. A session the core stops naming is closed without an
// event (the core has already moved on). Each connection gets a fresh
// TLS context pinning the server's address (its IP SAN), and is used only
// if the certificate's server URI names the server ID the target gives.
// Storage traffic carries DSCP AF41. A stream that does not split into
// frames of the transport's wire version ends its session.
//
// The process must ignore SIGPIPE, as the roles' mains do.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <vector>

#include "oar/blk/initiator.hpp"
#include "tls/tls.hpp"

namespace ak::oar::blk {

enum class NetworkVolumeError : std::uint8_t {
    tls,     // the TLS configuration does not load
    system,  // an eventfd, timerfd, epoll descriptor or a thread failed
};

[[nodiscard]] auto to_string(NetworkVolumeError e) noexcept -> const char*;

struct HoldTransportConfig {
    tls::Config tls;  // client; peer_name is set per connection
    std::chrono::milliseconds connect_timeout{2000};
    std::chrono::milliseconds write_timeout{2000};
    std::uint8_t wire_version{1};  // proto::hold_version or proto::hold_v2_version
};

class HoldTransport {
public:
    using Clock = std::chrono::steady_clock;
    using Bytes = std::vector<std::byte>;

    enum class EventKind : std::uint8_t {
        connected,
        disconnected,
        frame
    };
    struct Event {
        EventKind kind{EventKind::frame};
        std::uint64_t session{0};
        Bytes frame;
    };
    struct Outgoing {
        std::uint64_t session{0};
        Bytes frame;
    };

    [[nodiscard]] static auto create(HoldTransportConfig config)
        -> std::expected<std::unique_ptr<HoldTransport>, NetworkVolumeError>;

    HoldTransport(const HoldTransport&) = delete;
    auto operator=(const HoldTransport&) -> HoldTransport& = delete;
    HoldTransport(HoldTransport&&) = delete;
    auto operator=(HoldTransport&&) -> HoldTransport& = delete;
    // Stops every I/O thread (each after at most one connect_timeout).
    ~HoldTransport();

    // A renewed storage certificate: the next connection presents it.
    auto set_tls(const tls::Config& config) -> void;
    // The sessions to have open, and frames for them in order; frames for
    // a session not in `targets` are dropped.
    auto sync(const std::vector<HoldTarget>& targets, std::vector<Outgoing> frames) -> void;
    // Drains wake_fd() and returns what the I/O threads posted, in order.
    [[nodiscard]] auto take_events() -> std::vector<Event>;
    // Arms the timer for `wake` (steady_clock); nullopt disarms it.
    auto arm(std::optional<Clock::time_point> wake) -> void;
    [[nodiscard]] auto wake_fd() const noexcept -> int;

private:
    struct Shared;
    struct Conn;
    explicit HoldTransport(std::unique_ptr<Shared> shared) noexcept;
    auto reap(bool all) -> void;

    std::unique_ptr<Shared> _shared;
};

}  // namespace ak::oar::blk
