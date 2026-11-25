// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MetadataServer: the network role's metadata connections
// (.kiro/specs/oar-net-data-plane/ Requirements 13.5 to 13.7, design
// "Metadata service"; task 21.4).
//
// Each connection belongs to one NIC, fixed when it is accepted: the
// listening socket's peer address is mapped to its NIC by a PeerResolver
// (the TAP's per-NIC aliases, task 21.5), and adopt() takes a connection
// whose NIC is already known (socket pairs in tests, harbor's in-process
// placement). Nothing the guest sends can change it.
//
// Requests are served one at a time per connection (HTTP/1.1 keep-alive,
// no pipelining in parallel), each answered from the NIC's current view,
// looked up per request so a newer record applies at once. Limits:
//
//   - a request head must arrive within read_deadline (2 s) of its first
//     byte, and an idle connection is closed after idle_deadline (5 s);
//   - at most per_nic connections per NIC (16) and total in all (1,024);
//     one more is reset as it is accepted;
//   - a malformed request is answered 400, 414 or 431 and closed.
//
// A token answer's socket gets its IP TTL or IPv6 hop limit set to the
// record's hop limit before the answer is written (Requirement 13.6). It
// stays at that value for the rest of the connection: every later answer
// goes to the same peer, which the token answer already reached.
//
// A NIC whose endpoint is disabled, or that has no record, has its
// connections reset (SO_LINGER 0) instead of answered; reset_nic() does
// the same when the role learns of it between requests.
//
// Not thread-safe: run_once() belongs to the role's metadata thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <sys/socket.h>

#include "oar/net/metadata_http.hpp"

namespace ak::oar::net {

using MetadataClock = std::chrono::steady_clock;

struct MetadataLimits {
    std::chrono::milliseconds read_deadline{2000};
    std::chrono::milliseconds idle_deadline{5000};
    std::size_t per_nic{16};
    std::size_t total{1024};
};

// The NIC's view for one request; its record pointer need only stay
// valid until the next call.
using MetadataViews = std::function<MetadataView(std::uint64_t nic_id)>;

// The NIC a connection from `peer` belongs to, if any.
using PeerResolver =
    std::function<std::optional<std::uint64_t>(const sockaddr_storage& peer, socklen_t length)>;

// Sets a socket's unicast TTL or hop limit; true when set.
using HopLimitSetter = std::function<bool(int fd, std::uint8_t hops)>;

// IP_TTL on an IPv4 socket, IPV6_UNICAST_HOPS (and IP_TTL, for mapped
// addresses) on an IPv6 one; a socket of another family needs none and
// answers true.
[[nodiscard]] auto set_hop_limit(int fd, std::uint8_t hops) -> bool;

struct MetadataServerCounters {
    std::uint64_t accepted{0};
    std::uint64_t refused_limit{0};    // over per_nic or total
    std::uint64_t refused_unknown{0};  // a peer the resolver does not know
    std::uint64_t requests{0};
    std::uint64_t bad_requests{0};  // answered 400, 414 or 431
    std::uint64_t tokens{0};        // tokens issued
    std::uint64_t unauthorized{0};  // answered 401
    std::uint64_t timeouts{0};      // read or idle deadline
    std::uint64_t resets{0};        // endpoint disabled, no record, or reset_nic
    std::uint64_t hop_limit_failures{0};
};

class MetadataServer {
public:
    MetadataServer(TokenKey key, MetadataViews views, MetadataLimits limits = {});
    MetadataServer(const MetadataServer&) = delete;
    auto operator=(const MetadataServer&) -> MetadataServer& = delete;
    MetadataServer(MetadataServer&&) = delete;
    auto operator=(MetadataServer&&) -> MetadataServer& = delete;
    ~MetadataServer();

    // Takes a listening socket (made non-blocking here) and accepts from
    // it in run_once(), mapping each peer with `resolver`.
    auto listen(int fd, PeerResolver resolver) -> void;

    // Takes a connected socket for `nic_id`. False when over a limit: the
    // socket is reset and closed.
    auto adopt(int fd, std::uint64_t nic_id, MetadataClock::time_point now) -> bool;

    // Waits up to `timeout` for activity, then accepts, reads, answers,
    // writes and enforces the deadlines as of `now`.
    auto run_once(MetadataClock::time_point now, std::chrono::milliseconds timeout) -> void;

    // Resets every connection of `nic_id` (its endpoint was disabled, or
    // it was cleaned).
    auto reset_nic(std::uint64_t nic_id) -> void;

    auto set_hop_limit_setter(HopLimitSetter setter) -> void { _set_hops = std::move(setter); }

    [[nodiscard]] auto connections() const noexcept -> std::size_t { return _connections.size(); }
    [[nodiscard]] auto connections(std::uint64_t nic_id) const -> std::size_t;
    [[nodiscard]] auto counters() const noexcept -> const MetadataServerCounters& {
        return _counters;
    }

private:
    enum class Next : std::uint8_t {
        keep,
        close,
        reset
    };

    struct Connection {
        int fd{-1};
        std::uint64_t nic_id{0};
        std::string in;
        std::string out;
        std::size_t written{0};
        bool close_after{false};
        std::optional<MetadataClock::time_point> request_started;
        MetadataClock::time_point last_activity;
    };

    auto accept_ready(MetadataClock::time_point now) -> void;
    // What becomes of the connection after reading or writing.
    auto read_ready(Connection& c, MetadataClock::time_point now) -> Next;
    auto serve(Connection& c, MetadataClock::time_point now) -> Next;
    auto close(std::size_t index, bool reset) -> void;

    TokenKey _key;
    MetadataViews _views;
    MetadataLimits _limits;
    HopLimitSetter _set_hops;
    int _listen_fd{-1};
    PeerResolver _resolver;
    std::vector<std::unique_ptr<Connection>> _connections;
    std::map<std::uint64_t, std::size_t> _per_nic;
    MetadataServerCounters _counters;
};

}  // namespace ak::oar::net
