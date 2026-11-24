// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A hold role on the storage network (.kiro/specs/block-volume-service/
// task 6): a TLS 1.3 listener on the storage segment, one HoldServer
// session per connection. Each peer presents a certificate from the
// controller's CA; the server ID its URI subjectAltName carries
// (identity.hpp) is the only identity the server sees, and a certificate
// without exactly one is refused (Requirement 13.2). Sockets carry the
// storage I/O class (DSCP AF41; design "Priority").
//
// One thread: run_once() waits on the listener and the connections (or
// until the server's next QoS wake), reads and decodes frames, hands them
// to the server and runs it. A frame that does not decode closes its
// connection. v1 simplifications: the TLS handshake and replies are
// written with a deadline on this thread, so a stalled peer can delay the
// others by up to that deadline before it is dropped.
//
// Replication (task 8): the server dials its members through dial(). Each
// dial connects on a thread of its own (the same certificate, as a
// client, pinning the member's IP SAN), so a dead member never stalls the
// loop; run_once() takes the finished ones, keeps a connection only if its
// certificate names the member's server ID, and tells the server.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "hold/server/server.hpp"
#include "proto/codec.hpp"
#include "proto/hold_stream.hpp"
#include "proto/storage_net.hpp"
#include "tls/tls.hpp"

#include <mutex>
#include <thread>

namespace ak::hold {

using proto::FrameAssembler;

using proto::storage_io_tos;

struct NodeConfig {
    std::string host;       // the storage segment address to listen on
    std::uint16_t port{0};  // 0: any free port (see Node::port)
    tls::Config tls;        // role server; peer_name empty; also dials members
    ServerConfig server;
    std::chrono::milliseconds handshake_timeout{5000};
    std::chrono::milliseconds write_timeout{5000};
};

class Node final : public SessionSink {
public:
    [[nodiscard]] static auto create(store::FileLayer& files, NodeConfig config)
        -> std::expected<std::unique_ptr<Node>, tls::Error>;

    Node(const Node&) = delete;
    auto operator=(const Node&) -> Node& = delete;
    Node(Node&&) = delete;
    auto operator=(Node&&) -> Node& = delete;
    // Waits for dials still connecting (each at most handshake_timeout).
    ~Node() override;

    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return _listener.port(); }
    [[nodiscard]] auto server() noexcept -> HoldServer& { return _server; }
    [[nodiscard]] auto connections() const noexcept -> std::size_t { return _conns.size(); }

    // Waits up to max_wait for work, then does it. `extra_fd` (if not -1)
    // is waited on too, for the caller's own work (helm's sideband): true
    // when it is readable or has hung up.
    auto run_once(Clock::duration max_wait, int extra_fd = -1) -> bool;

    auto send(SessionId session, std::vector<std::byte> frame) -> void override;
    auto dial(SessionId session, std::uint64_t server_id, const proto::StorageEndpoint& endpoint,
              std::uint16_t port) -> void override;
    auto hang_up(SessionId session) -> void override;

private:
    struct Connection {
        tls::Stream stream;
        SessionId session{0};
        FrameAssembler in;
        bool dead{false};
    };

    // Dials finished on their threads, waiting for run_once().
    struct Dialed {
        SessionId session{0};
        std::uint64_t server_id{0};
        std::optional<tls::Stream> stream;
    };
    struct Dials {
        Dials(const Dials&) = delete;
        auto operator=(const Dials&) -> Dials& = delete;
        Dials(Dials&&) = delete;
        auto operator=(Dials&&) -> Dials& = delete;
        explicit Dials(int fd) noexcept : wake{fd} {}
        ~Dials();
        int wake;  // eventfd: a dial finished
        std::mutex mutex;
        std::vector<Dialed> done;
    };

    Node(store::FileLayer& files, NodeConfig config, tls::Context ctx, tls::Listener listener,
         int dial_wake) noexcept;

    auto accept() -> void;
    auto read(Connection& c, Clock::time_point now) -> void;
    auto reap() -> void;
    auto take_dials(Clock::time_point now) -> void;

    NodeConfig _config;
    tls::Context _ctx;
    tls::Listener _listener;
    HoldServer _server;
    std::map<SessionId, Connection> _conns;
    Dials _dials;
    std::map<SessionId, std::thread> _dialing;
    std::vector<SessionId> _cancelled;  // hung up while dialing
};

}  // namespace ak::hold
