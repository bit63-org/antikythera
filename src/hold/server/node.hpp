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
#include "tls/tls.hpp"

namespace ak::hold {

using proto::FrameAssembler;

// DSCP AF41 in the TOS / traffic class byte: storage I/O (design "Priority").
inline constexpr int storage_io_tos = 34 << 2;

struct NodeConfig {
    std::string host;       // the storage segment address to listen on
    std::uint16_t port{0};  // 0: any free port (see Node::port)
    tls::Config tls;        // role server; peer_name empty
    ServerConfig server;
    std::chrono::milliseconds handshake_timeout{5000};
    std::chrono::milliseconds write_timeout{5000};
};

class Node final : public SessionSink {
public:
    [[nodiscard]] static auto create(store::FileLayer& files, NodeConfig config)
        -> std::expected<std::unique_ptr<Node>, tls::Error>;

    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return _listener.port(); }
    [[nodiscard]] auto server() noexcept -> HoldServer& { return _server; }
    [[nodiscard]] auto connections() const noexcept -> std::size_t { return _conns.size(); }

    // Waits up to max_wait for work, then does it.
    auto run_once(Clock::duration max_wait) -> void;

    auto send(SessionId session, std::vector<std::byte> frame) -> void override;

private:
    struct Connection {
        tls::Stream stream;
        SessionId session{0};
        FrameAssembler in;
        bool dead{false};
    };

    Node(store::FileLayer& files, NodeConfig config, tls::Context ctx,
         tls::Listener listener) noexcept;

    auto accept() -> void;
    auto read(Connection& c, Clock::time_point now) -> void;
    auto reap() -> void;

    NodeConfig _config;
    tls::Context _ctx;
    tls::Listener _listener;
    HoldServer _server;
    std::map<SessionId, Connection> _conns;
};

}  // namespace ak::hold
