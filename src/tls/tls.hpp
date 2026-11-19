// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Mutually authenticated TLS over TCP for the ControllerLink
// (.kiro/specs/controller-interface/ Requirement 2.2): helm is the client,
// the controller (kythira, or harbor's test controller) the server.
//
// Policy, fixed here rather than configurable:
//   - TLS 1.3 only.
//   - Both sides present a certificate and verify the other's chain
//     against one trust anchor (the CA in Config::ca_pem): for helm that is
//     kythira's CA, for the controller the CA that issues server certs.
//   - The client checks the server's name (DNS SAN, or IP SAN when
//     peer_name is an address). The server optionally pins the client's
//     name the same way; empty accepts any certificate the CA issued.
//
// Sockets are non-blocking. Every call that can wait takes a deadline and
// polls, so a silent peer can never hang the caller.
//
// OpenSSL appears only in tls.cpp; this header exposes RAII types.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>

namespace ak::tls {

enum class Role : std::uint8_t {
    client,
    server,
};

struct Config {
    Role role{Role::client};
    std::string ca_pem;    // trust anchor for the peer's chain
    std::string cert_pem;  // our certificate, then any intermediates
    std::string key_pem;   // our private key
    // Client: the server's expected DNS name or IP address (required).
    // Server: the client's expected name, or empty for any CA-issued cert.
    std::string peer_name;
};

enum class Error : std::uint8_t {
    bad_config,        // a PEM did not parse, or the key does not match the cert
    resolve_failed,    // the host name did not resolve
    connect_failed,    // TCP connect failed or timed out
    handshake_failed,  // TLS handshake failed, including peer verification
    timed_out,         // a read or write deadline passed
    closed,            // the peer closed the connection cleanly
    io,                // any other socket or TLS failure
};

[[nodiscard]] auto to_string(Error e) noexcept -> const char*;

using Clock = std::chrono::steady_clock;

struct ContextImpl;
struct StreamImpl;

// A TLS configuration, shared by every connection made from it.
class Context {
public:
    [[nodiscard]] static auto create(const Config& config) -> std::expected<Context, Error>;

    Context(Context&&) noexcept;
    auto operator=(Context&&) noexcept -> Context&;
    Context(const Context&) = delete;
    auto operator=(const Context&) -> Context& = delete;
    ~Context();

    [[nodiscard]] auto role() const noexcept -> Role;
    [[nodiscard]] auto impl() const noexcept -> ContextImpl& { return *_impl; }

private:
    explicit Context(std::unique_ptr<ContextImpl> impl) noexcept;
    std::unique_ptr<ContextImpl> _impl;
};

// One established, verified TLS connection.
class Stream {
public:
    // Resolves host, connects and completes the handshake by the deadline.
    [[nodiscard]] static auto connect(const Context& ctx, const std::string& host,
                                      std::uint16_t port, Clock::time_point deadline)
        -> std::expected<Stream, Error>;

    // Takes ownership of an accepted socket and completes the handshake.
    [[nodiscard]] static auto accept(const Context& ctx, int fd, Clock::time_point deadline)
        -> std::expected<Stream, Error>;

    Stream(Stream&&) noexcept;
    auto operator=(Stream&&) noexcept -> Stream&;
    Stream(const Stream&) = delete;
    auto operator=(const Stream&) -> Stream& = delete;
    ~Stream();

    // The socket, for poll(). Readable data may also be buffered inside
    // TLS: check pending() before waiting on the socket.
    [[nodiscard]] auto fd() const noexcept -> int;
    [[nodiscard]] auto pending() const noexcept -> bool;

    // Reads what is available without waiting: 0 bytes means nothing yet.
    [[nodiscard]] auto read_some(std::span<std::byte> out) -> std::expected<std::size_t, Error>;

    // Writes everything by the deadline.
    [[nodiscard]] auto write_all(std::span<const std::byte> bytes, Clock::time_point deadline)
        -> std::expected<void, Error>;

    // Sends close_notify (best effort) and closes the socket.
    auto close() noexcept -> void;

private:
    explicit Stream(std::unique_ptr<StreamImpl> impl) noexcept;
    std::unique_ptr<StreamImpl> _impl;
};

// A listening TCP socket (the controller side).
class Listener {
public:
    // Binds host:port; port 0 picks a free port (see port()).
    [[nodiscard]] static auto bind(const std::string& host, std::uint16_t port)
        -> std::expected<Listener, Error>;

    Listener(Listener&&) noexcept;
    auto operator=(Listener&&) noexcept -> Listener&;
    Listener(const Listener&) = delete;
    auto operator=(const Listener&) -> Listener& = delete;
    ~Listener();

    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return _port; }
    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }

    // Waits for one TCP connection until the deadline and returns its
    // socket (non-blocking), for Stream::accept.
    [[nodiscard]] auto accept_fd(Clock::time_point deadline) -> std::expected<int, Error>;

private:
    Listener(int fd, std::uint16_t port) noexcept : _fd{fd}, _port{port} {}
    int _fd{-1};
    std::uint16_t _port{0};
};

}  // namespace ak::tls
