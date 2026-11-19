// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Sideband transport bindings for OarLink (.kiro/specs/helm-control-plane/
// Requirement 7.1, design "OarLink"; .kiro/specs/harbor-virt-on-virt/
// Requirement 3.2).
//
// A binding moves whole MCTP SMBus packets (helm/mctp.hpp: address, command
// code, byte count, transport header, payload, PEC) between helm and one
// data-plane role, one packet per send or receive. Every binding carries the
// same encoded packets the SMBus wire does, so the codec, reassembly and
// PEC checks run identically in every placement and only this layer
// differs (Requirement 7.1):
//
//   InProcessBinding  a pair of bounded in-memory queues, for the combined
//                     placement and for tests.
//   SocketBinding     one AF_UNIX SOCK_SEQPACKET socket per slot, for harbor
//                     board processes. Datagram boundaries are packet
//                     boundaries, so no extra framing is needed.
//   SmbusBinding      (hardware, later) and I3cBinding (later).
//
// A binding is used by one thread at a time per direction; InProcessBinding
// endpoints may sit on different threads. Neither binding authenticates
// (Requirement 5.3): segment isolation, here socket file permissions or
// process boundaries, is the boundary.

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <utility>
#include <vector>

namespace ak::helm {

enum class BindingError : std::uint8_t {
    timed_out,     // nothing arrived before the timeout
    disconnected,  // the peer is gone; the binding will not recover
    oversized,     // receive: a datagram larger than any MCTP packet was dropped
                   // send: the packet is larger than any MCTP packet
    queue_full,    // InProcessBinding: the peer is not draining its queue
    io,            // any other OS error
};

[[nodiscard]] auto to_string(BindingError e) noexcept -> const char*;

class Binding {
public:
    Binding() = default;
    Binding(const Binding&) = delete;
    auto operator=(const Binding&) -> Binding& = delete;
    Binding(Binding&&) = delete;
    auto operator=(Binding&&) -> Binding& = delete;
    virtual ~Binding() = default;

    // Sends one encoded packet (at most mctp::max_packet_size bytes).
    virtual auto send(std::span<const std::byte> packet) -> std::expected<void, BindingError> = 0;

    // Waits up to `timeout` for one packet. A zero timeout polls.
    virtual auto receive(std::chrono::milliseconds timeout)
        -> std::expected<std::vector<std::byte>, BindingError> = 0;
};

// ---- InProcessBinding ------------------------------------------------------

class InProcessBinding final : public Binding {
public:
    // Packets queued per direction before send() fails with queue_full. A
    // peer that stops reading must not make the other side buffer without
    // bound.
    static constexpr std::size_t default_capacity = 64;

    // Two connected endpoints. Destroying one disconnects the other.
    [[nodiscard]] static auto make_pair(std::size_t capacity = default_capacity)
        -> std::pair<std::unique_ptr<InProcessBinding>, std::unique_ptr<InProcessBinding>>;

    InProcessBinding(const InProcessBinding&) = delete;
    auto operator=(const InProcessBinding&) -> InProcessBinding& = delete;
    InProcessBinding(InProcessBinding&&) = delete;
    auto operator=(InProcessBinding&&) -> InProcessBinding& = delete;
    ~InProcessBinding() override;

    auto send(std::span<const std::byte> packet) -> std::expected<void, BindingError> override;
    auto receive(std::chrono::milliseconds timeout)
        -> std::expected<std::vector<std::byte>, BindingError> override;

private:
    struct Channel {
        std::mutex mutex;
        std::condition_variable ready;
        std::array<std::deque<std::vector<std::byte>>, 2> queues;  // indexed by receiver
        std::array<bool, 2> closed{};                              // indexed by endpoint
        std::size_t capacity{default_capacity};
    };

    InProcessBinding(std::shared_ptr<Channel> channel, std::size_t side) noexcept
        : _channel{std::move(channel)}, _side{side} {}

    std::shared_ptr<Channel> _channel;
    std::size_t _side;
};

// ---- SocketBinding ----------------------------------------------------------

class SocketBinding final : public Binding {
public:
    // Takes ownership of a connected SOCK_SEQPACKET socket.
    explicit SocketBinding(int fd) noexcept : _fd{fd} {}

    // Connects to a board process (or helm) listening on `path`.
    [[nodiscard]] static auto connect(const std::filesystem::path& path)
        -> std::expected<std::unique_ptr<SocketBinding>, BindingError>;

    // A connected pair (socketpair(2)), for tests and for a parent that
    // forks the board process itself.
    [[nodiscard]] static auto make_pair()
        -> std::expected<std::pair<std::unique_ptr<SocketBinding>, std::unique_ptr<SocketBinding>>,
                         BindingError>;

    SocketBinding(const SocketBinding&) = delete;
    auto operator=(const SocketBinding&) -> SocketBinding& = delete;
    SocketBinding(SocketBinding&&) = delete;
    auto operator=(SocketBinding&&) -> SocketBinding& = delete;
    ~SocketBinding() override;

    auto send(std::span<const std::byte> packet) -> std::expected<void, BindingError> override;
    auto receive(std::chrono::milliseconds timeout)
        -> std::expected<std::vector<std::byte>, BindingError> override;

    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }

private:
    int _fd;
};

// The listening end of a slot's socket. The path must not exist: a stale
// socket from an earlier run is the caller's to remove, so a typo can never
// unlink something else.
class SocketListener {
public:
    [[nodiscard]] static auto bind(const std::filesystem::path& path)
        -> std::expected<std::unique_ptr<SocketListener>, BindingError>;

    SocketListener(const SocketListener&) = delete;
    auto operator=(const SocketListener&) -> SocketListener& = delete;
    SocketListener(SocketListener&&) = delete;
    auto operator=(SocketListener&&) -> SocketListener& = delete;
    // Closes the socket and removes the path it created.
    ~SocketListener();

    // Waits up to `timeout` for the peer to connect.
    [[nodiscard]] auto accept(std::chrono::milliseconds timeout)
        -> std::expected<std::unique_ptr<SocketBinding>, BindingError>;

private:
    SocketListener(int fd, std::filesystem::path path) noexcept : _fd{fd}, _path{std::move(path)} {}

    int _fd;
    std::filesystem::path _path;
};

}  // namespace ak::helm
