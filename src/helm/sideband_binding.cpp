// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/sideband_binding.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <system_error>

#include "helm/mctp.hpp"

namespace ak::helm {

namespace {

using Clock = std::chrono::steady_clock;

// Waits for `events` on `fd` until `deadline`, retrying on EINTR.
auto wait_for(int fd, short events, Clock::time_point deadline)
    -> std::expected<void, BindingError> {
    for (;;) {
        const auto left =
            std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
        pollfd p{.fd = fd, .events = events, .revents = 0};
        const int n = ::poll(&p, 1, static_cast<int>(std::max<decltype(left)>(left, 0)));
        if (n > 0) {
            return {};
        }
        if (n == 0) {
            return std::unexpected(BindingError::timed_out);
        }
        if (errno != EINTR) {
            return std::unexpected(BindingError::io);
        }
    }
}

auto close_fd(int fd) noexcept -> void {
    if (fd >= 0) {
        (void)::close(fd);
    }
}

auto make_address(const std::filesystem::path& path) -> std::expected<sockaddr_un, BindingError> {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto& s = path.native();
    if (s.empty() || s.size() >= sizeof(addr.sun_path)) {
        return std::unexpected(BindingError::io);
    }
    std::ranges::copy(s, std::begin(addr.sun_path));
    return addr;
}

auto seqpacket_socket() -> int {
    return ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
}

}  // namespace

auto to_string(BindingError e) noexcept -> const char* {
    switch (e) {
        case BindingError::timed_out:
            return "timed_out";
        case BindingError::disconnected:
            return "disconnected";
        case BindingError::oversized:
            return "oversized";
        case BindingError::queue_full:
            return "queue_full";
        case BindingError::io:
            return "io";
    }
    return "unknown";
}

// ---- InProcessBinding -------------------------------------------------------

auto InProcessBinding::make_pair(std::size_t capacity)
    -> std::pair<std::unique_ptr<InProcessBinding>, std::unique_ptr<InProcessBinding>> {
    auto channel = std::make_shared<Channel>();
    channel->capacity = std::max<std::size_t>(capacity, 1);
    // The constructor is private, so make_unique cannot reach it.
    return {std::unique_ptr<InProcessBinding>{new InProcessBinding{channel, 0}},
            std::unique_ptr<InProcessBinding>{new InProcessBinding{channel, 1}}};
}

InProcessBinding::~InProcessBinding() {
    {
        const std::scoped_lock lock{_channel->mutex};
        _channel->closed.at(_side) = true;
        // Packets still queued for this endpoint will never be read.
        _channel->queues.at(_side).clear();
    }
    _channel->ready.notify_all();
}

auto InProcessBinding::send(std::span<const std::byte> packet)
    -> std::expected<void, BindingError> {
    if (packet.size() > mctp::max_packet_size) {
        return std::unexpected(BindingError::oversized);
    }
    const std::size_t peer = 1 - _side;
    {
        const std::scoped_lock lock{_channel->mutex};
        if (_channel->closed.at(peer)) {
            return std::unexpected(BindingError::disconnected);
        }
        auto& q = _channel->queues.at(peer);
        if (q.size() >= _channel->capacity) {
            return std::unexpected(BindingError::queue_full);
        }
        q.emplace_back(packet.begin(), packet.end());
    }
    _channel->ready.notify_all();
    return {};
}

auto InProcessBinding::receive(std::chrono::milliseconds timeout)
    -> std::expected<std::vector<std::byte>, BindingError> {
    const std::size_t peer = 1 - _side;
    std::unique_lock lock{_channel->mutex};
    auto& q = _channel->queues.at(_side);
    const bool woke = _channel->ready.wait_for(
        lock, timeout, [&] { return !q.empty() || _channel->closed.at(peer); });
    if (!q.empty()) {
        auto out = std::move(q.front());
        q.pop_front();
        return out;
    }
    if (woke) {
        return std::unexpected(BindingError::disconnected);
    }
    return std::unexpected(BindingError::timed_out);
}

// ---- SocketBinding ----------------------------------------------------------

SocketBinding::~SocketBinding() {
    close_fd(_fd);
}

auto SocketBinding::connect(const std::filesystem::path& path)
    -> std::expected<std::unique_ptr<SocketBinding>, BindingError> {
    auto addr = make_address(path);
    if (!addr) {
        return std::unexpected(addr.error());
    }
    const int fd = seqpacket_socket();
    if (fd < 0) {
        return std::unexpected(BindingError::io);
    }
    auto binding = std::make_unique<SocketBinding>(fd);
    int rc = 0;
    do {
        rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&*addr), sizeof(*addr));
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        return std::unexpected(errno == ENOENT || errno == ECONNREFUSED ? BindingError::disconnected
                                                                        : BindingError::io);
    }
    return binding;
}

auto SocketBinding::make_pair()
    -> std::expected<std::pair<std::unique_ptr<SocketBinding>, std::unique_ptr<SocketBinding>>,
                     BindingError> {
    std::array<int, 2> fds{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds.data()) != 0) {
        return std::unexpected(BindingError::io);
    }
    return std::pair{std::make_unique<SocketBinding>(fds[0]),
                     std::make_unique<SocketBinding>(fds[1])};
}

auto SocketBinding::send(std::span<const std::byte> packet) -> std::expected<void, BindingError> {
    if (packet.size() > mctp::max_packet_size) {
        return std::unexpected(BindingError::oversized);
    }
    for (;;) {
        const auto n = ::send(_fd, packet.data(), packet.size(), MSG_NOSIGNAL);
        if (n >= 0) {
            // SOCK_SEQPACKET sends a datagram whole or not at all.
            return {};
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN) {
            return std::unexpected(BindingError::disconnected);
        }
        return std::unexpected(BindingError::io);
    }
}

auto SocketBinding::receive(std::chrono::milliseconds timeout)
    -> std::expected<std::vector<std::byte>, BindingError> {
    const auto deadline = Clock::now() + timeout;
    if (auto ready = wait_for(_fd, POLLIN, deadline); !ready) {
        return std::unexpected(ready.error());
    }
    // One byte more than the largest packet, plus MSG_TRUNC so recv reports
    // the datagram's real length: anything longer is dropped whole.
    std::vector<std::byte> buf(mctp::max_packet_size + 1);
    for (;;) {
        const auto n = ::recv(_fd, buf.data(), buf.size(), MSG_TRUNC | MSG_DONTWAIT);
        if (n > 0) {
            const auto len = static_cast<std::size_t>(n);
            if (len > mctp::max_packet_size) {
                return std::unexpected(BindingError::oversized);
            }
            buf.resize(len);
            return buf;
        }
        if (n == 0) {
            // End of stream. A peer never sends an empty packet, so a zero
            // read is always the peer closing.
            return std::unexpected(BindingError::disconnected);
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // poll saw POLLIN but the datagram is gone (another reader):
            // treat as nothing arriving in time rather than spin.
            return std::unexpected(BindingError::timed_out);
        }
        if (errno == ECONNRESET) {
            return std::unexpected(BindingError::disconnected);
        }
        return std::unexpected(BindingError::io);
    }
}

// ---- SocketListener ---------------------------------------------------------

auto SocketListener::bind(const std::filesystem::path& path)
    -> std::expected<std::unique_ptr<SocketListener>, BindingError> {
    auto addr = make_address(path);
    if (!addr) {
        return std::unexpected(addr.error());
    }
    const int fd = seqpacket_socket();
    if (fd < 0) {
        return std::unexpected(BindingError::io);
    }
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&*addr), sizeof(*addr)) != 0) {
        close_fd(fd);
        return std::unexpected(BindingError::io);
    }
    // From here the listener owns the path and removes it on destruction.
    std::unique_ptr<SocketListener> listener{new SocketListener{fd, path}};
    // One peer per slot; a backlog of one is enough.
    if (::listen(fd, 1) != 0) {
        return std::unexpected(BindingError::io);
    }
    return listener;
}

SocketListener::~SocketListener() {
    close_fd(_fd);
    std::error_code ec;
    std::filesystem::remove(_path, ec);
}

auto SocketListener::accept(std::chrono::milliseconds timeout)
    -> std::expected<std::unique_ptr<SocketBinding>, BindingError> {
    const auto deadline = Clock::now() + timeout;
    if (auto ready = wait_for(_fd, POLLIN, deadline); !ready) {
        return std::unexpected(ready.error());
    }
    for (;;) {
        const int fd = ::accept4(_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd >= 0) {
            return std::make_unique<SocketBinding>(fd);
        }
        if (errno != EINTR) {
            return std::unexpected(BindingError::io);
        }
    }
}

}  // namespace ak::helm
