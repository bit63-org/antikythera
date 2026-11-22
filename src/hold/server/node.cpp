// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/server/node.hpp"

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <utility>

#include "hold/server/identity.hpp"

namespace ak::hold {

namespace {

constexpr std::size_t read_chunk = 64 * 1024;

auto mark_storage_class(int fd) -> void {
    const int tos = storage_io_tos;
    // Whichever family the socket is; the other call fails harmlessly.
    static_cast<void>(::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof tos));
    static_cast<void>(::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof tos));
}

}  // namespace

// ---- FrameAssembler ----------------------------------------------------------

auto FrameAssembler::feed(std::span<const std::byte> bytes) -> void {
    _buf.insert(_buf.end(), bytes.begin(), bytes.end());
}

auto FrameAssembler::next()
    -> std::expected<std::optional<std::vector<std::byte>>, proto::DecodeError> {
    if (_buf.size() < proto::hold_header_size) {
        return std::nullopt;
    }
    const auto header = proto::decode_hold_header(std::span{_buf}.first(proto::hold_header_size));
    if (!header) {
        return std::unexpected(header.error());
    }
    const std::size_t total = proto::hold_header_size + header->payload_len;
    if (_buf.size() < total) {
        return std::nullopt;
    }
    std::vector<std::byte> frame{_buf.begin(), _buf.begin() + static_cast<std::ptrdiff_t>(total)};
    _buf.erase(_buf.begin(), _buf.begin() + static_cast<std::ptrdiff_t>(total));
    return frame;
}

// ---- Node --------------------------------------------------------------------

Node::Node(store::FileLayer& files, NodeConfig config, tls::Context ctx,
           tls::Listener listener) noexcept
    : _config{std::move(config)},
      _ctx{std::move(ctx)},
      _listener{std::move(listener)},
      _server{files, _config.server, *this} {}

auto Node::create(store::FileLayer& files, NodeConfig config)
    -> std::expected<std::unique_ptr<Node>, tls::Error> {
    config.tls.role = tls::Role::server;
    auto ctx = tls::Context::create(config.tls);
    if (!ctx) {
        return std::unexpected(ctx.error());
    }
    auto listener = tls::Listener::bind(config.host, config.port);
    if (!listener) {
        return std::unexpected(listener.error());
    }
    return std::unique_ptr<Node>{
        new Node(files, std::move(config), std::move(*ctx), std::move(*listener))};
}

auto Node::run_once(Clock::duration max_wait) -> void {
    auto now = Clock::now();
    auto wait = max_wait;
    if (const auto wake = _server.next_wake(now); wake) {
        wait = std::clamp<Clock::duration>(*wake - now, Clock::duration::zero(), max_wait);
    }
    std::vector<pollfd> fds;
    std::vector<SessionId> ids;
    fds.push_back({.fd = _listener.fd(), .events = POLLIN, .revents = 0});
    for (auto& [id, c] : _conns) {
        if (c.stream.pending()) {
            wait = Clock::duration::zero();
        }
        fds.push_back({.fd = c.stream.fd(), .events = POLLIN, .revents = 0});
        ids.push_back(id);
    }
    const auto ms = std::chrono::ceil<std::chrono::milliseconds>(wait).count();
    static_cast<void>(::poll(fds.data(), fds.size(), static_cast<int>(ms)));
    now = Clock::now();
    for (std::size_t i = 0; i < ids.size(); ++i) {
        auto& c = _conns.at(ids[i]);
        if (fds[i + 1].revents != 0 || c.stream.pending()) {
            read(c, now);
        }
    }
    if ((fds[0].revents & POLLIN) != 0) {
        accept();
    }
    _server.run(Clock::now());
    reap();
}

auto Node::accept() -> void {
    auto fd = _listener.accept_fd(Clock::now());
    if (!fd) {
        return;
    }
    mark_storage_class(*fd);
    auto stream = tls::Stream::accept(_ctx, *fd, Clock::now() + _config.handshake_timeout);
    if (!stream) {
        return;
    }
    const auto uris = stream->peer_uris();
    const auto peer = server_id_of(uris);
    if (!peer) {
        stream->close();
        return;
    }
    const SessionId id = _server.open_session(*peer);
    _conns.emplace(
        id, Connection{.stream = std::move(*stream), .session = id, .in = {}, .dead = false});
}

auto Node::read(Connection& c, Clock::time_point now) -> void {
    std::array<std::byte, read_chunk> buf{};
    for (;;) {
        auto got = c.stream.read_some(buf);
        if (!got) {
            c.dead = true;
            return;
        }
        if (*got == 0) {
            break;
        }
        c.in.feed(std::span{buf}.first(*got));
        for (;;) {
            auto frame = c.in.next();
            if (!frame) {
                c.dead = true;  // not a hold frame: drop the peer
                return;
            }
            if (!*frame) {
                break;
            }
            auto decoded = proto::decode_hold_frame(**frame);
            if (!decoded) {
                c.dead = true;
                return;
            }
            _server.on_frame(c.session, *decoded, now);
            if (c.dead) {
                return;
            }
        }
    }
}

auto Node::send(SessionId session, std::vector<std::byte> frame) -> void {
    const auto it = _conns.find(session);
    if (it == _conns.end() || it->second.dead) {
        return;
    }
    if (!it->second.stream.write_all(frame, Clock::now() + _config.write_timeout)) {
        it->second.dead = true;
    }
}

auto Node::reap() -> void {
    for (auto it = _conns.begin(); it != _conns.end();) {
        if (it->second.dead) {
            _server.close_session(it->first);
            it->second.stream.close();
            it = _conns.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace ak::hold
