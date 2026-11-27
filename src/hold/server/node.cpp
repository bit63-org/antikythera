// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/server/node.hpp"

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <utility>

#include "proto/server_identity.hpp"

namespace ak::hold {

namespace {

constexpr std::size_t read_chunk = 64 * 1024;

auto mark_storage_class(int fd) -> void {
    proto::set_storage_class(fd);
}

}  // namespace

// ---- Node --------------------------------------------------------------------

Node::Dials::~Dials() {
    if (wake >= 0) {
        static_cast<void>(::close(wake));
    }
}

Node::Node(store::FileLayer& files, NodeConfig config, std::optional<tls::Context> ctx,
           tls::Listener listener, int dial_wake) noexcept
    : _config{std::move(config)},
      _ctx{std::move(ctx)},
      _listener{std::move(listener)},
      _server{files, _config.server, *this},
      _dials{dial_wake} {}

Node::~Node() {
    for (auto& [id, t] : _dialing) {
        t.join();
    }
}

auto Node::create(store::FileLayer& files, NodeConfig config)
    -> std::expected<std::unique_ptr<Node>, tls::Error> {
    config.tls.role = tls::Role::server;
    config.tls.peer_name.clear();
    std::optional<tls::Context> ctx;
    if (!config.tls.cert_pem.empty()) {
        auto created = tls::Context::create(config.tls);
        if (!created) {
            return std::unexpected(created.error());
        }
        ctx = std::move(*created);
    }
    auto listener = tls::Listener::bind(config.host, config.port);
    if (!listener) {
        return std::unexpected(listener.error());
    }
    const int wake = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake < 0) {
        return std::unexpected(tls::Error::io);
    }
    return std::unique_ptr<Node>{
        new Node(files, std::move(config), std::move(ctx), std::move(*listener), wake)};
}

auto Node::run_once(Clock::duration max_wait, int extra_fd) -> bool {
    auto now = Clock::now();
    auto wait = max_wait;
    if (const auto wake = _server.next_wake(now); wake) {
        wait = std::clamp<Clock::duration>(*wake - now, Clock::duration::zero(), max_wait);
    }
    std::vector<pollfd> fds;
    std::vector<SessionId> ids;
    fds.push_back({.fd = _listener.fd(), .events = POLLIN, .revents = 0});
    fds.push_back({.fd = _dials.wake, .events = POLLIN, .revents = 0});
    fds.push_back({.fd = extra_fd, .events = POLLIN, .revents = 0});  // poll() skips fd -1
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
        if (fds[i + 3].revents != 0 || c.stream.pending()) {
            read(c, now);
        }
    }
    if ((fds[0].revents & POLLIN) != 0) {
        accept();
    }
    if ((fds[1].revents & POLLIN) != 0) {
        take_dials(now);
    }
    _server.run(Clock::now());
    reap();
    return extra_fd >= 0 && fds[2].revents != 0;
}

auto Node::accept() -> void {
    auto fd = _listener.accept_fd(Clock::now());
    if (!fd) {
        return;
    }
    if (!_ctx) {
        static_cast<void>(::close(*fd));  // no certificate yet: unreachable
        return;
    }
    mark_storage_class(*fd);
    auto stream = tls::Stream::accept(*_ctx, *fd, Clock::now() + _config.handshake_timeout);
    if (!stream) {
        return;
    }
    const auto uris = stream->peer_uris();
    const auto peer = proto::server_id_of(uris);
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

auto Node::dial(SessionId session, std::uint64_t server_id, const proto::StorageEndpoint& endpoint,
                std::uint16_t port) -> void {
    auto config = _config.tls;
    config.role = tls::Role::client;
    // The member's IP SAN; none (the dial fails) while there is no
    // certificate to present.
    config.peer_name = _ctx ? proto::endpoint_text(endpoint) : std::string{};
    const auto deadline = Clock::now() + _config.handshake_timeout;
    _dialing.emplace(
        session, std::thread{[dials = &_dials, session, server_id, port, deadline,
                              config = std::move(config)] {
            Dialed d{.session = session, .server_id = server_id, .stream = std::nullopt};
            if (auto ctx = tls::Context::create(config); ctx && !config.peer_name.empty()) {
                if (auto s = tls::Stream::connect(*ctx, config.peer_name, port, deadline)) {
                    d.stream = std::move(*s);
                }
            }
            {
                const std::scoped_lock lock{dials->mutex};
                dials->done.push_back(std::move(d));
            }
            static_cast<void>(::eventfd_write(dials->wake, 1));
        }});
}

auto Node::set_tls(tls::Config config) -> std::expected<void, tls::Error> {
    config.role = tls::Role::server;
    config.peer_name.clear();
    auto ctx = tls::Context::create(config);
    if (!ctx) {
        return std::unexpected(ctx.error());
    }
    _ctx = std::move(*ctx);
    _config.tls = std::move(config);
    return {};
}

auto Node::hang_up(SessionId session) -> void {
    if (const auto it = _conns.find(session); it != _conns.end()) {
        it->second.dead = true;  // reap() closes it and tells the server
    } else if (_dialing.contains(session)) {
        _cancelled.push_back(session);
    }
}

auto Node::take_dials(Clock::time_point now) -> void {
    std::uint64_t n = 0;
    static_cast<void>(::eventfd_read(_dials.wake, &n));
    std::vector<Dialed> done;
    {
        const std::scoped_lock lock{_dials.mutex};
        done.swap(_dials.done);
    }
    for (auto& d : done) {
        if (const auto t = _dialing.find(d.session); t != _dialing.end()) {
            t->second.join();
            _dialing.erase(t);
        }
        const bool cancelled = std::erase(_cancelled, d.session) != 0;
        if (d.stream && !cancelled) {
            const auto uris = d.stream->peer_uris();
            const auto id = proto::server_id_of(uris);
            if (!id || *id != d.server_id) {
                d.stream->close();  // not the member the config names
                d.stream.reset();
            }
        }
        if (!d.stream || cancelled) {
            if (d.stream) {
                d.stream->close();
            }
            _server.close_session(d.session);
            continue;
        }
        mark_storage_class(d.stream->fd());
        _conns.emplace(
            d.session,
            Connection{
                .stream = std::move(*d.stream), .session = d.session, .in = {}, .dead = false});
        _server.connected(d.session, now);
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
