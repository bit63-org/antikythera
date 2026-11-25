// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/metadata_server.hpp"

#include <array>
#include <cerrno>
#include <span>
#include <utility>

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

namespace ak::oar::net {

namespace {

// Accepts per run_once(), so a flood of connections cannot starve the
// ones already open.
constexpr std::size_t max_accepts_per_pass = 64;

auto set_nonblocking(int fd) -> bool {
    const int flags = ::fcntl(fd, F_GETFL);
    return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// Closes `fd` with a reset rather than a FIN.
auto reset_close(int fd) -> void {
    const linger l{.l_onoff = 1, .l_linger = 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
    ::close(fd);
}

auto seconds(MetadataClock::time_point now) -> std::uint64_t {
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return s < 0 ? 0U : static_cast<std::uint64_t>(s);
}

}  // namespace

auto set_hop_limit(int fd, std::uint8_t hops) -> bool {
    sockaddr_storage local{};
    socklen_t length = sizeof local;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &length) != 0) {
        return false;
    }
    const int value = hops;
    if (local.ss_family == AF_INET) {
        return ::setsockopt(fd, IPPROTO_IP, IP_TTL, &value, sizeof value) == 0;
    }
    if (local.ss_family == AF_INET6) {
        (void)::setsockopt(fd, IPPROTO_IP, IP_TTL, &value, sizeof value);  // v4-mapped peers
        return ::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &value, sizeof value) == 0;
    }
    return true;  // not IP: no hops to limit
}

MetadataServer::MetadataServer(TokenKey key, MetadataViews views, MetadataLimits limits)
    : _key{std::move(key)}, _views{std::move(views)}, _limits{limits}, _set_hops{set_hop_limit} {}

MetadataServer::~MetadataServer() {
    for (const auto& c : _connections) {
        ::close(c->fd);
    }
    if (_listen_fd >= 0) {
        ::close(_listen_fd);
    }
}

auto MetadataServer::listen(int fd, PeerResolver resolver) -> void {
    if (_listen_fd >= 0) {
        ::close(_listen_fd);
    }
    (void)set_nonblocking(fd);
    _listen_fd = fd;
    _resolver = std::move(resolver);
}

auto MetadataServer::connections(std::uint64_t nic_id) const -> std::size_t {
    const auto it = _per_nic.find(nic_id);
    return it == _per_nic.end() ? 0U : it->second;
}

auto MetadataServer::adopt(int fd, std::uint64_t nic_id, MetadataClock::time_point now) -> bool {
    if (_connections.size() >= _limits.total || connections(nic_id) >= _limits.per_nic ||
        !set_nonblocking(fd)) {
        ++_counters.refused_limit;
        reset_close(fd);
        return false;
    }
    auto c = std::make_unique<Connection>();
    c->fd = fd;
    c->nic_id = nic_id;
    c->last_activity = now;
    _connections.push_back(std::move(c));
    ++_per_nic[nic_id];
    ++_counters.accepted;
    return true;
}

auto MetadataServer::close(std::size_t index, bool reset) -> void {
    auto& c = *_connections[index];
    if (reset) {
        ++_counters.resets;
        reset_close(c.fd);
    } else {
        ::close(c.fd);
    }
    if (const auto it = _per_nic.find(c.nic_id); it != _per_nic.end() && --it->second == 0) {
        _per_nic.erase(it);
    }
    _connections.erase(_connections.begin() + static_cast<std::ptrdiff_t>(index));
}

auto MetadataServer::reset_nic(std::uint64_t nic_id) -> void {
    for (std::size_t i = _connections.size(); i-- > 0;) {
        if (_connections[i]->nic_id == nic_id) {
            close(i, true);
        }
    }
}

auto MetadataServer::accept_ready(MetadataClock::time_point now) -> void {
    for (std::size_t n = 0; n < max_accepts_per_pass; ++n) {
        sockaddr_storage peer{};
        socklen_t length = sizeof peer;
        const int fd = ::accept4(_listen_fd, reinterpret_cast<sockaddr*>(&peer), &length,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            return;  // EAGAIN, or an error the next pass retries
        }
        const auto nic = _resolver ? _resolver(peer, length) : std::nullopt;
        if (!nic) {
            ++_counters.refused_unknown;
            reset_close(fd);
            continue;
        }
        (void)adopt(fd, *nic, now);
    }
}

// Writes what is pending, then answers buffered requests one at a time
// until one cannot be written in full or none is complete.
auto MetadataServer::serve(Connection& c, MetadataClock::time_point now) -> Next {
    for (;;) {
        while (c.written < c.out.size()) {
            const auto pending = std::span{c.out}.subspan(c.written);
            const auto n = ::send(c.fd, pending.data(), pending.size(), MSG_NOSIGNAL);
            if (n < 0) {
                const bool later = errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
                return later ? Next::keep : Next::close;
            }
            c.written += static_cast<std::size_t>(n);
            c.last_activity = now;
        }
        c.out.clear();
        c.written = 0;
        if (c.close_after) {
            return Next::close;
        }
        if (c.in.empty()) {
            return Next::keep;
        }
        const auto request = parse_request(std::as_bytes(std::span{c.in}));
        if (!request && request.error() == RequestError::incomplete) {
            return Next::keep;
        }
        if (!request) {
            ++_counters.bad_requests;
            c.out = render(error_response(request.error()), false);
            c.close_after = true;
            c.in.clear();
            continue;
        }
        ++_counters.requests;
        const auto view = _views(c.nic_id);
        auto response = answer(*request, view, _key, seconds(now));
        if (response.reset) {
            return Next::reset;  // write nothing
        }
        if (response.status == 401) {
            ++_counters.unauthorized;
        }
        if (response.hop_limit) {
            if (!_set_hops(c.fd, *response.hop_limit)) {
                // Never send a token farther than the record allows.
                ++_counters.hop_limit_failures;
                response = HttpResponse{.status = 500,
                                        .content_type = "text/plain",
                                        .body = {},
                                        .token_ttl = {},
                                        .hop_limit = {},
                                        .close = true,
                                        .reset = false};
            } else {
                ++_counters.tokens;
            }
        }
        c.out = render(response, request->method == HttpMethod::head);
        c.close_after = response.close;
        c.in.erase(0, request->head_bytes);
        c.request_started = c.in.empty() ? std::nullopt : std::optional{now};
    }
}

auto MetadataServer::read_ready(Connection& c, MetadataClock::time_point now) -> Next {
    std::array<char, 4096> buf{};
    while (c.in.size() < max_request_head + 1) {
        const auto n = ::recv(c.fd, buf.data(), buf.size(), 0);
        if (n == 0) {
            return Next::close;  // the guest closed
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                break;
            }
            return Next::close;
        }
        c.in.append(buf.data(), static_cast<std::size_t>(n));
        c.last_activity = now;
        if (!c.request_started) {
            c.request_started = now;
        }
    }
    return serve(c, now);
}

auto MetadataServer::run_once(MetadataClock::time_point now, std::chrono::milliseconds timeout)
    -> void {
    std::vector<pollfd> fds;
    fds.reserve(_connections.size() + 1);
    for (const auto& c : _connections) {
        const short events = c->written < c->out.size() ? POLLOUT : POLLIN;
        fds.push_back({.fd = c->fd, .events = events, .revents = 0});
    }
    if (_listen_fd >= 0) {
        fds.push_back({.fd = _listen_fd, .events = POLLIN, .revents = 0});
    }
    if (!fds.empty()) {
        (void)::poll(fds.data(), fds.size(), static_cast<int>(timeout.count()));
    }

    std::vector<Next> next(_connections.size(), Next::keep);
    for (std::size_t i = 0; i < _connections.size(); ++i) {
        auto& c = *_connections[i];
        const auto revents = fds[i].revents;
        if ((revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            next[i] = read_ready(c, now);
        } else if ((revents & POLLOUT) != 0) {
            next[i] = serve(c, now);
        }
        if (next[i] != Next::keep) {
            continue;
        }
        const bool idle = c.in.empty() && c.written >= c.out.size();
        if ((c.request_started && now - *c.request_started > _limits.read_deadline) ||
            (idle && now - c.last_activity > _limits.idle_deadline)) {
            ++_counters.timeouts;
            next[i] = Next::close;
        }
    }
    for (std::size_t i = next.size(); i-- > 0;) {
        if (next[i] != Next::keep) {
            close(i, next[i] == Next::reset);
        }
    }

    if (_listen_fd >= 0 && (fds.back().revents & POLLIN) != 0) {
        accept_ready(now);
    }
}

}  // namespace ak::oar::net
