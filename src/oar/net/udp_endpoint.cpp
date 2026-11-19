// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/udp_endpoint.hpp"

#include <cerrno>
#include <cstring>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace ak::oar::net {

namespace {

constexpr int sockopt_on = 1;

auto to_sockaddr(const Ipv6Address& addr, std::uint16_t port, std::uint32_t scope_id)
    -> sockaddr_in6 {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    std::memcpy(&sa.sin6_addr, addr.data(), addr.size());
    sa.sin6_scope_id = scope_id;
    return sa;
}

auto errno_text(const char* step) -> std::string {
    return std::string{step} + ": " + std::strerror(errno);
}

// An IPv6-only, non-blocking UDP socket bound to `addr`:`port`.
auto open_bound(const Ipv6Address& addr, std::uint16_t port, std::uint32_t scope_id)
    -> std::expected<int, std::string> {
    const int fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
    if (fd < 0) {
        return std::unexpected(errno_text("socket"));
    }
    if (::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt_on, sizeof sockopt_on) < 0) {
        auto err = errno_text("IPV6_V6ONLY");
        ::close(fd);
        return std::unexpected(std::move(err));
    }
    const sockaddr_in6 sa = to_sockaddr(addr, port, scope_id);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) < 0) {
        auto err = errno_text("bind") + " (port " + std::to_string(port) + ")";
        ::close(fd);
        return std::unexpected(std::move(err));
    }
    return fd;
}

}  // namespace

auto UdpEndpoint::create(const UdpConfig& config)
    -> std::expected<std::unique_ptr<UdpEndpoint>, std::string> {
    if (std::uint32_t{config.source_port_base} + config.source_ports > UINT16_MAX + 1U ||
        (config.source_ports > 0 && config.source_port_base == 0)) {
        return std::unexpected("source port range out of bounds");
    }
    std::unique_ptr<UdpEndpoint> ep(new UdpEndpoint());
    ep->_scope_id = config.scope_id;
    auto rx = open_bound(config.bind, config.port, config.scope_id);
    if (!rx) {
        return std::unexpected(rx.error());
    }
    ep->_rx = *rx;
    sockaddr_in6 bound{};
    socklen_t len = sizeof bound;
    if (::getsockname(ep->_rx, reinterpret_cast<sockaddr*>(&bound), &len) < 0) {
        return std::unexpected(errno_text("getsockname"));
    }
    ep->_port = ntohs(bound.sin6_port);
    ep->_tx.reserve(config.source_ports);
    for (std::uint32_t i = 0; i < config.source_ports; ++i) {
        auto tx = open_bound(config.bind, static_cast<std::uint16_t>(config.source_port_base + i),
                             config.scope_id);
        if (!tx) {
            return std::unexpected(tx.error());
        }
        ep->_tx.push_back(*tx);
    }
    return ep;
}

UdpEndpoint::~UdpEndpoint() {
    if (_rx >= 0) {
        ::close(_rx);
    }
    for (const int fd : _tx) {
        ::close(fd);
    }
}

auto UdpEndpoint::send_to(const Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                          std::span<const std::byte> payload) -> bool {
    const int fd = _tx.empty() ? _rx : _tx[flow_port % _tx.size()];
    const sockaddr_in6 sa = to_sockaddr(dst, dst_port, _scope_id);
    const ssize_t n = ::sendto(fd, payload.data(), payload.size(), MSG_DONTWAIT,
                               reinterpret_cast<const sockaddr*>(&sa), sizeof sa);
    return n >= 0 && static_cast<std::size_t>(n) == payload.size();
}

auto UdpEndpoint::receive(std::span<std::byte> buffer) -> std::optional<Datagram> {
    sockaddr_in6 from{};
    socklen_t len = sizeof from;
    // MSG_TRUNC makes recvfrom return the datagram's real length.
    const ssize_t n = ::recvfrom(_rx, buffer.data(), buffer.size(), MSG_DONTWAIT | MSG_TRUNC,
                                 reinterpret_cast<sockaddr*>(&from), &len);
    if (n < 0 || from.sin6_family != AF_INET6) {
        return std::nullopt;
    }
    Datagram d;
    d.truncated = static_cast<std::size_t>(n) > buffer.size();
    _rx_truncated += d.truncated ? 1 : 0;
    d.size = d.truncated ? buffer.size() : static_cast<std::size_t>(n);
    std::memcpy(d.source.data(), &from.sin6_addr, d.source.size());
    d.source_port = ntohs(from.sin6_port);
    return d;
}

auto pump(UdpEndpoint& endpoint, Vtep& vtep, VSwitch& vswitch, std::span<std::byte> buffer,
          std::size_t budget, VtepClock::time_point now) -> std::size_t {
    std::size_t read = 0;
    while (read < budget) {
        auto d = endpoint.receive(buffer);
        if (!d) {
            break;
        }
        ++read;
        if (d->truncated) {
            continue;  // larger than any frame the VSwitch could deliver
        }
        if (auto packet = vtep.receive(buffer.first(d->size), d->source, now)) {
            static_cast<void>(vswitch.receive(*packet, d->source));
        }
    }
    return read;
}

}  // namespace ak::oar::net
