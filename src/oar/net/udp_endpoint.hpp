// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// UdpEndpoint: the Vtep's IPv6/UDP sockets (.kiro/specs/oar-net-data-plane/
// Requirements 3.1 and 3.5, task 9).
//
// One socket is bound to the VTEP's underlay address and the Geneve port
// (6081) and receives every packet. Sending needs a per-flow source port
// (Requirement 3.5), which an ordinary UDP socket cannot choose per
// datagram, so the endpoint can also bind a pool of `source_ports` sockets
// to consecutive ports from `source_port_base`, and sends each datagram from
// the pool socket picked by its flow port. The same flow always leaves from
// the same port; ECMP sees `source_ports` distinct values. With
// source_ports = 0 everything goes out of the receiving socket. A raw
// socket could set any port, but needs CAP_NET_RAW, which harbor's
// unprivileged runs do not have.
//
// The sockets are IPv6-only, non-blocking and never fragment locally
// (IPV6_DONTFRAG): a datagram larger than the path MTU fails to send. A full send buffer drops the
// datagram (counted by the Vtep), as a congested link would.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "oar/net/vswitch.hpp"
#include "oar/net/vtep.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net {

struct UdpConfig {
    Ipv6Address bind{};                    // the VTEP's underlay address; all-zero binds any
    std::uint16_t port{geneve::udp_port};  // 0 picks an ephemeral port (tests)
    std::uint32_t scope_id{0};             // interface index, for link-local addresses
    std::uint16_t source_port_base{flow_port_base};
    std::uint16_t source_ports{0};
};

struct Datagram {
    std::size_t size{0};  // bytes written to the receive buffer
    Ipv6Address source{};
    std::uint16_t source_port{0};
    bool truncated{false};  // larger than the buffer; drop it
};

class UdpEndpoint final : public DatagramSender {
public:
    // Opens and binds every socket; a readable error naming the failing step
    // otherwise.
    static auto create(const UdpConfig& config)
        -> std::expected<std::unique_ptr<UdpEndpoint>, std::string>;

    UdpEndpoint(const UdpEndpoint&) = delete;
    auto operator=(const UdpEndpoint&) -> UdpEndpoint& = delete;
    UdpEndpoint(UdpEndpoint&&) = delete;
    auto operator=(UdpEndpoint&&) -> UdpEndpoint& = delete;
    ~UdpEndpoint() override;

    auto send_to(const Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                 std::span<const std::byte> payload) -> bool override;

    // Reads one datagram into `buffer` without blocking; nothing if none is
    // waiting (or the socket reported an error, which UDP does for ICMP
    // unreachables and which is not ours to act on).
    auto receive(std::span<std::byte> buffer) -> std::optional<Datagram>;

    // The receiving socket, for poll().
    [[nodiscard]] auto poll_fd() const noexcept -> int { return _rx; }
    // The port it is bound to (useful when config.port was 0).
    [[nodiscard]] auto local_port() const noexcept -> std::uint16_t { return _port; }
    // Datagrams larger than the buffer they were received into (dropped).
    [[nodiscard]] auto rx_truncated() const noexcept -> std::uint64_t { return _rx_truncated; }

private:
    UdpEndpoint() = default;

    std::uint32_t _scope_id{0};
    int _rx{-1};
    std::uint16_t _port{0};
    std::vector<int> _tx;
    std::uint64_t _rx_truncated{0};
};

// Reads up to `budget` datagrams from `endpoint`, passes each through
// `vtep` and hands data packets to `vswitch`. Returns how many were read; a
// return equal to `budget` means more may be waiting.
auto pump(UdpEndpoint& endpoint, Vtep& vtep, VSwitch& vswitch, std::span<std::byte> buffer,
          std::size_t budget, VtepClock::time_point now) -> std::size_t;

}  // namespace ak::oar::net
