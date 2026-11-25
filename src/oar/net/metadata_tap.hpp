// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MetadataTap: the network role's MetadataEndpoint
// (.kiro/specs/oar-net-data-plane/ Requirements 13.1 to 13.5, design
// "Metadata service"; task 21.5). It joins three things:
//
//   - the VSwitch intercept, which deliver()s guest packets to the
//     metadata address with the NIC they arrived on;
//   - a TUN device (one IP packet per read or write) holding the metadata
//     addresses, in the role's own network namespace, so the board's
//     kernel does TCP;
//   - MetadataServer, listening on port 80 there, which maps each peer's
//     alias back to its NIC through the same AliasTable.
//
// deliver() drops, and counts, packets from a NIC that has no record or
// whose endpoint is disabled (Requirement 13.4: no answer at all), then
// translates (to_kernel) and writes them to the TUN. poll() reads what the
// kernel sends, translates it back (to_guest) and injects it to the NIC
// through the VSwitch, which delivers it only from the metadata address to
// that NIC's own addresses (Requirement 13.3).
//
// open_metadata_tun() makes and configures the device with ioctls; it
// needs CAP_NET_ADMIN in the namespace (the board is the role's own
// machine). Tests use a datagram socket pair in its place.
//
// Not thread-safe: deliver() and poll() run on the role's data-plane thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <sys/socket.h>

#include "oar/net/metadata_nat.hpp"
#include "oar/net/vswitch.hpp"

namespace ak::oar::net {

inline constexpr std::string_view metadata_tun_name = "akmd0";

struct MetadataTapCounters {
    std::uint64_t to_kernel{0};
    std::uint64_t to_guest{0};
    std::uint64_t no_record{0};       // a NIC without a record, or its endpoint disabled
    std::uint64_t dropped_out{0};     // to_kernel refused it (see NatDrop)
    std::uint64_t dropped_in{0};      // to_guest refused it
    std::uint64_t inject_refused{0};  // the VSwitch would not deliver it
    std::uint64_t write_failures{0};
};

class MetadataTap final : public MetadataEndpoint {
public:
    using Clock = AliasTable::Clock;
    // True when the NIC has a record with its endpoint enabled.
    using Ready = std::function<bool(geneve::NicId)>;
    // Delivers a reply to a NIC (VSwitch::inject_metadata).
    using Inject = std::function<bool(geneve::NicId, std::span<const std::byte>)>;

    // Takes `fd` (made non-blocking here). `clock` empty: steady_clock.
    MetadataTap(int fd, AliasTable& aliases, Ready ready, Inject inject,
                std::function<Clock::time_point()> clock = {});
    MetadataTap(const MetadataTap&) = delete;
    auto operator=(const MetadataTap&) -> MetadataTap& = delete;
    MetadataTap(MetadataTap&&) = delete;
    auto operator=(MetadataTap&&) -> MetadataTap& = delete;
    ~MetadataTap() override;

    auto deliver(geneve::NicId nic, std::span<const std::byte> ip_packet) -> void override;

    // Reads and injects up to `budget` packets; true if any were read.
    auto poll(std::size_t budget) -> bool;

    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }
    [[nodiscard]] auto counters() const noexcept -> const MetadataTapCounters& { return _counters; }

private:
    int _fd;
    AliasTable& _aliases;
    Ready _ready;
    Inject _inject;
    std::function<Clock::time_point()> _clock;
    MetadataTapCounters _counters;
};

struct MetadataTun {
    int fd{-1};
    bool ipv6{false};  // the IPv6 address and route are set (IPv6 may be off)
};

// Creates the TUN `name`, assigns 169.254.169.254/32 (and fd00:ec2::254/128
// when IPv6 is available), brings it up and routes the alias prefixes to
// it. The error is the failing step and errno.
[[nodiscard]] auto open_metadata_tun(std::string_view name = metadata_tun_name)
    -> std::expected<MetadataTun, std::string>;

// A non-blocking listening socket on port `port` of every address in the
// namespace: dual-stack IPv6 when available, else IPv4.
[[nodiscard]] auto open_metadata_listener(std::uint16_t port = metadata_port)
    -> std::expected<int, std::string>;

// The NIC a metadata connection's peer address stands for, through its
// alias (an IPv4 alias may arrive v4-mapped on a dual-stack socket).
[[nodiscard]] auto resolve_peer(const AliasTable& aliases, const sockaddr_storage& peer,
                                socklen_t length) -> std::optional<std::uint64_t>;

}  // namespace ak::oar::net
