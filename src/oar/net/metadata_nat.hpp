// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The metadata service's address translation (.kiro/specs/oar-net-data-plane/
// Requirements 13.1, 13.3 to 13.5, design "Metadata service"; task 21.5).
//
// The board's kernel does TCP for the service through a TUN device in the
// role's own network namespace that holds 169.254.169.254/32 and
// fd00:ec2::254/128. Guests in different VPCs may share addresses, so each
// (NIC, guest address) pair gets an alias, 100.64.0.0/10 for IPv4 and
// fd00:ec2:1::/96 for IPv6, both routed to the TUN:
//
//   to_kernel  a guest packet (from the VSwitch intercept, with the NIC it
//              arrived on) has its source rewritten to the pair's alias;
//   to_guest   a kernel packet to an alias has its destination rewritten
//              back to the guest address, and names the NIC to inject to.
//
// The IPv4 header checksum and the TCP checksum are updated incrementally
// (RFC 1624), so a guest's bad checksum stays bad and the kernel drops it.
// Only TCP to port 80 goes to the kernel, and only TCP from port 80 comes
// back: anything else, ICMP errors and fragments included, is dropped and
// counted by the caller. Both directions read packets a guest or the
// kernel built, so they are fuzzed (fuzz/fuzz_metadata_nat.cpp).
//
// AliasTable hands out the aliases: at most max_aliases_per_nic per NIC
// (the least recently used is replaced), all released when the NIC is
// cleaned, and none reused for another pair while the kernel may still
// hold a connection for it (alias_quarantine, longer than TIME_WAIT).
// Not thread-safe: it belongs to the role's data-plane thread.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net {

inline constexpr std::uint16_t metadata_port = 80;
inline constexpr std::size_t max_aliases_per_nic = 16;
inline constexpr std::chrono::seconds alias_quarantine{120};

// 100.64.0.0/10 (RFC 6598 shared address space) and fd00:ec2:1::/96.
inline constexpr neighbor::Ipv4Address alias4_prefix{std::byte{100}, std::byte{64}, std::byte{0},
                                                     std::byte{0}};
inline constexpr std::uint8_t alias4_length = 10;
inline constexpr Ipv6Address alias6_prefix{std::byte{0xfd}, std::byte{0x00}, std::byte{0x0e},
                                           std::byte{0xc2}, std::byte{0x00}, std::byte{0x01}};
inline constexpr std::uint8_t alias6_length = 96;

// An IPv4 or IPv6 address; IPv4 in the first four bytes, the rest zero.
struct IpAddress {
    bool v6{false};
    Ipv6Address bytes{};

    [[nodiscard]] static auto from(const neighbor::Ipv4Address& a) -> IpAddress;
    [[nodiscard]] static auto from(const Ipv6Address& a) -> IpAddress;
    [[nodiscard]] auto v4() const -> neighbor::Ipv4Address;

    friend auto operator<=>(const IpAddress&, const IpAddress&) = default;
};

class AliasTable {
public:
    using Clock = std::chrono::steady_clock;

    // The alias for (nic, guest), made if needed; nullopt only when the
    // pool has no free alias.
    [[nodiscard]] auto alias(geneve::NicId nic, const IpAddress& guest, Clock::time_point now)
        -> std::optional<IpAddress>;
    // The pair an alias stands for.
    [[nodiscard]] auto lookup(const IpAddress& alias) const
        -> std::optional<std::pair<geneve::NicId, IpAddress>>;
    // Releases every alias of `nic` into quarantine.
    auto release(geneve::NicId nic, Clock::time_point now) -> void;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _by_alias.size(); }
    [[nodiscard]] auto size(geneve::NicId nic) const -> std::size_t;
    [[nodiscard]] auto quarantined() const noexcept -> std::size_t { return _quarantine.size(); }

private:
    struct Entry {
        geneve::NicId nic{};
        IpAddress guest;
        Clock::time_point used;
    };

    auto allocate(bool v6, Clock::time_point now) -> std::optional<IpAddress>;
    auto retire(const IpAddress& alias, Clock::time_point now) -> void;

    std::map<IpAddress, Entry> _by_alias;
    std::map<std::pair<std::uint64_t, IpAddress>, IpAddress> _by_pair;
    std::set<IpAddress> _quarantine;
    std::deque<std::pair<Clock::time_point, IpAddress>> _quarantine_order;  // by time
    std::uint32_t _next4{0};
    std::uint32_t _next6{0};
};

enum class NatDrop : std::uint8_t {
    malformed,      // not a whole IPv4 or IPv6 packet
    fragment,       // an IPv4 fragment
    not_tcp,        // another protocol, or IPv6 extension headers
    wrong_address,  // not to (or from) the metadata address
    wrong_port,     // not to (or from) port 80
    no_alias,       // the pool is exhausted
    unknown_alias,  // to an address no pair holds
};

[[nodiscard]] auto to_string(NatDrop d) noexcept -> const char*;

// A guest packet (IP header onward) from `nic`, rewritten for the kernel.
[[nodiscard]] auto to_kernel(geneve::NicId nic, std::span<const std::byte> ip_packet,
                             AliasTable& aliases, AliasTable::Clock::time_point now)
    -> std::expected<std::vector<std::byte>, NatDrop>;

struct ToGuest {
    geneve::NicId nic{};
    std::vector<std::byte> packet;
};

// A kernel packet, rewritten for the guest it answers.
[[nodiscard]] auto to_guest(std::span<const std::byte> ip_packet, const AliasTable& aliases)
    -> std::expected<ToGuest, NatDrop>;

}  // namespace ak::oar::net
