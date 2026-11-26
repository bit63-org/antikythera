// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// RouteTrie: longest-prefix match for one route table and one address
// family (.kiro/specs/vpc-subnets-routing/ design "The network role's VPC
// state", task 5).
//
// A binary trie over the address bits, built when a VpcConfig is applied
// and read on every routed frame. A lookup walks at most 32 or 128 nodes
// and remembers the last one holding a route, so its cost does not depend
// on how many routes the table has (at most 1,006 per table). Nodes live
// in one vector and refer to each other by index; the trie is immutable
// once built, so the data-plane thread reads it without locks.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "oar/net/geneve.hpp"

namespace ak::oar::net {

class RouteTrie {
public:
    // What a route leads to: the VPC's `local` route (the NIC owning the
    // destination) or one NIC.
    struct Target {
        bool local{false};
        geneve::NicId nic{};  // nic_invalid for a local route

        friend auto operator==(const Target&, const Target&) -> bool = default;
    };

    static constexpr std::size_t ipv4_bits = 32;
    static constexpr std::size_t ipv6_bits = 128;

    // A trie over `bits`-bit addresses (ipv4_bits or ipv6_bits).
    explicit RouteTrie(std::size_t bits);

    // Adds a route for the first `length` bits of `prefix` (which holds at
    // least bits / 8 bytes; bits past `length` are ignored). False, and no
    // change, if `length` exceeds the trie's width or the prefix is
    // already present.
    auto insert(std::span<const std::byte> prefix, std::size_t length, Target target) -> bool;

    // The target of the longest prefix matching `address` (at least
    // bits / 8 bytes), if any.
    [[nodiscard]] auto lookup(std::span<const std::byte> address) const -> std::optional<Target>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _size; }
    [[nodiscard]] auto bits() const noexcept -> std::size_t { return _bits; }

private:
    struct Node {
        std::array<std::uint32_t, 2> child{};  // 0: none (the root is never a child)
        std::optional<Target> target;
    };

    std::size_t _bits;
    std::vector<Node> _nodes;
    std::size_t _size{0};
};

}  // namespace ak::oar::net
