// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/route_trie.hpp"

namespace ak::oar::net {

namespace {

constexpr std::size_t byte_bits = 8;

auto bit_at(std::span<const std::byte> a, std::size_t i) noexcept -> std::size_t {
    const auto b = std::to_integer<unsigned>(a[i / byte_bits]);
    return (b >> (byte_bits - 1 - (i % byte_bits))) & 1U;
}

}  // namespace

RouteTrie::RouteTrie(std::size_t bits) : _bits{bits}, _nodes(1) {}

auto RouteTrie::insert(std::span<const std::byte> prefix, std::size_t length, Target target)
    -> bool {
    if (length > _bits || prefix.size() * byte_bits < _bits) {
        return false;
    }
    std::size_t node = 0;
    for (std::size_t i = 0; i < length; ++i) {
        const std::size_t b = bit_at(prefix, i);
        if (_nodes[node].child.at(b) == 0) {
            _nodes[node].child.at(b) = static_cast<std::uint32_t>(_nodes.size());
            _nodes.emplace_back();
        }
        node = _nodes[node].child.at(b);
    }
    if (_nodes[node].target) {
        return false;
    }
    _nodes[node].target = target;
    ++_size;
    return true;
}

auto RouteTrie::lookup(std::span<const std::byte> address) const -> std::optional<Target> {
    if (address.size() * byte_bits < _bits) {
        return std::nullopt;
    }
    std::optional<Target> best = _nodes[0].target;
    std::size_t node = 0;
    for (std::size_t i = 0; i < _bits; ++i) {
        node = _nodes[node].child.at(bit_at(address, i));
        if (node == 0) {
            break;
        }
        if (_nodes[node].target) {
            best = _nodes[node].target;
        }
    }
    return best;
}

}  // namespace ak::oar::net
