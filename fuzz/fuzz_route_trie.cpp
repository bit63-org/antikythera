// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes RouteTrie against a naive longest-prefix scan
// (.kiro/specs/vpc-subnets-routing/ design "Testing strategy").
//
// The first byte picks the family (even: IPv4, odd: IPv6). Then records
// of [length][target][prefix bytes] insert routes until a zero length
// byte with a high bit set ends the table; the rest of the input is
// addresses to look up. insert() must refuse exactly the duplicates and
// over-long prefixes, and every lookup must equal the scan's answer.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <span>
#include <vector>

#include "oar/net/route_trie.hpp"

namespace {

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;

using Addr = std::array<std::byte, 16>;

struct Route {
    Addr prefix;
    std::size_t length;
    net::RouteTrie::Target target;
};

auto bit(const Addr& a, std::size_t i) -> unsigned {
    return (std::to_integer<unsigned>(a.at(i / 8)) >> (7 - (i % 8))) & 1U;
}

auto same_bits(const Addr& a, const Addr& b, std::size_t n) -> bool {
    for (std::size_t i = 0; i < n; ++i) {
        if (bit(a, i) != bit(b, i)) {
            return false;
        }
    }
    return true;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::size_t bits =
        (data[0] & 1U) == 0 ? net::RouteTrie::ipv4_bits : net::RouteTrie::ipv6_bits;
    const std::size_t width = bits / 8;
    std::span<const std::uint8_t> in{data + 1, size - 1};

    net::RouteTrie trie{bits};
    std::vector<Route> routes;
    while (in.size() >= 2 + width) {
        if ((in[0] & 0x80U) != 0) {
            in = in.subspan(1);
            break;
        }
        // Lengths up to bits + 1, so over-long ones are exercised too.
        const std::size_t length = in[0] % (bits + 2);
        const net::RouteTrie::Target target{.local = (in[1] & 1U) != 0,
                                            .nic = geneve::NicId{in[1] + std::uint64_t{1}}};
        Addr prefix{};
        std::transform(in.begin() + 2, in.begin() + 2 + static_cast<std::ptrdiff_t>(width),
                       prefix.begin(), [](std::uint8_t b) { return std::byte{b}; });
        in = in.subspan(2 + width);
        const bool fresh = length <= bits && std::ranges::none_of(routes, [&](const Route& r) {
                               return r.length == length && same_bits(r.prefix, prefix, length);
                           });
        if (trie.insert(std::span{prefix}.first(width), length, target) != fresh) {
            std::abort();
        }
        if (fresh) {
            routes.push_back({prefix, length, target});
        }
    }
    if (trie.size() != routes.size()) {
        std::abort();
    }
    while (in.size() >= width) {
        Addr a{};
        std::transform(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(width), a.begin(),
                       [](std::uint8_t b) { return std::byte{b}; });
        in = in.subspan(width);
        const Route* best = nullptr;
        for (const Route& r : routes) {
            if (same_bits(r.prefix, a, r.length) && (best == nullptr || r.length > best->length)) {
                best = &r;
            }
        }
        const auto got = trie.lookup(std::span{a}.first(width));
        if (got.has_value() != (best != nullptr) || (got && *got != best->target)) {
            std::abort();
        }
    }
    return 0;
}
