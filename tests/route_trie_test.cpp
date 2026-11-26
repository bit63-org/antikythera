// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/vpc-subnets-routing/ task 5: RouteTrie's longest-prefix
// match, against a naive scan over the same routes.

#define BOOST_TEST_MODULE route_trie_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <span>
#include <vector>

#include "oar/net/route_trie.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
using ak::test::unit_timeout_seconds;
using Target = net::RouteTrie::Target;

namespace {

using Addr = std::array<std::byte, 16>;

auto v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> Addr {
    return {std::byte{a}, std::byte{b}, std::byte{c}, std::byte{d}};
}

auto nic(std::uint64_t id) -> Target {
    return {.local = false, .nic = geneve::NicId{id}};
}

constexpr Target local{.local = true, .nic = geneve::nic_invalid};

struct Route {
    Addr prefix;
    std::size_t length;
    Target target;
};

auto bit(const Addr& a, std::size_t i) -> unsigned {
    return (std::to_integer<unsigned>(a.at(i / 8)) >> (7 - (i % 8))) & 1U;
}

// The longest of `routes` matching `a` in its first `bits` bits.
auto naive(const std::vector<Route>& routes, const Addr& a) -> std::optional<Target> {
    const Route* best = nullptr;
    for (const Route& r : routes) {
        bool match = true;
        for (std::size_t i = 0; i < r.length && match; ++i) {
            match = bit(r.prefix, i) == bit(a, i);
        }
        if (match && (best == nullptr || r.length > best->length)) {
            best = &r;
        }
    }
    return best == nullptr ? std::nullopt : std::optional{best->target};
}

}  // namespace

BOOST_AUTO_TEST_CASE(longest_prefix_wins, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::RouteTrie t{net::RouteTrie::ipv4_bits};
    BOOST_TEST(!t.lookup(v4(10, 0, 0, 1)).has_value());  // empty: nothing matches
    BOOST_REQUIRE(t.insert(v4(10, 0, 0, 0), 16, local));
    BOOST_REQUIRE(t.insert(v4(10, 0, 2, 0), 24, nic(7)));
    BOOST_REQUIRE(t.insert(v4(0, 0, 0, 0), 0, nic(9)));
    BOOST_TEST(t.size() == 3U);
    BOOST_TEST((t.lookup(v4(10, 0, 1, 5)) == std::optional{local}));
    BOOST_TEST((t.lookup(v4(10, 0, 2, 5)) == std::optional{nic(7)}));
    BOOST_TEST((t.lookup(v4(8, 8, 8, 8)) == std::optional{nic(9)}));
    // A /32 host route.
    BOOST_REQUIRE(t.insert(v4(10, 0, 2, 5), 32, nic(8)));
    BOOST_TEST((t.lookup(v4(10, 0, 2, 5)) == std::optional{nic(8)}));
    BOOST_TEST((t.lookup(v4(10, 0, 2, 6)) == std::optional{nic(7)}));
}

BOOST_AUTO_TEST_CASE(bits_past_the_length_are_ignored,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::RouteTrie t{net::RouteTrie::ipv4_bits};
    BOOST_REQUIRE(t.insert(v4(192, 168, 7, 9), 16, nic(1)));
    BOOST_TEST((t.lookup(v4(192, 168, 200, 1)) == std::optional{nic(1)}));
    // The same /16 again, whatever its host bits, is a duplicate.
    BOOST_TEST(!t.insert(v4(192, 168, 0, 0), 16, nic(2)));
    BOOST_TEST(t.size() == 1U);
}

BOOST_AUTO_TEST_CASE(bad_inserts_change_nothing, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::RouteTrie t{net::RouteTrie::ipv4_bits};
    BOOST_TEST(!t.insert(v4(10, 0, 0, 0), 33, nic(1)));
    const std::array<std::byte, 2> short_prefix{};
    BOOST_TEST(!t.insert(short_prefix, 8, nic(1)));
    BOOST_TEST(!t.lookup(short_prefix).has_value());
    BOOST_TEST(t.size() == 0U);
    net::RouteTrie six{net::RouteTrie::ipv6_bits};
    BOOST_TEST(!six.insert(v4(0xfd, 0, 0, 0), 129, nic(1)));
    BOOST_TEST(six.insert(v4(0xfd, 0, 0, 0), 128, nic(1)));
    const Addr fd = v4(0xfd, 0, 0, 0);
    BOOST_TEST(!six.lookup(std::span{fd}.first(4)).has_value());
}

BOOST_AUTO_TEST_CASE(matches_a_naive_scan, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::mt19937_64 rng{0x5B01};  // fixed: reproducible
    for (const std::size_t bits : {net::RouteTrie::ipv4_bits, net::RouteTrie::ipv6_bits}) {
        for (int round = 0; round < 20; ++round) {
            net::RouteTrie t{bits};
            std::vector<Route> routes;
            // Prefixes cluster under one /8 so that they nest and overlap.
            Addr base{};
            base[0] = std::byte{0x0A};
            for (int i = 0; i < 300; ++i) {
                Addr p = base;
                for (std::size_t b = 1; b < bits / 8; ++b) {
                    p.at(b) = static_cast<std::byte>(rng() & 0x0FU);
                }
                const std::size_t length = rng() % (bits + 1);
                const Target target = rng() % 4 == 0 ? local : nic(1 + (rng() % 50));
                const bool fresh = !std::ranges::any_of(routes, [&](const Route& r) {
                    if (r.length != length) {
                        return false;
                    }
                    for (std::size_t k = 0; k < length; ++k) {
                        if (bit(r.prefix, k) != bit(p, k)) {
                            return false;
                        }
                    }
                    return true;
                });
                BOOST_REQUIRE(t.insert(p, length, target) == fresh);
                if (fresh) {
                    routes.push_back({p, length, target});
                }
            }
            BOOST_REQUIRE(t.size() == routes.size());
            for (int q = 0; q < 2000; ++q) {
                Addr a = base;
                for (std::size_t b = 1; b < bits / 8; ++b) {
                    a.at(b) = static_cast<std::byte>(rng() & 0x0FU);
                }
                if (q % 10 == 0) {
                    a[0] = static_cast<std::byte>(rng());
                }
                BOOST_REQUIRE((t.lookup(a) == naive(routes, a)));
            }
        }
    }
}
