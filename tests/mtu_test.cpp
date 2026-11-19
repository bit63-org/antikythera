// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 6 (task 11): the guest MTU
// from the underlay MTU.

#define BOOST_TEST_MODULE mtu_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

#include "oar/net/mtu.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
using ak::test::unit_timeout_seconds;
using net::MtuError;

namespace {

constexpr std::uint32_t ethernet_mtu = 1500;
constexpr std::uint32_t jumbo_mtu = 9000;
constexpr std::uint32_t requirement_guest_floor = 1500;  // Requirement 6.2

}  // namespace

BOOST_AUTO_TEST_CASE(overheads_add_up, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // 40 IPv6 + 8 UDP + 8 Geneve + 20 NIC-pair + 14 Ethernet + 4 VLAN.
    BOOST_TEST(net::encapsulation_overhead == 94U);
    BOOST_TEST(net::wireguard_ipv6_overhead == 80U);
}

BOOST_AUTO_TEST_CASE(plain_underlay, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto plan = net::plan_mtu(ethernet_mtu);
    BOOST_REQUIRE(plan.has_value());
    BOOST_TEST(plan->guest_mtu == 1406U);
    BOOST_TEST(plan->max_geneve_payload == 1452U);
    BOOST_TEST(plan->underlay_mtu == ethernet_mtu);
    BOOST_TEST(plan->tunnel_overhead == 0U);
}

BOOST_AUTO_TEST_CASE(jumbo_with_wireguard_gives_at_least_1500,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto plan = net::plan_mtu(jumbo_mtu, net::wireguard_ipv6_overhead);
    BOOST_REQUIRE(plan.has_value());
    BOOST_TEST(plan->guest_mtu == 8826U);
    BOOST_TEST(plan->guest_mtu >= requirement_guest_floor);
    BOOST_TEST(plan->max_geneve_payload == jumbo_mtu - 80U - 48U);
}

BOOST_AUTO_TEST_CASE(largest_guest_frame_fills_the_underlay,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // For every underlay and tunnel, a tagged frame of the guest MTU plus
    // all headers is exactly the underlay MTU: nothing fragments and nothing
    // is wasted.
    for (std::uint32_t underlay : {1280U, 1500U, 4000U, 9000U}) {
        for (std::uint32_t tunnel : {0U, 80U}) {
            auto plan = net::plan_mtu(underlay, tunnel);
            BOOST_REQUIRE(plan.has_value());
            const std::size_t inner = plan->guest_mtu + net::inner_frame_overhead;
            BOOST_TEST(inner + net::geneve_header_size == plan->max_geneve_payload);
            BOOST_TEST(plan->max_geneve_payload + net::outer_header_size + tunnel == underlay);
        }
    }
}

BOOST_AUTO_TEST_CASE(bounds, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((net::plan_mtu(net::min_underlay_mtu - 1).error() == MtuError::underlay_too_small));
    BOOST_TEST(net::plan_mtu(net::min_underlay_mtu).has_value());
    BOOST_TEST((net::plan_mtu(net::max_underlay_mtu + 1).error() == MtuError::underlay_too_large));

    // The largest underlay still yields a guest MTU in virtio's 16 bits.
    auto top = net::plan_mtu(net::max_underlay_mtu);
    BOOST_REQUIRE(top.has_value());
    BOOST_TEST(top->guest_mtu == net::max_underlay_mtu - net::encapsulation_overhead);

    // A tunnel that eats almost everything leaves exactly min_mtu, then too little.
    const std::uint32_t tunnel = ethernet_mtu - net::encapsulation_overhead - net::min_mtu;
    auto edge = net::plan_mtu(ethernet_mtu, tunnel);
    BOOST_REQUIRE(edge.has_value());
    BOOST_TEST(edge->guest_mtu == net::min_mtu);
    BOOST_TEST((net::plan_mtu(ethernet_mtu, tunnel + 1).error() == MtuError::guest_too_small));
    BOOST_TEST((net::plan_mtu(ethernet_mtu, UINT32_MAX).error() == MtuError::guest_too_small));
}

BOOST_AUTO_TEST_CASE(error_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (auto e :
         {MtuError::underlay_too_small, MtuError::underlay_too_large, MtuError::guest_too_small}) {
        BOOST_TEST(std::string{net::to_string(e)} != "unknown");
    }
}
