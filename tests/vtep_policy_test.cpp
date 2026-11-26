// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 4.2 and 4.3.

#define BOOST_TEST_MODULE vtep_policy_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/vtep_policy.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
using ak::test::unit_timeout_seconds;
using geneve::NicId;
using net::PolicyError;

namespace {

constexpr std::uint32_t vpc = 100;
constexpr std::uint32_t other_vpc = vpc + 1;

constexpr NicId remote_nic{11};
constexpr NicId local_nic{22};
constexpr NicId other_vpc_nic{33};
constexpr NicId remote_but_not_local{44};
constexpr NicId unknown_nic{999};

// Last byte of each NIC's MAC and each VTEP's address.
constexpr std::uint8_t remote_mac_tail = 0x11;
constexpr std::uint8_t local_mac_tail = 0x22;
constexpr std::uint8_t other_vpc_mac_tail = 0x33;
constexpr std::uint8_t not_local_mac_tail = 0x44;
constexpr std::uint8_t wrong_mac_tail = 0x99;
constexpr std::uint8_t near_miss_mac_tail = 0x23;

constexpr std::uint8_t remote_vtep_tail = 1;
constexpr std::uint8_t local_vtep_tail = 2;
constexpr std::uint8_t third_vtep_tail = 3;
constexpr std::uint8_t spoofed_vtep_tail = 9;

constexpr std::byte ula_prefix{0xfd};
constexpr std::byte locally_administered{0x02};
constexpr std::byte broadcast_byte{0xFF};
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::size_t src_mac_offset = 6;
constexpr std::size_t frame_size = 64;

auto addr(std::uint8_t last) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[ipv6_last] = std::byte{last};
    return a;
}

auto mac(std::uint8_t last) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = locally_administered;
    m[mac_last] = std::byte{last};
    return m;
}

class Table final : public net::MappingView {
public:
    Table() {
        _bindings[remote_nic] = {vpc, mac(remote_mac_tail), addr(remote_vtep_tail)};
        _bindings[local_nic] = {vpc, mac(local_mac_tail), addr(local_vtep_tail)};
        _bindings[other_vpc_nic] = {other_vpc, mac(other_vpc_mac_tail), addr(local_vtep_tail)};
        _bindings[remote_but_not_local] = {vpc, mac(not_local_mac_tail), addr(third_vtep_tail)};
        _local = {local_nic, other_vpc_nic};
    }
    [[nodiscard]] auto lookup(NicId id) const -> std::optional<net::NicBinding> override {
        if (auto it = _bindings.find(id); it != _bindings.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    [[nodiscard]] auto is_local(NicId id) const -> bool override { return _local.contains(id); }
    [[nodiscard]] auto gateway_mac(std::uint32_t vni) const
        -> std::optional<net::MacAddress> override {
        if (gateway && vni == vpc) {
            return gateway;
        }
        return std::nullopt;
    }
    std::optional<net::MacAddress> gateway;  // vpc's gateway MAC, if configured

private:
    std::map<NicId, net::NicBinding> _bindings;
    std::set<NicId> _local;
};

struct Case {
    std::vector<std::byte> frame;
    geneve::Packet pkt;
};

// A frame from remote_nic (behind the remote VTEP) to `dst`.
auto make(NicId dst, net::MacAddress dst_mac, net::MacAddress src_mac = mac(remote_mac_tail),
          std::uint32_t vni = vpc) -> Case {
    Case c;
    c.frame.resize(frame_size);
    std::ranges::copy(dst_mac, c.frame.begin());
    std::ranges::copy(src_mac, c.frame.begin() + src_mac_offset);
    c.pkt.vni = vni;
    c.pkt.nics = geneve::NicPair{remote_nic, dst};
    c.pkt.inner = c.frame;
    return c;
}

auto error_of(const Case& c, const net::Ipv6Address& from = addr(remote_vtep_tail)) -> PolicyError {
    const Table t;
    auto r = net::check_ingress(c.pkt, from, t);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(accepts_valid_unicast, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Table t;
    auto c = make(local_nic, mac(local_mac_tail));
    auto r = net::check_ingress(c.pkt, addr(remote_vtep_tail), t);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == local_nic));
}

BOOST_AUTO_TEST_CASE(accepts_valid_broadcast, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Table t;
    net::MacAddress bcast;
    bcast.fill(broadcast_byte);
    auto c = make(geneve::nic_broadcast, bcast);
    auto r = net::check_ingress(c.pkt, addr(remote_vtep_tail), t);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == geneve::nic_broadcast));
}

// vpc-subnets-routing Requirement 6.5: a routed frame's inner source is the
// VNI's gateway MAC, accepted only where this VTEP holds that VNI's config.
BOOST_AUTO_TEST_CASE(accepts_the_gateway_mac_only_with_a_config,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::uint8_t gateway_tail = 0xEE;
    Table t;
    auto c = make(local_nic, mac(local_mac_tail), mac(gateway_tail));
    BOOST_TEST((net::check_ingress(c.pkt, addr(remote_vtep_tail), t).error() ==
                PolicyError::src_mac_mismatch));
    t.gateway = mac(gateway_tail);
    BOOST_TEST((net::check_ingress(c.pkt, addr(remote_vtep_tail), t).value() == local_nic));
    // Another VNI's gateway grants nothing, and the source NIC must still
    // come from its own VTEP.
    t.gateway = mac(gateway_tail + 1);
    BOOST_TEST((net::check_ingress(c.pkt, addr(remote_vtep_tail), t).error() ==
                PolicyError::src_mac_mismatch));
    t.gateway = mac(gateway_tail);
    BOOST_TEST((net::check_ingress(c.pkt, addr(spoofed_vtep_tail), t).error() ==
                PolicyError::src_wrong_vtep));
}

BOOST_AUTO_TEST_CASE(rejects_spoofed_source_vtep,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((error_of(make(local_nic, mac(local_mac_tail)), addr(spoofed_vtep_tail)) ==
                PolicyError::src_wrong_vtep));
}

BOOST_AUTO_TEST_CASE(rejects_spoofed_source_mac, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((error_of(make(local_nic, mac(local_mac_tail), mac(wrong_mac_tail))) ==
                PolicyError::src_mac_mismatch));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_source, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make(local_nic, mac(local_mac_tail));
    c.pkt.nics->src = unknown_nic;
    BOOST_TEST((error_of(c) == PolicyError::unknown_src));
}

BOOST_AUTO_TEST_CASE(rejects_forged_vni, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Source is real but claims a different VPC: the cross-VPC injection case.
    BOOST_TEST((error_of(make(other_vpc_nic, mac(other_vpc_mac_tail), mac(remote_mac_tail),
                              other_vpc)) == PolicyError::src_wrong_vni));
}

BOOST_AUTO_TEST_CASE(rejects_destination_in_another_vpc,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(
        (error_of(make(other_vpc_nic, mac(other_vpc_mac_tail))) == PolicyError::dst_wrong_vni));
}

BOOST_AUTO_TEST_CASE(rejects_destination_not_on_this_vtep,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((error_of(make(remote_but_not_local, mac(not_local_mac_tail))) ==
                PolicyError::dst_not_local));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_destination,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((error_of(make(unknown_nic, mac(local_mac_tail))) == PolicyError::unknown_dst));
}

BOOST_AUTO_TEST_CASE(rejects_destination_mac_mismatch,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(
        (error_of(make(local_nic, mac(near_miss_mac_tail))) == PolicyError::dst_mac_mismatch));
}

BOOST_AUTO_TEST_CASE(rejects_broadcast_to_unicast_mac,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((error_of(make(geneve::nic_broadcast, mac(local_mac_tail))) ==
                PolicyError::broadcast_not_group));
}

BOOST_AUTO_TEST_CASE(oam_is_never_delivered, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make(local_nic, mac(local_mac_tail));
    c.pkt.oam = true;
    BOOST_TEST((error_of(c) == PolicyError::oam_not_data));
}

BOOST_AUTO_TEST_CASE(end_to_end_with_decode, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Encode on the sender, decode and police on the receiver.
    const Table t;
    std::vector<std::byte> frame(frame_size);
    std::ranges::copy(mac(local_mac_tail), frame.begin());
    std::ranges::copy(mac(remote_mac_tail), frame.begin() + src_mac_offset);
    auto wire = geneve::encode({.vni = vpc, .nics = {remote_nic, local_nic}, .oam = false}, frame);
    BOOST_REQUIRE(wire.has_value());
    auto pkt = geneve::decode(*wire);
    BOOST_REQUIRE(pkt.has_value());
    auto r = net::check_ingress(*pkt, addr(remote_vtep_tail), t);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == local_nic));
}
