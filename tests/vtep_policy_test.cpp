// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE vtep_policy_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/vtep_policy.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
using geneve::NicId;
using net::PolicyError;

namespace {

constexpr std::uint32_t vpc = 100;
constexpr NicId remote_nic{11};
constexpr NicId local_nic{22};
constexpr NicId other_vpc_nic{33};
constexpr NicId remote_but_not_local{44};

net::Ipv6Address addr(std::uint8_t last) {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[15] = std::byte{last};
    return a;
}

net::MacAddress mac(std::uint8_t last) {
    return {std::byte{0x02}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{last}};
}

class Table final : public net::MappingView {
public:
    Table() {
        bindings_[remote_nic] = {vpc, mac(0x11), addr(1)};
        bindings_[local_nic] = {vpc, mac(0x22), addr(2)};
        bindings_[other_vpc_nic] = {vpc + 1, mac(0x33), addr(2)};
        bindings_[remote_but_not_local] = {vpc, mac(0x44), addr(3)};
        local_ = {local_nic, other_vpc_nic};
    }
    [[nodiscard]] std::optional<net::NicBinding> lookup(NicId id) const override {
        if (auto it = bindings_.find(id); it != bindings_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    [[nodiscard]] bool is_local(NicId id) const override { return local_.contains(id); }

private:
    std::map<NicId, net::NicBinding> bindings_;
    std::set<NicId> local_;
};

struct Case {
    std::vector<std::byte> frame;
    geneve::Packet pkt;
};

// A frame from remote_nic (behind VTEP ::1) to `dst`.
Case make(NicId dst, net::MacAddress dst_mac, net::MacAddress src_mac = mac(0x11), std::uint32_t vni = vpc) {
    Case c;
    c.frame.resize(64);
    std::ranges::copy(dst_mac, c.frame.begin());
    std::ranges::copy(src_mac, c.frame.begin() + 6);
    c.pkt.vni = vni;
    c.pkt.nics = geneve::NicPair{remote_nic, dst};
    c.pkt.inner = c.frame;
    return c;
}

PolicyError error_of(const Case& c, const net::Ipv6Address& from = addr(1)) {
    const Table t;
    auto r = net::check_ingress(c.pkt, from, t);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(accepts_valid_unicast) {
    const Table t;
    auto c = make(local_nic, mac(0x22));
    auto r = net::check_ingress(c.pkt, addr(1), t);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == local_nic));
}

BOOST_AUTO_TEST_CASE(accepts_valid_broadcast) {
    const Table t;
    net::MacAddress bcast;
    bcast.fill(std::byte{0xFF});
    auto c = make(geneve::nic_broadcast, bcast);
    auto r = net::check_ingress(c.pkt, addr(1), t);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == geneve::nic_broadcast));
}

BOOST_AUTO_TEST_CASE(rejects_spoofed_source_vtep) {
    BOOST_TEST((error_of(make(local_nic, mac(0x22)), addr(9)) == PolicyError::src_wrong_vtep));
}

BOOST_AUTO_TEST_CASE(rejects_spoofed_source_mac) {
    BOOST_TEST((error_of(make(local_nic, mac(0x22), mac(0x99))) == PolicyError::src_mac_mismatch));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_source) {
    auto c = make(local_nic, mac(0x22));
    c.pkt.nics->src = NicId{999};
    BOOST_TEST((error_of(c) == PolicyError::unknown_src));
}

BOOST_AUTO_TEST_CASE(rejects_forged_vni) {
    // Source is real but claims a different VPC: the cross-VPC injection case.
    BOOST_TEST((error_of(make(other_vpc_nic, mac(0x33), mac(0x11), vpc + 1)) == PolicyError::src_wrong_vni));
}

BOOST_AUTO_TEST_CASE(rejects_destination_in_another_vpc) {
    BOOST_TEST((error_of(make(other_vpc_nic, mac(0x33))) == PolicyError::dst_wrong_vni));
}

BOOST_AUTO_TEST_CASE(rejects_destination_not_on_this_vtep) {
    BOOST_TEST((error_of(make(remote_but_not_local, mac(0x44))) == PolicyError::dst_not_local));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_destination) {
    BOOST_TEST((error_of(make(NicId{999}, mac(0x22))) == PolicyError::unknown_dst));
}

BOOST_AUTO_TEST_CASE(rejects_destination_mac_mismatch) {
    BOOST_TEST((error_of(make(local_nic, mac(0x23))) == PolicyError::dst_mac_mismatch));
}

BOOST_AUTO_TEST_CASE(rejects_broadcast_to_unicast_mac) {
    BOOST_TEST((error_of(make(geneve::nic_broadcast, mac(0x22))) == PolicyError::broadcast_not_group));
}

BOOST_AUTO_TEST_CASE(oam_is_never_delivered) {
    auto c = make(local_nic, mac(0x22));
    c.pkt.oam = true;
    BOOST_TEST((error_of(c) == PolicyError::oam_not_data));
}

BOOST_AUTO_TEST_CASE(end_to_end_with_decode) {
    // Encode on the sender, decode and police on the receiver.
    const Table t;
    std::vector<std::byte> frame(64);
    std::ranges::copy(mac(0x22), frame.begin());
    std::ranges::copy(mac(0x11), frame.begin() + 6);
    auto wire = geneve::encode({.vni = vpc, .nics = {remote_nic, local_nic}, .oam = false}, frame);
    BOOST_REQUIRE(wire.has_value());
    auto pkt = geneve::decode(*wire);
    BOOST_REQUIRE(pkt.has_value());
    auto r = net::check_ingress(*pkt, addr(1), t);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == local_nic));
}
