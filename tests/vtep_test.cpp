// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 3 and 4.4 (task 9): the Vtep
// runtime: encapsulation, flow source ports, decode drop counters, OAM
// keepalives and peer liveness, and the UDP endpoint.

#define BOOST_TEST_MODULE vtep_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/wire.hpp"
#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/oam.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/vswitch.hpp"
#include "oar/net/vtep.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
namespace oam = ak::oar::net::oam;
using ak::test::unit_timeout_seconds;
using geneve::NicId;
using net::MapEntry;
using net::PeerState;
using std::chrono::milliseconds;

namespace {

constexpr std::uint32_t vpc = 100;
constexpr std::uint32_t lonely_vpc = 300;

// vpc: a here (VTEP 1), c on VTEP 2, d on VTEP 3. lonely_vpc: z on VTEP 4
// only, so VTEP 4 is no peer of VTEP 1.
constexpr NicId nic_a{11};
constexpr NicId nic_c{33};
constexpr NicId nic_d{44};
constexpr NicId nic_z{99};

constexpr std::uint8_t self_tail = 1;
constexpr std::uint8_t peer_tail = 2;
constexpr std::uint8_t third_tail = 3;
constexpr std::uint8_t fourth_tail = 4;
constexpr std::uint8_t stranger_tail = 9;

constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::byte ula_prefix{0xfd};
constexpr std::byte locally_administered{0x02};
constexpr std::size_t payload_size = 32;
constexpr std::uint16_t ethertype_test = 0x88B5;
constexpr std::uint16_t ethertype_ipv4 = 0x0800;
constexpr std::uint16_t ethertype_ipv6 = 0x86DD;
constexpr std::uint16_t ethertype_vlan = 0x8100;
constexpr std::uint8_t ipproto_udp = 17;
constexpr std::uint8_t ipv4_version_ihl = 0x45;
constexpr std::uint8_t ttl = 64;
constexpr std::uint16_t ipv4_more_fragments = 0x2000;
constexpr std::uint32_t ipv6_version_word = 0x6000'0000;
constexpr std::uint16_t vlan_tci = 42;
constexpr std::uint16_t client_port = 40000;
constexpr std::uint16_t server_port = 80;
constexpr unsigned flows = 256;
constexpr std::size_t min_distinct_ports = 200;

constexpr milliseconds interval{1000};
constexpr unsigned misses = 3;
constexpr milliseconds half_interval{500};

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto mac_of(NicId id) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = locally_administered;
    m[mac_last] = static_cast<std::byte>(id.value);
    return m;
}

auto entry(NicId id, std::uint8_t vtep_tail) -> MapEntry {
    return {.nic_id = id, .mac = mac_of(id), .owner_vtep = vtep(vtep_tail)};
}

auto frame(const net::MacAddress& dst, const net::MacAddress& src) -> std::vector<std::byte> {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    w.bytes(dst);
    w.bytes(src);
    w.be16(ethertype_test);
    f.resize(f.size() + payload_size, std::byte{0x5a});
    return f;
}

// An Ethernet/IPv4/UDP frame, optionally VLAN-tagged or a non-first fragment.
auto udp4(std::uint16_t sport, std::uint16_t dport, bool tagged = false, std::uint16_t fragment = 0)
    -> std::vector<std::byte> {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    w.bytes(mac_of(nic_c));
    w.bytes(mac_of(nic_a));
    if (tagged) {
        w.be16(ethertype_vlan);
        w.be16(vlan_tci);
    }
    w.be16(ethertype_ipv4);
    w.u8(ipv4_version_ihl);
    w.u8(0);
    w.be16(0);  // total length: not checked by the hash
    w.be16(0);
    w.be16(fragment);
    w.u8(ttl);
    w.u8(ipproto_udp);
    w.be16(0);
    w.be32(0x0A00'0001);
    w.be32(0x0A00'0002);
    w.be16(sport);
    w.be16(dport);
    w.be32(0);
    return f;
}

auto udp6(std::uint16_t sport, std::uint16_t dport) -> std::vector<std::byte> {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    w.bytes(mac_of(nic_c));
    w.bytes(mac_of(nic_a));
    w.be16(ethertype_ipv6);
    w.be32(ipv6_version_word);
    w.be16(0);
    w.u8(ipproto_udp);
    w.u8(ttl);
    w.bytes(vtep(peer_tail));
    w.bytes(vtep(third_tail));
    w.be16(sport);
    w.be16(dport);
    w.be32(0);
    return f;
}

struct Datagram {
    net::Ipv6Address dst{};
    std::uint16_t dst_port{0};
    std::uint16_t flow_port{0};
    std::vector<std::byte> payload;
};

class FakeSender final : public net::DatagramSender {
public:
    auto send_to(const net::Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                 std::span<const std::byte> payload) -> bool override {
        if (refuse) {
            return false;
        }
        sent.push_back({dst, dst_port, flow_port, {payload.begin(), payload.end()}});
        return true;
    }
    [[nodiscard]] auto keepalives_to(const net::Ipv6Address& dst) const -> std::size_t {
        std::size_t n = 0;
        for (const Datagram& d : sent) {
            auto p = geneve::decode(d.payload);
            n += (d.dst == dst && p && p->oam) ? 1U : 0U;
        }
        return n;
    }
    std::vector<Datagram> sent;
    bool refuse{false};
};

class Recorder final : public net::PeerObserver {
public:
    auto peer_changed(const net::Ipv6Address& vtep, PeerState state) -> void override {
        changes.emplace_back(vtep, state);
    }
    std::vector<std::pair<net::Ipv6Address, PeerState>> changes;
};

class FakePort final : public net::RxPort {
public:
    auto deliver(std::span<const std::byte> f) -> net::RxResult override {
        frames.emplace_back(f.begin(), f.end());
        return net::RxResult::delivered;
    }
    std::vector<std::vector<std::byte>> frames;
};

auto standard_mappings(net::MappingTable& table) -> void {
    BOOST_REQUIRE(table.apply(
        {.vni = vpc,
         .version = 1,
         .entries = {entry(nic_a, self_tail), entry(nic_c, peer_tail), entry(nic_d, third_tail)}}));
    BOOST_REQUIRE(
        table.apply({.vni = lonely_vpc, .version = 1, .entries = {entry(nic_z, fourth_tail)}}));
}

auto config() -> net::VtepConfig {
    return {.keepalive_interval = interval, .keepalive_misses = misses};
}

struct Fixture {
    Fixture() {
        standard_mappings(table);
        auto v = net::Vtep::create(table, sender, &recorder, config());
        BOOST_REQUIRE(v.has_value());
        vtep_ = std::move(*v);
    }

    auto keepalive(std::uint64_t seq = 1) const -> std::vector<std::byte> {
        return oam::encode({.type = oam::Type::keepalive, .sequence = seq});
    }

    net::MappingTable table{vtep(self_tail)};
    FakeSender sender;
    Recorder recorder;
    std::unique_ptr<net::Vtep> vtep_;
    net::VtepClock::time_point t0{std::chrono::seconds{1000}};
};

auto state_of(const net::Vtep& v, const net::Ipv6Address& addr) -> std::optional<PeerState> {
    for (const auto& p : v.peers()) {
        if (p.vtep == addr) {
            return p.state;
        }
    }
    return std::nullopt;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(flow_ports)

BOOST_AUTO_TEST_CASE(in_range_and_stable, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = udp4(client_port, server_port);
    const auto p = net::flow_port(vpc, f);
    BOOST_TEST(p >= net::flow_port_base);
    BOOST_TEST(net::flow_port(vpc, f) == p);
    BOOST_TEST(net::flow_port(vpc + 1, f) != p);  // the VNI is part of the flow
}

BOOST_AUTO_TEST_CASE(spread_over_flows, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::set<std::uint16_t> v4;
    std::set<std::uint16_t> v6;
    for (unsigned i = 0; i < flows; ++i) {
        v4.insert(
            net::flow_port(vpc, udp4(static_cast<std::uint16_t>(client_port + i), server_port)));
        v6.insert(
            net::flow_port(vpc, udp6(static_cast<std::uint16_t>(client_port + i), server_port)));
    }
    BOOST_TEST(v4.size() >= min_distinct_ports);
    BOOST_TEST(v6.size() >= min_distinct_ports);
}

BOOST_AUTO_TEST_CASE(vlan_tag_does_not_split_flow,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(net::flow_port(vpc, udp4(client_port, server_port, true)) ==
               net::flow_port(vpc, udp4(client_port, server_port)));
}

BOOST_AUTO_TEST_CASE(fragments_ignore_ports, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A fragment's "ports" are payload bytes: every fragment of a datagram
    // must hash alike.
    BOOST_TEST(net::flow_port(vpc, udp4(client_port, server_port, false, ipv4_more_fragments)) ==
               net::flow_port(vpc, udp4(client_port + 1, server_port, false, ipv4_more_fragments)));
}

BOOST_AUTO_TEST_CASE(short_frames_still_hash, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = udp4(client_port, server_port);
    for (std::size_t n = 0; n <= f.size(); ++n) {
        BOOST_TEST(net::flow_port(vpc, std::span{f}.first(n)) >= net::flow_port_base);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(config_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table{vtep(self_tail)};
    FakeSender sender;
    auto bad = config();
    bad.keepalive_interval = milliseconds{0};
    BOOST_TEST((net::Vtep::create(table, sender, nullptr, bad).error() ==
                net::VtepConfigError::bad_interval));
    bad = config();
    bad.keepalive_misses = 0;
    BOOST_TEST((net::Vtep::create(table, sender, nullptr, bad).error() ==
                net::VtepConfigError::bad_misses));
    bad = config();
    bad.peer_port = 0;
    BOOST_TEST(
        (net::Vtep::create(table, sender, nullptr, bad).error() == net::VtepConfigError::bad_port));
    BOOST_TEST(net::Vtep::create(table, sender, nullptr, config()).has_value());
}

BOOST_FIXTURE_TEST_SUITE(encapsulation, Fixture)

BOOST_AUTO_TEST_CASE(send_encodes_geneve, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto inner = udp4(client_port, server_port);
    vtep_->send({.vtep = vtep(peer_tail), .vni = vpc, .nics = {nic_a, nic_c}, .frame = inner});
    BOOST_REQUIRE(sender.sent.size() == 1);
    const Datagram& d = sender.sent[0];
    BOOST_TEST((d.dst == vtep(peer_tail)));
    BOOST_TEST(d.dst_port == geneve::udp_port);
    BOOST_TEST(d.flow_port == net::flow_port(vpc, inner));
    auto p = geneve::decode(d.payload);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(!p->oam);
    BOOST_TEST(p->vni == vpc);
    BOOST_TEST((p->nics == geneve::NicPair{nic_a, nic_c}));
    BOOST_TEST((std::vector<std::byte>(p->inner.begin(), p->inner.end()) == inner));
    BOOST_TEST(vtep_->counters().tx_packets == 1);
    BOOST_TEST(vtep_->counters().tx_bytes == d.payload.size());
}

BOOST_AUTO_TEST_CASE(send_failures_counted, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto inner = frame(mac_of(nic_c), mac_of(nic_a));
    vtep_->send({.vtep = vtep(peer_tail),
                 .vni = geneve::vni_max + 1,
                 .nics = {nic_a, nic_c},
                 .frame = inner});
    BOOST_TEST(vtep_->counters().tx_encode_failed == 1);
    sender.refuse = true;
    vtep_->send({.vtep = vtep(peer_tail), .vni = vpc, .nics = {nic_a, nic_c}, .frame = inner});
    BOOST_TEST(vtep_->counters().tx_send_failed == 1);
    BOOST_TEST(vtep_->counters().tx_packets == 0);
}

BOOST_AUTO_TEST_CASE(receive_returns_data, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto inner = frame(mac_of(nic_a), mac_of(nic_c));
    auto bytes = geneve::encode({.vni = vpc, .nics = {nic_c, nic_a}}, inner);
    BOOST_REQUIRE(bytes.has_value());
    auto p = vtep_->receive(*bytes, vtep(peer_tail), t0);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST((p->nics == geneve::NicPair{nic_c, nic_a}));
    BOOST_TEST(vtep_->counters().rx_data == 1);
}

BOOST_AUTO_TEST_CASE(decode_drops_counted_per_reason,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto inner = frame(mac_of(nic_a), mac_of(nic_c));
    auto good = geneve::encode({.vni = vpc, .nics = {nic_c, nic_a}}, inner);
    BOOST_REQUIRE(good.has_value());

    auto bad_version = *good;
    bad_version[0] |= std::byte{0x40};
    auto short_inner = std::vector<std::byte>(
        good->begin(), good->begin() + geneve::base_header_size + geneve::nic_pair_option_size + 1);

    BOOST_TEST(!vtep_->receive(std::span{*good}.first(3), vtep(peer_tail), t0));
    BOOST_TEST(!vtep_->receive(bad_version, vtep(peer_tail), t0));
    BOOST_TEST(!vtep_->receive(short_inner, vtep(peer_tail), t0));

    const auto& drops = vtep_->counters().rx_drop_decode;
    auto at = [&drops](geneve::DecodeError e) { return drops.at(static_cast<std::size_t>(e)); };
    BOOST_TEST(at(geneve::DecodeError::truncated) == 1);
    BOOST_TEST(at(geneve::DecodeError::bad_version) == 1);
    BOOST_TEST(at(geneve::DecodeError::inner_frame_too_short) == 1);
    BOOST_TEST(vtep_->counters().rx_datagrams == 3);
    BOOST_TEST(vtep_->counters().rx_data == 0);
}

BOOST_AUTO_TEST_CASE(oam_never_returned, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!vtep_->receive(keepalive(), vtep(peer_tail), t0));
    // An OAM-flagged packet with an Ethernet payload and NIC pair: still OAM,
    // and not a keepalive.
    const auto inner = frame(mac_of(nic_a), mac_of(nic_c));
    auto oam_data = geneve::encode({.vni = vpc, .nics = {nic_c, nic_a}, .oam = true}, inner);
    BOOST_REQUIRE(oam_data.has_value());
    BOOST_TEST(!vtep_->receive(*oam_data, vtep(peer_tail), t0));
    BOOST_TEST(vtep_->counters().rx_data == 0);
    BOOST_TEST(vtep_->counters().keepalives_rx == 1);
    BOOST_TEST(vtep_->counters().rx_drop_oam.at(
                   static_cast<std::size_t>(oam::OamError::bad_protocol)) == 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(keepalives, Fixture)

BOOST_AUTO_TEST_CASE(peers_follow_mappings, *boost::unit_test::timeout(unit_timeout_seconds)) {
    static_cast<void>(vtep_->tick(t0));
    const auto peers = vtep_->peers();
    BOOST_REQUIRE(peers.size() == 2);
    BOOST_TEST((peers[0].vtep == vtep(peer_tail)));
    BOOST_TEST((peers[1].vtep == vtep(third_tail)));
    BOOST_TEST((peers[0].state == PeerState::pending));

    // d leaves: VTEP 3 is no longer a peer.
    BOOST_REQUIRE(table.apply(
        {.vni = vpc, .version = 2, .entries = {entry(nic_a, self_tail), entry(nic_c, peer_tail)}}));
    static_cast<void>(vtep_->tick(t0 + half_interval));
    BOOST_TEST(vtep_->peers().size() == 1);
    BOOST_TEST(!state_of(*vtep_, vtep(third_tail)).has_value());
}

BOOST_AUTO_TEST_CASE(sent_every_interval, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto next = vtep_->tick(t0);
    BOOST_TEST(sender.keepalives_to(vtep(peer_tail)) == 1);
    BOOST_TEST(sender.keepalives_to(vtep(third_tail)) == 1);
    BOOST_TEST(sender.keepalives_to(vtep(fourth_tail)) == 0);  // not a peer
    BOOST_TEST((next == t0 + interval));
    for (const Datagram& d : sender.sent) {
        BOOST_TEST(d.dst_port == geneve::udp_port);
        auto p = geneve::decode(d.payload);
        BOOST_REQUIRE(p.has_value());
        BOOST_TEST(oam::parse(*p).has_value());
    }

    static_cast<void>(vtep_->tick(t0 + half_interval));
    BOOST_TEST(sender.keepalives_to(vtep(peer_tail)) == 1);  // not due yet
    static_cast<void>(vtep_->tick(t0 + interval));
    BOOST_TEST(sender.keepalives_to(vtep(peer_tail)) == 2);
    BOOST_TEST(vtep_->counters().keepalives_tx == 4);

    sender.refuse = true;
    static_cast<void>(vtep_->tick(t0 + (2 * interval)));
    BOOST_TEST(vtep_->counters().keepalive_send_failed == 2);
}

BOOST_AUTO_TEST_CASE(up_then_down, *boost::unit_test::timeout(unit_timeout_seconds)) {
    static_cast<void>(vtep_->tick(t0));
    BOOST_TEST(!vtep_->receive(keepalive(7), vtep(peer_tail), t0 + half_interval));
    BOOST_TEST((state_of(*vtep_, vtep(peer_tail)) == PeerState::up));
    BOOST_REQUIRE(recorder.changes.size() == 1);
    BOOST_TEST((recorder.changes[0] == std::pair{vtep(peer_tail), PeerState::up}));
    const auto peers = vtep_->peers();
    BOOST_TEST(peers[0].keepalives_rx == 1);
    BOOST_TEST(peers[0].last_sequence == 7);

    // Still up just before misses * interval of silence.
    const auto heard = t0 + half_interval;
    static_cast<void>(vtep_->tick(heard + (misses * interval) - milliseconds{1}));
    BOOST_TEST((state_of(*vtep_, vtep(peer_tail)) == PeerState::up));
    static_cast<void>(vtep_->tick(heard + (misses * interval)));
    BOOST_TEST((state_of(*vtep_, vtep(peer_tail)) == PeerState::down));

    // And up again when it speaks.
    BOOST_TEST(!vtep_->receive(keepalive(8), vtep(peer_tail), heard + (4 * interval)));
    BOOST_TEST((state_of(*vtep_, vtep(peer_tail)) == PeerState::up));
}

BOOST_AUTO_TEST_CASE(silent_new_peer_goes_down_after_grace,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto next = vtep_->tick(t0);
    BOOST_TEST((next == t0 + interval));
    const auto late = t0 + (misses * interval) - milliseconds{1};
    static_cast<void>(vtep_->tick(late));  // a late tick: the keepalive goes now
    BOOST_TEST((state_of(*vtep_, vtep(third_tail)) == PeerState::pending));
    next = vtep_->tick(t0 + (misses * interval));
    BOOST_TEST((state_of(*vtep_, vtep(third_tail)) == PeerState::down));
    BOOST_TEST(recorder.changes.size() == 2);  // both peers, both down
    // Down peers still get keepalives, so the next wake is the next send,
    // one interval after the late one.
    BOOST_TEST((next == late + interval));
}

BOOST_AUTO_TEST_CASE(keepalive_from_stranger_dropped,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    static_cast<void>(vtep_->tick(t0));
    BOOST_TEST(!vtep_->receive(keepalive(), vtep(stranger_tail), t0));
    BOOST_TEST(!vtep_->receive(keepalive(), vtep(fourth_tail), t0));  // no shared VNI
    BOOST_TEST(vtep_->counters().rx_drop_oam_unknown_peer == 2);
    BOOST_TEST(vtep_->counters().keepalives_rx == 0);
    BOOST_TEST(recorder.changes.empty());
}

BOOST_AUTO_TEST_CASE(keepalive_before_first_tick,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!vtep_->receive(keepalive(), vtep(peer_tail), t0));
    BOOST_TEST((state_of(*vtep_, vtep(peer_tail)) == PeerState::up));
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

// Two VTEPs, each with its own mappings, VSwitch and Vtep, joined by a
// sender that hands datagrams straight to the other side.
struct Side;

class Wire final : public net::DatagramSender {
public:
    auto send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool override;
    Side* self{nullptr};
    std::vector<Side*> others;
};

struct Side {
    explicit Side(std::uint8_t tail) : addr{vtep(tail)}, table{addr} {
        standard_mappings(table);
        auto v = net::Vtep::create(table, wire, nullptr, config());
        BOOST_REQUIRE(v.has_value());
        vtep_ = std::move(*v);
        sw = std::make_unique<net::VSwitch>(table, *vtep_);
        wire.self = this;
    }
    net::Ipv6Address addr;
    net::MappingTable table;
    Wire wire;
    std::unique_ptr<net::Vtep> vtep_;
    std::unique_ptr<net::VSwitch> sw;
    net::VtepClock::time_point now{std::chrono::seconds{1}};
};

auto Wire::send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                   std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool {
    for (Side* s : others) {
        if (s->addr == dst) {
            if (auto p = s->vtep_->receive(payload, self->addr, s->now)) {
                static_cast<void>(s->sw->receive(*p, self->addr));
            }
            return true;
        }
    }
    return false;
}

}  // namespace

BOOST_AUTO_TEST_CASE(two_vteps_end_to_end, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Side one{self_tail};
    Side two{peer_tail};
    one.wire.others = {&two};
    two.wire.others = {&one};
    FakePort port_a;
    FakePort port_c;
    BOOST_REQUIRE(one.sw->attach(nic_a, port_a));
    BOOST_REQUIRE(two.sw->attach(nic_c, port_c));

    // Keepalives bring each up in the other's view.
    static_cast<void>(one.vtep_->tick(one.now));
    static_cast<void>(two.vtep_->tick(two.now));
    BOOST_TEST((state_of(*one.vtep_, two.addr) == PeerState::up));
    BOOST_TEST((state_of(*two.vtep_, one.addr) == PeerState::up));

    const auto f = frame(mac_of(nic_c), mac_of(nic_a));
    one.sw->transmit({.source = nic_a, .frame = f});
    BOOST_REQUIRE(port_c.frames.size() == 1);
    BOOST_TEST(port_c.frames[0] == f);

    const auto back = frame(mac_of(nic_a), mac_of(nic_c));
    two.sw->transmit({.source = nic_c, .frame = back});
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST(port_a.frames[0] == back);

    // A frame claiming to come from d (VTEP 3) but sent by VTEP 2 is refused
    // by the receiving side's ingress policy.
    auto forged =
        geneve::encode({.vni = vpc, .nics = {nic_d, nic_a}}, frame(mac_of(nic_a), mac_of(nic_d)));
    BOOST_REQUIRE(forged.has_value());
    BOOST_TEST(two.wire.send_to(one.addr, geneve::udp_port, net::flow_port_base, *forged));
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(one.sw->counters().rx_drop_policy.at(
                   static_cast<std::size_t>(net::PolicyError::src_wrong_vtep)) == 1);
}

namespace {

// The UDP tests need IPv6 loopback, which some sandboxes lack.
auto ipv6_loopback_available() -> bool {
    const int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_loopback;
    const bool ok = ::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) == 0;
    ::close(fd);
    return ok;
}

struct Ipv6Loopback {
    auto operator()(boost::unit_test::test_unit_id /*id*/) const
        -> boost::test_tools::assertion_result {
        boost::test_tools::assertion_result r{ipv6_loopback_available()};
        r.message() << "no IPv6 loopback in this environment";
        return r;
    }
};

auto loopback() -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[ipv6_last] = std::byte{1};
    return a;
}

constexpr std::size_t receive_buffer = 2048;
constexpr int receive_wait_ms = 2000;
constexpr std::uint16_t pool_size = 4;

auto wait_readable(int fd) -> bool {
    pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
    return ::poll(&p, 1, receive_wait_ms) == 1;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(udp, *boost::unit_test::precondition(Ipv6Loopback{}))

BOOST_AUTO_TEST_CASE(pump_feeds_vtep_and_vswitch,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto ep = net::UdpEndpoint::create({.bind = loopback(), .port = 0});
    BOOST_REQUIRE_MESSAGE(ep.has_value(), ep.error());
    // The Vtep's identity is VTEP 1; the remote side of the mappings is ::1,
    // where the test sends from.
    net::MappingTable table{vtep(self_tail)};
    BOOST_REQUIRE(table.apply(
        {.vni = vpc,
         .version = 1,
         .entries = {entry(nic_a, self_tail),
                     {.nic_id = nic_c, .mac = mac_of(nic_c), .owner_vtep = loopback()}}}));
    auto v = net::Vtep::create(table, **ep, nullptr, config());
    BOOST_REQUIRE(v.has_value());
    net::VSwitch sw{table, **v};
    FakePort port_a;
    BOOST_REQUIRE(sw.attach(nic_a, port_a));
    const auto now = net::VtepClock::now();

    // Keepalive and data, both from ::1 to the endpoint's port.
    const auto f = frame(mac_of(nic_a), mac_of(nic_c));
    auto data = geneve::encode({.vni = vpc, .nics = {nic_c, nic_a}}, f);
    BOOST_REQUIRE(data.has_value());
    const auto ka = oam::encode({.sequence = 1});
    BOOST_REQUIRE((*ep)->send_to(loopback(), (*ep)->local_port(), 0, ka));
    BOOST_REQUIRE((*ep)->send_to(loopback(), (*ep)->local_port(), 0, *data));

    std::vector<std::byte> buffer(receive_buffer);
    std::size_t got = 0;
    while (got < 2 && wait_readable((*ep)->poll_fd())) {
        got += net::pump(**ep, **v, sw, buffer, 2, now);
    }
    BOOST_TEST(got == 2);
    BOOST_TEST((state_of(**v, loopback()) == PeerState::up));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST(port_a.frames[0] == f);
}

BOOST_AUTO_TEST_CASE(truncated_datagrams_dropped,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto ep = net::UdpEndpoint::create({.bind = loopback(), .port = 0});
    BOOST_REQUIRE_MESSAGE(ep.has_value(), ep.error());
    const std::vector<std::byte> big(receive_buffer, std::byte{0});
    BOOST_REQUIRE((*ep)->send_to(loopback(), (*ep)->local_port(), 0, big));
    BOOST_REQUIRE(wait_readable((*ep)->poll_fd()));
    std::vector<std::byte> small(receive_buffer / 2);
    auto d = (*ep)->receive(small);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->truncated);
    BOOST_TEST((*ep)->rx_truncated() == 1);
}

BOOST_AUTO_TEST_CASE(source_port_pool, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto rx = net::UdpEndpoint::create({.bind = loopback(), .port = 0});
    BOOST_REQUIRE_MESSAGE(rx.has_value(), rx.error());
    // A pool at a port range the kernel just handed out is very likely free.
    auto probe = net::UdpEndpoint::create({.bind = loopback(), .port = 0});
    BOOST_REQUIRE(probe.has_value());
    const auto base = (*probe)->local_port();
    probe->reset();
    auto tx = net::UdpEndpoint::create(
        {.bind = loopback(), .port = 0, .source_port_base = base, .source_ports = 1});
    if (!tx) {
        BOOST_TEST_MESSAGE("pool port taken, skipping: " << tx.error());
        return;
    }
    std::vector<std::byte> buffer(receive_buffer);
    const std::vector<std::byte> payload(payload_size, std::byte{1});
    for (std::uint16_t flow = 0; flow < pool_size; ++flow) {
        BOOST_REQUIRE((*tx)->send_to(loopback(), (*rx)->local_port(), flow, payload));
        BOOST_REQUIRE(wait_readable((*rx)->poll_fd()));
        auto d = (*rx)->receive(buffer);
        BOOST_REQUIRE(d.has_value());
        BOOST_TEST(d->source_port == base);  // one pool socket: every flow leaves from it
        BOOST_TEST(d->size == payload.size());
    }
}

BOOST_AUTO_TEST_CASE(bad_pool_range_refused, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!net::UdpEndpoint::create(
                    {.bind = loopback(), .port = 0, .source_port_base = 65535, .source_ports = 2})
                    .has_value());
}

BOOST_AUTO_TEST_SUITE_END()
