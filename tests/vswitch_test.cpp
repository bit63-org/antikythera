// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 2, 7 and 10 (tasks 8, 12):
// VSwitch forwarding, the ARP/ND proxy, the dead VPC, and the group policy:
// group frames dropped by default, opt-in multicast with head-end
// replication, rate limits, the flood-list cap and per-NIC meters.

#define BOOST_TEST_MODULE vswitch_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <climits>
#include <initializer_list>
#include <cstdint>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/vswitch.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
namespace nb = ak::oar::net::neighbor;
using ak::test::unit_timeout_seconds;
using geneve::NicId;
using net::MapEntry;
using net::MapUpdate;

namespace {

constexpr std::uint32_t vpc = 100;
constexpr std::uint32_t other_vpc = 200;

// vpc: a, b local; c, e on peer; d on third. other_vpc: x local, y on peer.
constexpr NicId nic_a{11};
constexpr NicId nic_b{22};
constexpr NicId nic_c{33};
constexpr NicId nic_d{44};
constexpr NicId nic_e{55};
constexpr NicId nic_x{66};
constexpr NicId nic_y{77};
constexpr NicId nic_unmapped{88};

constexpr std::uint8_t self_tail = 1;
constexpr std::uint8_t peer_tail = 2;
constexpr std::uint8_t third_tail = 3;

constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::byte ula_prefix{0xfd};
constexpr std::byte locally_administered{0x02};
constexpr std::size_t payload_size = 32;
constexpr std::uint16_t ethertype_test = 0x88B5;  // IEEE local experimental
constexpr std::uint16_t arp_htype_ethernet = 1;
constexpr std::uint8_t mac_size = 6;
constexpr std::uint8_t ipv4_size = 4;
constexpr std::uint32_t ipv6_version_word = 0x6000'0000;
constexpr std::uint8_t nd_option_source_lladdr = 1;
constexpr std::size_t ethernet_header_size = 14;

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

auto broadcast_mac() -> net::MacAddress {
    net::MacAddress m{};
    m.fill(std::byte{0xff});
    return m;
}

// 224.0.0.251 (mDNS).
auto mdns_mac() -> net::MacAddress {
    return {std::byte{0x01}, std::byte{0x00}, std::byte{0x5e},
            std::byte{0x00}, std::byte{0x00}, std::byte{0xfb}};
}

constexpr std::uint32_t test_rate_frames = 10;
constexpr std::uint32_t test_burst_frames = 4;
constexpr std::uint64_t test_rate_bytes = 1'000'000;
constexpr std::uint64_t test_burst_bytes = 100'000;
constexpr std::uint32_t test_max_remote_vteps = 8;

auto multicast_policy() -> net::GroupPolicy {
    return {.mode = net::GroupMode::multicast,
            .rate_frames = test_rate_frames,
            .burst_frames = test_burst_frames,
            .rate_bytes = test_rate_bytes,
            .burst_bytes = test_burst_bytes,
            .max_remote_vteps = test_max_remote_vteps};
}

auto entry(NicId id, std::uint8_t vtep_tail) -> MapEntry {
    return {.nic_id = id, .mac = mac_of(id), .owner_vtep = vtep(vtep_tail)};
}

auto ip4(std::uint8_t last) -> nb::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{last}};
}

auto ip6(std::uint8_t last) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[1] = std::byte{0x10};
    a[ipv6_last] = std::byte{last};
    return a;
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

auto arp_request(NicId from, const nb::Ipv4Address& sender_ip, const nb::Ipv4Address& target_ip,
                 const net::MacAddress& sender_mac) -> std::vector<std::byte> {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    w.bytes(broadcast_mac());
    w.bytes(mac_of(from));
    w.be16(nb::ethertype_arp);
    w.be16(arp_htype_ethernet);
    w.be16(nb::ethertype_ipv4);
    w.u8(mac_size);
    w.u8(ipv4_size);
    w.be16(nb::arp_op_request);
    w.bytes(sender_mac);
    w.bytes(sender_ip);
    w.bytes(net::MacAddress{});
    w.bytes(target_ip);
    return f;
}

auto arp_request(NicId from, const nb::Ipv4Address& sender_ip, const nb::Ipv4Address& target_ip)
    -> std::vector<std::byte> {
    return arp_request(from, sender_ip, target_ip, mac_of(from));
}

auto neighbor_solicitation(NicId from, const net::Ipv6Address& source,
                           const net::Ipv6Address& target) -> std::vector<std::byte> {
    net::Ipv6Address dst{};
    dst[0] = std::byte{0xff};
    dst[1] = std::byte{0x02};
    dst[11] = std::byte{0x01};
    dst[12] = std::byte{0xff};
    dst[ipv6_last] = target[ipv6_last];
    const bool dad = source == net::Ipv6Address{};

    std::vector<std::byte> message;
    ak::wire::Writer m{message};
    m.u8(nb::icmpv6_neighbor_solicitation);
    m.u8(0);
    m.be16(0);
    m.be32(0);
    m.bytes(target);
    if (!dad) {
        m.u8(nd_option_source_lladdr);
        m.u8(1);
        m.bytes(mac_of(from));
    }
    const std::uint16_t sum = nb::icmpv6_checksum(source, dst, message);
    message[2] = static_cast<std::byte>(sum >> CHAR_BIT);
    message[3] = static_cast<std::byte>(sum & UINT8_MAX);

    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    w.bytes(net::MacAddress{std::byte{0x33}, std::byte{0x33}, std::byte{0xff}, std::byte{0},
                            std::byte{0}, target[ipv6_last]});
    w.bytes(mac_of(from));
    w.be16(nb::ethertype_ipv6);
    w.be32(ipv6_version_word);
    w.be16(static_cast<std::uint16_t>(message.size()));
    w.u8(nb::ipproto_icmpv6);
    w.u8(nb::nd_hop_limit);
    w.bytes(source);
    w.bytes(dst);
    w.bytes(message);
    return f;
}

class FakePort final : public net::RxPort {
public:
    auto deliver(std::span<const std::byte> f) -> net::RxResult override {
        if (refuse) {
            return net::RxResult::no_buffer;
        }
        frames.emplace_back(f.begin(), f.end());
        return net::RxResult::delivered;
    }
    std::vector<std::vector<std::byte>> frames;
    bool refuse{false};
};

struct Sent {
    net::Ipv6Address vtep{};
    std::uint32_t vni{0};
    geneve::NicPair nics{};
    std::vector<std::byte> frame;
};

class FakeUnderlay final : public net::Underlay {
public:
    auto send(const net::RemoteFrame& f) -> void override {
        sent.push_back({f.vtep, f.vni, f.nics, {f.frame.begin(), f.frame.end()}});
    }
    std::vector<Sent> sent;
};

struct Fixture {
    Fixture() {
        BOOST_REQUIRE(table.apply(
            {.vni = vpc,
             .version = 1,
             .entries = {entry(nic_a, self_tail), entry(nic_b, self_tail), entry(nic_c, peer_tail),
                         entry(nic_d, third_tail), entry(nic_e, peer_tail)}}));
        BOOST_REQUIRE(table.apply({.vni = other_vpc,
                                   .version = 1,
                                   .entries = {entry(nic_x, self_tail), entry(nic_y, peer_tail)}}));
        BOOST_REQUIRE(sw.attach(nic_a, port_a));
        BOOST_REQUIRE(sw.attach(nic_b, port_b));
        BOOST_REQUIRE(sw.attach(nic_x, port_x));
    }

    auto opt_in(const net::GroupPolicy& policy = multicast_policy()) -> void {
        BOOST_REQUIRE(sw.set_group_policy(vpc, policy));
    }

    auto send(NicId from, const std::vector<std::byte>& f) -> void {
        sw.transmit({.source = from, .frame = f});
    }

    auto nothing_delivered() const -> bool {
        return port_a.frames.empty() && port_b.frames.empty() && port_x.frames.empty() &&
               underlay.sent.empty();
    }

    net::MappingTable table{vtep(self_tail)};
    FakeUnderlay underlay;
    net::VSwitch::Clock::time_point now{};
    net::VSwitch sw{table, underlay, [this] { return now; }};
    FakePort port_a;
    FakePort port_b;
    FakePort port_x;
};

// Builds the Geneve packet `from` (on `from_vtep`) would send, decoded.
struct Inbound {
    Inbound(NicId src, NicId dst, std::uint32_t vni, const std::vector<std::byte>& inner) {
        auto enc = geneve::encode({.vni = vni, .nics = {.src = src, .dst = dst}}, inner);
        BOOST_REQUIRE(enc.has_value());
        bytes = std::move(*enc);
        auto dec = geneve::decode(bytes);
        BOOST_REQUIRE(dec.has_value());
        packet = *dec;
    }
    std::vector<std::byte> bytes;
    geneve::Packet packet;
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(transmit, Fixture)

BOOST_AUTO_TEST_CASE(local_unicast, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = frame(mac_of(nic_b), mac_of(nic_a));
    send(nic_a, f);
    BOOST_REQUIRE(port_b.frames.size() == 1);
    BOOST_TEST(port_b.frames[0] == f);
    BOOST_TEST(port_a.frames.empty());
    BOOST_TEST(underlay.sent.empty());
    BOOST_TEST(sw.counters().tx_local == 1);
}

BOOST_AUTO_TEST_CASE(remote_unicast, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = frame(mac_of(nic_c), mac_of(nic_a));
    send(nic_a, f);
    BOOST_REQUIRE(underlay.sent.size() == 1);
    const Sent& s = underlay.sent[0];
    BOOST_TEST((s.vtep == vtep(peer_tail)));
    BOOST_TEST(s.vni == vpc);
    BOOST_TEST((s.nics == geneve::NicPair{.src = nic_a, .dst = nic_c}));
    BOOST_TEST(s.frame == f);
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(sw.counters().tx_remote == 1);
}

BOOST_AUTO_TEST_CASE(unknown_unicast_dropped, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, frame(mac_of(nic_unmapped), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_unknown_unicast == 1);
}

BOOST_AUTO_TEST_CASE(vpcs_are_isolated, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // x and y exist, but in another VPC: unknown from a's point of view.
    send(nic_a, frame(mac_of(nic_x), mac_of(nic_a)));
    send(nic_a, frame(mac_of(nic_y), mac_of(nic_a)));
    send(nic_x, frame(mac_of(nic_b), mac_of(nic_x)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_unknown_unicast == 3);
}

BOOST_AUTO_TEST_CASE(group_dropped_by_default, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, frame(broadcast_mac(), mac_of(nic_a)));
    send(nic_a, frame(mdns_mac(), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_group == 2);
    BOOST_TEST(sw.counters().tx_flooded == 0);
    BOOST_TEST(sw.group_meter(nic_a)->drop_policy == 2);
    BOOST_TEST(sw.group_meter(nic_a)->frames == 0);
}

BOOST_AUTO_TEST_CASE(multicast_replication, *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    const auto f = frame(mdns_mac(), mac_of(nic_a));
    send(nic_a, f);
    BOOST_TEST(port_a.frames.empty());  // never back to the sender
    BOOST_REQUIRE(port_b.frames.size() == 1);
    BOOST_TEST(port_b.frames[0] == f);
    BOOST_TEST(port_x.frames.empty());  // other VPC
    // One copy per VTEP hosting the VNI, though peer hosts two NICs.
    BOOST_REQUIRE(underlay.sent.size() == 2);
    for (const Sent& s : underlay.sent) {
        BOOST_TEST(s.vni == vpc);
        BOOST_TEST((s.nics == geneve::NicPair{.src = nic_a, .dst = geneve::nic_broadcast}));
        BOOST_TEST(s.frame == f);
    }
    BOOST_TEST((underlay.sent[0].vtep != underlay.sent[1].vtep));
    BOOST_TEST(sw.counters().tx_flooded == 1);
    BOOST_TEST(sw.counters().tx_replicas_local == 1);
    BOOST_TEST(sw.counters().tx_replicas_remote == 2);
    const net::GroupMeter expected{.frames = 1,
                                   .bytes = f.size(),
                                   .replicas_remote = 2,
                                   .replica_bytes_remote = 2 * f.size(),
                                   .replicas_local = 1,
                                   .replica_bytes_local = f.size()};
    BOOST_TEST((*sw.group_meter(nic_a) == expected));
}

BOOST_AUTO_TEST_CASE(only_ip_multicast_when_opted_in,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    const auto mac = [](std::initializer_list<std::uint8_t> b) {
        net::MacAddress m{};
        std::ranges::transform(b, m.begin(), [](std::uint8_t v) { return std::byte{v}; });
        return m;
    };
    // Refused: broadcast, 01:00:5e upper half (not IPv4 multicast),
    // solicited-node (ND), and other group addresses (STP).
    for (const auto& dst :
         {broadcast_mac(), mac({0x01, 0x00, 0x5e, 0x80, 0x00, 0x01}),
          mac({0x33, 0x33, 0xff, 0x00, 0x00, 0x01}), mac({0x01, 0x80, 0xc2, 0x00, 0x00, 0x00})}) {
        send(nic_a, frame(dst, mac_of(nic_a)));
    }
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.group_meter(nic_a)->drop_policy == 4);
    // Admitted: IPv4 multicast and IPv6 all-nodes / other groups.
    for (const auto& dst :
         {mac({0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}), mac({0x33, 0x33, 0x00, 0x00, 0x00, 0x01})}) {
        send(nic_a, frame(dst, mac_of(nic_a)));
    }
    BOOST_TEST(port_b.frames.size() == 2);
    BOOST_TEST(sw.group_meter(nic_a)->frames == 2);
}

BOOST_AUTO_TEST_CASE(rate_limited_per_nic, *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    const auto f = frame(mdns_mac(), mac_of(nic_a));
    for (std::uint32_t i = 0; i < test_burst_frames + 2; ++i) {
        send(nic_a, f);
    }
    BOOST_TEST(sw.group_meter(nic_a)->frames == test_burst_frames);
    BOOST_TEST(sw.group_meter(nic_a)->drop_rate == 2);
    // b has its own bucket.
    send(nic_b, frame(mdns_mac(), mac_of(nic_b)));
    BOOST_TEST(sw.group_meter(nic_b)->frames == 1);
    // 10 frames/s: one more after 100 ms, and never more than the burst.
    now += std::chrono::milliseconds{100};
    send(nic_a, f);
    send(nic_a, f);
    BOOST_TEST(sw.group_meter(nic_a)->frames == test_burst_frames + 1);
    now += std::chrono::hours{1};
    for (std::uint32_t i = 0; i < test_burst_frames + 1; ++i) {
        send(nic_a, f);
    }
    BOOST_TEST(sw.group_meter(nic_a)->frames == 2 * test_burst_frames + 1);
    BOOST_TEST(sw.group_meter(nic_a)->drop_rate == 4);
}

BOOST_AUTO_TEST_CASE(byte_rate_limited, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto policy = multicast_policy();
    policy.burst_bytes = 100;  // two 46-byte test frames fit, a third does not
    policy.rate_bytes = 46;    // one frame's worth per second
    opt_in(policy);
    const auto f = frame(mdns_mac(), mac_of(nic_a));
    BOOST_REQUIRE(f.size() == 46);
    send(nic_a, f);
    send(nic_a, f);
    send(nic_a, f);
    BOOST_TEST(sw.group_meter(nic_a)->frames == 2);
    BOOST_TEST(sw.group_meter(nic_a)->drop_rate == 1);
    // 8 bytes of credit left; 38 more take 826 ms at 46 bytes/s.
    now += std::chrono::milliseconds{800};
    send(nic_a, f);
    BOOST_TEST(sw.group_meter(nic_a)->frames == 2);
    now += std::chrono::milliseconds{30};
    send(nic_a, f);
    BOOST_TEST(sw.group_meter(nic_a)->frames == 3);
}

BOOST_AUTO_TEST_CASE(flood_list_cap, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto policy = multicast_policy();
    policy.max_remote_vteps = 1;  // vpc spans peer and third
    opt_in(policy);
    send(nic_a, frame(mdns_mac(), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());  // dropped whole, local copies too
    BOOST_TEST(sw.group_meter(nic_a)->drop_fanout == 1);
    policy.max_remote_vteps = 2;
    opt_in(policy);
    send(nic_a, frame(mdns_mac(), mac_of(nic_a)));
    BOOST_TEST(underlay.sent.size() == 2);
}

BOOST_AUTO_TEST_CASE(policy_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using net::GroupPolicyError;
    BOOST_TEST(
        (sw.set_group_policy(0, multicast_policy()).error() == GroupPolicyError::vni_out_of_range));
    BOOST_TEST((sw.set_group_policy(geneve::vni_max + 1, multicast_policy()).error() ==
                GroupPolicyError::vni_out_of_range));
    auto p = multicast_policy();
    p.mode = static_cast<net::GroupMode>(7);
    BOOST_TEST((sw.set_group_policy(vpc, p).error() == GroupPolicyError::unknown_mode));
    for (int field = 0; field < 5; ++field) {
        p = multicast_policy();
        switch (field) {
            case 0:
                p.rate_frames = 0;
                break;
            case 1:
                p.burst_frames = 0;
                break;
            case 2:
                p.rate_bytes = 0;
                break;
            case 3:
                p.burst_bytes = 0;
                break;
            default:
                p.max_remote_vteps = 0;
                break;
        }
        BOOST_TEST((sw.set_group_policy(vpc, p).error() == GroupPolicyError::missing_limit));
    }
    for (int field = 0; field < 5; ++field) {
        p = multicast_policy();
        switch (field) {
            case 0:
                p.rate_frames = net::group_rate_frames_max + 1;
                break;
            case 1:
                p.burst_frames = net::group_burst_frames_max + 1;
                break;
            case 2:
                p.rate_bytes = net::group_rate_bytes_max + 1;
                break;
            case 3:
                p.burst_bytes = net::group_burst_bytes_max + 1;
                break;
            default:
                p.max_remote_vteps = net::group_max_remote_vteps_max + 1;
                break;
        }
        BOOST_TEST((sw.set_group_policy(vpc, p).error() == GroupPolicyError::limit_too_large));
    }
    BOOST_TEST(
        (sw.set_group_policy(vpc, {.mode = net::GroupMode::drop, .rate_frames = 1}).error() ==
         GroupPolicyError::nonzero_limits));

    // A rejected policy leaves the previous one; drop restores the default.
    opt_in();
    p = multicast_policy();
    p.burst_frames = 0;
    BOOST_TEST(!sw.set_group_policy(vpc, p));
    BOOST_TEST((sw.group_policy(vpc).mode == net::GroupMode::multicast));
    BOOST_REQUIRE(sw.set_group_policy(vpc, {}));
    BOOST_TEST((sw.group_policy(vpc).mode == net::GroupMode::drop));
    send(nic_a, frame(mdns_mac(), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());
}

BOOST_AUTO_TEST_CASE(lowered_burst_clamps_tokens,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    const auto f = frame(mdns_mac(), mac_of(nic_a));
    send(nic_a, f);  // primes a full bucket of 4, leaves 3
    auto p = multicast_policy();
    p.burst_frames = 1;
    opt_in(p);
    send(nic_a, f);
    send(nic_a, f);
    BOOST_TEST(sw.group_meter(nic_a)->frames == 2);
    BOOST_TEST(sw.group_meter(nic_a)->drop_rate == 1);
}

BOOST_AUTO_TEST_CASE(spoofed_source_mac, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, frame(mac_of(nic_b), mac_of(nic_c)));
    send(nic_a, frame(broadcast_mac(), mac_of(nic_b)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_spoofed == 2);
}

BOOST_AUTO_TEST_CASE(short_frame, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = frame(mac_of(nic_b), mac_of(nic_a));
    sw.transmit({.source = nic_a, .frame = std::span{f}.first(ethernet_header_size - 1)});
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_short == 1);
}

BOOST_AUTO_TEST_CASE(hairpin, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, frame(mac_of(nic_a), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_hairpin == 1);
}

BOOST_AUTO_TEST_CASE(unattached_destination, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(sw.detach(nic_b));
    send(nic_a, frame(mac_of(nic_b), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_unattached == 1);
}

BOOST_AUTO_TEST_CASE(refused_delivery_counted, *boost::unit_test::timeout(unit_timeout_seconds)) {
    port_b.refuse = true;
    send(nic_a, frame(mac_of(nic_b), mac_of(nic_a)));
    BOOST_TEST(sw.counters().deliver_failed == 1);
    BOOST_TEST(sw.counters().tx_local == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(dead_vpc, Fixture)

BOOST_AUTO_TEST_CASE(unmapped_nic_reaches_nothing,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    FakePort port;
    BOOST_REQUIRE(sw.attach(nic_unmapped, port));
    send(nic_unmapped, frame(broadcast_mac(), mac_of(nic_unmapped)));
    send(nic_unmapped, frame(mac_of(nic_a), mac_of(nic_unmapped)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_dead_vpc == 2);
}

BOOST_AUTO_TEST_CASE(unattached_source, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(sw.detach(nic_a));
    send(nic_a, frame(mac_of(nic_b), mac_of(nic_a)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_dead_vpc == 1);
}

BOOST_AUTO_TEST_CASE(remote_nic_cannot_send_here,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // c belongs to another VTEP; a function claiming it here is not trusted.
    FakePort port;
    BOOST_REQUIRE(sw.attach(nic_c, port));
    send(nic_c, frame(mac_of(nic_a), mac_of(nic_c)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_dead_vpc == 1);
}

BOOST_AUTO_TEST_CASE(detached_by_map_update, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // helm moves b to the dead VPC by dropping it from the VNI (Requirement 8.2).
    BOOST_REQUIRE(table.apply(
        {.vni = vpc, .version = 2, .entries = {entry(nic_a, self_tail), entry(nic_c, peer_tail)}}));
    opt_in();
    send(nic_a, frame(mac_of(nic_b), mac_of(nic_a)));
    send(nic_a, frame(mdns_mac(), mac_of(nic_a)));
    send(nic_b, frame(mac_of(nic_a), mac_of(nic_b)));
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(port_a.frames.empty());
    BOOST_TEST(underlay.sent.size() == 1);  // a's multicast, to c's VTEP
    BOOST_TEST(sw.counters().tx_drop_unknown_unicast == 1);
    BOOST_TEST(sw.counters().tx_drop_dead_vpc == 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(proxy, Fixture)

BOOST_AUTO_TEST_CASE(answers_arp, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_neighbors(
        {.vni = vpc, .ipv4 = {{ip4(1), nic_a}, {ip4(2), nic_b}, {ip4(3), nic_c}}}));
    for (const std::uint8_t target : std::initializer_list<std::uint8_t>{2, 3}) {
        send(nic_a, arp_request(nic_a, ip4(1), ip4(target)));
    }
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(underlay.sent.empty());
    BOOST_REQUIRE(port_a.frames.size() == 2);
    const NicId owners[] = {nic_b, nic_c};
    for (std::size_t i = 0; i < 2; ++i) {
        const auto reply = nb::parse_arp(port_a.frames[i]);
        BOOST_REQUIRE(reply.has_value());
        BOOST_TEST(reply->op == nb::arp_op_reply);
        BOOST_TEST((reply->sender_mac == mac_of(owners[i])));
        BOOST_TEST((reply->target_mac == mac_of(nic_a)));
        BOOST_TEST((reply->target_ip == ip4(1)));
    }
    BOOST_TEST(sw.counters().arp_replies == 2);
}

BOOST_AUTO_TEST_CASE(drops_unanswerable_arp, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // x is registered in vpc but mapped in other_vpc: never answered for.
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(1), nic_a}, {ip4(9), nic_x}}}));
    send(nic_a, arp_request(nic_a, ip4(1), ip4(7)));  // unknown
    send(nic_a, arp_request(nic_a, ip4(1), ip4(9)));  // other VPC
    send(nic_a, arp_request(nic_a, ip4(1), ip4(1)));  // gratuitous
    BOOST_TEST(nothing_delivered());  // broadcast is never flooded (Requirement 10.1)
    BOOST_TEST(sw.counters().arp_replies == 0);
    BOOST_TEST(sw.counters().tx_drop_group == 3);
    opt_in();  // not even in a multicast VPC
    send(nic_a, arp_request(nic_a, ip4(1), ip4(7)));
    BOOST_TEST(nothing_delivered());
}

BOOST_AUTO_TEST_CASE(drops_arp_spoofing, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(1), nic_a}, {ip4(2), nic_b}}}));
    send(nic_a, arp_request(nic_a, ip4(2), ip4(1)));                 // claims b's address
    send(nic_a, arp_request(nic_a, ip4(1), ip4(2), mac_of(nic_b)));  // sender MAC is b's
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_neighbor_spoofed == 2);
    // Unregistered sender addresses and probes from 0.0.0.0 pass the spoofing
    // check and then meet the group policy.
    send(nic_a, arp_request(nic_a, ip4(5), ip4(7)));
    send(nic_a, arp_request(nic_a, nb::Ipv4Address{}, ip4(7)));
    BOOST_TEST(sw.counters().tx_drop_neighbor_spoofed == 2);
    BOOST_TEST(sw.counters().tx_drop_group == 2);
}

BOOST_AUTO_TEST_CASE(answers_neighbor_solicitation,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc, .ipv6 = {{ip6(1), nic_a}, {ip6(2), nic_b}}}));
    send(nic_a, neighbor_solicitation(nic_a, ip6(1), ip6(2)));
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(underlay.sent.empty());
    BOOST_REQUIRE(port_a.frames.size() == 1);
    const auto& na = port_a.frames[0];
    BOOST_TEST(std::ranges::equal(std::span{na}.first(mac_size), mac_of(nic_a)));
    BOOST_TEST(std::ranges::equal(std::span{na}.subspan(mac_size, mac_size), mac_of(nic_b)));
    const std::size_t message_at = ethernet_header_size + nb::ipv6_header_size;
    BOOST_TEST(nb::icmpv6_checksum(ip6(2), ip6(1), std::span{na}.subspan(message_at)) == 0);
    BOOST_TEST(std::to_integer<int>(na[message_at]) == nb::icmpv6_neighbor_advertisement);
    BOOST_TEST(sw.counters().nd_replies == 1);
}

BOOST_AUTO_TEST_CASE(never_answers_dad, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc, .ipv6 = {{ip6(1), nic_a}, {ip6(2), nic_b}}}));
    send(nic_a, neighbor_solicitation(nic_a, net::Ipv6Address{}, ip6(1)));
    send(nic_a, neighbor_solicitation(nic_a, net::Ipv6Address{}, ip6(2)));
    BOOST_TEST(nothing_delivered());  // unanswered, and solicited-node never floods
    BOOST_TEST(sw.counters().nd_replies == 0);
    BOOST_TEST(sw.counters().tx_drop_group == 2);
}

BOOST_AUTO_TEST_CASE(neighbor_update_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using net::NeighborError;
    BOOST_TEST((sw.set_neighbors({.vni = 0}).error() == NeighborError::vni_out_of_range));
    BOOST_TEST((sw.set_neighbors({.vni = geneve::vni_max + 1}).error() ==
                NeighborError::vni_out_of_range));
    BOOST_TEST((sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(1), geneve::nic_invalid}}}).error() ==
                NeighborError::invalid_nic_id));
    BOOST_TEST((sw.set_neighbors({.vni = vpc, .ipv4 = {{nb::Ipv4Address{}, nic_a}}}).error() ==
                NeighborError::invalid_address));
    const nb::Ipv4Address multicast{std::byte{224}, std::byte{0}, std::byte{0}, std::byte{1}};
    BOOST_TEST((sw.set_neighbors({.vni = vpc, .ipv4 = {{multicast, nic_a}}}).error() ==
                NeighborError::invalid_address));
    net::Ipv6Address all_nodes{};
    all_nodes[0] = std::byte{0xff};
    BOOST_TEST((sw.set_neighbors({.vni = vpc, .ipv6 = {{all_nodes, nic_a}}}).error() ==
                NeighborError::invalid_address));
    BOOST_TEST(
        (sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(1), nic_a}, {ip4(1), nic_b}}}).error() ==
         NeighborError::duplicate_address));

    // A rejected update leaves the previous one; an empty one removes it.
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(2), nic_b}}}));
    BOOST_TEST(!sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(2), nic_b}, {ip4(2), nic_a}}}));
    send(nic_a, arp_request(nic_a, ip4(1), ip4(2)));
    BOOST_TEST(sw.counters().arp_replies == 1);
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc}));
    send(nic_a, arp_request(nic_a, ip4(1), ip4(2)));
    BOOST_TEST(sw.counters().arp_replies == 1);
    BOOST_TEST(sw.counters().tx_drop_group == 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(receive, Fixture)

BOOST_AUTO_TEST_CASE(unicast_from_peer, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = frame(mac_of(nic_a), mac_of(nic_c));
    const Inbound in{nic_c, nic_a, vpc, f};
    const auto got = sw.receive(in.packet, vtep(peer_tail));
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == nic_a));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST(port_a.frames[0] == f);
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(sw.counters().rx_delivered == 1);
}

BOOST_AUTO_TEST_CASE(multicast_from_peer, *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    const Inbound in{nic_c, geneve::nic_broadcast, vpc, frame(mdns_mac(), mac_of(nic_c))};
    BOOST_REQUIRE(sw.receive(in.packet, vtep(peer_tail)).has_value());
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(port_b.frames.size() == 1);
    BOOST_TEST(port_x.frames.empty());
    BOOST_TEST(underlay.sent.empty());  // never re-flooded
    BOOST_TEST(sw.counters().rx_delivered == 2);
}

BOOST_AUTO_TEST_CASE(receiver_applies_its_own_policy,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A peer with a stale or hostile policy: this VTEP has not opted in.
    const Inbound mcast{nic_c, geneve::nic_broadcast, vpc, frame(mdns_mac(), mac_of(nic_c))};
    BOOST_TEST(sw.receive(mcast.packet, vtep(peer_tail)).has_value());
    // Opted in, but broadcast is never admitted.
    opt_in();
    const Inbound bcast{nic_c, geneve::nic_broadcast, vpc, frame(broadcast_mac(), mac_of(nic_c))};
    BOOST_TEST(sw.receive(bcast.packet, vtep(peer_tail)).has_value());
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().rx_drop_group == 2);
}

BOOST_AUTO_TEST_CASE(policy_drops_counted, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using net::PolicyError;
    // c claimed from the wrong VTEP, and a forged VNI.
    const Inbound forged_vtep{nic_c, nic_a, vpc, frame(mac_of(nic_a), mac_of(nic_c))};
    BOOST_TEST(
        (sw.receive(forged_vtep.packet, vtep(third_tail)).error() == PolicyError::src_wrong_vtep));
    const Inbound forged_vni{nic_c, nic_x, other_vpc, frame(mac_of(nic_x), mac_of(nic_c))};
    BOOST_TEST(
        (sw.receive(forged_vni.packet, vtep(peer_tail)).error() == PolicyError::src_wrong_vni));
    BOOST_TEST(nothing_delivered());
    const auto& drops = sw.counters().rx_drop_policy;
    BOOST_TEST(drops.at(static_cast<std::size_t>(PolicyError::src_wrong_vtep)) == 1);
    BOOST_TEST(drops.at(static_cast<std::size_t>(PolicyError::src_wrong_vni)) == 1);
}

BOOST_AUTO_TEST_CASE(unattached_destination, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(sw.detach(nic_a));
    const Inbound in{nic_c, nic_a, vpc, frame(mac_of(nic_a), mac_of(nic_c))};
    BOOST_TEST(sw.receive(in.packet, vtep(peer_tail)).has_value());
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().rx_drop_unattached == 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ports)

BOOST_AUTO_TEST_CASE(attach_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table{vtep(self_tail)};
    FakeUnderlay underlay;
    net::VSwitch sw{table, underlay};
    FakePort p;
    BOOST_TEST((sw.attach(geneve::nic_invalid, p).error() == net::AttachError::invalid_nic_id));
    BOOST_TEST((sw.attach(geneve::nic_broadcast, p).error() == net::AttachError::invalid_nic_id));
    BOOST_TEST(sw.attach(nic_a, p).has_value());
    BOOST_TEST((sw.attach(nic_a, p).error() == net::AttachError::already_attached));
    BOOST_TEST(sw.attached(nic_a));
    BOOST_TEST(sw.detach(nic_a));
    BOOST_TEST(!sw.detach(nic_a));
    BOOST_TEST(!sw.attached(nic_a));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(metering, Fixture)

BOOST_AUTO_TEST_CASE(usage_reports_attached_then_retired,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    send(nic_b, frame(mdns_mac(), mac_of(nic_b)));
    send(nic_a, frame(mdns_mac(), mac_of(nic_a)));
    auto usage = sw.group_usage();
    BOOST_REQUIRE(usage.size() == 3);  // a, b, x in NIC ID order
    BOOST_TEST((usage[0].nic == nic_a));
    BOOST_TEST((usage[1].nic == nic_b));
    BOOST_TEST((usage[2].nic == nic_x));
    BOOST_TEST(usage[0].meter.replicas_remote == 2);
    BOOST_TEST(usage[1].meter.replicas_remote == 2);
    BOOST_TEST(usage[2].meter.frames == 0);
    BOOST_TEST(!usage[0].detached);
    const std::uint64_t first_a = usage[0].attachment;

    // Detach keeps a's final reading for exactly one read.
    BOOST_REQUIRE(sw.detach(nic_a));
    BOOST_TEST(!sw.group_meter(nic_a).has_value());
    usage = sw.group_usage();
    BOOST_REQUIRE(usage.size() == 3);  // b, x, then retired a
    BOOST_TEST((usage[2].nic == nic_a));
    BOOST_TEST(usage[2].detached);
    BOOST_TEST(usage[2].attachment == first_a);
    BOOST_TEST(usage[2].meter.replicas_remote == 2);
    BOOST_TEST(sw.group_usage().size() == 2);

    // Re-attaching starts a new series from zero.
    BOOST_REQUIRE(sw.attach(nic_a, port_a));
    BOOST_TEST(sw.group_meter(nic_a)->replicas_remote == 0);
    usage = sw.group_usage();
    BOOST_TEST(usage[0].attachment > first_a);
}

BOOST_AUTO_TEST_SUITE_END()

// Requirement 7.2: in split placement two boards in one server are two
// VTEPs, and traffic between them is encapsulated. Each switch's underlay
// encodes, decodes and hands the packet to the other switch.
BOOST_AUTO_TEST_SUITE(split_placement)

namespace {

class Loopback final : public net::Underlay {
public:
    auto send(const net::RemoteFrame& f) -> void override {
        auto bytes = geneve::encode({.vni = f.vni, .nics = f.nics}, f.frame);
        BOOST_REQUIRE(bytes.has_value());
        const auto pkt = geneve::decode(*bytes);
        BOOST_REQUIRE(pkt.has_value());
        BOOST_REQUIRE((f.vtep == peer_addr));
        if (peers == nullptr) {
            BOOST_FAIL("loopback has no peer");
            return;
        }
        static_cast<void>(peers->receive(*pkt, self_addr));
    }
    net::VSwitch* peers{nullptr};
    net::Ipv6Address self_addr{};
    net::Ipv6Address peer_addr{};
};

}  // namespace

BOOST_AUTO_TEST_CASE(boards_talk_through_geneve, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const MapUpdate update{
        .vni = vpc, .version = 1, .entries = {entry(nic_a, self_tail), entry(nic_b, peer_tail)}};
    net::MappingTable table1{vtep(self_tail)};
    net::MappingTable table2{vtep(peer_tail)};
    BOOST_REQUIRE(table1.apply(update));
    BOOST_REQUIRE(table2.apply(update));
    Loopback under1;
    Loopback under2;
    net::VSwitch board1{table1, under1};
    net::VSwitch board2{table2, under2};
    under1.peers = &board2;
    under1.self_addr = vtep(self_tail);
    under1.peer_addr = vtep(peer_tail);
    under2.peers = &board1;
    under2.self_addr = vtep(peer_tail);
    under2.peer_addr = vtep(self_tail);
    FakePort port_a;
    FakePort port_b;
    BOOST_REQUIRE(board1.attach(nic_a, port_a));
    BOOST_REQUIRE(board2.attach(nic_b, port_b));

    const auto to_b = frame(mac_of(nic_b), mac_of(nic_a));
    board1.transmit({.source = nic_a, .frame = to_b});
    BOOST_REQUIRE(port_b.frames.size() == 1);
    BOOST_TEST(port_b.frames[0] == to_b);

    BOOST_REQUIRE(board1.set_group_policy(vpc, multicast_policy()));
    BOOST_REQUIRE(board2.set_group_policy(vpc, multicast_policy()));
    const auto mcast = frame(mdns_mac(), mac_of(nic_b));
    board2.transmit({.source = nic_b, .frame = mcast});
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST(port_a.frames[0] == mcast);
    BOOST_TEST(board1.counters().tx_remote == 1);
    BOOST_TEST(board2.counters().tx_replicas_remote == 1);
}

BOOST_AUTO_TEST_SUITE_END()
