// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 2, 7, 10 and 11 (tasks 8,
// 12, 16): VSwitch forwarding, the ARP/ND proxy, the dead VPC, the group
// policy (group frames dropped by default, opt-in multicast with head-end
// replication, rate limits, the flood-list cap and per-NIC meters) and the
// IP source/destination check.

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
#include "net_frames.hpp"
#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/dhcp6.hpp"
#include "oar/net/packet.hpp"
#include "oar/net/vswitch.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
namespace nb = ak::oar::net::neighbor;
namespace pk = ak::oar::net::packet;
namespace fr = ak::test::frames;
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
constexpr std::size_t payload_size = 4;           // a 46-byte frame: 14 + 20 + 8 + 4
constexpr std::uint16_t ethertype_test = 0x88B5;  // IEEE local experimental
constexpr std::uint16_t test_port = 9999;
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

// The IPv4 address frame() uses for a MAC: a NIC's guest address, or a
// group address for a group MAC (the low 23 bits of 01:00:5e, 255.255.255.255
// for broadcast, 239.0.0.1 for any other group).
auto ip_for(const net::MacAddress& mac) -> nb::Ipv4Address {
    if ((mac[0] & std::byte{1}) == std::byte{0}) {
        return ip4(std::to_integer<std::uint8_t>(mac[mac_last]));
    }
    if (mac == broadcast_mac()) {
        return {std::byte{255}, std::byte{255}, std::byte{255}, std::byte{255}};
    }
    if (mac[0] == std::byte{0x01} && mac[1] == std::byte{0x00} && mac[2] == std::byte{0x5e}) {
        return {std::byte{224}, mac[3] & std::byte{0x7f}, mac[4], mac[5]};
    }
    return {std::byte{239}, std::byte{0}, std::byte{0}, std::byte{1}};
}

// A UDP datagram between the guest addresses behind two MACs.
auto frame(const net::MacAddress& dst, const net::MacAddress& src) -> std::vector<std::byte> {
    return fr::ipv4(
        dst, src, ip_for(src), ip_for(dst), pk::ipproto_udp,
        fr::udp(test_port, test_port, std::vector<std::byte>(payload_size, std::byte{0x5a})));
}

auto udp4(const net::MacAddress& dst, const net::MacAddress& src, const nb::Ipv4Address& src_ip,
          const nb::Ipv4Address& dst_ip, std::uint16_t sport = test_port,
          std::uint16_t dport = test_port) -> std::vector<std::byte> {
    return fr::ipv4(dst, src, src_ip, dst_ip, pk::ipproto_udp, fr::udp(sport, dport, {}));
}

auto udp6(const net::MacAddress& dst, const net::MacAddress& src, const net::Ipv6Address& src_ip,
          const net::Ipv6Address& dst_ip, std::uint16_t sport = test_port,
          std::uint16_t dport = test_port) -> std::vector<std::byte> {
    return fr::ipv6(dst, src, src_ip, dst_ip, pk::ipproto_udp, fr::udp(sport, dport, {}));
}

auto link_local(NicId id) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfe};
    a[1] = std::byte{0x80};
    a[ipv6_last] = static_cast<std::byte>(id.value);
    return a;
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
        // Every NIC owns 10.0.0.<id> and fd10::<id> (MapUpdate v2's guest
        // addresses, as NetRole hands them over).
        BOOST_REQUIRE(sw.set_neighbors(addresses(vpc, {nic_a, nic_b, nic_c, nic_d, nic_e})));
        BOOST_REQUIRE(sw.set_neighbors(addresses(other_vpc, {nic_x, nic_y})));
    }

    static auto addresses(std::uint32_t vni, std::initializer_list<NicId> nics)
        -> net::NeighborUpdate {
        net::NeighborUpdate u{.vni = vni};
        for (const NicId n : nics) {
            const auto last = static_cast<std::uint8_t>(n.value);
            u.ipv4.push_back({ip4(last), n});
            u.ipv6.push_back({ip6(last), n});
        }
        return u;
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
    // Requirement 11.6: an unregistered sender address is not a's either;
    // a probe from 0.0.0.0 passes and then meets the group policy.
    send(nic_a, arp_request(nic_a, ip4(5), ip4(7)));
    BOOST_TEST(sw.counters().tx_drop_neighbor_spoofed == 3);
    send(nic_a, arp_request(nic_a, nb::Ipv4Address{}, ip4(7)));
    BOOST_TEST(sw.counters().tx_drop_neighbor_spoofed == 3);
    BOOST_TEST(sw.counters().tx_drop_group == 1);
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
    BOOST_TEST(nothing_delivered());  // unanswered, and :: is never forwarded
    BOOST_TEST(sw.counters().nd_replies == 0);
    BOOST_TEST(sw.counters().tx_drop_local_only == 2);
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

    // A rejected update leaves the previous one; an empty one removes it,
    // after which a no longer owns 10.0.0.1 either.
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(1), nic_a}, {ip4(2), nic_b}}}));
    BOOST_TEST(!sw.set_neighbors({.vni = vpc, .ipv4 = {{ip4(2), nic_b}, {ip4(2), nic_a}}}));
    send(nic_a, arp_request(nic_a, ip4(1), ip4(2)));
    BOOST_TEST(sw.counters().arp_replies == 1);
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc}));
    send(nic_a, arp_request(nic_a, ip4(1), ip4(2)));
    BOOST_TEST(sw.counters().arp_replies == 1);
    BOOST_TEST(sw.counters().tx_drop_neighbor_spoofed == 1);
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
    const net::NeighborUpdate addrs{.vni = vpc, .ipv4 = {{ip4(11), nic_a}, {ip4(22), nic_b}}};
    BOOST_REQUIRE(board1.set_neighbors(addrs));
    BOOST_REQUIRE(board2.set_neighbors(addrs));

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

// Requirement 11 (task 16): the IP source/destination check.
BOOST_FIXTURE_TEST_SUITE(ip_check, Fixture)

namespace {

constexpr std::uint16_t dhcp4_server = 67;
constexpr std::uint16_t dhcp4_client = 68;
constexpr std::uint16_t dhcp6_client = 546;
constexpr std::uint16_t dhcp6_server = 547;
constexpr std::uint8_t icmp_redirect = 5;
constexpr std::uint8_t icmpv6_router_solicitation = 133;
constexpr std::uint8_t icmpv6_router_advertisement = 134;
constexpr std::uint8_t icmpv6_redirect = 137;
constexpr std::uint32_t na_solicited_override = 0x6000'0000;

auto all_nodes() -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xff};
    a[1] = std::byte{0x02};
    a[ipv6_last] = std::byte{1};
    return a;
}

auto all_nodes_mac() -> net::MacAddress {
    return {std::byte{0x33}, std::byte{0x33}, std::byte{0},
            std::byte{0},    std::byte{0},    std::byte{1}};
}

// A solicited NA from `from` for `target`, to `to`.
auto neighbor_advertisement(NicId from, NicId to, const net::Ipv6Address& source,
                            const net::Ipv6Address& target) -> std::vector<std::byte> {
    std::vector<std::byte> body;
    ak::wire::Writer w{body};
    w.be32(na_solicited_override);
    w.bytes(target);
    const auto msg = fr::icmpv6(source, ip6(static_cast<std::uint8_t>(to.value)),
                                nb::icmpv6_neighbor_advertisement, 0, body);
    return fr::ipv6(mac_of(to), mac_of(from), source, ip6(static_cast<std::uint8_t>(to.value)),
                    pk::ipproto_icmpv6, msg, nb::nd_hop_limit);
}

auto icmpv6_frame(NicId from, const net::MacAddress& dst_mac, const net::Ipv6Address& src,
                  const net::Ipv6Address& dst, std::uint8_t type) -> std::vector<std::byte> {
    const std::vector<std::byte> body(12, std::byte{0});
    return fr::ipv6(dst_mac, mac_of(from), src, dst, pk::ipproto_icmpv6,
                    fr::icmpv6(src, dst, type, 0, body), nb::nd_hop_limit);
}

}  // namespace

BOOST_AUTO_TEST_CASE(only_ip_and_arp, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> f;
    ak::wire::Writer w{f};
    fr::ethernet(w, mac_of(nic_b), mac_of(nic_a), ethertype_test);
    f.resize(64, std::byte{0});
    send(nic_a, f);
    // A VLAN tag wrapping a valid IPv4 frame is not IP (Requirement 11.1).
    auto tagged = frame(mac_of(nic_b), mac_of(nic_a));
    const std::vector<std::byte> tag{std::byte{0x81}, std::byte{0x00}, std::byte{0x00},
                                     std::byte{0x05}};
    tagged.insert(tagged.begin() + 12, tag.begin(), tag.end());
    send(nic_a, tagged);
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_ethertype == 2);
}

BOOST_AUTO_TEST_CASE(malformed_ip_dropped, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto f = frame(mac_of(nic_b), mac_of(nic_a));
    f[ethernet_header_size] = std::byte{0x41};  // IHL 1
    send(nic_a, f);
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_malformed == 1);
}

BOOST_AUTO_TEST_CASE(forged_source_dropped, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(22), ip4(22)));  // b's address
    send(nic_a, udp4(mac_of(nic_c), mac_of(nic_a), ip4(99), ip4(33)));  // nobody's
    send(nic_a, udp6(mac_of(nic_b), mac_of(nic_a), ip6(33), ip6(22)));  // c's
    send(nic_x, udp4(mac_of(nic_y), mac_of(nic_x), ip4(11), ip4(77)));  // a's, other VPC
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 4);
    // The genuine sources go through, local and remote, both families.
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(22)));
    send(nic_a, udp6(mac_of(nic_c), mac_of(nic_a), ip6(11), ip6(33)));
    BOOST_TEST(port_b.frames.size() == 1);
    BOOST_TEST(underlay.sent.size() == 1);
}

BOOST_AUTO_TEST_CASE(no_address_no_ip, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // a keeps its IPv4 address but loses its IPv6 one.
    net::NeighborUpdate u = Fixture::addresses(vpc, {nic_b, nic_c, nic_d, nic_e});
    u.ipv4.push_back({ip4(11), nic_a});
    BOOST_REQUIRE(sw.set_neighbors(u));
    send(nic_a, udp6(mac_of(nic_b), mac_of(nic_a), ip6(11), ip6(22)));
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 1);
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(22)));
    BOOST_TEST(port_b.frames.size() == 1);
    // The change applies to the very next frame, and an empty table means no IP.
    BOOST_REQUIRE(sw.set_neighbors({.vni = vpc}));
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(22)));
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 2);
    BOOST_TEST(port_b.frames.size() == 1);
}

BOOST_AUTO_TEST_CASE(destination_must_own_address,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(33)));  // c's address, b's MAC
    send(nic_a, udp6(mac_of(nic_c), mac_of(nic_a), ip6(11), ip6(99)));  // nobody's
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(66)));  // x's, other VPC
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 3);
}

BOOST_AUTO_TEST_CASE(local_only_sources, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const nb::Ipv4Address any{};
    const nb::Ipv4Address bcast{std::byte{255}, std::byte{255}, std::byte{255}, std::byte{255}};
    // A DHCP client message from 0.0.0.0 is for the gateway; without a
    // VpcConfig it is dropped and counted, never flooded (Requirement 12.6).
    send(nic_a, udp4(broadcast_mac(), mac_of(nic_a), any, bcast, dhcp4_client, dhcp4_server));
    // Link-local and unspecified IPv6 sources, unicast or multicast.
    send(nic_a, udp6(mac_of(nic_b), mac_of(nic_a), link_local(nic_a), link_local(nic_b)));
    send(nic_a, udp6(mac_of(nic_b), mac_of(nic_a), link_local(nic_a), ip6(22)));
    send(nic_a, icmpv6_frame(nic_a, all_nodes_mac(), net::Ipv6Address{}, all_nodes(),
                             icmpv6_router_solicitation));
    send(nic_a, udp6(all_nodes_mac(), mac_of(nic_a), link_local(nic_a), all_nodes(), dhcp6_client,
                     dhcp6_server));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().dhcp4_no_config == 1);
    BOOST_TEST(sw.counters().rs_dropped == 1);  // no IPv6 gateway for the RS
    BOOST_TEST(sw.counters().tx_drop_local_only == 3);
    // 0.0.0.0 for anything but a DHCP client message is a forgery.
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), any, ip4(22)));
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 1);
    // Link-local destinations from a real source are not anyone's address.
    send(nic_a, udp6(mac_of(nic_b), mac_of(nic_a), ip6(11), link_local(nic_b)));
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 1);
    BOOST_TEST(nothing_delivered());
}

BOOST_AUTO_TEST_CASE(guests_are_not_routers, *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();  // even where multicast is allowed
    send(nic_a, icmpv6_frame(nic_a, all_nodes_mac(), link_local(nic_a), all_nodes(),
                             icmpv6_router_advertisement));
    send(nic_a, icmpv6_frame(nic_a, mac_of(nic_b), ip6(11), ip6(22), icmpv6_redirect));
    const std::vector<std::byte> redirect{std::byte{icmp_redirect},
                                          std::byte{1},
                                          std::byte{0},
                                          std::byte{0},
                                          std::byte{0},
                                          std::byte{0},
                                          std::byte{0},
                                          std::byte{0}};
    send(nic_a,
         fr::ipv4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(22), pk::ipproto_icmp, redirect));
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), ip4(22), dhcp4_server, dhcp4_client));
    send(nic_a, udp6(mac_of(nic_b), mac_of(nic_a), ip6(11), ip6(22), dhcp6_server, dhcp6_client));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_router_msg == 5);
}

BOOST_AUTO_TEST_CASE(neighbor_advertisement_target,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, neighbor_advertisement(nic_a, nic_b, ip6(11), ip6(33)));  // claims c's address
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_neighbor_spoofed == 1);
    send(nic_a, neighbor_advertisement(nic_a, nic_b, ip6(11), ip6(11)));
    BOOST_TEST(port_b.frames.size() == 1);
}

BOOST_AUTO_TEST_CASE(replicated_needs_multicast_destination,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    opt_in();
    send(nic_a, udp4(mdns_mac(), mac_of(nic_a), ip4(11), ip4(22)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 1);
    BOOST_TEST(sw.group_meter(nic_a)->drop_policy == 1);
    send(nic_a, udp6(all_nodes_mac(), mac_of(nic_a), ip6(11), all_nodes()));
    BOOST_TEST(port_b.frames.size() == 1);
}

BOOST_AUTO_TEST_CASE(unicast_arp_still_forwarded,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto reply = arp_request(nic_a, ip4(11), ip4(22));
    std::ranges::copy(mac_of(nic_b), reply.begin());
    reply[ethernet_header_size + 7] = std::byte{nb::arp_op_reply};
    send(nic_a, reply);
    BOOST_TEST(port_b.frames.size() == 1);
}

BOOST_AUTO_TEST_CASE(receiver_checks_inner_frame,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // c (on peer) forges a's address; claims a destination a does not own;
    // sends a non-IP EtherType; sends a broken IPv4 header.
    const Inbound spoofed{nic_c, nic_a, vpc, udp4(mac_of(nic_a), mac_of(nic_c), ip4(22), ip4(11))};
    const Inbound wrong_dst{nic_c, nic_a, vpc,
                            udp4(mac_of(nic_a), mac_of(nic_c), ip4(33), ip4(22))};
    std::vector<std::byte> other;
    ak::wire::Writer w{other};
    fr::ethernet(w, mac_of(nic_a), mac_of(nic_c), ethertype_test);
    other.resize(64, std::byte{0});
    const Inbound not_ip{nic_c, nic_a, vpc, other};
    auto broken_bytes = frame(mac_of(nic_a), mac_of(nic_c));
    broken_bytes[ethernet_header_size + 3] = std::byte{0xff};  // total length past the frame
    const Inbound broken{nic_c, nic_a, vpc, broken_bytes};
    const Inbound link{nic_c, nic_a, vpc,
                       udp6(mac_of(nic_a), mac_of(nic_c), link_local(nic_c), ip6(11))};
    for (const Inbound* in : {&spoofed, &wrong_dst, &not_ip, &broken, &link}) {
        BOOST_TEST(sw.receive(in->packet, vtep(peer_tail)).has_value());
    }
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().rx_drop_ip_spoofed == 2);
    BOOST_TEST(sw.counters().rx_drop_ip_dst == 1);
    BOOST_TEST(sw.counters().rx_drop_ethertype == 1);
    BOOST_TEST(sw.counters().rx_drop_malformed == 1);

    // A replicated frame needs a multicast destination too.
    opt_in();
    const Inbound mcast_unicast_ip{nic_c, geneve::nic_broadcast, vpc,
                                   udp4(mdns_mac(), mac_of(nic_c), ip4(33), ip4(11))};
    BOOST_TEST(sw.receive(mcast_unicast_ip.packet, vtep(peer_tail)).has_value());
    BOOST_TEST(sw.counters().rx_drop_ip_dst == 2);
    BOOST_TEST(nothing_delivered());
}

BOOST_AUTO_TEST_SUITE_END()

// Requirement 12.1-12.3 (task 17): the VPC gateway's ARP/ND answers and
// the stateless DHCPv4 server.
BOOST_FIXTURE_TEST_SUITE(gateway, Fixture)

namespace {

constexpr std::uint16_t dhcp_server = 67;
constexpr std::uint16_t dhcp_client = 68;
constexpr std::uint32_t xid = 0x1234'5678;
constexpr std::uint16_t nic_mtu = 8874;
constexpr std::uint32_t lease = 3600;
constexpr std::uint8_t opt_requested_ip = 50;
constexpr std::uint8_t opt_server_id = 54;
constexpr std::size_t yiaddr_offset = 16;
constexpr std::size_t udp_offset = ethernet_header_size + pk::ipv4_min_header_size;

auto gw_mac() -> net::MacAddress {
    return {std::byte{0x02}, std::byte{0xaa}, std::byte{0},
            std::byte{0},    std::byte{0},    std::byte{0x01}};
}

auto gw_ip() -> nb::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}};
}

auto config() -> net::VpcConfig {
    net::Ipv6Address prefix{};
    prefix[0] = ula_prefix;
    prefix[1] = std::byte{0x10};
    return {.gateway_mac = gw_mac(),
            .ipv4 = {.address = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}},
                     .length = 16},
            .ipv4_gateway = gw_ip(),
            .ipv6_prefix = prefix,
            .dns4 = {{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{2}}},
            .dns6 = {},
            .domain = "ec2.internal",
            .lease_seconds = lease};
}

auto bcast_ip() -> nb::Ipv4Address {
    return {std::byte{255}, std::byte{255}, std::byte{255}, std::byte{255}};
}

auto dhcp(NicId from, const net::MacAddress& dst_mac, const nb::Ipv4Address& src_ip,
          const nb::Ipv4Address& dst_ip, const std::vector<std::byte>& bootp)
    -> std::vector<std::byte> {
    return fr::ipv4(dst_mac, mac_of(from), src_ip, dst_ip, pk::ipproto_udp,
                    fr::udp(dhcp_client, dhcp_server, bootp));
}

auto discover(NicId from, std::uint16_t flags = 0) -> std::vector<std::byte> {
    return dhcp(from, broadcast_mac(), nb::Ipv4Address{}, bcast_ip(),
                fr::dhcp4_request(1, mac_of(from), xid, {}, flags));
}

auto request(NicId from, const nb::Ipv4Address& wanted, const nb::Ipv4Address& server = gw_ip())
    -> std::vector<std::byte> {
    return dhcp(from, broadcast_mac(), nb::Ipv4Address{}, bcast_ip(),
                fr::dhcp4_request(3, mac_of(from), xid,
                                  {{opt_requested_ip, {wanted.begin(), wanted.end()}},
                                   {opt_server_id, {server.begin(), server.end()}}}));
}

auto option(const std::vector<std::byte>& frame, std::uint8_t code) -> std::vector<std::byte> {
    for (auto& [c, v] : fr::dhcp4_options(std::span{frame}.subspan(udp_offset + 8))) {
        if (c == code) {
            return v;
        }
    }
    return {};
}

}  // namespace

BOOST_AUTO_TEST_CASE(config_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using net::VpcConfigError;
    BOOST_TEST((sw.set_vpc_config(0, config()).error() == VpcConfigError::vni_out_of_range));
    auto c = config();
    c.gateway_mac[0] = std::byte{0x00};  // universally administered
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_gateway_mac));
    c = config();
    c.gateway_mac[0] = std::byte{0x03};  // group
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_gateway_mac));
    c = config();
    c.ipv4.length = 31;
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_ipv4_prefix));
    c = config();
    c.ipv4.address[3] = std::byte{1};  // host bits
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_ipv4_prefix));
    c = config();
    c.ipv4_gateway = {std::byte{10}, std::byte{1}, std::byte{0}, std::byte{0}};
    c.ipv4.length = 24;  // 10.1.0.0 is outside 10.0.0.0/24
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_ipv4_gateway));
    c = config();
    c.ipv4_gateway = {std::byte{10}, std::byte{0}, std::byte{255}, std::byte{255}};  // broadcast
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_ipv4_gateway));
    c = config();
    (*c.ipv6_prefix)[ipv6_last] = std::byte{1};  // not a /64
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_ipv6_prefix));
    c = config();
    c.dns4.resize(net::max_dns_servers + 1, gw_ip());
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::too_many_dns));
    c = config();
    c.dns4 = {bcast_ip()};
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_dns));
    for (const char* bad : {"-a.b", "a..b", "a_b.c", "a.b-"}) {
        c = config();
        c.domain = bad;
        BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_domain));
    }
    c = config();
    c.domain = std::string(64, 'a');  // a label over 63 bytes
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_domain));
    c = config();
    c.lease_seconds = 59;
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_lease));

    BOOST_TEST(sw.vpc_config(vpc) == nullptr);  // nothing applied so far
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    BOOST_TEST((*sw.vpc_config(vpc) == config()));
    sw.clear_vpc_config(vpc);
    BOOST_TEST(sw.vpc_config(vpc) == nullptr);
}

BOOST_AUTO_TEST_CASE(dhcp_without_config_dropped,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, discover(nic_a));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().dhcp4_no_config == 1);
}

BOOST_AUTO_TEST_CASE(discover_gets_offer, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.detach(nic_a));
    BOOST_REQUIRE(sw.attach(nic_a, port_a, nic_mtu));
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    send(nic_a, discover(nic_a, 0x8000));
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(underlay.sent.empty());
    BOOST_REQUIRE(port_a.frames.size() == 1);
    const auto& f = port_a.frames[0];
    BOOST_TEST(std::ranges::equal(std::span{f}.first(mac_size), mac_of(nic_a)));
    BOOST_TEST(std::ranges::equal(std::span{f}.subspan(mac_size, mac_size), gw_mac()));
    const auto p = pk::parse(f);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST((p->src4 == gw_ip()));
    BOOST_TEST((p->dst4 == bcast_ip()));  // the client asked for broadcast
    BOOST_TEST(p->l4->src_port == dhcp_server);
    BOOST_TEST(p->l4->dst_port == dhcp_client);
    BOOST_TEST(fr::ipv4_header_checksum(p->ip.first(pk::ipv4_min_header_size)) == 0);
    BOOST_TEST(std::ranges::equal(p->payload.subspan(yiaddr_offset, 4), ip4(11)));
    BOOST_TEST((option(f, 53) == std::vector<std::byte>{std::byte{2}}));  // OFFER
    BOOST_TEST((option(f, 1) == std::vector<std::byte>{std::byte{255}, std::byte{255}, std::byte{0},
                                                       std::byte{0}}));
    BOOST_TEST(std::ranges::equal(option(f, 3), gw_ip()));
    BOOST_TEST(std::ranges::equal(option(f, 54), gw_ip()));
    BOOST_TEST((option(f, 26) == std::vector<std::byte>{std::byte{0x22}, std::byte{0xaa}}));
    BOOST_TEST(option(f, 15).size() == std::string{"ec2.internal"}.size());
    BOOST_TEST(sw.counters().dhcp4_replies == 1);

    // Without the broadcast flag, the reply goes to the offered address.
    send(nic_a, discover(nic_a));
    BOOST_REQUIRE(port_a.frames.size() == 2);
    BOOST_TEST((pk::parse(port_a.frames[1])->dst4 == ip4(11)));
    // Attached without an MTU (b): no option 26.
    send(nic_b, discover(nic_b));
    BOOST_REQUIRE(port_b.frames.size() == 1);
    BOOST_TEST(option(port_b.frames[0], 26).empty());
}

BOOST_AUTO_TEST_CASE(request_ack_nak_ignore, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    send(nic_a, request(nic_a, ip4(11)));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST((option(port_a.frames[0], 53) == std::vector<std::byte>{std::byte{5}}));  // ACK
    BOOST_TEST(option(port_a.frames[0], 51).size() == 4);

    send(nic_a, request(nic_a, ip4(22)));  // b's address
    BOOST_REQUIRE(port_a.frames.size() == 2);
    BOOST_TEST((option(port_a.frames[1], 53) == std::vector<std::byte>{std::byte{6}}));  // NAK
    BOOST_TEST((pk::parse(port_a.frames[1])->dst4 == bcast_ip()));

    send(nic_a, request(nic_a, ip4(11), ip4(99)));  // chose another server
    BOOST_TEST(port_a.frames.size() == 2);
    BOOST_TEST(sw.counters().dhcp4_ignored == 1);
}

BOOST_AUTO_TEST_CASE(renew_and_inform_unicast, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    // RENEWING: unicast from the leased address to the server.
    send(nic_a, dhcp(nic_a, gw_mac(), ip4(11), gw_ip(),
                     fr::dhcp4_request(3, mac_of(nic_a), xid, {}, 0, ip4(11))));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST((option(port_a.frames[0], 53) == std::vector<std::byte>{std::byte{5}}));
    BOOST_TEST((pk::parse(port_a.frames[0])->dst4 == ip4(11)));
    // INFORM: configuration only, no lease and no yiaddr.
    send(nic_a, dhcp(nic_a, gw_mac(), ip4(11), gw_ip(),
                     fr::dhcp4_request(8, mac_of(nic_a), xid, {}, 0, ip4(11))));
    BOOST_REQUIRE(port_a.frames.size() == 2);
    BOOST_TEST(option(port_a.frames[1], 51).empty());
    BOOST_TEST(std::ranges::equal(pk::parse(port_a.frames[1])->payload.subspan(yiaddr_offset, 4),
                                  nb::Ipv4Address{}));
    // RELEASE is accepted silently.
    send(nic_a, dhcp(nic_a, gw_mac(), ip4(11), gw_ip(),
                     fr::dhcp4_request(7, mac_of(nic_a), xid, {}, 0, ip4(11))));
    BOOST_TEST(port_a.frames.size() == 2);
    BOOST_TEST(sw.counters().dhcp4_ignored == 1);
    BOOST_TEST(underlay.sent.empty());
}

BOOST_AUTO_TEST_CASE(dhcp_checks, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    // chaddr is b's MAC.
    send(nic_a, dhcp(nic_a, broadcast_mac(), nb::Ipv4Address{}, bcast_ip(),
                     fr::dhcp4_request(1, mac_of(nic_b), xid)));
    // Not a DHCP message at all.
    send(nic_a, dhcp(nic_a, broadcast_mac(), nb::Ipv4Address{}, bcast_ip(),
                     std::vector<std::byte>(20, std::byte{0})));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().dhcp4_bad == 2);

    // The lowest address inside the prefix wins; none inside means no answer.
    net::NeighborUpdate u = Fixture::addresses(vpc, {nic_b, nic_c, nic_d, nic_e});
    u.ipv4.push_back({ip4(11), nic_a});
    u.ipv4.push_back({ip4(3), nic_a});
    u.ipv4.push_back({{std::byte{9}, std::byte{0}, std::byte{0}, std::byte{1}}, nic_a});
    BOOST_REQUIRE(sw.set_neighbors(u));
    send(nic_a, discover(nic_a));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST(
        std::ranges::equal(pk::parse(port_a.frames[0])->payload.subspan(yiaddr_offset, 4), ip4(3)));
    auto c = config();
    c.ipv4 = {.address = {std::byte{192}, std::byte{168}, std::byte{0}, std::byte{0}},
              .length = 16};
    c.ipv4_gateway = {std::byte{192}, std::byte{168}, std::byte{0}, std::byte{1}};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, discover(nic_a));
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(sw.counters().dhcp4_no_address == 1);
}

BOOST_AUTO_TEST_CASE(answers_arp_for_gateway, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, arp_request(nic_a, ip4(11), gw_ip()));
    BOOST_TEST(nothing_delivered());  // no config: unanswered, and never flooded
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    send(nic_a, arp_request(nic_a, ip4(11), gw_ip()));
    send(nic_a, arp_request(nic_a, ip4(11), net::metadata_ipv4));
    auto unicast = arp_request(nic_a, ip4(11), gw_ip());  // a NUD refresh
    std::ranges::copy(gw_mac(), unicast.begin());
    send(nic_a, unicast);
    BOOST_REQUIRE(port_a.frames.size() == 3);
    for (const auto& f : port_a.frames) {
        const auto reply = nb::parse_arp(f);
        BOOST_REQUIRE(reply.has_value());
        BOOST_TEST((reply->sender_mac == gw_mac()));
    }
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(underlay.sent.empty());
}

BOOST_AUTO_TEST_CASE(answers_nd_for_gateway, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto gw_ll = net::gateway_link_local(gw_mac());
    BOOST_TEST(std::to_integer<int>(gw_ll[8]) == 0x00);  // 02 with the U/L bit flipped
    BOOST_TEST(std::to_integer<int>(gw_ll[11]) == 0xff);
    BOOST_TEST(std::to_integer<int>(gw_ll[12]) == 0xfe);
    auto c = config();
    c.ipv6_prefix.reset();
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, neighbor_solicitation(nic_a, link_local(nic_a), gw_ll));
    BOOST_TEST(nothing_delivered());  // no IPv6 prefix: no IPv6 gateway
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    send(nic_a, neighbor_solicitation(nic_a, link_local(nic_a), gw_ll));
    send(nic_a, neighbor_solicitation(nic_a, ip6(11), net::metadata_ipv6));
    BOOST_REQUIRE(port_a.frames.size() == 2);
    for (const auto& f : port_a.frames) {
        BOOST_TEST(std::ranges::equal(std::span{f}.subspan(mac_size, mac_size), gw_mac()));
    }
    // R is set for the gateway (a router), clear for the metadata address.
    constexpr std::size_t na_flags = ethernet_header_size + nb::ipv6_header_size + 4;
    BOOST_TEST(std::to_integer<int>(port_a.frames[0][na_flags]) == 0xe0);
    BOOST_TEST(std::to_integer<int>(port_a.frames[1][na_flags]) == 0x60);
    BOOST_TEST(sw.counters().nd_replies == 2);
}

BOOST_AUTO_TEST_CASE(gateway_routes_nothing_yet, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, config()));
    const nb::Ipv4Address outside{std::byte{8}, std::byte{8}, std::byte{8}, std::byte{8}};
    send(nic_a, udp4(gw_mac(), mac_of(nic_a), ip4(11), outside));
    send(nic_a, udp4(gw_mac(), mac_of(nic_a), ip4(11), ip4(22)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().tx_drop_no_route == 2);
}

BOOST_AUTO_TEST_SUITE_END()

// Requirements 12.4-12.5 (task 18): router advertisements and DHCPv6.
BOOST_FIXTURE_TEST_SUITE(gateway6, Fixture)

namespace {

constexpr std::uint16_t dhcp6_client_port = 546;
constexpr std::uint16_t dhcp6_server_port = 547;
constexpr std::uint16_t opt_client_id = 1;
constexpr std::uint16_t opt_server_id = 2;
constexpr std::uint16_t opt_ia_na = 3;
constexpr std::uint16_t opt_status = 13;
constexpr std::uint16_t opt_rapid_commit = 14;
constexpr std::uint32_t iaid = 77;
constexpr std::size_t udp6_payload = ethernet_header_size + nb::ipv6_header_size + 8;
constexpr std::size_t icmp6_body = ethernet_header_size + nb::ipv6_header_size + 4;

auto all_routers() -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xff};
    a[1] = std::byte{0x02};
    a[ipv6_last] = std::byte{2};
    return a;
}

auto multicast_mac(const net::Ipv6Address& group) -> net::MacAddress {
    return {std::byte{0x33}, std::byte{0x33}, group[12], group[13], group[14], group[15]};
}

auto router_solicitation(NicId from, const net::Ipv6Address& src,
                         std::uint8_t hop_limit = nb::nd_hop_limit) -> std::vector<std::byte> {
    const std::vector<std::byte> reserved(4, std::byte{0});
    return fr::ipv6(multicast_mac(all_routers()), mac_of(from), src, all_routers(),
                    pk::ipproto_icmpv6, fr::icmpv6(src, all_routers(), 133, 0, reserved),
                    hop_limit);
}

auto client_duid(NicId n) -> std::vector<std::byte> {
    return {std::byte{0}, std::byte{3}, std::byte{0}, std::byte{1}, mac_of(n)[0],
            mac_of(n)[1], mac_of(n)[2], mac_of(n)[3], mac_of(n)[4], mac_of(n)[5]};
}

auto dhcp6(NicId from, std::uint8_t type, std::vector<fr::DhcpOption6> options)
    -> std::vector<std::byte> {
    return fr::ipv6(
        multicast_mac(ak::oar::net::dhcp6::all_servers), mac_of(from), link_local(from),
        ak::oar::net::dhcp6::all_servers, pk::ipproto_udp,
        fr::udp(dhcp6_client_port, dhcp6_server_port, fr::dhcp6_message(type, 1, options)));
}

auto reply_options(const std::vector<std::byte>& frame) {
    return fr::dhcp6_options(std::span{frame}.subspan(udp6_payload));
}

auto has(const std::vector<std::pair<std::uint16_t, std::vector<std::byte>>>& opts,
         std::uint16_t code) -> const std::vector<std::byte>* {
    for (const auto& [c, v] : opts) {
        if (c == code) {
            return &v;
        }
    }
    return nullptr;
}

}  // namespace

BOOST_AUTO_TEST_CASE(answers_router_solicitation,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, router_solicitation(nic_a, link_local(nic_a)));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().rs_dropped == 1);
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));
    BOOST_REQUIRE(sw.detach(nic_a));
    BOOST_REQUIRE(sw.attach(nic_a, port_a, 8874));
    send(nic_a, router_solicitation(nic_a, link_local(nic_a)));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    const auto& f = port_a.frames[0];
    const auto p = pk::parse(f);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->hop_limit == nb::nd_hop_limit);
    BOOST_TEST((p->src6 == net::gateway_link_local(gateway::gw_mac())));
    BOOST_TEST((p->dst6 == link_local(nic_a)));
    BOOST_TEST(p->l4->icmp_type == 134);
    BOOST_TEST(nb::icmpv6_checksum(p->src6, p->dst6, p->l4_data) == 0);
    BOOST_TEST(std::to_integer<int>(f[icmp6_body + 1]) == 0xC0);  // M | O
    BOOST_TEST(sw.counters().ra_sent == 1);
    // From :: the answer goes to all-nodes; a hop limit other than 255 is
    // not a real solicitation (RFC 4861 6.1.1).
    send(nic_a, router_solicitation(nic_a, net::Ipv6Address{}));
    BOOST_REQUIRE(port_a.frames.size() == 2);
    BOOST_TEST(std::to_integer<int>(pk::parse(port_a.frames[1])->dst6[1]) == 0x02);
    send(nic_a, router_solicitation(nic_a, link_local(nic_a), 64));
    BOOST_TEST(port_a.frames.size() == 2);
    BOOST_TEST(sw.counters().rs_dropped == 2);
    BOOST_TEST(port_b.frames.empty());
    BOOST_TEST(underlay.sent.empty());
}

BOOST_AUTO_TEST_CASE(periodic_advertisements, *boost::unit_test::timeout(unit_timeout_seconds)) {
    sw.poll();
    BOOST_TEST(nothing_delivered());  // no IPv6 gateway anywhere
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));
    sw.poll();
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(port_b.frames.size() == 1);
    BOOST_TEST(port_x.frames.empty());  // other VPC
    now += std::chrono::seconds{199};
    sw.poll();
    BOOST_TEST(port_a.frames.size() == 1);
    now += std::chrono::seconds{1};
    sw.poll();
    BOOST_TEST(port_a.frames.size() == 2);
    BOOST_TEST(port_b.frames.size() == 2);
    // A re-attached NIC gets one at the next poll.
    BOOST_REQUIRE(sw.detach(nic_b));
    BOOST_REQUIRE(sw.attach(nic_b, port_b));
    sw.poll();
    BOOST_TEST(port_b.frames.size() == 3);
    BOOST_TEST(port_a.frames.size() == 2);
    BOOST_TEST(underlay.sent.empty());
}

BOOST_AUTO_TEST_CASE(dhcp6_solicit_request, *boost::unit_test::timeout(unit_timeout_seconds)) {
    send(nic_a, dhcp6(nic_a, 1, {{opt_client_id, client_duid(nic_a)}}));
    BOOST_TEST(nothing_delivered());
    BOOST_TEST(sw.counters().dhcp6_no_config == 1);
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));

    send(nic_a,
         dhcp6(nic_a, 1, {{opt_client_id, client_duid(nic_a)}, {opt_ia_na, fr::ia_na(iaid)}}));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    const auto p = pk::parse(port_a.frames[0]);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST((p->dst6 == link_local(nic_a)));
    BOOST_TEST(p->l4->src_port == dhcp6_server_port);
    BOOST_TEST(std::to_integer<int>(port_a.frames[0][udp6_payload]) == 2);  // Advertise
    auto opts = reply_options(port_a.frames[0]);
    const auto* server = has(opts, opt_server_id);
    BOOST_REQUIRE(server != nullptr);
    const auto* ia = has(opts, opt_ia_na);
    BOOST_REQUIRE(ia != nullptr);
    BOOST_TEST(ia->size() == 12 + 28);  // a's one address, fd10::11
    BOOST_TEST(std::ranges::equal(std::span{*ia}.subspan(16, 16), ip6(11)));

    // Request naming us gets a Reply; naming someone else is ignored.
    const std::vector<std::byte> ours = *server;
    send(nic_a, dhcp6(nic_a, 3,
                      {{opt_client_id, client_duid(nic_a)},
                       {opt_server_id, ours},
                       {opt_ia_na, fr::ia_na(iaid)}}));
    BOOST_REQUIRE(port_a.frames.size() == 2);
    BOOST_TEST(std::to_integer<int>(port_a.frames[1][udp6_payload]) == 7);
    send(nic_a, dhcp6(nic_a, 3,
                      {{opt_client_id, client_duid(nic_a)},
                       {opt_server_id, client_duid(nic_b)},
                       {opt_ia_na, fr::ia_na(iaid)}}));
    send(nic_a, dhcp6(nic_a, 1, {{opt_client_id, client_duid(nic_a)}, {opt_server_id, ours}}));
    BOOST_TEST(port_a.frames.size() == 2);
    BOOST_TEST(sw.counters().dhcp6_ignored == 2);

    // Rapid commit: straight to a Reply that says so.
    send(nic_a, dhcp6(nic_a, 1,
                      {{opt_client_id, client_duid(nic_a)},
                       {opt_ia_na, fr::ia_na(iaid)},
                       {opt_rapid_commit, {}}}));
    BOOST_REQUIRE(port_a.frames.size() == 3);
    BOOST_TEST(std::to_integer<int>(port_a.frames[2][udp6_payload]) == 7);
    BOOST_TEST(has(reply_options(port_a.frames[2]), opt_rapid_commit) != nullptr);
    BOOST_TEST(underlay.sent.empty());
    BOOST_TEST(port_b.frames.empty());
}

BOOST_AUTO_TEST_CASE(dhcp6_confirm_info_release, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));
    const auto ours = ak::oar::net::dhcp6::server_duid(gateway::gw_mac());
    net::Ipv6Address elsewhere{};
    elsewhere[0] = std::byte{0x20};
    send(nic_a,
         dhcp6(nic_a, 4,
               {{opt_client_id, client_duid(nic_a)}, {opt_ia_na, fr::ia_na(iaid, {ip6(11)})}}));
    send(nic_a,
         dhcp6(nic_a, 4,
               {{opt_client_id, client_duid(nic_a)}, {opt_ia_na, fr::ia_na(iaid, {elsewhere})}}));
    send(nic_a, dhcp6(nic_a, 11, {}));  // information-request, no client ID needed
    send(nic_a, dhcp6(nic_a, 8,
                      {{opt_client_id, client_duid(nic_a)},
                       {opt_server_id, ours},
                       {opt_ia_na, fr::ia_na(iaid, {ip6(11)})}}));
    BOOST_REQUIRE(port_a.frames.size() == 4);
    BOOST_TEST(std::to_integer<int>((*has(reply_options(port_a.frames[0]), opt_status))[1]) == 0);
    BOOST_TEST(std::to_integer<int>((*has(reply_options(port_a.frames[1]), opt_status))[1]) == 4);
    BOOST_TEST(has(reply_options(port_a.frames[2]), opt_ia_na) == nullptr);
    BOOST_TEST(has(reply_options(port_a.frames[2]), 24) != nullptr);  // domain list
    BOOST_TEST(std::to_integer<int>((*has(reply_options(port_a.frames[3]), opt_status))[1]) == 0);
    // No client ID on a Solicit is malformed.
    send(nic_a, dhcp6(nic_a, 1, {}));
    BOOST_TEST(sw.counters().dhcp6_bad == 1);
    BOOST_TEST(sw.counters().dhcp6_replies == 4);
}

BOOST_AUTO_TEST_SUITE_END()

// Requirement 13.1-13.3 (task 19): the metadata intercept.
BOOST_FIXTURE_TEST_SUITE(metadata, Fixture)

namespace {

class FakeEndpoint final : public net::MetadataEndpoint {
public:
    auto deliver(NicId nic, std::span<const std::byte> ip) -> void override {
        got.push_back({nic, {ip.begin(), ip.end()}});
    }
    struct Got {
        NicId nic;
        std::vector<std::byte> ip;
    };
    std::vector<Got> got;
};

constexpr std::uint16_t http = 80;

// The IP part of a frame.
auto ip_of(const std::vector<std::byte>& frame) -> std::vector<std::byte> {
    return {frame.begin() + ethernet_header_size, frame.end()};
}

}  // namespace

BOOST_AUTO_TEST_CASE(intercepted_with_trusted_nic,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));
    const auto syn4 = fr::ipv4(gateway::gw_mac(), mac_of(nic_a), ip4(11), net::metadata_ipv4,
                               pk::ipproto_tcp, fr::tcp(40000, http));
    send(nic_a, syn4);
    BOOST_TEST(sw.counters().metadata_no_endpoint == 1);
    FakeEndpoint ep;
    sw.set_metadata_endpoint(&ep);
    send(nic_a, syn4);
    send(nic_b, fr::ipv6(gateway::gw_mac(), mac_of(nic_b), ip6(22), net::metadata_ipv6,
                         pk::ipproto_tcp, fr::tcp(40000, http)));
    BOOST_REQUIRE(ep.got.size() == 2);
    BOOST_TEST((ep.got[0].nic == nic_a));
    BOOST_TEST(ep.got[0].ip == ip_of(syn4));
    BOOST_TEST((ep.got[1].nic == nic_b));
    BOOST_TEST(nothing_delivered());  // never into the fabric
    // A forged source is stopped before the endpoint sees it (13.2).
    send(nic_a, fr::ipv4(gateway::gw_mac(), mac_of(nic_a), ip4(22), net::metadata_ipv4,
                         pk::ipproto_tcp, fr::tcp(40000, http)));
    BOOST_TEST(ep.got.size() == 2);
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 1);
    // The metadata address at a guest's MAC is just an unowned destination.
    send(nic_a, fr::ipv4(mac_of(nic_b), mac_of(nic_a), ip4(11), net::metadata_ipv4, pk::ipproto_tcp,
                         fr::tcp(40000, http)));
    BOOST_TEST(ep.got.size() == 2);
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 1);
}

BOOST_AUTO_TEST_CASE(rate_limited_per_nic, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));
    FakeEndpoint ep;
    sw.set_metadata_endpoint(&ep);
    const auto pkt = fr::ipv4(gateway::gw_mac(), mac_of(nic_a), ip4(11), net::metadata_ipv4,
                              pk::ipproto_tcp, fr::tcp(40000, http));
    for (std::uint32_t i = 0; i < net::metadata_burst + 10; ++i) {
        send(nic_a, pkt);
    }
    BOOST_TEST(ep.got.size() == net::metadata_burst);
    BOOST_TEST(sw.counters().metadata_drop_rate == 10);
    send(nic_b, fr::ipv4(gateway::gw_mac(), mac_of(nic_b), ip4(22), net::metadata_ipv4,
                         pk::ipproto_tcp, fr::tcp(40000, http)));
    BOOST_TEST(ep.got.size() == net::metadata_burst + 1);  // b has its own bucket
    now += std::chrono::milliseconds{10};                  // ~10 packets at 1024/s
    for (int i = 0; i < 20; ++i) {
        send(nic_a, pkt);
    }
    BOOST_TEST(ep.got.size() == net::metadata_burst + 1 + 10);
}

BOOST_AUTO_TEST_CASE(injected_replies_checked, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, gateway::config()));
    const auto reply4 = ip_of(fr::ipv4(mac_of(nic_a), gateway::gw_mac(), net::metadata_ipv4,
                                       ip4(11), pk::ipproto_tcp, fr::tcp(http, 40000)));
    BOOST_TEST(sw.inject_metadata(nic_a, reply4));
    BOOST_REQUIRE(port_a.frames.size() == 1);
    BOOST_TEST(std::ranges::equal(std::span{port_a.frames[0]}.first(mac_size), mac_of(nic_a)));
    BOOST_TEST(std::ranges::equal(std::span{port_a.frames[0]}.subspan(mac_size, mac_size),
                                  gateway::gw_mac()));
    const auto reply6 = ip_of(fr::ipv6(mac_of(nic_b), gateway::gw_mac(), net::metadata_ipv6,
                                       ip6(22), pk::ipproto_tcp, fr::tcp(http, 40000)));
    BOOST_TEST(sw.inject_metadata(nic_b, reply6));
    BOOST_TEST(port_b.frames.size() == 1);

    // Refused: to b's address through a; not from the metadata address;
    // garbage; a NIC that is not attached; a VNI without a gateway.
    BOOST_TEST(!sw.inject_metadata(
        nic_a, ip_of(fr::ipv4(mac_of(nic_a), gateway::gw_mac(), net::metadata_ipv4, ip4(22),
                              pk::ipproto_tcp, fr::tcp(http, 1)))));
    BOOST_TEST(
        !sw.inject_metadata(nic_a, ip_of(fr::ipv4(mac_of(nic_a), gateway::gw_mac(), ip4(33),
                                                  ip4(11), pk::ipproto_tcp, fr::tcp(http, 1)))));
    BOOST_TEST(!sw.inject_metadata(nic_a, std::vector<std::byte>(10, std::byte{0x45})));
    BOOST_TEST(!sw.inject_metadata(nic_c, reply4));
    BOOST_TEST(!sw.inject_metadata(nic_x, reply4));
    BOOST_TEST(sw.counters().metadata_inject_refused == 5);
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(underlay.sent.empty());
}

BOOST_AUTO_TEST_SUITE_END()

// Requirement 11.10 and 12.7 (oar-net task 22): NICs whose mapping turns
// the source/destination check off, and VpcConfig routes that send
// packets for the gateway to them.
BOOST_FIXTURE_TEST_SUITE(routing, Fixture)

namespace {

constexpr std::size_t ip_at = ethernet_header_size;
constexpr std::size_t ttl_at = ip_at + 8;
constexpr std::size_t hop_limit_at = ip_at + 7;

auto addr4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> nb::Ipv4Address {
    return {std::byte{a}, std::byte{b}, std::byte{c}, std::byte{d}};
}

auto route4(const nb::Ipv4Address& prefix, std::uint8_t length, NicId target) -> net::VpcRoute {
    net::VpcRoute r{.ipv6 = false, .prefix = {}, .length = length, .target = target};
    std::ranges::copy(prefix, r.prefix.begin());
    return r;
}

// fd99::/16
auto far6() -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[1] = std::byte{0x99};
    return a;
}

// gateway::config() with a default route to b, 192.168.0.0/16 to c and
// fd99::/16 to b.
auto routed_config() -> net::VpcConfig {
    auto c = gateway::config();
    c.routes = {route4({}, 0, nic_b),
                route4(addr4(192, 168, 0, 0), 16, nic_c),
                {.ipv6 = true, .prefix = far6(), .length = 16, .target = nic_b}};
    return c;
}

auto valid_ipv4_checksum(const std::vector<std::byte>& f) -> bool {
    return fr::ipv4_header_checksum(std::span{f}.subspan(ip_at, pk::ipv4_min_header_size)) == 0;
}

}  // namespace

struct Routing : Fixture {
    // Version 2 of the map: b (local) and c (remote) have the check off.
    Routing() {
        auto b = entry(nic_b, self_tail);
        b.source_dest_check = false;
        auto c = entry(nic_c, peer_tail);
        c.source_dest_check = false;
        BOOST_REQUIRE(
            table.apply({.vni = vpc,
                         .version = 2,
                         .entries = {entry(nic_a, self_tail), b, c, entry(nic_d, third_tail),
                                     entry(nic_e, peer_tail)}}));
    }
};

BOOST_AUTO_TEST_CASE(route_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using net::VpcConfigError;
    auto c = routed_config();
    c.routes.push_back(route4(addr4(10, 1, 0, 1), 16, nic_c));  // host bits
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_route));
    c = routed_config();
    c.routes.push_back(route4({}, 33, nic_c));
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_route));
    c = routed_config();
    c.routes.push_back(route4({}, 0, nic_c));  // the same prefix twice
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_route));
    c = routed_config();
    c.routes.push_back(route4(addr4(172, 16, 0, 0), 12, geneve::nic_invalid));
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_route));
    c = routed_config();
    c.routes.push_back(route4(addr4(172, 16, 0, 0), 12, geneve::nic_broadcast));
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::bad_route));
    c = routed_config();
    for (std::size_t i = c.routes.size(); i <= net::max_vpc_routes; ++i) {
        c.routes.push_back(route4(addr4(100, static_cast<std::uint8_t>(i), 0, 0), 16, nic_b));
    }
    BOOST_TEST((sw.set_vpc_config(vpc, c).error() == VpcConfigError::too_many_routes));
    // The same prefix in the other family is a different route.
    c = routed_config();
    c.routes.push_back({.ipv6 = true, .prefix = {}, .length = 0, .target = nic_c});
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    BOOST_TEST((*sw.vpc_config(vpc) == c));
}

BOOST_FIXTURE_TEST_CASE(routed_to_local_and_remote_targets, Routing,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(sw.set_vpc_config(vpc, routed_config()));
    // The default route: a local target.
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    BOOST_REQUIRE(port_b.frames.size() == 1);
    const auto& local = port_b.frames[0];
    BOOST_TEST(std::ranges::equal(std::span{local}.first(mac_size), mac_of(nic_b)));
    BOOST_TEST(std::ranges::equal(std::span{local}.subspan(mac_size, mac_size), mac_of(nic_a)));
    BOOST_TEST(std::to_integer<int>(local[ttl_at]) == fr::default_ttl - 1);
    BOOST_TEST(valid_ipv4_checksum(local));

    // The longer prefix wins: a remote target, tunnelled to its VTEP.
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(192, 168, 7, 9)));
    BOOST_REQUIRE(underlay.sent.size() == 1);
    const Sent& s = underlay.sent[0];
    BOOST_TEST((s.vtep == vtep(peer_tail)));
    BOOST_TEST((s.nics == geneve::NicPair{.src = nic_a, .dst = nic_c}));
    BOOST_TEST(std::ranges::equal(std::span{s.frame}.first(mac_size), mac_of(nic_c)));
    BOOST_TEST(std::to_integer<int>(s.frame[ttl_at]) == fr::default_ttl - 1);
    BOOST_TEST(valid_ipv4_checksum(s.frame));

    // IPv6: the hop limit drops by one.
    auto far = far6();
    far[ipv6_last] = std::byte{1};
    send(nic_a, udp6(gateway::gw_mac(), mac_of(nic_a), ip6(11), far));
    BOOST_REQUIRE(port_b.frames.size() == 2);
    BOOST_TEST(std::to_integer<int>(port_b.frames[1][hop_limit_at]) == fr::default_ttl - 1);

    BOOST_TEST(sw.counters().tx_routed == 3);
    BOOST_TEST(sw.counters().tx_local == 2);
    BOOST_TEST(sw.counters().tx_remote == 1);
    BOOST_TEST(port_a.frames.empty());
}

BOOST_FIXTURE_TEST_CASE(unroutable_packets_dropped, Routing,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // No VpcConfig: no gateway, so its MAC is just an unknown destination.
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    BOOST_TEST(sw.counters().tx_drop_no_route == 0);

    auto c = gateway::config();
    c.routes = {route4(addr4(192, 168, 0, 0), 16, nic_c)};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    // No matching route, and no IPv6 routes at all.
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    send(nic_a, udp6(gateway::gw_mac(), mac_of(nic_a), ip6(11), far6()));
    // Broadcast and multicast destinations are never routed.
    c.routes = {route4({}, 0, nic_b)};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(255, 255, 255, 255)));
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(239, 0, 0, 1)));
    BOOST_TEST(sw.counters().tx_drop_no_route == 4);

    // A target this VTEP does not map, or one in another VPC.
    c.routes = {route4({}, 0, nic_unmapped)};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    c.routes = {route4({}, 0, nic_x)};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    BOOST_TEST(sw.counters().tx_drop_route_target == 2);

    // A target that keeps its check refuses addresses it does not own.
    c.routes = {route4({}, 0, nic_d)};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 1);

    // The target sending to its own route.
    c.routes = {route4({}, 0, nic_b)};
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_b, udp4(gateway::gw_mac(), mac_of(nic_b), ip4(22), addr4(8, 8, 8, 8)));
    BOOST_TEST(sw.counters().tx_drop_hairpin == 1);

    // A packet with one hop left.
    auto last_hop = udp4(gateway::gw_mac(), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8));
    last_hop[ttl_at] = std::byte{1};
    last_hop[ip_at + fr::ipv4_checksum_offset] = std::byte{0};
    last_hop[ip_at + fr::ipv4_checksum_offset + 1] = std::byte{0};
    const auto sum =
        fr::ipv4_header_checksum(std::span{last_hop}.subspan(ip_at, pk::ipv4_min_header_size));
    last_hop[ip_at + fr::ipv4_checksum_offset] = static_cast<std::byte>(sum >> 8U);
    last_hop[ip_at + fr::ipv4_checksum_offset + 1] = static_cast<std::byte>(sum & 0xFFU);
    send(nic_a, last_hop);
    c.routes.push_back({.ipv6 = true, .prefix = far6(), .length = 16, .target = nic_b});
    BOOST_REQUIRE(sw.set_vpc_config(vpc, c));
    send(nic_a, fr::ipv6(gateway::gw_mac(), mac_of(nic_a), ip6(11), far6(), pk::ipproto_udp,
                         fr::udp(test_port, test_port, {}), 1));
    BOOST_TEST(sw.counters().tx_drop_ttl == 2);
    BOOST_TEST(sw.counters().tx_routed == 0);
    BOOST_TEST(nothing_delivered());
}

BOOST_FIXTURE_TEST_CASE(check_off_on_transmit, Routing,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // b sends from an address it does not own, locally and remotely.
    send(nic_b, udp4(mac_of(nic_a), mac_of(nic_b), addr4(8, 8, 8, 8), ip4(11)));
    send(nic_b, udp4(mac_of(nic_d), mac_of(nic_b), addr4(8, 8, 8, 8), ip4(44)));
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(underlay.sent.size() == 1);
    // a sends b and c packets for addresses they do not own.
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    send(nic_a, udp4(mac_of(nic_c), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    BOOST_TEST(port_b.frames.size() == 1);
    BOOST_TEST(underlay.sent.size() == 2);
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 0);
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 0);
    // The others keep theirs: a cannot spoof, d does not take foreign packets.
    send(nic_a, udp4(mac_of(nic_b), mac_of(nic_a), addr4(8, 8, 8, 8), ip4(22)));
    send(nic_a, udp4(mac_of(nic_d), mac_of(nic_a), ip4(11), addr4(8, 8, 8, 8)));
    BOOST_TEST(sw.counters().tx_drop_ip_spoofed == 1);
    BOOST_TEST(sw.counters().tx_drop_ip_dst == 1);
}

BOOST_FIXTURE_TEST_CASE(check_off_on_receive, Routing,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // c's packets from foreign addresses come in, judged by this VTEP's map.
    const Inbound from_c{nic_c, nic_a, vpc,
                         udp4(mac_of(nic_a), mac_of(nic_c), addr4(8, 8, 8, 8), ip4(11))};
    BOOST_TEST(sw.receive(from_c.packet, vtep(peer_tail)).has_value());
    // b takes packets for foreign addresses.
    const Inbound to_b{nic_e, nic_b, vpc,
                       udp4(mac_of(nic_b), mac_of(nic_e), ip4(55), addr4(8, 8, 8, 8))};
    BOOST_TEST(sw.receive(to_b.packet, vtep(peer_tail)).has_value());
    BOOST_TEST(port_a.frames.size() == 1);
    BOOST_TEST(port_b.frames.size() == 1);
    // e keeps its check, and so does a.
    const Inbound from_e{nic_e, nic_a, vpc,
                         udp4(mac_of(nic_a), mac_of(nic_e), addr4(8, 8, 8, 8), ip4(11))};
    BOOST_TEST(sw.receive(from_e.packet, vtep(peer_tail)).has_value());  // dropped inside
    const Inbound to_a{nic_e, nic_a, vpc,
                       udp4(mac_of(nic_a), mac_of(nic_e), ip4(55), addr4(8, 8, 8, 8))};
    BOOST_TEST(sw.receive(to_a.packet, vtep(peer_tail)).has_value());
    BOOST_TEST(sw.counters().rx_drop_ip_spoofed == 1);
    BOOST_TEST(sw.counters().rx_drop_ip_dst == 1);
    BOOST_TEST(port_a.frames.size() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
