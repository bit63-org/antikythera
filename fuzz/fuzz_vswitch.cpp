// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VSwitch and the ARP/ND parsers it runs on guest frames.
//
// The first byte picks a mode:
//   even: the input after it is one frame for parse_arp and
//         parse_neighbor_solicitation; accepted requests are answered and
//         the answers must parse (ARP) or carry a valid checksum (NA).
//   odd:  the input is a stream of records [source][length][bytes] fed to a
//         VSwitch with two VPCs, a dead NIC and a proxy table, alternating
//         transmit() from the chosen NIC and receive() of the bytes as a
//         Geneve payload. After each record: nothing reached a NIC outside
//         the sender's VNI, a dead NIC never sent or received, and every
//         underlay send carries the true source NIC and VNI.
//         Requirement 11: every IP frame that reaches another NIC or the
//         underlay carries a source address owned by the NIC it came from
//         (the sender on transmit, the Geneve source NIC on receive), never
//         a link-local or unspecified one, and nothing but IPv4, IPv6 and
//         ARP is ever forwarded. vpc_one has a VPC gateway, so DHCP and the
//         gateway's ARP/ND answers run too, and their replies (from the
//         gateway's address) may only reach the asking NIC. Its metadata
//         endpoint must only hear from the NIC a packet came from, with
//         that NIC's own source address. poll() runs between records.
//         vpc_one has three subnets (vpc-subnets-routing Requirements 3,
//         6 and 8.1): a alone in A, b and remote c in B, remote e in C.
//         Table 1 (A and B) holds the local routes and 10.0.2.0/25 to e;
//         table 2 (C) the local routes and 10.0.1.0/24 to b. A frame
//         crosses subnets only through the router: then it carries the
//         gateway MAC as source, a TTL one lower than the sender's (on
//         transmit), and reaches only the NIC the source subnet's table
//         names, on transmit and on receive.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/packet.hpp"
#include "oar/net/vswitch.hpp"

namespace {

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
namespace nb = ak::oar::net::neighbor;
namespace pk = ak::oar::net::packet;

constexpr std::uint32_t vpc_one = 1;
constexpr std::uint32_t vpc_two = 2;
// a, b local + c, e remote in one; x local in two; dead
constexpr std::size_t nic_count = 6;
constexpr std::array<std::uint64_t, nic_count> nic_ids{1, 2, 3, 4, 5, 6};
constexpr std::array<std::uint32_t, nic_count> nic_vnis{vpc_one, vpc_one, vpc_one,
                                                        vpc_two, 0,       vpc_one};
// The subnet (third IPv4 octet, IPv6 byte 7) of each vpc_one NIC.
constexpr std::array<std::uint8_t, nic_count> nic_subnets{0, 1, 1, 0, 0, 2};
constexpr std::size_t subnet_count = 3;
constexpr std::uint64_t subnet_id_base = 0x5B00;
constexpr std::size_t remote_index = 2;
constexpr std::size_t dead_index = 4;
constexpr std::size_t e_index = 5;
constexpr std::uint8_t self_tail = 1;
constexpr std::uint8_t peer_tail = 2;
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::byte ula_prefix{0xfd};
constexpr std::byte locally_administered{0x02};
constexpr std::size_t message_offset = geneve::ethernet_header_size + nb::ipv6_header_size;

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto mac(std::size_t index) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = locally_administered;
    m[mac_last] = static_cast<std::byte>(index + 1);
    return m;
}

class Port final : public net::RxPort {
public:
    auto deliver(std::span<const std::byte> frame) -> net::RxResult override {
        ++frames;
        last.assign(frame.begin(), frame.end());
        return net::RxResult::delivered;
    }
    std::size_t frames{0};
    std::vector<std::byte> last;
};

class Recorder final : public net::Underlay {
public:
    auto send(const net::RemoteFrame& f) -> void override {
        sent.push_back({f.vni, f.nics, {f.frame.begin(), f.frame.end()}});
    }
    struct Sent {
        std::uint32_t vni;
        geneve::NicPair nics;
        std::vector<std::byte> frame;
    };
    std::vector<Sent> sent;
};

// Guest addresses: b (local), c and e (remote) in vpc_one own one of each
// family, inside their subnet.
auto ip4_of(std::size_t index) -> nb::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{nic_subnets.at(index)},
            static_cast<std::byte>(index + 1)};
}

auto ip6_of(std::size_t index) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[1] = std::byte{1};
    a[7] = std::byte{nic_subnets.at(index)};
    a[ipv6_last] = static_cast<std::byte>(index + 1);
    return a;
}

constexpr std::size_t b_index = 1;

auto owns_addresses(std::size_t index) -> bool {
    return index == b_index || index == remote_index || index == e_index;
}

// Whether a frame from `sender` may reach `receiver`: the same subnet in
// vpc_one (the VNI check is separate).
auto same_subnet(std::size_t sender, std::size_t receiver) -> bool {
    return sender >= nic_count || nic_vnis.at(sender) != vpc_one ||
           nic_subnets.at(sender) == nic_subnets.at(receiver);
}

constexpr net::MacAddress gateway_mac{locally_administered, std::byte{0xaa}, std::byte{0},
                                      std::byte{0},         std::byte{0},    std::byte{1}};
constexpr std::size_t src_mac_at = 6;
constexpr std::size_t ipv6_block_bytes = 7;

// The NIC the source subnet's table sends `p` to, or nic_count for none:
// an independent model of the router's lookup (Requirement 8.1).
auto expected_target(std::size_t sender, const pk::ParsedPacket& p) -> std::size_t {
    if (sender >= nic_count || nic_vnis.at(sender) != vpc_one) {
        return nic_count;
    }
    const bool table2 = nic_subnets.at(sender) == 2;
    if (p.family == pk::IpFamily::ipv4) {
        const auto& d = p.dst4;
        if (d[0] != std::byte{10} || d[1] != std::byte{0}) {
            return nic_count;
        }
        if (!table2 && d[2] == std::byte{2} && d[3] < std::byte{128}) {
            return e_index;
        }
        if (table2 && d[2] == std::byte{1}) {
            return b_index;
        }
    } else {
        const auto block = ip6_of(0);
        if (!std::equal(block.begin(), block.begin() + ipv6_block_bytes, p.dst6.begin())) {
            return nic_count;
        }
    }
    for (const std::size_t i : {b_index, remote_index, e_index}) {  // the local route
        if (p.family == pk::IpFamily::ipv4 ? p.dst4 == ip4_of(i) : p.dst6 == ip6_of(i)) {
            return i;
        }
    }
    return nic_count;
}

// Whether `frame` from `sender` may reach `receiver`: switched inside the
// sender's subnet, or routed to the table's target with the gateway MAC
// as source and (when the sent frame `original` is known) one hop fewer.
auto from_gateway(std::span<const std::byte> frame) -> bool {
    return std::equal(gateway_mac.begin(), gateway_mac.end(), frame.begin() + src_mac_at);
}

auto reach_ok(std::size_t sender, std::size_t receiver, std::span<const std::byte> frame,
              const pk::ParsedPacket* original) -> bool {
    if (!from_gateway(frame)) {
        return same_subnet(sender, receiver);
    }
    const auto p = pk::parse(frame);
    return p && expected_target(sender, *p) == receiver &&
           (original == nullptr || original->hop_limit == p->hop_limit + 1);
}

// Requirement 11: a forwarded frame is ARP, or IP from the true sender's
// own address.
auto forwarded_ok(std::span<const std::byte> frame, std::size_t sender) -> bool {
    const std::uint16_t type = pk::ethertype(frame);
    if (type == nb::ethertype_arp) {
        return true;
    }
    const auto p = pk::parse(frame);
    if (!p) {
        return false;
    }
    if (!owns_addresses(sender)) {
        return false;
    }
    return p->family == pk::IpFamily::ipv4 ? p->src4 == ip4_of(sender) : p->src6 == ip6_of(sender);
}

// Requirement 13: the endpoint only ever hears from the NIC a packet came
// from, and only from that NIC's own address.
class Endpoint final : public net::MetadataEndpoint {
public:
    auto deliver(geneve::NicId nic, std::span<const std::byte> ip) -> void override {
        calls.push_back({nic, {ip.begin(), ip.end()}});
    }
    struct Call {
        geneve::NicId nic;
        std::vector<std::byte> ip;
    };
    std::vector<Call> calls;
};

auto index_of(geneve::NicId id) -> std::size_t {
    for (std::size_t i = 0; i < nic_count; ++i) {
        if (nic_ids.at(i) == id.value) {
            return i;
        }
    }
    return nic_count;
}

auto fuzz_parsers(std::span<const std::byte> in) -> void {
    if (const auto arp = nb::parse_arp(in); arp) {
        const auto reply = nb::parse_arp(nb::build_arp_reply(*arp, mac(0)));
        if (!reply || reply->op != nb::arp_op_reply || reply->target_ip != arp->sender_ip) {
            std::abort();
        }
    }
    if (const auto ns = nb::parse_neighbor_solicitation(in); ns) {
        const auto na = nb::build_neighbor_advertisement(*ns, mac(0));
        const auto message = std::span{na}.subspan(message_offset);
        if (nb::icmpv6_checksum(ns->target_ip, ns->source_ip, message) != 0) {
            std::abort();
        }
    }
}

auto fuzz_switch(std::span<const std::byte> in) -> void {
    net::MappingTable table{vtep(self_tail)};
    const auto entry = [](std::size_t i, std::uint8_t tail) {
        return net::MapEntry{.nic_id = geneve::NicId{nic_ids.at(i)},
                             .mac = mac(i),
                             .owner_vtep = vtep(tail),
                             .subnet_id = subnet_id_base + nic_subnets.at(i)};
    };
    if (!table.apply({.vni = vpc_one,
                      .version = 1,
                      .entries = {entry(0, self_tail), entry(1, self_tail),
                                  entry(remote_index, peer_tail), entry(e_index, peer_tail)}}) ||
        !table.apply({.vni = vpc_two, .version = 1, .entries = {entry(3, self_tail)}})) {
        std::abort();
    }
    Recorder underlay;
    net::VSwitch::Clock::time_point now{};
    net::VSwitch sw{table, underlay, [&now] { return now; }};
    // vpc_one opts in to multicast (one remote VTEP, cap 1); vpc_two keeps
    // the default drop policy.
    if (!sw.set_group_policy(vpc_one, {.mode = net::GroupMode::multicast,
                                       .rate_frames = 2,
                                       .burst_frames = 3,
                                       .rate_bytes = 512,
                                       .burst_bytes = 1024,
                                       .max_remote_vteps = 1,
                                       .max_groups_per_nic = 2})) {
        std::abort();
    }
    std::array<Port, nic_count> ports{};
    for (std::size_t i = 0; i < nic_count; ++i) {
        if (i != remote_index && i != e_index &&
            !sw.attach(geneve::NicId{nic_ids.at(i)}, ports.at(i),
                       static_cast<std::uint16_t>(1500))) {
            std::abort();
        }
    }
    const geneve::NicId nic_b{nic_ids[b_index]};
    const geneve::NicId nic_c{nic_ids[remote_index]};
    const geneve::NicId nic_e{nic_ids[e_index]};
    if (!sw.set_neighbors({.vni = vpc_one,
                           .ipv4 = {{ip4_of(b_index), nic_b},
                                    {ip4_of(remote_index), nic_c},
                                    {ip4_of(e_index), nic_e}},
                           .ipv6 = {{ip6_of(b_index), nic_b},
                                    {ip6_of(remote_index), nic_c},
                                    {ip6_of(e_index), nic_e}}})) {
        std::abort();
    }
    // vpc_one has a gateway (DHCP, gateway ARP/ND); vpc_two has none. The
    // gateway's own address is nobody's, so a reply leaking to another NIC
    // or the underlay fails forwarded_ok().
    net::Ipv6Address block6 = ip6_of(0);
    block6[ipv6_last] = std::byte{0};
    net::VpcConfig config{
        .gateway_mac = gateway_mac,
        .ipv4_blocks = {{.address = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}},
                         .length = 16}},
        .ipv6_block = block6,
        .subnets = {},
        .dns4 = {},
        .dns6 = {},
        .domain = "fuzz.internal",
        .lease_seconds = 60,
        .tables = {}};
    const auto route4 = [](std::uint8_t third, std::uint8_t length, std::size_t target) {
        return net::VpcRoute{.ipv6 = false,
                             .prefix = {std::byte{10}, std::byte{0}, std::byte{third}},
                             .length = length,
                             .target = geneve::NicId{nic_ids.at(target)}};
    };
    const net::VpcRoute local4{.ipv6 = false,
                               .prefix = {std::byte{10}},
                               .length = 16,
                               .target = geneve::nic_invalid,
                               .local = true};
    const net::VpcRoute local6{
        .ipv6 = true, .prefix = block6, .length = 56, .target = geneve::nic_invalid, .local = true};
    config.tables = {
        {.table = 1, .main = true, .routes = {local4, local6, route4(2, 25, e_index)}},
        {.table = 2, .main = false, .routes = {local4, local6, route4(1, 24, b_index)}}};
    for (std::uint8_t i = 0; i < subnet_count; ++i) {
        net::Ipv6Address prefix6 = block6;
        prefix6[7] = std::byte{i};
        config.subnets.push_back(
            {.id = subnet_id_base + i,
             .ipv4 = {.address = {std::byte{10}, std::byte{0}, std::byte{i}, std::byte{0}},
                      .length = 24},
             .gateway = {std::byte{10}, std::byte{0}, std::byte{i}, std::byte{254}},
             .ipv6_prefix = prefix6,
             .table = static_cast<std::uint16_t>(i == 2 ? 2 : 1)});
    }
    if (!sw.set_vpc_config(vpc_one, config)) {
        std::abort();
    }

    Endpoint endpoint;
    sw.set_metadata_endpoint(&endpoint);

    bool transmit = true;
    while (in.size() >= 2) {
        const std::size_t src = std::to_integer<std::size_t>(in[0]) % nic_count;
        now += std::chrono::milliseconds{std::to_integer<int>(in[0]) >> 3};
        const std::size_t len = std::min(std::to_integer<std::size_t>(in[1]), in.size() - 2);
        const auto bytes = in.subspan(2, len);
        in = in.subspan(2 + len);

        std::array<std::size_t, nic_count> before{};
        for (std::size_t i = 0; i < nic_count; ++i) {
            before.at(i) = ports.at(i).frames;
        }
        underlay.sent.clear();
        endpoint.calls.clear();

        std::uint32_t vni = 0;
        if (transmit) {
            vni = nic_vnis.at(src);
            sw.transmit({.source = geneve::NicId{nic_ids.at(src)}, .frame = bytes});
            const auto original = pk::parse(bytes);
            const pk::ParsedPacket* const sent_ip = original ? &*original : nullptr;
            for (const auto& s : underlay.sent) {
                if (src == dead_index || s.vni != vni || s.nics.src.value != nic_ids.at(src) ||
                    !forwarded_ok(s.frame, src)) {
                    std::abort();
                }
                // Unicast reaches only the sender's subnet; replicas go only
                // to the peer VTEP, which hosts a NIC of B and of C.
                const std::size_t dst = index_of(s.nics.dst);
                if (s.nics.dst == geneve::nic_broadcast
                        ? (vni == vpc_one && nic_subnets.at(src) == 0) || from_gateway(s.frame)
                        : dst >= nic_count || !reach_ok(src, dst, s.frame, sent_ip)) {
                    std::abort();
                }
            }
            for (std::size_t i = 0; i < nic_count; ++i) {
                if (i != src && ports.at(i).frames != before.at(i) &&
                    (!forwarded_ok(ports.at(i).last, src) ||
                     !reach_ok(src, i, ports.at(i).last, sent_ip))) {
                    std::abort();
                }
            }
            for (const auto& c : endpoint.calls) {
                const auto framed = pk::build_ethernet(net::MacAddress{}, net::MacAddress{}, c.ip);
                if (c.nic.value != nic_ids.at(src) || !forwarded_ok(framed, src)) {
                    std::abort();
                }
            }
            // A drop-policy VNI never replicates: the only delivery a group
            // frame there can cause is a proxy reply to the sender.
            const bool group = !bytes.empty() && (bytes[0] & std::byte{1}) == std::byte{1};
            if (group && vni == vpc_two) {
                for (std::size_t i = 0; i < nic_count; ++i) {
                    if (i != src && ports.at(i).frames != before.at(i)) {
                        std::abort();
                    }
                }
                if (!underlay.sent.empty()) {
                    std::abort();
                }
            }
        } else {
            const auto pkt = geneve::decode(bytes);
            if (pkt) {
                vni = pkt->vni;
                static_cast<void>(sw.receive(*pkt, vtep(src % 2 == 0 ? peer_tail : self_tail)));
                const std::size_t sender = pkt->nics ? index_of(pkt->nics->src) : nic_count;
                for (std::size_t i = 0; i < nic_count; ++i) {
                    if (ports.at(i).frames != before.at(i) &&
                        (!forwarded_ok(ports.at(i).last, sender) ||
                         !reach_ok(sender, i, ports.at(i).last, nullptr))) {
                        std::abort();
                    }
                }
            }
            if (!underlay.sent.empty()) {
                std::abort();  // received traffic is never re-sent
            }
        }
        for (std::size_t i = 0; i < nic_count; ++i) {
            const bool got = ports.at(i).frames != before.at(i);
            if (got && (i == dead_index || nic_vnis.at(i) != vni)) {
                std::abort();
            }
        }
        if (!transmit && !endpoint.calls.empty()) {
            std::abort();  // received traffic never reaches the endpoint
        }
        transmit = !transmit;
        sw.poll();  // periodic RAs, outside the per-record delivery checks
    }

    // Meters are consistent: one remote VTEP, so at most one remote replica
    // per accepted frame, and replica bytes follow frame bytes.
    for (const auto& u : sw.group_usage()) {
        const auto& m = u.meter;
        if (m.replicas_remote > m.frames || m.replica_bytes_remote > m.bytes ||
            m.replicas_local > m.frames || m.replica_bytes_local > m.bytes ||
            (u.nic.value == nic_ids[3] && m.frames != 0)) {
            std::abort();
        }
    }
    // Snooped joins: only from vpc_one (vpc_two never opted in), at most
    // the policy's two per NIC, and only replicable groups.
    std::array<std::size_t, nic_count> joins{};
    for (const auto& j : sw.memberships()) {
        const std::size_t i = index_of(j.nic);
        if (i >= nic_count || j.vni != vpc_one || ++joins.at(i) > 2 ||
            !net::igmp::replicable(j.group)) {
            std::abort();
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::span<const std::byte> in{reinterpret_cast<const std::byte*>(data), size};
    if ((data[0] & 1U) == 0) {
        fuzz_parsers(in.subspan(1));
    } else {
        fuzz_switch(in.subspan(1));
    }
    return 0;
}
