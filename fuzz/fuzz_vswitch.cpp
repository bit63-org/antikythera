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
//         ARP is ever forwarded.

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
constexpr std::size_t nic_count = 5;  // a, b local + c remote in one; x local in two; dead
constexpr std::array<std::uint64_t, nic_count> nic_ids{1, 2, 3, 4, 5};
constexpr std::array<std::uint32_t, nic_count> nic_vnis{vpc_one, vpc_one, vpc_one, vpc_two, 0};
constexpr std::size_t remote_index = 2;
constexpr std::size_t dead_index = 4;
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

// Guest addresses: b (local) and c (remote) in vpc_one own one of each family.
auto ip4_of(std::size_t index) -> nb::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{0}, static_cast<std::byte>(index + 1)};
}

auto ip6_of(std::size_t index) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[1] = std::byte{1};
    a[ipv6_last] = static_cast<std::byte>(index + 1);
    return a;
}

constexpr std::size_t b_index = 1;

auto owns_addresses(std::size_t index) -> bool {
    return index == b_index || index == remote_index;
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
        return net::MapEntry{
            .nic_id = geneve::NicId{nic_ids.at(i)}, .mac = mac(i), .owner_vtep = vtep(tail)};
    };
    if (!table.apply({.vni = vpc_one,
                      .version = 1,
                      .entries = {entry(0, self_tail), entry(1, self_tail),
                                  entry(remote_index, peer_tail)}}) ||
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
                                       .max_remote_vteps = 1})) {
        std::abort();
    }
    std::array<Port, nic_count> ports{};
    for (std::size_t i = 0; i < nic_count; ++i) {
        if (i != remote_index && !sw.attach(geneve::NicId{nic_ids.at(i)}, ports.at(i))) {
            std::abort();
        }
    }
    const geneve::NicId nic_b{nic_ids[b_index]};
    const geneve::NicId nic_c{nic_ids[remote_index]};
    if (!sw.set_neighbors({.vni = vpc_one,
                           .ipv4 = {{ip4_of(b_index), nic_b}, {ip4_of(remote_index), nic_c}},
                           .ipv6 = {{ip6_of(b_index), nic_b}, {ip6_of(remote_index), nic_c}}})) {
        std::abort();
    }

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

        std::uint32_t vni = 0;
        if (transmit) {
            vni = nic_vnis.at(src);
            sw.transmit({.source = geneve::NicId{nic_ids.at(src)}, .frame = bytes});
            for (const auto& s : underlay.sent) {
                if (src == dead_index || s.vni != vni || s.nics.src.value != nic_ids.at(src) ||
                    !forwarded_ok(s.frame, src)) {
                    std::abort();
                }
            }
            for (std::size_t i = 0; i < nic_count; ++i) {
                if (i != src && ports.at(i).frames != before.at(i) &&
                    !forwarded_ok(ports.at(i).last, src)) {
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
                        !forwarded_ok(ports.at(i).last, sender)) {
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
        transmit = !transmit;
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
