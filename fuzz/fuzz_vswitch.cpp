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

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/vswitch.hpp"

namespace {

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
namespace nb = ak::oar::net::neighbor;

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
    auto deliver(std::span<const std::byte> /*frame*/) -> net::RxResult override {
        ++frames;
        return net::RxResult::delivered;
    }
    std::size_t frames{0};
};

class Recorder final : public net::Underlay {
public:
    auto send(const net::RemoteFrame& f) -> void override { sent.push_back({f.vni, f.nics}); }
    struct Sent {
        std::uint32_t vni;
        geneve::NicPair nics;
    };
    std::vector<Sent> sent;
};

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
    net::VSwitch sw{table, underlay};
    std::array<Port, nic_count> ports{};
    for (std::size_t i = 0; i < nic_count; ++i) {
        if (i != remote_index && !sw.attach(geneve::NicId{nic_ids.at(i)}, ports.at(i))) {
            std::abort();
        }
    }
    const nb::Ipv4Address ip_b{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{2}};
    net::Ipv6Address ip6_b = vtep(peer_tail);
    ip6_b[1] = std::byte{1};
    if (!sw.set_neighbors({.vni = vpc_one,
                           .ipv4 = {{ip_b, geneve::NicId{nic_ids[1]}}},
                           .ipv6 = {{ip6_b, geneve::NicId{nic_ids[1]}}}})) {
        std::abort();
    }

    bool transmit = true;
    while (in.size() >= 2) {
        const std::size_t src = std::to_integer<std::size_t>(in[0]) % nic_count;
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
                if (src == dead_index || s.vni != vni || s.nics.src.value != nic_ids.at(src)) {
                    std::abort();
                }
            }
        } else {
            const auto pkt = geneve::decode(bytes);
            if (pkt) {
                vni = pkt->vni;
                static_cast<void>(sw.receive(*pkt, vtep(src % 2 == 0 ? peer_tail : self_tail)));
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
