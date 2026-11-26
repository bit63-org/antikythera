// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Router benchmark (vpc-subnets-routing task 8): frames per second through
// one VSwitch for switched versus routed traffic, in a VPC at the limits
// the controller may send: 200 subnets, 16 route tables holding 4,096
// routes between them (two local routes and 254 NIC routes each).
//
//   vswitch_bench [--frames N]
//
// Each case sends N copies of one 64-byte UDP frame from a local NIC and
// checks that every copy arrived where it should; the counts are the
// benchmark's own test, so ctest runs it with a small N. The figures in
// .kiro/specs/vpc-subnets-routing/design.md ("Router benchmark") come from
// a Release build with the default N.
//
//   switched      same subnet, local port to local port
//   switched-vtep same subnet, to a NIC on another VTEP (Underlay::send)
//   routed        another subnet, local route, local port
//   routed-vtep   another subnet, local route, NIC on another VTEP
//   routed-nic    a NIC route (a /24 among the table's 254) to a local
//                 appliance with its source/destination check off
//   routed6       routed, IPv6

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <print>
#include <span>
#include <string_view>
#include <vector>

#include "net_frames.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/vswitch.hpp"

namespace {

namespace net = ak::oar::net;
namespace fr = ak::test::frames;
using net::geneve::NicId;

constexpr std::uint32_t vni = 100;
constexpr std::size_t subnet_count = 200;
constexpr std::size_t table_count = 16;
constexpr std::size_t nic_routes_per_table = 254;  // 16 * (2 + 254) = 4,096
constexpr std::uint64_t subnet_base = 0x5000;
constexpr std::uint64_t far_subnet = 199;
constexpr std::uint64_t remote_subnet = 100;
constexpr NicId nic_peer{1000};        // subnet 0, same subnet as NIC 1
constexpr NicId nic_remote{1001};      // subnet 0, on another VTEP
constexpr NicId nic_remote_far{1002};  // subnet 100, on another VTEP
constexpr NicId nic_appliance{1003};   // subnet 1, check off: NIC routes lead here
constexpr std::uint8_t peer_last = 20;
constexpr std::uint8_t remote_last = 30;
constexpr std::uint8_t appliance_last = 40;
constexpr std::uint8_t nic_last = 10;
constexpr std::uint16_t udp_port = 4000;
constexpr std::size_t payload_size = 18;  // 14 + 20 + 8 + 18 = 60 bytes, 64 with an FCS
constexpr std::size_t default_frames = 2'000'000;
constexpr std::size_t subnet_byte = 7;
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::uint8_t subnet_length = 24;
constexpr std::uint8_t block_length = 8;
constexpr std::uint8_t ula_length = 56;
constexpr std::uint32_t lease_seconds = 3600;

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto mac_of(NicId id) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = std::byte{0x02};
    m[mac_last - 1] = static_cast<std::byte>(id.value >> 8U);
    m[mac_last] = static_cast<std::byte>(id.value & 0xFFU);
    return m;
}

// NIC i + 1 is the local NIC of subnet i, at 10.i.0.10.
auto subnet_nic(std::size_t subnet) -> NicId {
    return NicId{subnet + 1};
}

auto ip4(std::size_t subnet, std::uint8_t last) -> net::neighbor::Ipv4Address {
    return {std::byte{10}, static_cast<std::byte>(subnet), std::byte{0}, std::byte{last}};
}

auto ula(std::size_t subnet) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[1] = std::byte{0x10};
    a[subnet_byte] = static_cast<std::byte>(subnet);
    return a;
}

auto ip6(std::size_t subnet, std::uint8_t last) -> net::Ipv6Address {
    auto a = ula(subnet);
    a[ipv6_last] = std::byte{last};
    return a;
}

class CountingPort final : public net::RxPort {
public:
    auto deliver(std::span<const std::byte> /*frame*/) -> net::RxResult override {
        ++frames;
        return net::RxResult::delivered;
    }
    std::size_t frames{0};
};

class CountingUnderlay final : public net::Underlay {
public:
    auto send(const net::RemoteFrame& f) -> void override {
        ++frames;
        last = f.nics.dst;
    }
    std::size_t frames{0};
    NicId last{};
};

auto vpc_config() -> net::VpcConfig {
    net::VpcConfig c{};
    c.gateway_mac = mac_of(NicId{0xFFFE});
    c.ipv4_blocks = {{.address = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}},
                      .length = block_length}};
    c.ipv6_block = ula(0);
    for (std::size_t s = 0; s < subnet_count; ++s) {
        c.subnets.push_back({.id = subnet_base + s,
                             .ipv4 = {.address = ip4(s, 0), .length = subnet_length},
                             .gateway = ip4(s, 1),
                             .ipv6_prefix = ula(s),
                             .table = static_cast<std::uint16_t>((s % table_count) + 1)});
    }
    for (std::size_t t = 0; t < table_count; ++t) {
        net::VpcRouteTable table{.table = static_cast<std::uint16_t>(t + 1), .main = t == 0};
        net::VpcRoute local4{.ipv6 = false,
                             .prefix = {},
                             .length = block_length,
                             .target = net::geneve::nic_invalid,
                             .local = true};
        local4.prefix[0] = std::byte{10};
        table.routes.push_back(local4);
        table.routes.push_back({.ipv6 = true,
                                .prefix = ula(0),
                                .length = ula_length,
                                .target = net::geneve::nic_invalid,
                                .local = true});
        // NIC routes outside the VPC, in 172.16.0.0/12, mixed lengths so
        // the trie is not one flat level: /24s, /20s and /28s.
        for (std::size_t r = 0; r < nic_routes_per_table; ++r) {
            net::VpcRoute nic{
                .ipv6 = false, .prefix = {}, .length = 0, .target = nic_appliance, .local = false};
            nic.prefix[0] = std::byte{172};
            nic.prefix[1] = static_cast<std::byte>(16 + (r % 16));
            nic.prefix[2] = static_cast<std::byte>(r);
            constexpr std::array<std::uint8_t, 3> lengths{24, 20, 28};
            nic.length = lengths.at(r % lengths.size());
            if (nic.length == 20) {
                nic.prefix[2] = static_cast<std::byte>(r & 0xF0U);
                nic.prefix[1] = static_cast<std::byte>(16 + ((r / 16) % 16));
            }
            if (nic.length == 28) {
                nic.prefix[3] = static_cast<std::byte>((r % 16) << 4U);
            }
            const bool twice = std::ranges::any_of(table.routes, [&](const net::VpcRoute& o) {
                return o.ipv6 == nic.ipv6 && o.length == nic.length && o.prefix == nic.prefix;
            });
            if (twice) {
                nic.prefix[1] = std::byte{31};  // 172.31.r.0, never otherwise used
                nic.length = 24;
                nic.prefix[3] = std::byte{0};
                nic.prefix[2] = static_cast<std::byte>(r);
            }
            table.routes.push_back(nic);
        }
        c.tables.push_back(std::move(table));
    }
    c.dns4 = {ip4(0, 2)};
    c.domain = "ec2.internal";
    c.lease_seconds = lease_seconds;
    return c;
}

auto udp4(const net::MacAddress& dst_mac, const net::MacAddress& src_mac,
          const net::neighbor::Ipv4Address& src, const net::neighbor::Ipv4Address& dst)
    -> std::vector<std::byte> {
    const std::vector<std::byte> payload(payload_size, std::byte{0x5A});
    return fr::ipv4(dst_mac, src_mac, src, dst, ak::oar::net::packet::ipproto_udp,
                    fr::udp(udp_port, udp_port, payload));
}

auto udp6(const net::MacAddress& dst_mac, const net::MacAddress& src_mac,
          const net::Ipv6Address& src, const net::Ipv6Address& dst) -> std::vector<std::byte> {
    const std::vector<std::byte> payload(payload_size, std::byte{0x5A});
    return fr::ipv6(dst_mac, src_mac, src, dst, ak::oar::net::packet::ipproto_udp,
                    fr::udp(udp_port, udp_port, payload));
}

struct Bench {
    Bench() {
        net::MapUpdate update{.vni = vni, .version = 1, .entries = {}};
        net::NeighborUpdate neighbors{.vni = vni};
        for (std::size_t s = 0; s < subnet_count; ++s) {
            update.entries.push_back({.nic_id = subnet_nic(s),
                                      .mac = mac_of(subnet_nic(s)),
                                      .owner_vtep = vtep(1),
                                      .subnet_id = subnet_base + s});
            neighbors.ipv4.push_back({ip4(s, nic_last), subnet_nic(s)});
            neighbors.ipv6.push_back({ip6(s, nic_last), subnet_nic(s)});
        }
        const auto add = [&](NicId id, std::size_t subnet, std::uint8_t last, std::uint8_t tail,
                             bool check) {
            update.entries.push_back({.nic_id = id,
                                      .mac = mac_of(id),
                                      .owner_vtep = vtep(tail),
                                      .source_dest_check = check,
                                      .subnet_id = subnet_base + subnet});
            neighbors.ipv4.push_back({ip4(subnet, last), id});
            neighbors.ipv6.push_back({ip6(subnet, last), id});
        };
        add(nic_peer, 0, peer_last, 1, true);
        add(nic_remote, 0, remote_last, 2, true);
        add(nic_remote_far, remote_subnet, remote_last, 2, true);
        add(nic_appliance, 1, appliance_last, 1, false);
        std::ranges::sort(neighbors.ipv4, {}, &net::Ipv4Neighbor::ip);
        std::ranges::sort(neighbors.ipv6, {}, &net::Ipv6Neighbor::ip);
        ok = table.apply(update).has_value() && sw.set_neighbors(neighbors).has_value() &&
             sw.set_vpc_config(vni, vpc_config()).has_value();
        for (std::size_t s = 0; s < subnet_count && ok; ++s) {
            ok = sw.attach(subnet_nic(s), ports.at(s)).has_value();
        }
        ok = ok && sw.attach(nic_peer, peer_port).has_value() &&
             sw.attach(nic_appliance, appliance_port).has_value();
    }

    net::MappingTable table{vtep(1)};
    CountingUnderlay underlay;
    net::VSwitch sw{table, underlay};
    std::array<CountingPort, subnet_count> ports;
    CountingPort peer_port;
    CountingPort appliance_port;
    bool ok{false};
};

struct Case {
    std::string_view name;
    std::vector<std::byte> frame;
    std::size_t* counter;
};

}  // namespace

auto main(int argc, char** argv) -> int {
    std::size_t frames = default_frames;
    if (argc == 3 && std::string_view{argv[1]} == "--frames") {
        frames = std::strtoull(argv[2], nullptr, 10);
    } else if (argc != 1) {
        std::println(stderr, "usage: vswitch_bench [--frames N]");
        return 2;
    }
    auto bench = std::make_unique<Bench>();
    if (!bench->ok) {
        std::println(stderr, "vswitch_bench: setup refused");
        return EXIT_FAILURE;
    }
    const auto gw = mac_of(NicId{0xFFFE});
    const auto src = subnet_nic(0);
    const auto src_mac = mac_of(src);
    std::size_t remote_far = 0;
    std::size_t remote_near = 0;
    std::array cases{
        Case{"switched", udp4(mac_of(nic_peer), src_mac, ip4(0, nic_last), ip4(0, peer_last)),
             &bench->peer_port.frames},
        Case{"switched-vtep",
             udp4(mac_of(nic_remote), src_mac, ip4(0, nic_last), ip4(0, remote_last)),
             &remote_near},
        Case{"routed", udp4(gw, src_mac, ip4(0, nic_last), ip4(far_subnet, nic_last)),
             &bench->ports.at(far_subnet).frames},
        Case{"routed-vtep", udp4(gw, src_mac, ip4(0, nic_last), ip4(remote_subnet, remote_last)),
             &remote_far},
        Case{"routed-nic",
             udp4(gw, src_mac, ip4(0, nic_last),
                  {std::byte{172}, std::byte{16}, std::byte{0}, std::byte{9}}),
             &bench->appliance_port.frames},
        Case{"routed6", udp6(gw, src_mac, ip6(0, nic_last), ip6(far_subnet, nic_last)),
             &bench->ports.at(far_subnet).frames},
    };
    std::println("{} subnets, {} tables, {} routes; {} frames of {} bytes per case", subnet_count,
                 table_count, table_count * (2 + nic_routes_per_table), frames,
                 cases[0].frame.size());
    bool all = true;
    for (Case& c : cases) {
        const std::size_t before = *c.counter;
        const std::size_t underlay_before = bench->underlay.frames;
        const auto start = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < frames; ++i) {
            bench->sw.transmit({.source = src, .frame = c.frame});
        }
        const std::chrono::duration<double> took = std::chrono::steady_clock::now() - start;
        const std::size_t sent = bench->underlay.frames - underlay_before;
        if (c.counter == &remote_near || c.counter == &remote_far) {
            const NicId want = c.counter == &remote_near ? nic_remote : nic_remote_far;
            *c.counter += bench->underlay.last == want ? sent : 0;
        }
        const std::size_t arrived = *c.counter - before;
        const double fps = static_cast<double>(frames) / took.count();
        std::println("{:<14} {:>12.0f} frames/s  {:>7.1f} ns/frame{}", c.name, fps, 1e9 / fps,
                     arrived == frames ? "" : "  MISDELIVERED");
        all = all && arrived == frames;
    }
    return all ? EXIT_SUCCESS : EXIT_FAILURE;
}
