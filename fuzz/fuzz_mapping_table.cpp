// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes MappingTable::apply with a stream of map_updates drawn from small
// VNI, NIC, MAC and VTEP spaces (so collisions are common), and checks after
// every call that a rejected update changed nothing and an accepted one is
// exactly what the table now holds.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/mapping_table.hpp"

namespace {

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;

// Per update: vni, version, entry count; per entry: nic, mac, vtep.
constexpr std::size_t header_bytes = 3;
constexpr std::size_t entry_bytes = 3;
constexpr std::uint8_t vni_space = 4;  // 0..3: 0 is invalid
constexpr std::uint8_t entry_limit = 8;
constexpr std::uint8_t vtep_space = 3;  // 0 is invalid, 1 is this VTEP
constexpr std::uint8_t nic_space = 16;  // 0 is invalid, 15 maps to broadcast
constexpr std::uint8_t version_space = 8;
constexpr std::size_t mac_last = 5;
constexpr std::size_t ipv6_last = 15;
constexpr std::byte ula_prefix{0xfd};

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    if (tail != 0) {
        a[0] = ula_prefix;
        a[ipv6_last] = std::byte{tail};
    }
    return a;
}

auto check(bool ok) -> void {
    if (!ok) {
        std::abort();
    }
}

auto check_consistent(const net::MappingSnapshot& snap) -> void {
    std::size_t total = 0;
    for (std::uint32_t vni = 1; vni < vni_space; ++vni) {
        for (const net::MapEntry& e : snap.entries(vni)) {
            ++total;
            const auto b = snap.lookup(e.nic_id);
            check(b && b->vni == vni && b->mac == e.mac && b->owner_vtep == e.owner_vtep);
            check(snap.find_by_mac(vni, e.mac) == e.nic_id);
            check(snap.is_local(e.nic_id) == (e.owner_vtep == snap.local_vtep()));
        }
    }
    check(total == snap.nic_count());
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::span<const std::uint8_t> in{data, size};
    net::MappingTable table(vtep(1));

    while (in.size() >= header_bytes) {
        net::MapUpdate u;
        u.vni = in[0] % vni_space;
        u.version = in[1] % version_space;
        const std::size_t count = in[2] % entry_limit;
        in = in.subspan(header_bytes);
        for (std::size_t i = 0; i < count && in.size() >= entry_bytes; ++i) {
            net::MapEntry e;
            const std::uint8_t nic = in[0] % nic_space;
            e.nic_id = nic == nic_space - 1 ? geneve::nic_broadcast : geneve::NicId{nic};
            e.mac[0] = std::byte{in[1]};  // low bit set makes it a group address
            e.mac[mac_last] = std::byte{in[1]};
            e.owner_vtep = vtep(in[2] % vtep_space);
            u.entries.push_back(e);
            in = in.subspan(entry_bytes);
        }

        const auto before = table.snapshot();
        const auto got = table.apply(u);
        const auto after = table.snapshot();
        if (!got) {
            check(after == before);
        } else {
            check(*got == u.version && after->version(u.vni) == u.version);
            check(after->version(u.vni) > before->version(u.vni));
            const auto list = after->entries(u.vni);
            check(list.size() == u.entries.size());
            for (std::size_t i = 0; i < list.size(); ++i) {
                check(list[i] == u.entries[i]);
            }
        }
        check_consistent(*after);
    }
    return 0;
}
