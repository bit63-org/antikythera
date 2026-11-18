// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 2.5 and 8 (task 7).

#define BOOST_TEST_MODULE mapping_table_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstdint>
#include <thread>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/vtep_policy.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
using ak::test::unit_timeout_seconds;
using geneve::NicId;
using net::MapEntry;
using net::MapUpdate;
using net::MapUpdateError;

namespace {

constexpr std::uint32_t vpc = 100;
constexpr std::uint32_t other_vpc = 200;
constexpr std::uint32_t unseen_vpc = 300;

constexpr NicId nic_a{11};
constexpr NicId nic_b{22};
constexpr NicId nic_c{33};

constexpr std::uint8_t mac_a = 0x11;
constexpr std::uint8_t mac_b = 0x22;
constexpr std::uint8_t mac_c = 0x33;

constexpr std::uint8_t self_tail = 1;
constexpr std::uint8_t peer_tail = 2;

constexpr std::byte ula_prefix{0xfd};
constexpr std::byte locally_administered{0x02};
constexpr std::byte multicast{0x01};
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;

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

auto entry(NicId id, std::uint8_t mac_tail, std::uint8_t vtep_tail) -> MapEntry {
    return {.nic_id = id, .mac = mac(mac_tail), .owner_vtep = addr(vtep_tail)};
}

// vpc v1: a local, b remote.
auto first_update() -> MapUpdate {
    return {.vni = vpc,
            .version = 1,
            .entries = {entry(nic_a, mac_a, self_tail), entry(nic_b, mac_b, peer_tail)}};
}

auto expect_rejected(net::MappingTable& table, const MapUpdate& update, MapUpdateError want)
    -> void {
    const auto before = table.snapshot();
    const auto got = table.apply(update);
    BOOST_REQUIRE(!got.has_value());
    BOOST_TEST(net::to_string(got.error()) == net::to_string(want));
    // Rejected whole: the published snapshot is the same object as before.
    BOOST_TEST(table.snapshot() == before);
}

}  // namespace

BOOST_AUTO_TEST_CASE(empty_table_knows_nothing, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const net::MappingTable table(addr(self_tail));
    const auto snap = table.snapshot();
    BOOST_REQUIRE(snap != nullptr);
    BOOST_TEST(!table.lookup(nic_a).has_value());
    BOOST_TEST(!table.is_local(nic_a));
    BOOST_TEST(snap->version(vpc) == 0U);
    BOOST_TEST(snap->vni_count() == 0U);
    BOOST_TEST(snap->nic_count() == 0U);
    BOOST_TEST(snap->entries(vpc).empty());
}

BOOST_AUTO_TEST_CASE(apply_publishes_bindings, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    const auto applied = table.apply(first_update());
    BOOST_REQUIRE(applied.has_value());
    BOOST_TEST(*applied == 1U);

    const auto a = table.lookup(nic_a);
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST(a->vni == vpc);
    BOOST_TEST((a->mac == mac(mac_a)));
    BOOST_TEST((a->owner_vtep == addr(self_tail)));
    BOOST_TEST(table.is_local(nic_a));
    BOOST_TEST(!table.is_local(nic_b));
    BOOST_TEST(table.lookup(nic_b).has_value());

    const auto snap = table.snapshot();
    BOOST_TEST(snap->version(vpc) == 1U);
    BOOST_TEST(snap->vni_count() == 1U);
    BOOST_TEST(snap->nic_count() == 2U);
    BOOST_TEST(snap->entries(vpc).size() == 2U);
    BOOST_TEST((snap->find_by_mac(vpc, mac(mac_b)) == nic_b));
    BOOST_TEST(!snap->find_by_mac(other_vpc, mac(mac_b)).has_value());
    BOOST_TEST(!snap->find_by_mac(vpc, mac(mac_c)).has_value());
}

BOOST_AUTO_TEST_CASE(update_replaces_whole_vni, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    BOOST_REQUIRE(table.apply(first_update()).has_value());
    const auto old = table.snapshot();

    // v2 drops b and adds c; a moves to the peer VTEP.
    const MapUpdate v2{.vni = vpc,
                       .version = 2,
                       .entries = {entry(nic_a, mac_a, peer_tail), entry(nic_c, mac_c, self_tail)}};
    BOOST_REQUIRE(table.apply(v2).has_value());

    BOOST_TEST(!table.lookup(nic_b).has_value());
    BOOST_TEST(table.is_local(nic_c));
    BOOST_TEST(!table.is_local(nic_a));
    BOOST_TEST(table.snapshot()->version(vpc) == 2U);

    // A snapshot taken before the update is immutable.
    BOOST_TEST(old->lookup(nic_b).has_value());
    BOOST_TEST(old->is_local(nic_a));
    BOOST_TEST(!old->lookup(nic_c).has_value());
    BOOST_TEST(old->version(vpc) == 1U);
}

BOOST_AUTO_TEST_CASE(vnis_are_independent, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    BOOST_REQUIRE(table.apply(first_update()).has_value());
    // A different VNI may start at any version, and may reuse a MAC.
    const MapUpdate other{
        .vni = other_vpc, .version = 1, .entries = {entry(nic_c, mac_a, peer_tail)}};
    BOOST_REQUIRE(table.apply(other).has_value());

    const auto snap = table.snapshot();
    BOOST_TEST(snap->vni_count() == 2U);
    BOOST_TEST(snap->nic_count() == 3U);
    BOOST_TEST((snap->find_by_mac(vpc, mac(mac_a)) == nic_a));
    BOOST_TEST((snap->find_by_mac(other_vpc, mac(mac_a)) == nic_c));
    BOOST_TEST(snap->lookup(nic_c)->vni == other_vpc);
    BOOST_TEST(snap->version(unseen_vpc) == 0U);
}

BOOST_AUTO_TEST_CASE(empty_update_removes_vni_but_keeps_version,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    BOOST_REQUIRE(table.apply(first_update()).has_value());
    BOOST_REQUIRE(table.apply({.vni = vpc, .version = 2, .entries = {}}).has_value());

    auto snap = table.snapshot();
    BOOST_TEST(!snap->lookup(nic_a).has_value());
    BOOST_TEST(snap->vni_count() == 0U);
    BOOST_TEST(snap->nic_count() == 0U);
    BOOST_TEST(snap->version(vpc) == 2U);

    // Replaying v1 after the removal is refused.
    expect_rejected(table, first_update(), MapUpdateError::stale_version);

    // A NIC of a removed VNI no longer blocks a mapping in another VNI.
    BOOST_REQUIRE(
        table.apply({.vni = other_vpc, .version = 1, .entries = {entry(nic_a, mac_a, self_tail)}})
            .has_value());
    snap = table.snapshot();
    BOOST_TEST(snap->lookup(nic_a)->vni == other_vpc);
}

BOOST_AUTO_TEST_CASE(stale_and_replayed_versions_rejected,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    expect_rejected(table, {.vni = vpc, .version = 0, .entries = {}},
                    MapUpdateError::stale_version);
    BOOST_REQUIRE(table.apply(first_update()).has_value());
    expect_rejected(table, first_update(), MapUpdateError::stale_version);
    // Versions may skip (the controller may coalesce), but never go back.
    auto v5 = first_update();
    v5.version = 5;
    BOOST_REQUIRE(table.apply(v5).has_value());
    auto v4 = first_update();
    v4.version = 4;
    expect_rejected(table, v4, MapUpdateError::stale_version);
}

BOOST_AUTO_TEST_CASE(bad_vni_rejected, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    auto u = first_update();
    u.vni = 0;
    expect_rejected(table, u, MapUpdateError::vni_out_of_range);
    u.vni = geneve::vni_max + 1;
    expect_rejected(table, u, MapUpdateError::vni_out_of_range);
    u.vni = geneve::vni_max;
    BOOST_TEST(table.apply(u).has_value());
}

BOOST_AUTO_TEST_CASE(bad_entries_rejected_whole, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    BOOST_REQUIRE(table.apply(first_update()).has_value());

    // Each bad update also carries a good new entry (c), which must not
    // appear: the update is all or nothing.
    auto with_c = [](MapEntry bad) {
        return MapUpdate{
            .vni = vpc, .version = 2, .entries = {entry(nic_c, mac_c, self_tail), bad}};
    };

    expect_rejected(table, with_c(entry(geneve::nic_invalid, mac_a, self_tail)),
                    MapUpdateError::invalid_nic_id);
    expect_rejected(table, with_c(entry(geneve::nic_broadcast, mac_a, self_tail)),
                    MapUpdateError::invalid_nic_id);
    expect_rejected(table, with_c(entry(nic_c, mac_a, self_tail)),
                    MapUpdateError::duplicate_nic_id);
    expect_rejected(table, with_c(entry(nic_a, mac_c, self_tail)), MapUpdateError::duplicate_mac);

    MapEntry zero_mac = entry(nic_a, mac_a, self_tail);
    zero_mac.mac = {};
    expect_rejected(table, with_c(zero_mac), MapUpdateError::invalid_mac);
    MapEntry group_mac = entry(nic_a, mac_a, self_tail);
    group_mac.mac[0] |= multicast;
    expect_rejected(table, with_c(group_mac), MapUpdateError::invalid_mac);

    MapEntry zero_vtep = entry(nic_a, mac_a, self_tail);
    zero_vtep.owner_vtep = {};
    expect_rejected(table, with_c(zero_vtep), MapUpdateError::invalid_vtep);

    BOOST_TEST(!table.lookup(nic_c).has_value());
    BOOST_TEST(table.snapshot()->version(vpc) == 1U);
}

BOOST_AUTO_TEST_CASE(nic_cannot_be_in_two_vnis, *boost::unit_test::timeout(unit_timeout_seconds)) {
    net::MappingTable table(addr(self_tail));
    BOOST_REQUIRE(table.apply(first_update()).has_value());
    expect_rejected(table,
                    {.vni = other_vpc, .version = 1, .entries = {entry(nic_b, mac_b, peer_tail)}},
                    MapUpdateError::nic_in_other_vni);
    BOOST_TEST(table.snapshot()->version(other_vpc) == 0U);
}

BOOST_AUTO_TEST_CASE(drives_ingress_policy, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // The table is a MappingView: a packet from remote b to local a passes,
    // and fails once v2 removes b.
    constexpr std::size_t frame_size = 64;
    constexpr std::size_t src_mac_offset = 6;
    net::MappingTable table(addr(self_tail));
    BOOST_REQUIRE(table.apply(first_update()).has_value());

    std::vector<std::byte> frame(frame_size);
    const auto dst = mac(mac_a);
    const auto src = mac(mac_b);
    std::ranges::copy(dst, frame.begin());
    std::ranges::copy(src, frame.begin() + src_mac_offset);
    const geneve::Packet pkt{.vni = vpc, .nics = geneve::NicPair{nic_b, nic_a}, .inner = frame};

    const auto ok = net::check_ingress(pkt, addr(peer_tail), *table.snapshot());
    BOOST_REQUIRE(ok.has_value());
    BOOST_TEST((*ok == nic_a));

    BOOST_REQUIRE(
        table.apply({.vni = vpc, .version = 2, .entries = {entry(nic_a, mac_a, self_tail)}})
            .has_value());
    const auto gone = net::check_ingress(pkt, addr(peer_tail), table);
    BOOST_REQUIRE(!gone.has_value());
    BOOST_TEST(net::to_string(gone.error()) == net::to_string(net::PolicyError::unknown_src));
}

BOOST_AUTO_TEST_CASE(readers_see_whole_snapshots,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Each version maps exactly `version` NICs, all with that version's
    // VTEP tail; a reader must never see a mix.
    constexpr std::uint64_t versions = 200;
    constexpr unsigned readers = 4;
    net::MappingTable table(addr(self_tail));
    std::atomic<bool> done{false};
    std::atomic<bool> torn{false};

    std::vector<std::jthread> pool;
    pool.reserve(readers);
    for (unsigned r = 0; r < readers; ++r) {
        pool.emplace_back([&] {
            while (!done.load(std::memory_order_acquire)) {
                const auto snap = table.snapshot();
                const auto v = snap->version(vpc);
                const auto list = snap->entries(vpc);
                if (list.size() != v || snap->nic_count() != v) {
                    torn.store(true);
                }
                for (const MapEntry& e : list) {
                    const auto tail = static_cast<std::uint8_t>(v);
                    if (e.owner_vtep != addr(tail) || !snap->lookup(e.nic_id)) {
                        torn.store(true);
                    }
                }
            }
        });
    }

    for (std::uint64_t v = 1; v <= versions; ++v) {
        MapUpdate u{.vni = vpc, .version = v, .entries = {}};
        for (std::uint64_t i = 1; i <= v; ++i) {
            net::MacAddress m = mac(0);
            m[mac_last - 1] = static_cast<std::byte>(i >> CHAR_BIT);
            m[mac_last] = static_cast<std::byte>(i);
            u.entries.push_back(
                {.nic_id = NicId{i}, .mac = m, .owner_vtep = addr(static_cast<std::uint8_t>(v))});
        }
        BOOST_REQUIRE(table.apply(u).has_value());
    }
    done.store(true, std::memory_order_release);
    pool.clear();
    BOOST_TEST(!torn.load());
}
