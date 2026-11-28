// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 6: the hardware identity
// helm reports. What goes into the report (helm's own identity, each
// slot's board and a storage slot's drives, hull's host facts once
// reported), reporting only on change, the baseline kept in the sealed
// store and compared after a restart, a baseline taken only once every
// slot has answered, and a rolled-back store losing the baseline.

#define BOOST_TEST_MODULE hardware_identity_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/sha.h>

#include "helm/flash.hpp"
#include "helm/hardware_identity.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/report.hpp"

namespace {

namespace helm = ak::helm;
namespace oar = ak::helm::oar;
namespace proto = ak::proto;

constexpr std::uint64_t flash_size = std::uint64_t{1} << 20;
constexpr std::uint64_t server = 7;
constexpr std::uint64_t drive_bytes = std::uint64_t{4} << 40;

auto ephemeral_anchor() -> std::unique_ptr<helm::SoftwareStoreAnchor> {
    auto a = helm::SoftwareStoreAnchor::ephemeral();
    BOOST_REQUIRE(a.has_value());
    return std::move(*a);
}

auto open_store(helm::Flash& f, helm::StoreAnchor& a) -> helm::SealedStore {
    auto s = helm::SealedStore::open(f, a);
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto helm_identity() -> helm::HelmIdentity {
    helm::HelmIdentity h;
    h.ek_hash.fill(std::byte{0x11});
    h.board_serial = proto::identity_text("HELM-1");
    h.firmware = proto::identity_text("helm 1.0");
    return h;
}

auto board(std::string_view serial, std::vector<oar::RoleDrive> drives = {}) -> oar::RoleIdentity {
    return {.serial = proto::identity_text(serial),
            .firmware = proto::identity_text("fw 2"),
            .drives = std::move(drives)};
}

auto drive(std::string_view serial) -> oar::RoleDrive {
    return {.serial = proto::identity_text(serial), .size_bytes = drive_bytes};
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_report_carries_helm_slots_and_storage_drives) {
    helm::HardwareIdentityTracker t{server, helm_identity(), nullptr};
    t.set_slot(2, oar::Role::hold, board("STOR-2", {drive("D-A"), drive("D-B")}));
    t.set_slot(0, oar::Role::net, board("NET-0", {drive("ignored")}));

    const auto id = t.current();
    BOOST_TEST((id.ek_hash == helm_identity().ek_hash));
    BOOST_TEST(proto::identity_text_view(id.board_serial) == "HELM-1");
    BOOST_TEST(id.flags == 0);  // hull has not reported the host
    BOOST_REQUIRE(id.slots.size() == 2U);
    BOOST_TEST(id.slots[0].slot == 0);
    BOOST_TEST((id.slots[0].kind == proto::SlotKind::network));
    BOOST_TEST(id.slots[1].slot == 2);
    BOOST_TEST((id.slots[1].kind == proto::SlotKind::storage));
    // Only a storage slot lists drives.
    BOOST_REQUIRE(id.drives.size() == 2U);
    BOOST_TEST(id.drives[0].slot == 2);
    BOOST_TEST(proto::identity_text_view(id.drives[0].serial) == "D-A");
    BOOST_TEST(id.drives[1].size_bytes == drive_bytes);
    // It encodes: the report is well formed.
    BOOST_TEST(
        proto::encode_report({.server_id = server, .report_seq = 1, .body = id}).has_value());

    t.set_host({.secure_boot = true, .iommu = true, .memory_bytes = 1U << 30, .cpu_count = 8});
    const auto with_host = t.current();
    BOOST_TEST(with_host.flags == (proto::identity_host_reported | proto::identity_secure_boot |
                                   proto::identity_iommu));
    BOOST_TEST(with_host.cpu_count == 8U);
}

BOOST_AUTO_TEST_CASE(a_report_is_sent_first_and_then_only_on_change) {
    helm::HardwareIdentityTracker t{server, helm_identity(), nullptr};
    t.set_slot(1, oar::Role::blk, board("BLK-1"));
    const auto first = t.poll();
    BOOST_REQUIRE(first.has_value());
    BOOST_TEST(!first->changed);  // the first report is the baseline
    BOOST_TEST(t.baseline().has_value());
    BOOST_TEST(!t.poll().has_value());

    // The same answer again (a sideband that dropped and came back).
    t.set_slot(1, oar::Role::blk, board("BLK-1"));
    BOOST_TEST(!t.poll().has_value());

    t.set_slot(1, oar::Role::blk, board("BLK-9"));
    const auto swapped = t.poll();
    BOOST_REQUIRE(swapped.has_value());
    BOOST_TEST(swapped->changed);
    BOOST_TEST(proto::identity_text_view(swapped->report.slots[0].serial) == "BLK-9");

    // Put back: reported again, and no longer a change.
    t.set_slot(1, oar::Role::blk, board("BLK-1"));
    const auto back = t.poll();
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(!back->changed);
}

BOOST_AUTO_TEST_CASE(no_baseline_is_taken_until_every_slot_has_answered) {
    helm::HardwareIdentityTracker t{server, helm_identity(), nullptr};
    t.set_slot(0, oar::Role::net, board("NET-0"));
    const auto early = t.poll(false);
    BOOST_REQUIRE(early.has_value());  // reported all the same
    BOOST_TEST(!early->changed);
    BOOST_TEST(!t.baseline().has_value());

    t.set_slot(1, oar::Role::khold, board("STOR-1", {drive("D-1")}));
    const auto settled = t.poll(true);
    BOOST_REQUIRE(settled.has_value());
    BOOST_TEST(!settled->changed);  // the late slot is not new hardware
    BOOST_REQUIRE(t.baseline().has_value());
    BOOST_TEST(t.baseline()->slots.size() == 2U);
}

BOOST_AUTO_TEST_CASE(host_facts_complete_the_baseline_rather_than_change_it) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    const helm::HostIdentity host{
        .secure_boot = true, .iommu = true, .memory_bytes = 1U << 30, .cpu_count = 8};
    {
        auto store = open_store(flash, *anchor);
        helm::HardwareIdentityTracker t{server, helm_identity(), &store};
        t.load();
        t.set_slot(0, oar::Role::net, board("NET-0"));
        BOOST_REQUIRE(t.poll().has_value());
        t.set_host(host);
        const auto u = t.poll();
        BOOST_REQUIRE(u.has_value());
        BOOST_TEST(!u->changed);
        BOOST_TEST((t.baseline()->flags & proto::identity_host_reported) != 0);
    }
    // After helm restarts, hull has not reported yet: still no change.
    auto store = open_store(flash, *anchor);
    helm::HardwareIdentityTracker t{server, helm_identity(), &store};
    t.load();
    BOOST_REQUIRE(t.baseline().has_value());
    BOOST_TEST(t.baseline()->cpu_count == 8U);
    t.set_slot(0, oar::Role::net, board("NET-0"));
    const auto before_hull = t.poll();
    BOOST_REQUIRE(before_hull.has_value());
    BOOST_TEST(!before_hull->changed);
    // hull reports less memory than was enrolled: a change.
    t.set_host({.secure_boot = true, .iommu = true, .memory_bytes = 1U << 29, .cpu_count = 8});
    const auto less = t.poll();
    BOOST_REQUIRE(less.has_value());
    BOOST_TEST(less->changed);
}

BOOST_AUTO_TEST_CASE(the_baseline_survives_a_restart_and_catches_a_swap) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    {
        auto store = open_store(flash, *anchor);
        helm::HardwareIdentityTracker t{server, helm_identity(), &store};
        t.load();
        t.set_slot(3, oar::Role::hold, board("STOR-3", {drive("D-1")}));
        BOOST_REQUIRE(t.poll().has_value());
    }
    auto store = open_store(flash, *anchor);
    helm::HardwareIdentityTracker t{server, helm_identity(), &store};
    t.load();
    BOOST_REQUIRE(t.baseline().has_value());
    t.set_slot(3, oar::Role::hold, board("STOR-3", {drive("D-2")}));  // a drive swapped
    const auto u = t.poll();
    BOOST_REQUIRE(u.has_value());
    BOOST_TEST(u->changed);

    // Another server's baseline is not this one's.
    helm::HardwareIdentityTracker other{server + 1, helm_identity(), &store};
    other.load();
    BOOST_TEST(!other.baseline().has_value());
}

BOOST_AUTO_TEST_CASE(clearing_the_baseline_takes_the_next_report_as_it) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    helm::HardwareIdentityTracker t{server, helm_identity(), &store};
    t.load();
    t.set_slot(0, oar::Role::net, board("NET-0"));
    BOOST_REQUIRE(t.poll().has_value());
    t.clear_baseline();
    BOOST_TEST(!store.contains(helm::identity_baseline_object));
    t.set_slot(0, oar::Role::net, board("NET-7"));
    const auto u = t.poll();
    BOOST_REQUIRE(u.has_value());
    BOOST_TEST(!u->changed);
    BOOST_TEST(store.contains(helm::identity_baseline_object));
}

BOOST_AUTO_TEST_CASE(a_rolled_back_store_loses_the_baseline) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    std::vector<std::byte> old_copy;
    {
        auto store = open_store(flash, *anchor);
        helm::HardwareIdentityTracker t{server, helm_identity(), &store};
        t.load();
        t.set_slot(0, oar::Role::net, board("NET-0"));
        BOOST_REQUIRE(t.poll().has_value());
        old_copy = flash.bytes();
        BOOST_REQUIRE(store.put("other", std::vector<std::byte>{std::byte{1}}).has_value());
    }
    flash.bytes() = old_copy;
    auto store = open_store(flash, *anchor);
    BOOST_REQUIRE(store.rolled_back());
    helm::HardwareIdentityTracker t{server, helm_identity(), &store};
    t.load();
    BOOST_TEST(!t.baseline().has_value());
    BOOST_TEST(!store.contains(helm::identity_baseline_object));
}

BOOST_AUTO_TEST_CASE(the_key_hash_is_sha256) {
    const std::array<std::byte, 3> key{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    const auto h = helm::key_hash(key);
    BOOST_REQUIRE(h.has_value());
    std::array<unsigned char, SHA256_DIGEST_LENGTH> want{};
    SHA256(reinterpret_cast<const unsigned char*>(key.data()), key.size(), want.data());
    BOOST_TEST(std::memcmp(h->data(), want.data(), want.size()) == 0);
}
