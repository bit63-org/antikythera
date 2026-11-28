// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 3 (task 5): the local power-on
// policy. The keeper that verifies and stores the newest power_policy
// record, the wait it plans, and the marker that tells helm's own power
// loss from a helm restart.

#define BOOST_TEST_MODULE power_on_test
#include <boost/test/unit_test.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "helm/flash.hpp"
#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/power_policy.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::HostPowerOverride;
using helm::PolicyVerdict;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t server = 42;
constexpr std::uint64_t flash_size = 64 * 1024;
constexpr std::byte good_sig{0x01};

// Accepts a signature whose first byte is 0x01, under key 1 only.
struct FakeVerifier final : helm::RecordVerifier {
    mutable std::size_t calls{0};
    [[nodiscard]] auto verify(std::span<const std::byte> message,
                              std::span<const std::byte, proto::ed25519_signature_size> sig,
                              std::uint16_t key_id) const -> bool override {
        ++calls;
        return message.size() == proto::power_policy_signed_size && key_id == 1 &&
               sig[0] == good_sig;
    }
};

struct Policy {
    proto::PowerPolicy policy;
    std::vector<std::byte> frame;
};

auto make_policy(std::uint64_t version, std::uint8_t tier = 1, std::uint16_t slot = 4,
                 std::byte sig = good_sig, std::uint64_t server_id = server) -> Policy {
    proto::PowerPolicy p = proto::default_power_policy(server_id);
    p.key_id = 1;
    p.policy_version = version;
    p.tier = tier;
    p.slot = slot;
    p.tier_delay_s = 60;
    p.slot_interval_ms = 5000;
    p.max_jitter_ms = 2000;
    p.signature.fill(sig);
    auto bytes = proto::encode_power_policy(p);
    BOOST_REQUIRE(bytes.has_value());
    return {.policy = p, .frame = *bytes};
}

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

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-power-on-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(keeper, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(defaults_with_no_policy) {
    FakeVerifier v;
    helm::PowerPolicyKeeper k{server, nullptr, &v};
    BOOST_TEST((k.load() == PolicyVerdict::none));
    BOOST_TEST(!k.from_record());
    BOOST_TEST((k.current() == proto::default_power_policy(server)));
    BOOST_TEST(k.current().tier == 3U);
    BOOST_TEST(k.current().slot == 0U);
}

BOOST_AUTO_TEST_CASE(keeps_only_verified_newer_policies_for_this_server) {
    FakeVerifier v;
    helm::PowerPolicyKeeper k{server, nullptr, &v};
    const auto p2 = make_policy(2);
    BOOST_TEST((k.offer(p2.policy, p2.frame) == PolicyVerdict::kept));
    BOOST_TEST(k.from_record());
    BOOST_TEST(k.current().policy_version == 2U);

    const auto p1 = make_policy(1, 0);
    BOOST_TEST((k.offer(p1.policy, p1.frame) == PolicyVerdict::stale));
    BOOST_TEST((k.offer(p2.policy, p2.frame) == PolicyVerdict::stale));
    const auto forged = make_policy(3, 0, 0, std::byte{0});
    BOOST_TEST((k.offer(forged.policy, forged.frame) == PolicyVerdict::bad_signature));
    const auto other = make_policy(4, 0, 0, good_sig, server + 1);
    BOOST_TEST((k.offer(other.policy, other.frame) == PolicyVerdict::wrong_server));
    // The frame must be the record's exact encoding.
    const auto p5 = make_policy(5);
    BOOST_TEST(
        (k.offer(p5.policy, std::span{p5.frame}.first(0x50)) == PolicyVerdict::bad_signature));
    BOOST_TEST(k.current().policy_version == 2U);
    BOOST_TEST((k.offer(p5.policy, p5.frame) == PolicyVerdict::kept));
    BOOST_TEST(k.current().policy_version == 5U);
}

BOOST_AUTO_TEST_CASE(without_a_verifier_every_record_is_refused) {
    helm::PowerPolicyKeeper k{server, nullptr, nullptr};
    const auto p = make_policy(1);
    BOOST_TEST((k.offer(p.policy, p.frame) == PolicyVerdict::bad_signature));
    BOOST_TEST(!k.from_record());
}

BOOST_AUTO_TEST_CASE(the_newest_policy_survives_power_loss) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    FakeVerifier v;
    {
        auto store = open_store(flash, *anchor);
        helm::PowerPolicyKeeper k{server, &store, &v};
        BOOST_TEST((k.load() == PolicyVerdict::none));
        const auto p = make_policy(7, 0, 9);
        BOOST_TEST((k.offer(p.policy, p.frame) == PolicyVerdict::kept));
    }
    auto store = open_store(flash, *anchor);
    helm::PowerPolicyKeeper k{server, &store, &v};
    BOOST_TEST((k.load() == PolicyVerdict::kept));
    BOOST_TEST(k.current().policy_version == 7U);
    BOOST_TEST(k.current().slot == 9U);
    // Stale relative to what was loaded.
    const auto older = make_policy(6);
    BOOST_TEST((k.offer(older.policy, older.frame) == PolicyVerdict::stale));
}

BOOST_AUTO_TEST_CASE(a_stored_policy_is_checked_again_on_load) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    // Written directly, as an older helm with another key table might have.
    const auto unsigned_policy = make_policy(3, 0, 0, std::byte{0});
    BOOST_REQUIRE(store.put(helm::power_policy_object, unsigned_policy.frame).has_value());
    FakeVerifier v;
    helm::PowerPolicyKeeper k{server, &store, &v};
    BOOST_TEST((k.load() == PolicyVerdict::bad_signature));
    BOOST_TEST(!k.from_record());

    const std::vector<std::byte> junk(8, std::byte{0});
    BOOST_REQUIRE(store.put(helm::power_policy_object, junk).has_value());
    helm::PowerPolicyKeeper k2{server, &store, &v};
    BOOST_TEST((k2.load() == PolicyVerdict::corrupt));

    const auto other = make_policy(3, 0, 0, good_sig, server + 1);
    BOOST_REQUIRE(store.put(helm::power_policy_object, other.frame).has_value());
    helm::PowerPolicyKeeper k3{server, &store, &v};
    BOOST_TEST((k3.load() == PolicyVerdict::wrong_server));
}

// Requirement 1.5: a partition restored from an older copy may hold an
// older policy, so it is discarded and the default applies.
BOOST_AUTO_TEST_CASE(a_rolled_back_store_loses_its_policy) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    FakeVerifier v;
    std::vector<std::byte> old_copy;
    {
        auto store = open_store(flash, *anchor);
        helm::PowerPolicyKeeper k{server, &store, &v};
        const auto p = make_policy(1);
        BOOST_REQUIRE((k.offer(p.policy, p.frame) == PolicyVerdict::kept));
        old_copy = flash.bytes();
        const auto p2 = make_policy(2);
        BOOST_REQUIRE((k.offer(p2.policy, p2.frame) == PolicyVerdict::kept));
    }
    flash.bytes() = old_copy;
    auto store = open_store(flash, *anchor);
    BOOST_REQUIRE(store.rolled_back());
    helm::PowerPolicyKeeper k{server, &store, &v};
    BOOST_TEST((k.load() == PolicyVerdict::none));
    BOOST_TEST(!k.from_record());
    BOOST_TEST(!store.contains(helm::power_policy_object));
}

BOOST_AUTO_TEST_CASE(a_failed_store_keeps_the_policy_in_force) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    FakeVerifier v;
    helm::PowerPolicyKeeper k{server, &store, &v};
    const auto p = make_policy(1);
    BOOST_REQUIRE((k.offer(p.policy, p.frame) == PolicyVerdict::kept));
    BOOST_REQUIRE(store.erase().has_value());
    const auto p2 = make_policy(2, 0);
    BOOST_TEST((k.offer(p2.policy, p2.frame) == PolicyVerdict::store_failed));
    BOOST_TEST(k.current().policy_version == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(plan, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(waits_tier_delay_plus_slot_times_interval_plus_jitter) {
    const auto p = make_policy(1, 1, 4).policy;  // 60 s + 4 x 5 s
    BOOST_TEST((helm::plan_power_on(p, true, HostPowerOverride::none, 750) ==
                helm::PowerOnPlan{.wait = 80'750ms, .hold = false}));
    // Jitter beyond the policy's maximum is clamped.
    BOOST_TEST(helm::plan_power_on(p, true, HostPowerOverride::none, 99'999).wait == 82'000ms);
    // The default policy: tier 3, slot 0, 300 s.
    const auto d = proto::default_power_policy(server);
    BOOST_TEST(helm::plan_power_on(d, true, HostPowerOverride::none, 0).wait == 300s);
}

BOOST_AUTO_TEST_CASE(a_helm_restart_does_not_wait) {
    const auto p = make_policy(1).policy;
    BOOST_TEST(
        (helm::plan_power_on(p, false, HostPowerOverride::none, 1000) == helm::PowerOnPlan{}));
}

BOOST_AUTO_TEST_CASE(host_power_overrides_the_wait) {
    const auto p = make_policy(1).policy;
    BOOST_TEST((helm::plan_power_on(p, true, HostPowerOverride::on, 1000) == helm::PowerOnPlan{}));
    BOOST_TEST((helm::plan_power_on(p, true, HostPowerOverride::hold, 1000) ==
                helm::PowerOnPlan{.wait = 0ms, .hold = true}));
    BOOST_TEST(helm::plan_power_on(p, false, HostPowerOverride::hold, 0).hold);
}

BOOST_AUTO_TEST_CASE(jitter_stays_in_range) {
    BOOST_TEST(helm::draw_jitter(0) == 0U);
    std::uint32_t lo = UINT32_MAX;
    std::uint32_t hi = 0;
    for (int i = 0; i < 2000; ++i) {
        const auto j = helm::draw_jitter(10);
        lo = std::min(lo, j);
        hi = std::max(hi, j);
    }
    BOOST_TEST(lo == 0U);
    BOOST_TEST(hi == 10U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(marker, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(tells_power_loss_from_a_restart) {
    TempDir dir;
    const auto marker = dir.path / "run" / "powered";
    BOOST_TEST(helm::helm_power_returned(marker).value());
    BOOST_TEST(!helm::helm_power_returned(marker).value());
    BOOST_TEST(!helm::helm_power_returned(marker).value());
    struct stat st{};
    BOOST_REQUIRE(::stat(marker.c_str(), &st) == 0);
    BOOST_TEST((st.st_mode & 0777) == 0600U);
    // The tmpfs is cleared when power is lost.
    std::filesystem::remove(marker);
    BOOST_TEST(helm::helm_power_returned(marker).value());
}

BOOST_AUTO_TEST_CASE(a_symlink_or_directory_is_an_error) {
    TempDir dir;
    const auto marker = dir.path / "powered";
    std::filesystem::create_symlink(dir.path / "elsewhere", marker);
    BOOST_TEST(!helm::helm_power_returned(marker).has_value());
    const auto d = dir.path / "dir";
    std::filesystem::create_directory(d);
    BOOST_TEST(!helm::helm_power_returned(d).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
