// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 8 (task 9): the cold_start and
// boot_cache reports helm builds. Every report they produce must pass the
// schema's check, whatever helm hands them, or the session would drop it.

#define BOOST_TEST_MODULE cold_start_reports_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "helm/cold_start_reports.hpp"
#include "helm/flash.hpp"
#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/power_policy.hpp"
#include "proto/report.hpp"
#include "proto/standing_set.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t server = 42;
constexpr std::uint64_t flash_size = 64 * 1024;

struct AcceptAll final : helm::RecordVerifier {
    [[nodiscard]] auto verify(std::span<const std::byte> /*message*/,
                              std::span<const std::byte, proto::ed25519_signature_size> /*sig*/,
                              std::uint16_t /*key_id*/) const -> bool override {
        return true;
    }
};

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

// Encodes and decodes the report, as the session and controller would.
auto round_trip(proto::ReportBody body) -> proto::ReportBody {
    auto bytes = proto::encode_report({.server_id = server, .report_seq = 1, .body = body});
    BOOST_REQUIRE(bytes.has_value());
    auto back = proto::decode_report(*bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->body == body));
    return back->body;
}

auto digest(std::uint8_t fill) -> proto::ImageDigest {
    proto::ImageDigest d{};
    d.fill(std::byte{fill});
    return d;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(cold_start, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(carries_the_facts_without_a_store) {
    const auto c = helm::make_cold_start({.power_return_time = 1'795'000'100,
                                          .time_floor = 1'795'000'000,
                                          .waited = 65'500ms,
                                          .boot_source = proto::BootSource::netboot,
                                          .rtc_below_floor = false,
                                          .standing = {}},
                                         nullptr);
    BOOST_TEST(c.power_return_time == 1'795'000'100U);
    BOOST_TEST(c.time_floor == 1'795'000'000U);
    BOOST_TEST(c.waited_ms == 65'500U);
    BOOST_TEST((c.boot_source == proto::BootSource::netboot));
    BOOST_TEST(c.flags == 0U);
    BOOST_TEST(c.store_faults == 0U);
    BOOST_TEST(c.standing.empty());
    (void)round_trip(c);
}

BOOST_AUTO_TEST_CASE(flags_a_slow_clock_and_a_rolled_back_store) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    std::vector<std::byte> old_copy;
    {
        auto store = open_store(flash, *anchor);
        BOOST_REQUIRE(store.put("x", std::vector<std::byte>{std::byte{1}}).has_value());
        old_copy = flash.bytes();
        BOOST_REQUIRE(store.put("x", std::vector<std::byte>{std::byte{2}}).has_value());
    }
    flash.bytes() = old_copy;
    auto store = open_store(flash, *anchor);
    BOOST_REQUIRE(store.rolled_back());

    const auto c = helm::make_cold_start({.rtc_below_floor = true}, &store);
    BOOST_TEST(c.flags == (proto::cold_start_rollback | proto::cold_start_rtc_below_floor));
    const auto u = helm::make_cold_start(
        {.rtc_below_floor = false, .assigned_image_unavailable = true}, &store);
    BOOST_TEST(u.flags == (proto::cold_start_rollback | proto::cold_start_assigned_unavailable));
    BOOST_TEST(c.store_faults == store.faults());
    (void)round_trip(c);
}

BOOST_AUTO_TEST_CASE(keeps_the_report_within_the_schema) {
    std::vector<proto::StandingStartResult> standing;
    // Out of order, a zero VM, a retry of VM 9, and more than the limit.
    standing.push_back({.vm_id = 9, .result = proto::StandingResult::failed, .attempts = 1});
    standing.push_back({.vm_id = 0, .result = proto::StandingResult::started, .attempts = 1});
    standing.push_back({.vm_id = 3, .result = proto::StandingResult::started, .attempts = 1});
    standing.push_back({.vm_id = 9, .result = proto::StandingResult::started, .attempts = 2});
    for (std::uint64_t vm = 100; vm < 100 + proto::max_standing_instances; ++vm) {
        standing.push_back({.vm_id = vm, .result = proto::StandingResult::started, .attempts = 1});
    }
    const auto c = helm::make_cold_start({.power_return_time = -5,
                                          .waited = std::chrono::milliseconds{1LL << 40},
                                          .standing = standing},
                                         nullptr);
    BOOST_TEST(c.power_return_time == 0U);
    BOOST_TEST(c.waited_ms == 0xFFFF'FFFFU);
    BOOST_REQUIRE(c.standing.size() == proto::max_standing_instances);
    BOOST_TEST(c.standing[0].vm_id == 3U);
    BOOST_TEST(c.standing[1].vm_id == 9U);
    BOOST_TEST((c.standing[1].result == proto::StandingResult::started));
    BOOST_TEST(c.standing[1].attempts == 2U);
    BOOST_TEST(c.standing.back().vm_id == 100U + proto::max_standing_instances - 3);
    (void)round_trip(c);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(boot_cache, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(defaults_with_no_store_or_policy) {
    const helm::PowerPolicyKeeper keeper{server, nullptr, nullptr};
    const auto b = helm::make_boot_cache({}, 0, keeper, nullptr);
    BOOST_TEST((b == proto::BootCache{}));
    (void)round_trip(b);
}

BOOST_AUTO_TEST_CASE(reports_the_policy_the_images_and_the_store) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    AcceptAll verifier;
    helm::PowerPolicyKeeper keeper{server, &store, &verifier};
    auto p = proto::default_power_policy(server);
    p.key_id = 1;
    p.policy_version = 12;
    auto frame = proto::encode_power_policy(p);
    BOOST_REQUIRE(frame.has_value());
    BOOST_REQUIRE((keeper.offer(p, *frame) == helm::PolicyVerdict::kept));

    const auto b =
        helm::make_boot_cache({.lkg = digest(0xAA), .previous = digest(0xBB)}, 4, keeper, &store);
    BOOST_TEST((b.lkg_image == digest(0xAA)));
    BOOST_TEST((b.previous_image == digest(0xBB)));
    BOOST_TEST(b.standing_generation == 4U);
    BOOST_TEST(b.policy_version == 12U);
    BOOST_TEST(b.store_total_bytes == store.half_size());
    BOOST_TEST(b.store_free_bytes == store.free_bytes());
    BOOST_TEST(b.store_free_bytes < b.store_total_bytes);  // the policy takes room
    (void)round_trip(b);
}

BOOST_AUTO_TEST_CASE(a_previous_image_needs_an_lkg) {
    const helm::PowerPolicyKeeper keeper{server, nullptr, nullptr};
    const auto b = helm::make_boot_cache({.lkg = {}, .previous = digest(0xBB)}, 0, keeper, nullptr);
    BOOST_TEST((b.previous_image == proto::ImageDigest{}));
    (void)round_trip(b);
}

BOOST_AUTO_TEST_SUITE_END()
