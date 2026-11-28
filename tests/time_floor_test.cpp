// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 7 (task 8): helm's time floor. It
// only rises, survives power loss in the sealed store, marks an RTC below
// it as untrusted, and moves certificate checks to max(RTC, floor).

#define BOOST_TEST_MODULE time_floor_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>

#include "helm/flash.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "helm/time_floor.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::uint64_t flash_size = 64 * 1024;
constexpr std::uint64_t nov_2026 = 1'795'000'000;  // a floor in late 2026

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

}  // namespace

BOOST_AUTO_TEST_SUITE(time_floor, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(only_rises) {
    helm::TimeFloor f{nullptr};
    BOOST_TEST(f.floor() == 0U);
    BOOST_TEST(f.observe(nov_2026));
    BOOST_TEST(!f.observe(nov_2026));
    BOOST_TEST(!f.observe(nov_2026 - 600));
    BOOST_TEST(f.observe(nov_2026 + 600));
    BOOST_TEST(f.floor() == nov_2026 + 600);
    BOOST_TEST(!f.observe(0));  // a record with no floor changes nothing
}

BOOST_AUTO_TEST_CASE(an_rtc_below_the_floor_is_not_trusted) {
    helm::TimeFloor f{nullptr};
    BOOST_TEST(f.rtc_trusted(0));  // no floor yet
    (void)f.observe(nov_2026);
    BOOST_TEST(!f.rtc_trusted(0));             // a dead RTC battery: 1970
    BOOST_TEST(!f.rtc_trusted(nov_2026 - 1));  // just below
    BOOST_TEST(f.rtc_trusted(nov_2026));
    BOOST_TEST(f.rtc_trusted(nov_2026 + 86'400));
}

BOOST_AUTO_TEST_CASE(certificates_are_checked_at_max_of_rtc_and_floor) {
    helm::TimeFloor f{nullptr};
    BOOST_TEST(f.verification_time(12345) == 12345);
    (void)f.observe(nov_2026);
    BOOST_TEST(f.verification_time(0) == static_cast<std::int64_t>(nov_2026));
    BOOST_TEST(f.verification_time(-5) == static_cast<std::int64_t>(nov_2026));
    // A clock ahead of the floor is not pulled back.
    BOOST_TEST(f.verification_time(nov_2026 + 99) == static_cast<std::int64_t>(nov_2026 + 99));
    // A floor beyond int64 is clamped rather than wrapping negative.
    (void)f.observe(std::numeric_limits<std::uint64_t>::max());
    BOOST_TEST(f.verification_time(0) == std::numeric_limits<std::int64_t>::max());
    BOOST_TEST(!f.rtc_trusted(std::numeric_limits<std::int64_t>::max() - 1));
}

BOOST_AUTO_TEST_CASE(survives_power_loss) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    {
        auto store = open_store(flash, *anchor);
        helm::TimeFloor f{&store};
        BOOST_REQUIRE(f.load().has_value());
        BOOST_TEST(f.floor() == 0U);
        BOOST_TEST(f.observe(nov_2026));
        BOOST_TEST(f.store_failures() == 0U);
    }
    auto store = open_store(flash, *anchor);
    helm::TimeFloor f{&store};
    BOOST_REQUIRE(f.load().has_value());
    BOOST_TEST(f.floor() == nov_2026);
    BOOST_TEST(!f.rtc_trusted(0));
}

BOOST_AUTO_TEST_CASE(a_floor_that_cannot_be_stored_still_applies) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    helm::TimeFloor f{&store};
    BOOST_REQUIRE(store.erase().has_value());
    BOOST_TEST(f.observe(nov_2026));
    BOOST_TEST(f.store_failures() == 1U);
    BOOST_TEST(f.floor() == nov_2026);
    BOOST_TEST(!f.load().has_value());  // a closed store
}

BOOST_AUTO_TEST_CASE(a_corrupt_stored_floor_is_ignored) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    const std::array<std::byte, 3> junk{};
    BOOST_REQUIRE(store.put(helm::time_floor_object, junk).has_value());
    helm::TimeFloor f{&store};
    BOOST_REQUIRE(f.load().has_value());
    BOOST_TEST(f.corrupt());
    BOOST_TEST(f.floor() == 0U);
    // A new floor overwrites it.
    BOOST_TEST(f.observe(nov_2026));
    helm::TimeFloor again{&store};
    BOOST_REQUIRE(again.load().has_value());
    BOOST_TEST(again.floor() == nov_2026);
}

BOOST_AUTO_TEST_SUITE_END()
