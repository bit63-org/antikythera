// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 6 (task 3): the boot epoch and the
// command sequence floor that keep an envelope captured before a power
// cycle from being accepted after it. The provisioning frame helm hands
// hull, the epoch counter, and the sequence number recorded in the sealed
// store across power loss.

#define BOOST_TEST_MODULE boot_state_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "helm/boot_state.hpp"
#include "helm/flash.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/provisioning.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::Counter;
using proto::DecodeError;

namespace {

constexpr std::uint64_t flash_size = 64 * 1024;
constexpr std::uint64_t server = 42;

auto ephemeral_anchor() -> std::unique_ptr<helm::SoftwareStoreAnchor> {
    auto a = helm::SoftwareStoreAnchor::ephemeral();
    BOOST_REQUIRE(a.has_value());
    return std::move(*a);
}

// The same secure element after power returns.
auto clone(helm::StoreAnchor& a) -> std::unique_ptr<helm::SoftwareStoreAnchor> {
    helm::SoftwareStoreAnchor::State s;
    auto key = a.store_key();
    BOOST_REQUIRE(key.has_value());
    std::ranges::copy(key->span(), s.key.span().begin());
    for (std::size_t i = 0; i < helm::counter_count; ++i) {
        s.counters.at(i) = a.counter(static_cast<Counter>(i)).value();
    }
    return std::make_unique<helm::SoftwareStoreAnchor>(std::nullopt, std::move(s));
}

auto open_store(helm::Flash& f, helm::StoreAnchor& a) -> helm::SealedStore {
    auto s = helm::SealedStore::open(f, a);
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto frame_bytes(std::initializer_list<int> v) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (int b : v) {
        out.push_back(static_cast<std::byte>(b));
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(provisioning_frame, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(encodes_to_the_documented_layout) {
    const proto::Provisioning p{
        .server_id = 0x0102'0304'0506'0708, .boot_epoch = 3, .sequence_floor = 0x1234};
    const auto bytes = proto::encode_provisioning(p);
    BOOST_TEST_REQUIRE(bytes.has_value());
    const auto want =
        frame_bytes({'A', 'K', 'P', 'V', 1, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                     3,   0,   0,   0,   0, 0, 0, 0, 0x34, 0x12, 0,    0,    0,    0,    0,    0});
    BOOST_TEST((*bytes == want));
    BOOST_TEST(bytes->size() == proto::provisioning_size);
    BOOST_TEST(proto::is_provisioning_frame(*bytes));
    const auto back = proto::decode_provisioning(*bytes);
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((*back == p));
}

BOOST_AUTO_TEST_CASE(a_zero_floor_is_valid) {
    const auto bytes = proto::encode_provisioning({.server_id = 1, .boot_epoch = 1});
    BOOST_TEST_REQUIRE(bytes.has_value());
    BOOST_TEST(proto::decode_provisioning(*bytes)->sequence_floor == 0U);
}

BOOST_AUTO_TEST_CASE(refuses_bad_frames) {
    const auto good =
        *proto::encode_provisioning({.server_id = 7, .boot_epoch = 2, .sequence_floor = 9});
    const auto error = [](std::vector<std::byte> b) {
        const auto r = proto::decode_provisioning(b);
        BOOST_REQUIRE(!r.has_value());
        return r.error();
    };
    BOOST_TEST((error({good.begin(), good.end() - 1}) == DecodeError::truncated));
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((error(longer) == DecodeError::trailing_bytes));
    auto b = good;
    b.at(3) = std::byte{'W'};
    BOOST_TEST((error(b) == DecodeError::bad_magic));
    BOOST_TEST(!proto::is_provisioning_frame(b));
    b = good;
    b.at(4) = std::byte{2};
    BOOST_TEST((error(b) == DecodeError::bad_version));
    b = good;
    b.at(7) = std::byte{1};
    BOOST_TEST((error(b) == DecodeError::reserved_not_zero));
    b = good;
    std::fill(b.begin() + 0x08, b.begin() + 0x10, std::byte{0});
    BOOST_TEST((error(b) == DecodeError::bad_server_id));
    b = good;
    std::fill(b.begin() + 0x10, b.begin() + 0x18, std::byte{0});
    BOOST_TEST((error(b) == DecodeError::bad_id));

    BOOST_TEST((proto::encode_provisioning({.server_id = 0, .boot_epoch = 1}).error() ==
                DecodeError::bad_server_id));
    BOOST_TEST((proto::encode_provisioning({.server_id = 1, .boot_epoch = 0}).error() ==
                DecodeError::bad_id));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(boot_state, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(every_boot_gets_a_new_epoch_that_survives_power_loss) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    {
        auto store = open_store(flash, *anchor);
        const auto first = helm::begin_host_boot(store, *anchor, server);
        BOOST_TEST_REQUIRE(first.has_value());
        BOOST_TEST(first->server_id == server);
        BOOST_TEST(first->boot_epoch == 1U);
        BOOST_TEST(first->sequence_floor == 0U);
        BOOST_TEST(helm::begin_host_boot(store, *anchor, server)->boot_epoch == 2U);
    }
    // Power lost: the epoch lives in the secure element, not the flash.
    auto after = clone(*anchor);
    auto store = open_store(flash, *after);
    BOOST_TEST(helm::begin_host_boot(store, *after, server)->boot_epoch == 3U);
    BOOST_TEST(after->counter(Counter::boot_epoch).value() == 3U);
}

BOOST_AUTO_TEST_CASE(the_recorded_sequence_becomes_the_next_boots_floor) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    {
        auto store = open_store(flash, *anchor);
        const auto floor = helm::load_sequence_floor(store);
        BOOST_TEST_REQUIRE(floor.has_value());
        BOOST_TEST(*floor == 0U);
        helm::StoreSequenceRecorder rec{store, *floor};
        BOOST_TEST(rec.record(5));
        BOOST_TEST(rec.record(9));
        // Not above the last recorded: already covered, nothing written.
        const auto version = store.version();
        BOOST_TEST(rec.record(7));
        BOOST_TEST(rec.record(9));
        BOOST_TEST(store.version() == version);
        BOOST_TEST(rec.recorded() == 9U);
    }
    auto after = clone(*anchor);
    auto store = open_store(flash, *after);
    BOOST_TEST(helm::load_sequence_floor(store).value() == 9U);
    const auto p = helm::begin_host_boot(store, *after, server);
    BOOST_TEST_REQUIRE(p.has_value());
    BOOST_TEST(p->sequence_floor == 9U);
    // The frame hull gets carries it.
    const auto bytes = proto::encode_provisioning(*p);
    BOOST_TEST(proto::decode_provisioning(*bytes)->sequence_floor == 9U);
}

BOOST_AUTO_TEST_CASE(a_record_cut_by_power_loss_keeps_the_previous_floor) {
    // Each store commit makes several writes; cut every one of the second
    // record's in turn. Either the new number is kept or the old one is;
    // never anything else, and recording reports the failure.
    for (std::uint64_t cut = 0;; ++cut) {
        helm::MemoryFlash flash{flash_size};
        auto anchor = ephemeral_anchor();
        std::uint64_t writes_before = 0;
        {
            auto store = open_store(flash, *anchor);
            helm::StoreSequenceRecorder rec{store, 0};
            BOOST_REQUIRE(rec.record(10));
        }
        helm::FaultInjectingFlash faulty{flash, cut};
        auto mid = clone(*anchor);
        bool recorded = false;
        {
            auto store = open_store(faulty, *mid);
            writes_before = faulty.writes();
            helm::StoreSequenceRecorder rec{store, 10};
            recorded = rec.record(20);
            if (!recorded) {
                BOOST_TEST(rec.failures() == 1U);
                BOOST_TEST(rec.recorded() == 10U);
            }
        }
        auto after = clone(*mid);
        auto store = open_store(flash, *after);
        const auto floor = helm::load_sequence_floor(store).value();
        BOOST_TEST((floor == 10U || floor == 20U), "cut " << cut << ": floor " << floor);
        if (recorded) {
            BOOST_TEST(floor == 20U);
        }
        if (!faulty.cut()) {
            BOOST_TEST(cut >= writes_before);
            break;
        }
    }
}

BOOST_AUTO_TEST_CASE(refuses_server_zero_and_a_corrupt_record) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    BOOST_TEST((helm::begin_host_boot(store, *anchor, 0).error().error ==
                helm::BootStateError::bad_server));
    BOOST_TEST(anchor->counter(Counter::boot_epoch).value() == 0U);

    const std::array<std::byte, 4> short_record{};
    BOOST_REQUIRE(store.put(helm::last_command_seq_object, short_record).has_value());
    BOOST_TEST((helm::load_sequence_floor(store).error().error == helm::BootStateError::corrupt));
    // A boot with an unreadable floor does not happen, and burns no epoch.
    BOOST_TEST((helm::begin_host_boot(store, *anchor, server).error().error ==
                helm::BootStateError::corrupt));
    BOOST_TEST(anchor->counter(Counter::boot_epoch).value() == 0U);
}

BOOST_AUTO_TEST_CASE(a_closed_store_fails_the_boot_and_the_record) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = ephemeral_anchor();
    auto store = open_store(flash, *anchor);
    BOOST_REQUIRE(store.erase().has_value());
    const auto r = helm::begin_host_boot(store, *anchor, server);
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error().error == helm::BootStateError::store));
    BOOST_TEST((r.error().store_error == helm::StoreError::closed));
    helm::StoreSequenceRecorder rec{store, 0};
    BOOST_TEST(!rec.record(1));
    BOOST_TEST((rec.last_error() == helm::StoreError::closed));
}

BOOST_AUTO_TEST_SUITE_END()
