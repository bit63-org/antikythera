// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirements 4.1-4.3 and 1.5 (task 6): helm's
// StandingSetKeeper. It keeps only verified, newer standing sets for this
// server, anchors each accepted generation in the secure element so an
// older set is refused even from a restored store, and loses its set
// when the store opens rolled back.

#define BOOST_TEST_MODULE standing_set_keeper_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include "helm/flash.hpp"
#include "helm/sealed_store.hpp"
#include "helm/standing_set_keeper.hpp"
#include "helm/store_anchor.hpp"
#include "proto/standing_set.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::StandingVerdict;

namespace {

constexpr std::uint64_t server = 42;
constexpr std::uint64_t flash_size = 64 * 1024;
constexpr std::byte good_sig{0x01};
constexpr std::uint64_t vm = 0x1001;

// Accepts a signature whose first byte is 0x01, under key 1 only.
struct FakeVerifier final : helm::RecordVerifier {
    [[nodiscard]] auto verify(std::span<const std::byte> /*message*/,
                              std::span<const std::byte, proto::ed25519_signature_size> sig,
                              std::uint16_t key_id) const -> bool override {
        return key_id == 1 && sig[0] == good_sig;
    }
};

// A software anchor whose counters can be made to fail.
struct FlakyAnchor final : helm::StoreAnchor {
    std::unique_ptr<helm::SoftwareStoreAnchor> real = [] {
        auto a = helm::SoftwareStoreAnchor::ephemeral();
        BOOST_REQUIRE(a.has_value());
        return std::move(*a);
    }();
    bool fail_advance{false};
    bool fail_read{false};

    auto store_key()
        -> std::expected<helm::SecretBytes<helm::store_key_size>, helm::AnchorError> override {
        return real->store_key();
    }
    auto counter(helm::Counter c) -> std::expected<std::uint64_t, helm::AnchorError> override {
        if (fail_read && c == helm::Counter::standing_generation) {
            return std::unexpected(helm::AnchorError::io);
        }
        return real->counter(c);
    }
    auto advance(helm::Counter c, std::uint64_t value)
        -> std::expected<void, helm::AnchorError> override {
        if (fail_advance && c == helm::Counter::standing_generation) {
            return std::unexpected(helm::AnchorError::io);
        }
        return real->advance(c, value);
    }
    auto destroy_store_key() -> std::expected<void, helm::AnchorError> override {
        return real->destroy_store_key();
    }
};

auto make_set(std::uint64_t generation, bool pinned = true, std::byte sig = good_sig,
              std::uint64_t server_id = server) -> std::vector<std::byte> {
    proto::StandingSet s{.server_id = server_id,
                         .key_id = 1,
                         .generation = generation,
                         .time_floor = 1'700'000'000,
                         .instances = {},
                         .signature = {}};
    if (pinned) {
        proto::StandingInstance in;
        in.vm_id = vm;
        in.manifest_digest.fill(std::byte{0xAB});
        in.commands.push_back({.type = proto::StandingCommandType::create_vm,
                               .body = std::vector<std::byte>(16, std::byte{1})});
        s.instances.push_back(in);
    }
    s.signature.fill(sig);
    auto bytes = proto::encode_standing_set(s);
    BOOST_REQUIRE(bytes.has_value());
    return *bytes;
}

auto open_store(helm::Flash& f, helm::StoreAnchor& a) -> helm::SealedStore {
    auto s = helm::SealedStore::open(f, a);
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto standing_counter(helm::StoreAnchor& a) -> std::uint64_t {
    auto c = a.counter(helm::Counter::standing_generation);
    BOOST_REQUIRE(c.has_value());
    return *c;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(keeper, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(nothing_kept_pins_nothing) {
    FakeVerifier v;
    helm::StandingSetKeeper k{server, nullptr, nullptr, &v};
    BOOST_TEST((k.load() == StandingVerdict::none));
    BOOST_TEST(!k.current().has_value());
    BOOST_TEST(k.pinned() == 0U);
    BOOST_TEST(k.generation() == 0U);
}

BOOST_AUTO_TEST_CASE(keeps_only_verified_newer_sets_for_this_server) {
    FlakyAnchor anchor;
    FakeVerifier v;
    helm::StandingSetKeeper k{server, nullptr, &anchor, &v};
    const auto s5 = make_set(5);
    BOOST_TEST((k.offer(s5) == StandingVerdict::kept));
    BOOST_TEST(k.pinned() == 1U);
    BOOST_TEST(k.generation() == 5U);
    BOOST_TEST((std::vector<std::byte>(k.frame().begin(), k.frame().end()) == s5));
    BOOST_TEST(standing_counter(anchor) == 5U);  // anchored (Requirement 4.2)

    BOOST_TEST((k.offer(make_set(5)) == StandingVerdict::stale));
    BOOST_TEST((k.offer(make_set(4)) == StandingVerdict::stale));
    BOOST_TEST((k.offer(make_set(6, true, std::byte{0})) == StandingVerdict::bad_signature));
    BOOST_TEST((k.offer(make_set(7, true, good_sig, server + 1)) == StandingVerdict::wrong_server));
    auto broken = make_set(8);
    broken[0] = std::byte{'X'};
    BOOST_TEST((k.offer(broken) == StandingVerdict::corrupt));
    BOOST_TEST(k.generation() == 5U);

    // An empty set unpins everything (Requirement 4.3).
    BOOST_TEST((k.offer(make_set(9, false)) == StandingVerdict::kept));
    BOOST_TEST(k.current().has_value());
    BOOST_TEST(k.pinned() == 0U);
    BOOST_TEST(standing_counter(anchor) == 9U);
}

BOOST_AUTO_TEST_CASE(no_verifier_refuses_everything) {
    helm::StandingSetKeeper k{server, nullptr, nullptr, nullptr};
    BOOST_TEST((k.offer(make_set(1)) == StandingVerdict::bad_signature));
    BOOST_TEST(!k.current().has_value());
}

BOOST_AUTO_TEST_CASE(survives_a_restart) {
    helm::MemoryFlash flash{flash_size};
    FlakyAnchor anchor;
    FakeVerifier v;
    {
        auto store = open_store(flash, anchor);
        helm::StandingSetKeeper k{server, &store, &anchor, &v};
        BOOST_REQUIRE((k.offer(make_set(3)) == StandingVerdict::kept));
    }
    auto store = open_store(flash, anchor);
    helm::StandingSetKeeper k{server, &store, &anchor, &v};
    BOOST_TEST((k.load() == StandingVerdict::kept));
    BOOST_TEST(k.generation() == 3U);
    BOOST_TEST(k.pinned() == 1U);
    // Still refuses older sets after the restart.
    BOOST_TEST((k.offer(make_set(2)) == StandingVerdict::stale));
}

// Requirement 4.2: a copy of the store older than the newest set this
// element accepted is refused, even if the store itself opens cleanly.
BOOST_AUTO_TEST_CASE(a_set_below_the_anchor_is_rolled_back) {
    helm::MemoryFlash flash{flash_size};
    FlakyAnchor anchor;
    FakeVerifier v;
    {
        auto store = open_store(flash, anchor);
        helm::StandingSetKeeper k{server, &store, &anchor, &v};
        BOOST_REQUIRE((k.offer(make_set(3)) == StandingVerdict::kept));
    }
    // A newer set was accepted elsewhere in this element's life.
    BOOST_REQUIRE(anchor.advance(helm::Counter::standing_generation, 7).has_value());
    auto store = open_store(flash, anchor);
    helm::StandingSetKeeper k{server, &store, &anchor, &v};
    BOOST_TEST((k.load() == StandingVerdict::rolled_back));
    BOOST_TEST(!k.current().has_value());
    BOOST_TEST(!store.contains(helm::standing_set_object));
    BOOST_TEST(k.generation() == 7U);
}

// Requirement 1.5: a rolled-back store loses its standing set.
BOOST_AUTO_TEST_CASE(a_rolled_back_store_loses_its_set) {
    helm::MemoryFlash flash{flash_size};
    FlakyAnchor anchor;
    FakeVerifier v;
    std::vector<std::byte> old_copy;
    {
        auto store = open_store(flash, anchor);
        helm::StandingSetKeeper k{server, &store, &anchor, &v};
        BOOST_REQUIRE((k.offer(make_set(1)) == StandingVerdict::kept));
        old_copy = flash.bytes();
        BOOST_REQUIRE((k.offer(make_set(2)) == StandingVerdict::kept));
    }
    flash.bytes() = old_copy;
    auto store = open_store(flash, anchor);
    BOOST_REQUIRE(store.rolled_back());
    helm::StandingSetKeeper k{server, &store, &anchor, &v};
    BOOST_TEST((k.load() == StandingVerdict::none));
    BOOST_TEST(!k.current().has_value());
    BOOST_TEST(!store.contains(helm::standing_set_object));
}

BOOST_AUTO_TEST_CASE(a_lagging_counter_is_advanced_at_load) {
    helm::MemoryFlash flash{flash_size};
    FlakyAnchor anchor;
    FakeVerifier v;
    {
        auto store = open_store(flash, anchor);
        helm::StandingSetKeeper k{server, &store, &anchor, &v};
        anchor.fail_advance = true;
        BOOST_TEST((k.offer(make_set(4)) == StandingVerdict::anchor_failed));
        BOOST_TEST(k.pinned() == 1U);  // kept all the same
        BOOST_TEST(standing_counter(anchor) == 0U);
        BOOST_TEST(k.generation() == 4U);
        BOOST_TEST((k.offer(make_set(4)) == StandingVerdict::stale));
    }
    anchor.fail_advance = false;
    auto store = open_store(flash, anchor);
    helm::StandingSetKeeper k{server, &store, &anchor, &v};
    BOOST_TEST((k.load() == StandingVerdict::kept));
    BOOST_TEST(standing_counter(anchor) == 4U);
}

BOOST_AUTO_TEST_CASE(an_unreadable_counter_refuses_sets) {
    FlakyAnchor anchor;
    FakeVerifier v;
    helm::StandingSetKeeper k{server, nullptr, &anchor, &v};
    anchor.fail_read = true;
    BOOST_TEST((k.offer(make_set(1)) == StandingVerdict::anchor_unreadable));
    BOOST_TEST(!k.current().has_value());
}

BOOST_AUTO_TEST_CASE(a_failed_store_keeps_the_set_held) {
    helm::MemoryFlash flash{flash_size};
    FlakyAnchor anchor;
    FakeVerifier v;
    auto store = open_store(flash, anchor);
    helm::StandingSetKeeper k{server, &store, &anchor, &v};
    BOOST_REQUIRE((k.offer(make_set(1)) == StandingVerdict::kept));
    BOOST_REQUIRE(store.erase().has_value());
    BOOST_TEST((k.offer(make_set(2)) == StandingVerdict::store_failed));
    BOOST_TEST(k.current()->generation == 1U);
    BOOST_TEST(standing_counter(anchor) == 1U);  // never advanced past an unstored set
}

BOOST_AUTO_TEST_CASE(verdicts_have_names) {
    BOOST_TEST(std::string_view{helm::to_string(StandingVerdict::rolled_back)} ==
               "stored set is older than the anchored generation");
    BOOST_TEST(std::string_view{helm::to_string(StandingVerdict::kept)} == "kept");
}

BOOST_AUTO_TEST_SUITE_END()
