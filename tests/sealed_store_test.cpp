// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 1 (task 2): helm's sealed store,
// its secure-element anchor and the flash under it. Power cut at every
// write step, rollback to an older copy, corruption, garbage collection,
// erase on decommission.

#define BOOST_TEST_MODULE sealed_store_test
#include <boost/test/unit_test.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "helm/flash.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
using ak::test::unit_timeout_seconds;
using helm::Counter;
using helm::FlashError;
using helm::SealedStore;
using helm::StoreError;

namespace {

constexpr std::uint64_t small_flash = 64 * 1024;  // two 28 KiB halves

auto bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto fill(std::size_t n, std::uint8_t v) -> std::vector<std::byte> {
    return std::vector<std::byte>(n, std::byte{v});
}

auto ephemeral_anchor() -> std::unique_ptr<helm::SoftwareStoreAnchor> {
    auto a = helm::SoftwareStoreAnchor::ephemeral();
    BOOST_REQUIRE(a.has_value());
    return std::move(*a);
}

// The same secure element, as it is after power returns.
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

auto open(helm::Flash& f, helm::StoreAnchor& a) -> SealedStore {
    auto s = SealedStore::open(f, a);
    BOOST_REQUIRE_MESSAGE(s.has_value(), (s ? "" : helm::to_string(s.error())));
    return std::move(*s);
}

auto get(SealedStore& s, std::string_view name) -> std::optional<std::vector<std::byte>> {
    auto r = s.get(name);
    BOOST_REQUIRE_MESSAGE(r.has_value(), (r ? "" : helm::to_string(r.error())));
    return *r;
}

auto put(SealedStore& s, std::string_view name, const std::vector<std::byte>& data) -> void {
    auto r = s.put(name, data);
    BOOST_REQUIRE_MESSAGE(r.has_value(), (r ? "" : helm::to_string(r.error())));
}

// An anchor whose counter updates fail on demand, as when power is cut
// between the superblock write and the secure element.
class FlakyAnchor final : public helm::StoreAnchor {
public:
    explicit FlakyAnchor(helm::StoreAnchor& inner) noexcept : _inner{inner} {}
    bool fail_advance = false;
    auto store_key()
        -> std::expected<helm::SecretBytes<helm::store_key_size>, helm::AnchorError> override {
        return _inner.store_key();
    }
    auto counter(Counter c) -> std::expected<std::uint64_t, helm::AnchorError> override {
        return _inner.counter(c);
    }
    auto advance(Counter c, std::uint64_t v) -> std::expected<void, helm::AnchorError> override {
        if (fail_advance) {
            return std::unexpected(helm::AnchorError::io);
        }
        return _inner.advance(c, v);
    }
    auto destroy_store_key() -> std::expected<void, helm::AnchorError> override {
        return _inner.destroy_store_key();
    }

private:
    helm::StoreAnchor& _inner;
};

struct TempDir {
    TempDir() {
        auto base = std::filesystem::temp_directory_path() / "ak-sealed-store-XXXXXX";
        std::string s = base.string();
        BOOST_REQUIRE(::mkdtemp(s.data()) != nullptr);
        path = s;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(sealed_store, *boost::unit_test::timeout(unit_timeout_seconds * 4))

BOOST_AUTO_TEST_CASE(fresh_store_round_trips_and_survives_reopen) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    {
        auto s = open(flash, *anchor);
        BOOST_TEST(!s.rolled_back());
        BOOST_TEST(!s.degraded());
        BOOST_TEST(s.names().empty());
        BOOST_TEST(s.version() == 1U);
        BOOST_TEST(anchor->counter(Counter::store_version).value() == 1U);
        BOOST_TEST(!get(s, "standing_set").has_value());
        put(s, "standing_set", bytes("set v1"));
        put(s, "power_policy", bytes("policy"));
        put(s, "standing_set", bytes("set v2"));
        put(s, "empty", {});
        BOOST_TEST(s.version() == 5U);
        BOOST_TEST(
            (s.names() == std::vector<std::string>{"empty", "power_policy", "standing_set"}));
    }
    auto again = clone(*anchor);
    auto s = open(flash, *again);
    BOOST_TEST(!s.rolled_back());
    BOOST_TEST(!s.degraded());
    BOOST_TEST((get(s, "standing_set") == bytes("set v2")));
    BOOST_TEST((get(s, "power_policy") == bytes("policy")));
    BOOST_TEST((get(s, "empty") == std::vector<std::byte>{}));
    BOOST_REQUIRE(s.remove("power_policy").has_value());
    BOOST_TEST(!s.contains("power_policy"));
    BOOST_TEST(!get(s, "power_policy").has_value());
    auto third = clone(*again);
    auto t = open(flash, *third);
    BOOST_TEST(!t.contains("power_policy"));
    BOOST_TEST(t.contains("standing_set"));
}

BOOST_AUTO_TEST_CASE(nothing_is_stored_in_the_clear) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    auto s = open(flash, *anchor);
    const auto secret = bytes("hsm unseal share 0123456789abcdef");
    put(s, "secret", secret);
    BOOST_TEST(std::ranges::search(flash.bytes(), secret).empty());
}

BOOST_AUTO_TEST_CASE(names_are_checked) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    auto s = open(flash, *anchor);
    for (const std::string& bad : {std::string{}, std::string{"Upper"}, std::string{"a/b"},
                                   std::string(helm::max_store_name_size + 1, 'a')}) {
        BOOST_TEST((s.put(bad, bytes("x")).error() == StoreError::bad_name));
    }
    const std::array twice{helm::StoreWrite{.name = "a", .data = bytes("1")},
                           helm::StoreWrite{.name = "a", .data = bytes("2")}};
    BOOST_TEST((s.commit(twice).error() == StoreError::bad_name));
    BOOST_TEST(s.version() == 1U);
}

BOOST_AUTO_TEST_CASE(a_commit_is_all_or_nothing_at_every_cut) {
    // Baseline: a=1 committed. The commit under test writes a=2 and b=1.
    helm::MemoryFlash base{small_flash};
    auto base_anchor = ephemeral_anchor();
    {
        auto s = open(base, *base_anchor);
        put(s, "a", bytes("one"));
    }
    const std::array writes{helm::StoreWrite{.name = "a", .data = bytes("two")},
                            helm::StoreWrite{.name = "b", .data = bytes("bee")}};
    bool completed = false;
    for (std::uint64_t cut = 0; !completed; ++cut) {
        BOOST_REQUIRE(cut < 32U);
        helm::MemoryFlash flash{small_flash};
        flash.bytes() = base.bytes();
        auto anchor = clone(*base_anchor);
        {
            helm::FaultInjectingFlash faulty{flash, cut};
            auto s = open(faulty, *anchor);
            const auto r = s.commit(writes);
            completed = !faulty.cut();
            BOOST_TEST(r.has_value() == completed);
        }
        auto after = clone(*anchor);
        auto s = open(flash, *after);
        BOOST_TEST(!s.rolled_back());
        BOOST_TEST(!s.degraded());
        const auto a = get(s, "a");
        const auto b = get(s, "b");
        if (b) {
            BOOST_TEST((a == bytes("two")));
            BOOST_TEST((b == bytes("bee")));
        } else {
            BOOST_TEST((a == bytes("one")));
        }
        BOOST_TEST_MESSAGE("cut " << cut << (b ? ": new" : ": old"));
    }
}

BOOST_AUTO_TEST_CASE(garbage_collection_is_all_or_nothing_at_every_cut) {
    // Fill the active half with versions of one object so the next commit
    // must copy the live objects into the other half.
    helm::MemoryFlash base{small_flash};
    auto base_anchor = ephemeral_anchor();
    {
        auto s = open(base, *base_anchor);
        put(s, "keep", fill(1000, 0x11));
        while (s.free_bytes() > SealedStore::record_size(3, 6000)) {
            put(s, "big", fill(6000, 0x22));
        }
    }
    const std::array writes{helm::StoreWrite{.name = "big", .data = fill(6000, 0x33)}};
    bool completed = false;
    for (std::uint64_t cut = 0; !completed; ++cut) {
        BOOST_REQUIRE(cut < 32U);
        helm::MemoryFlash flash{small_flash};
        flash.bytes() = base.bytes();
        auto anchor = clone(*base_anchor);
        {
            helm::FaultInjectingFlash faulty{flash, cut};
            auto s = open(faulty, *anchor);
            const auto r = s.commit(writes);
            completed = !faulty.cut();
            BOOST_TEST(r.has_value() == completed);
        }
        auto after = clone(*anchor);
        auto s = open(flash, *after);
        BOOST_TEST(!s.degraded());
        BOOST_TEST((get(s, "keep") == fill(1000, 0x11)));
        const auto big = get(s, "big");
        BOOST_TEST((big == fill(6000, 0x22) || big == fill(6000, 0x33)));
        if (completed) {
            BOOST_TEST((big == fill(6000, 0x33)));
            BOOST_TEST(s.free_bytes() > SealedStore::record_size(3, 6000));
        }
    }
}

BOOST_AUTO_TEST_CASE(too_large_for_a_half_is_refused) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    auto s = open(flash, *anchor);
    put(s, "keep", bytes("x"));
    BOOST_TEST((s.put("huge", fill(s.half_size(), 1)).error() == StoreError::no_space));
    BOOST_TEST((get(s, "keep") == bytes("x")));
    BOOST_TEST(!s.contains("huge"));
}

BOOST_AUTO_TEST_CASE(a_restored_older_copy_reads_as_rolled_back) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    std::vector<std::byte> old_copy;
    {
        auto s = open(flash, *anchor);
        put(s, "standing_set", bytes("generation 1"));
        old_copy = flash.bytes();
        put(s, "standing_set", bytes("generation 2"));
    }
    flash.bytes() = old_copy;
    {
        auto s = open(flash, *anchor);
        BOOST_TEST(s.rolled_back());
        // The old contents still read: helm decides what to discard.
        BOOST_TEST((get(s, "standing_set") == bytes("generation 1")));
        BOOST_REQUIRE(s.remove("standing_set").has_value());  // re-anchors the store
    }
    auto s = open(flash, *anchor);
    BOOST_TEST(!s.rolled_back());
    BOOST_TEST(!s.contains("standing_set"));
}

BOOST_AUTO_TEST_CASE(destroyed_superblocks_read_as_rolled_back) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    {
        auto s = open(flash, *anchor);
        put(s, "a", bytes("x"));
    }
    std::fill_n(flash.bytes().begin(), 2 * helm::store_page_size, std::byte{0});
    auto s = open(flash, *anchor);
    BOOST_TEST(s.rolled_back());
    BOOST_TEST(s.names().empty());
}

BOOST_AUTO_TEST_CASE(a_cut_counter_update_is_finished_on_open) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    FlakyAnchor flaky{*anchor};
    {
        auto s = open(flash, flaky);
        flaky.fail_advance = true;
        const auto r = s.put("a", bytes("x"));
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == StoreError::anchor));
        BOOST_TEST(s.contains("a"));  // durable all the same
    }
    BOOST_TEST(anchor->counter(Counter::store_version).value() == 1U);
    flaky.fail_advance = false;
    auto s = open(flash, flaky);
    BOOST_TEST(!s.rolled_back());
    BOOST_TEST((get(s, "a") == bytes("x")));
    BOOST_TEST(anchor->counter(Counter::store_version).value() == 2U);
}

BOOST_AUTO_TEST_CASE(a_corrupted_object_is_discarded_and_counted) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    const auto marker = fill(64, 0x5A);
    std::uint64_t bad_offset = 0;
    {
        auto s = open(flash, *anchor);
        put(s, "good", bytes("fine"));
        // Find the record's ciphertext by its effect on the flash.
        const auto before = flash.bytes();
        put(s, "bad", marker);
        const auto& after = flash.bytes();
        for (std::size_t i = 2 * helm::store_page_size; i < after.size(); ++i) {
            if (before[i] != after[i]) {
                bad_offset = i + helm::store_record_header_size + 3 + 10;  // inside the ciphertext
                break;
            }
        }
    }
    BOOST_REQUIRE(bad_offset != 0U);
    flash.bytes()[bad_offset] ^= std::byte{1};
    auto s = open(flash, *anchor);
    BOOST_TEST(s.degraded());
    BOOST_TEST(s.faults() == 1U);
    BOOST_TEST(!s.contains("bad"));
    BOOST_TEST((get(s, "good") == bytes("fine")));
}

BOOST_AUTO_TEST_CASE(another_servers_key_opens_nothing) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    {
        auto s = open(flash, *anchor);
        put(s, "a", bytes("x"));
    }
    auto other = ephemeral_anchor();
    BOOST_REQUIRE(other->advance(Counter::store_version, 2).has_value());
    auto s = open(flash, *other);
    BOOST_TEST(s.rolled_back());
    BOOST_TEST(s.names().empty());
}

BOOST_AUTO_TEST_CASE(erase_destroys_the_key) {
    helm::MemoryFlash flash{small_flash};
    auto anchor = ephemeral_anchor();
    {
        auto s = open(flash, *anchor);
        put(s, "standing_set", bytes("pinned"));
        const auto copy = flash.bytes();
        BOOST_REQUIRE(s.erase().has_value());
        BOOST_TEST((s.get("standing_set").error() == StoreError::closed));
        BOOST_TEST((s.put("a", bytes("x")).error() == StoreError::closed));
        // Even the records left on flash do not open under the new key.
        flash.bytes() = copy;
    }
    auto s = open(flash, *anchor);
    BOOST_TEST(s.rolled_back());
    BOOST_TEST(s.names().empty());
}

BOOST_AUTO_TEST_CASE(partition_too_small) {
    helm::MemoryFlash flash{helm::min_store_size - 1};
    auto anchor = ephemeral_anchor();
    BOOST_TEST((SealedStore::open(flash, *anchor).error() == StoreError::too_small));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(store_anchor, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(file_anchor_persists_and_only_moves_forward) {
    TempDir dir;
    const auto path = dir.path / "anchor";
    std::array<std::byte, helm::store_key_size> key{};
    {
        auto a = helm::SoftwareStoreAnchor::open(path);
        BOOST_REQUIRE(a.has_value());
        struct stat st{};
        BOOST_REQUIRE(::stat(path.c_str(), &st) == 0);
        BOOST_TEST((st.st_mode & 0777U) == 0600U);
        BOOST_TEST((*a)->counter(Counter::boot_epoch).value() == 0U);
        BOOST_REQUIRE((*a)->advance(Counter::boot_epoch, 3).has_value());
        BOOST_TEST(
            ((*a)->advance(Counter::boot_epoch, 3).error() == helm::AnchorError::not_monotonic));
        BOOST_TEST(
            ((*a)->advance(Counter::boot_epoch, 2).error() == helm::AnchorError::not_monotonic));
        BOOST_REQUIRE((*a)->advance(Counter::standing_generation, 9).has_value());
        std::ranges::copy((*a)->store_key().value().span(), key.begin());
    }
    auto a = helm::SoftwareStoreAnchor::open(path);
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST((*a)->counter(Counter::boot_epoch).value() == 3U);
    BOOST_TEST((*a)->counter(Counter::standing_generation).value() == 9U);
    BOOST_TEST((*a)->counter(Counter::store_version).value() == 0U);
    BOOST_TEST(std::ranges::equal((*a)->store_key().value().span(), key));
    BOOST_REQUIRE((*a)->destroy_store_key().has_value());
    BOOST_TEST(!std::ranges::equal((*a)->store_key().value().span(), key));
    BOOST_TEST((*a)->counter(Counter::boot_epoch).value() == 3U);
    auto reopened = helm::SoftwareStoreAnchor::open(path);
    BOOST_REQUIRE(reopened.has_value());
    BOOST_TEST(!std::ranges::equal((*reopened)->store_key().value().span(), key));
}

BOOST_AUTO_TEST_CASE(file_anchor_refuses_insecure_or_corrupt_files) {
    TempDir dir;
    const auto path = dir.path / "anchor";
    BOOST_REQUIRE(helm::SoftwareStoreAnchor::open(path).has_value());
    BOOST_REQUIRE(::chmod(path.c_str(), 0644) == 0);
    BOOST_TEST((helm::SoftwareStoreAnchor::open(path).error() == helm::AnchorError::insecure));
    BOOST_REQUIRE(::chmod(path.c_str(), 0600) == 0);
    std::filesystem::resize_file(path, 10);
    BOOST_TEST((helm::SoftwareStoreAnchor::open(path).error() == helm::AnchorError::corrupt));
    const auto link = dir.path / "link";
    std::filesystem::create_symlink(path, link);
    BOOST_TEST((helm::SoftwareStoreAnchor::open(link).error() == helm::AnchorError::insecure));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(flash, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(file_flash_keeps_a_store_across_reopen) {
    TempDir dir;
    const auto path = dir.path / "flash";
    auto anchor = helm::SoftwareStoreAnchor::open(dir.path / "anchor");
    BOOST_REQUIRE(anchor.has_value());
    {
        auto f = helm::FileFlash::open(path, small_flash);
        BOOST_REQUIRE(f.has_value());
        BOOST_TEST(std::filesystem::file_size(path) == small_flash);
        auto s = open(**f, **anchor);
        put(s, "lkg", fill(5000, 0xAB));
    }
    BOOST_TEST((helm::FileFlash::open(path, small_flash * 2).error() == FlashError::wrong_size));
    auto f = helm::FileFlash::open(path, small_flash);
    BOOST_REQUIRE(f.has_value());
    auto again = helm::SoftwareStoreAnchor::open(dir.path / "anchor");
    BOOST_REQUIRE(again.has_value());
    auto s = open(**f, **again);
    BOOST_TEST(!s.rolled_back());
    BOOST_TEST((get(s, "lkg") == fill(5000, 0xAB)));
    std::array<std::byte, 4> out{};
    BOOST_TEST(((*f)->read(small_flash - 2, out).error() == FlashError::out_of_range));
}

BOOST_AUTO_TEST_CASE(fault_injection_cuts_one_write_in_half) {
    helm::MemoryFlash inner{16};
    helm::FaultInjectingFlash f{inner, 1};
    BOOST_REQUIRE(f.write(0, fill(4, 1)).has_value());
    BOOST_TEST((f.write(4, fill(4, 2)).error() == FlashError::power_lost));
    BOOST_TEST(f.cut());
    BOOST_TEST((f.sync().error() == FlashError::power_lost));
    std::array<std::byte, 1> b{};
    BOOST_TEST((f.read(0, b).error() == FlashError::power_lost));
    const auto& raw = inner.bytes();
    BOOST_TEST(std::to_integer<int>(raw[5]) == 2);  // the first half landed
    BOOST_TEST(std::to_integer<int>(raw[6]) == 0);  // the rest did not
}

BOOST_AUTO_TEST_SUITE_END()
