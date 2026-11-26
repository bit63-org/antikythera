// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 23.2 (Requirement 8.6): the keyed
// copy behind local <-> network conversion. VolumeCopier is driven between
// in-memory backends, synchronous and asynchronous, with faults injected:
// every written block arrives decrypted from the source's key and
// encrypted under the target's at its own number, never-written blocks
// stay unwritten, I/O errors are retried and then fail the copy, a source
// awaiting hydration fails at once, and the copy is completed only once
// the target is flushed. A FileBackend case copies a real local volume.

#define BOOST_TEST_MODULE volume_copier_test
#include <boost/test/unit_test.hpp>

#include <stdlib.h>  // NOLINT(modernize-deprecated-headers): mkdtemp

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "oar/blk/file_backend.hpp"
#include "oar/blk/volume_copier.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, CopyError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, CopyState s) -> std::ostream& {
    return os << to_string(s);
}
auto operator<<(std::ostream& os, CopyFailure f) -> std::ostream& {
    return os << to_string(f);
}
}  // namespace ak::oar::blk

namespace {

namespace blk = ak::oar::blk;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using Bytes = std::vector<std::byte>;
using Key = std::array<std::byte, blk::xts_key_size>;
using Clock = blk::VolumeCopier::Clock;

constexpr std::uint32_t bs = 512;
constexpr std::uint64_t region = 8ULL * bs;  // 8 blocks a region in these tests

auto key_of(std::uint8_t seed) -> Key {
    Key k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<std::byte>(seed + (i * 7) + (i < 32 ? 0 : 101));
    }
    return k;
}

auto plain_block(std::uint64_t lba, std::uint32_t size = bs) -> Bytes {
    Bytes b(size);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<std::byte>((lba * 31) + i + 1);
    }
    return b;
}

// A volume in memory: whole ciphertext, zeros where never written. Its
// operations complete at once (sync) or on the next poll (async), and
// faults can be queued per operation kind.
class MemBackend final : public blk::BlockBackend {
public:
    MemBackend(std::uint64_t bytes, bool async) : data(bytes), _async{async} {}

    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override { return data.size(); }
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, blk::BackendCompletion done)
        -> void override {
        ++reads;
        auto r = take(read_faults, offset, out.size());
        if (r) {
            std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset), out.size(),
                        out.begin());
        }
        finish(std::move(done), r);
    }
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in,
                      blk::BackendCompletion done) -> void override {
        ++writes;
        written_bytes += in.size();
        auto r = take(write_faults, offset, in.size());
        if (r) {
            std::ranges::copy(in, data.begin() + static_cast<std::ptrdiff_t>(offset));
        }
        finish(std::move(done), r);
    }
    auto submit_flush(blk::BackendCompletion done) -> void override {
        ++flushes;
        blk::BackendResult r{};
        if (fail_flush) {
            r = std::unexpected(blk::BackendError::io);
        }
        finish(std::move(done), r);
    }
    [[nodiscard]] auto poll() -> bool override {
        auto ready = std::exchange(_pending, {});
        for (auto& [done, r] : ready) {
            done(r);
        }
        return !_pending.empty();
    }

    // The next `n` operations of a kind touching [lo, hi) fail with `e`.
    struct Fault {
        std::uint64_t lo{0};
        std::uint64_t hi{0};
        blk::BackendError error{blk::BackendError::io};
        unsigned count{1};
    };

    Bytes data;
    std::vector<Fault> read_faults;
    std::vector<Fault> write_faults;
    bool fail_flush{false};
    unsigned reads{0};
    unsigned writes{0};
    unsigned flushes{0};
    std::uint64_t written_bytes{0};

private:
    static auto take(std::vector<Fault>& faults, std::uint64_t off, std::size_t len)
        -> blk::BackendResult {
        for (auto& f : faults) {
            if (f.count > 0 && off < f.hi && off + len > f.lo) {
                --f.count;
                return std::unexpected(f.error);
            }
        }
        return {};
    }
    auto finish(blk::BackendCompletion done, blk::BackendResult r) -> void {
        if (_async) {
            _pending.emplace_back(std::move(done), r);
        } else {
            done(r);
        }
    }

    bool _async;
    std::deque<std::pair<blk::BackendCompletion, blk::BackendResult>> _pending;
};

// Writes `lbas` of a volume under `key`, as VirtioBlkFunction would.
auto fill(MemBackend& m, const Key& key, const std::vector<std::uint64_t>& lbas,
          std::uint32_t block = bs) -> void {
    auto c = blk::XtsCipher::create(key, block);
    BOOST_REQUIRE(c.has_value());
    for (const auto lba : lbas) {
        auto b = plain_block(lba, block);
        BOOST_REQUIRE(c->encrypt(lba, b, b).has_value());
        std::ranges::copy(b, m.data.begin() + static_cast<std::ptrdiff_t>(lba * block));
    }
}

// Block `lba` of `m`, decrypted under `key`; nullopt where never written.
auto read_plain(const MemBackend& m, const Key& key, std::uint64_t lba, std::uint32_t block = bs)
    -> std::optional<Bytes> {
    Bytes b(m.data.begin() + static_cast<std::ptrdiff_t>(lba * block),
            m.data.begin() + static_cast<std::ptrdiff_t>((lba + 1) * block));
    if (std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; })) {
        return std::nullopt;
    }
    auto c = blk::XtsCipher::create(key, block);
    BOOST_REQUIRE(c.has_value());
    BOOST_REQUIRE(c->decrypt(lba, b, b).has_value());
    return b;
}

struct Rig {
    MemBackend* source{nullptr};
    MemBackend* target{nullptr};
    std::unique_ptr<blk::VolumeCopier> copier;
    Clock::time_point now{std::chrono::hours{1}};
    Key from = key_of(1);
    Key to = key_of(77);

    explicit Rig(std::uint64_t blocks, bool async, std::uint32_t mib_per_s = 0,
                 std::size_t in_flight = 2, std::uint32_t block = bs,
                 std::uint64_t region_bytes = region) {
        auto s = std::make_unique<MemBackend>(blocks * block, async);
        auto t = std::make_unique<MemBackend>(blocks * block, async);
        source = s.get();
        target = t.get();
        auto c = blk::VolumeCopier::create({.source = std::move(s),
                                            .target = std::move(t),
                                            .logical_block_size = block,
                                            .region_bytes = region_bytes,
                                            .max_in_flight = in_flight,
                                            .mib_per_s = mib_per_s,
                                            .max_tries = 3,
                                            .retry_backoff = 1s,
                                            .clock = [this] { return now; }});
        BOOST_REQUIRE(c.has_value());
        copier = std::move(*c);
    }
    auto start() -> void { BOOST_REQUIRE(copier->load_keys(from, to).has_value()); }
    // Polls until the copy ends or `rounds` pass; moves the clock 1 s a round.
    auto run(int rounds = 1000) -> void {
        for (int i = 0; i < rounds; ++i) {
            const auto st = copier->state();
            if (st == blk::CopyState::completed || st == blk::CopyState::failed) {
                return;
            }
            if (!copier->poll()) {
                now += 1s;
            }
        }
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(volume_copier, *utf::timeout(ak::test::unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(rewraps_every_written_block_and_skips_the_rest) {
    for (const bool async : {false, true}) {
        BOOST_TEST_INFO("async " << async);
        Rig rig{43, async};  // five whole regions and a short one of 3 blocks
        const std::vector<std::uint64_t> written{0, 1, 2, 7, 8, 20, 21, 22, 23, 24, 41, 42};
        fill(*rig.source, rig.from, written);
        const auto before = rig.source->data;
        BOOST_TEST((rig.copier->state() == blk::CopyState::waiting_for_keys));
        BOOST_TEST(!rig.copier->poll());  // nothing without keys
        BOOST_TEST(rig.source->reads == 0U);
        rig.start();
        rig.run();
        BOOST_TEST_REQUIRE((rig.copier->state() == blk::CopyState::completed));
        for (std::uint64_t lba = 0; lba < 43; ++lba) {
            BOOST_TEST_INFO("block " << lba);
            const bool w = std::ranges::find(written, lba) != written.end();
            const auto got = read_plain(*rig.target, rig.to, lba);
            BOOST_TEST(got.has_value() == w);
            if (w && got) {
                BOOST_TEST((*got == plain_block(lba)));
            }
        }
        // The ciphertext changed with the key; the source never did.
        BOOST_TEST((rig.target->data != rig.source->data));
        BOOST_TEST((rig.source->data == before));
        // Runs of written blocks go as one write each: 0-2, 7-8 (two
        // regions: 7 and 8), 20-23 and 24 (a region boundary), 41-42.
        BOOST_TEST(rig.target->writes == 6U);
        BOOST_TEST(rig.target->flushes == 1U);
        const auto& p = rig.copier->progress();
        BOOST_TEST(p.total_bytes == 43U * bs);
        BOOST_TEST(p.done_bytes == p.total_bytes);
        BOOST_TEST(p.written_bytes == written.size() * bs);
        BOOST_TEST(p.retries == 0U);
        BOOST_TEST((rig.copier->failure() == blk::CopyFailure::none));
    }
}

BOOST_AUTO_TEST_CASE(copies_4k_blocks_at_their_own_numbers) {
    Rig rig{12, true, 0, 2, blk::data_unit_4k, 4 * blk::data_unit_4k};
    fill(*rig.source, rig.from, {0, 5, 11}, blk::data_unit_4k);
    rig.start();
    rig.run();
    BOOST_TEST_REQUIRE((rig.copier->state() == blk::CopyState::completed));
    for (const std::uint64_t lba : {0U, 5U, 11U}) {
        BOOST_TEST((read_plain(*rig.target, rig.to, lba, blk::data_unit_4k) ==
                    plain_block(lba, blk::data_unit_4k)));
    }
    BOOST_TEST(!read_plain(*rig.target, rig.to, 6, blk::data_unit_4k).has_value());
}

BOOST_AUTO_TEST_CASE(a_poll_starts_at_most_max_in_flight_regions) {
    // Synchronous backends finish inside their submits; the copier still
    // hands the role thread back after max_in_flight regions.
    Rig rig{64, false, 0, 2};
    fill(*rig.source, rig.from, {0, 63});
    rig.start();
    BOOST_TEST(rig.copier->poll());  // more to do at once
    BOOST_TEST(rig.source->reads == 2U);
    BOOST_TEST(rig.copier->progress().done_bytes == 2U * region);
    int polls = 1;
    while (rig.copier->poll()) {
        ++polls;
    }
    BOOST_TEST(polls == 3);  // 8 regions, 2 a poll: the fourth starts the last and is false
    BOOST_TEST((rig.copier->state() == blk::CopyState::completed));
}

BOOST_AUTO_TEST_CASE(paces_regions_at_the_rate) {
    // 1 MiB/s and 4 KiB regions, one region of burst: however many slots
    // are free, a region starts only when the bucket is out of debt.
    Rig rig{8 * 64, true, 1, 64};  // 64 regions: 256 KiB, a quarter second
    rig.start();
    static_cast<void>(rig.copier->poll());
    BOOST_TEST(rig.source->reads == 2U);  // the burst, then one into debt
    static_cast<void>(rig.copier->poll());
    BOOST_TEST(rig.source->reads == 2U);  // no time has passed
    rig.now += 8ms;                       // two regions' worth
    static_cast<void>(rig.copier->poll());
    BOOST_TEST(rig.source->reads <= 5U);
    BOOST_TEST(rig.source->reads >= 3U);
    // Driven at 1 ms steps, it takes about a quarter second in all.
    const auto start = rig.now;
    for (int i = 0; i < 10000 && rig.copier->state() != blk::CopyState::completed; ++i) {
        static_cast<void>(rig.copier->poll());
        rig.now += 1ms;
    }
    BOOST_TEST((rig.copier->state() == blk::CopyState::completed));
    BOOST_TEST((rig.now - start >= 200ms));
    BOOST_TEST((rig.now - start <= 300ms));
}

BOOST_AUTO_TEST_CASE(retries_io_errors_then_succeeds) {
    Rig rig{24, true};
    fill(*rig.source, rig.from, {3, 12, 20});
    rig.source->read_faults.push_back({.lo = 0, .hi = region, .count = 2});
    rig.target->write_faults.push_back({.lo = 2 * region, .hi = 3 * region, .count = 1});
    rig.start();
    rig.run();
    BOOST_TEST_REQUIRE((rig.copier->state() == blk::CopyState::completed));
    BOOST_TEST(rig.copier->progress().retries == 3U);
    for (const std::uint64_t lba : {3U, 12U, 20U}) {
        BOOST_TEST((read_plain(*rig.target, rig.to, lba) == plain_block(lba)));
    }
}

BOOST_AUTO_TEST_CASE(fails_after_max_tries) {
    {
        Rig rig{24, true};
        fill(*rig.source, rig.from, {9});
        rig.source->read_faults.push_back({.lo = region, .hi = 2 * region, .count = 3});
        rig.start();
        rig.run();
        BOOST_TEST((rig.copier->state() == blk::CopyState::failed));
        BOOST_TEST((rig.copier->failure() == blk::CopyFailure::source_io));
        BOOST_TEST(rig.target->flushes == 0U);  // never completed
        BOOST_TEST(rig.copier->progress().done_bytes < rig.copier->progress().total_bytes);
        BOOST_TEST(!rig.copier->poll());  // stays failed and idle
    }
    {
        Rig rig{24, false};
        fill(*rig.source, rig.from, {17});
        rig.target->write_faults.push_back({.lo = 2 * region, .hi = 3 * region, .count = 9});
        rig.start();
        rig.run();
        BOOST_TEST((rig.copier->failure() == blk::CopyFailure::target_io));
    }
}

BOOST_AUTO_TEST_CASE(a_source_awaiting_hydration_fails_at_once) {
    Rig rig{24, true};
    rig.source->read_faults.push_back(
        {.lo = region, .hi = 2 * region, .error = blk::BackendError::not_hydrated, .count = 100});
    rig.start();
    rig.run();
    BOOST_TEST((rig.copier->state() == blk::CopyState::failed));
    BOOST_TEST((rig.copier->failure() == blk::CopyFailure::not_hydrated));
    BOOST_TEST(rig.copier->progress().retries == 0U);
}

BOOST_AUTO_TEST_CASE(completes_only_once_the_target_is_flushed) {
    Rig rig{16, true};
    fill(*rig.source, rig.from, {1});
    rig.target->fail_flush = true;
    rig.start();
    rig.run();
    BOOST_TEST((rig.copier->state() == blk::CopyState::failed));
    BOOST_TEST((rig.copier->failure() == blk::CopyFailure::target_io));
    BOOST_TEST(rig.copier->progress().done_bytes == rig.copier->progress().total_bytes);
}

BOOST_AUTO_TEST_CASE(cancelling_mid_copy_drops_pending_completions) {
    Rig rig{64, true};
    fill(*rig.source, rig.from, {0, 9, 40});
    rig.start();
    BOOST_TEST(!rig.copier->poll());
    BOOST_TEST(rig.source->reads == 2U);  // in flight, unanswered
    rig.copier.reset();                   // the backends go with it
}

BOOST_AUTO_TEST_CASE(refuses_bad_parameters_and_keys) {
    const auto make = [](std::uint64_t src, std::uint64_t dst, std::uint32_t block,
                         std::uint64_t region_bytes) {
        return blk::VolumeCopier::create({.source = std::make_unique<MemBackend>(src, false),
                                          .target = std::make_unique<MemBackend>(dst, false),
                                          .logical_block_size = block,
                                          .region_bytes = region_bytes,
                                          .max_in_flight = 1,
                                          .mib_per_s = 0,
                                          .max_tries = 1,
                                          .retry_backoff = 1s,
                                          .clock = {}});
    };
    BOOST_TEST((make(4096, 4096, 1024, 4096).error() == blk::CopyError::bad_block_size));
    BOOST_TEST((make(4096, 4096, bs, 0).error() == blk::CopyError::bad_region));
    BOOST_TEST((make(4096, 4096, bs, 700).error() == blk::CopyError::bad_region));
    BOOST_TEST((make(4096, 2048, bs, 4096).error() == blk::CopyError::bad_capacity));
    BOOST_TEST((make(0, 2048, bs, 4096).error() == blk::CopyError::bad_capacity));
    BOOST_TEST((make(1000, 2048, bs, 4096).error() == blk::CopyError::bad_capacity));
    BOOST_TEST(make(2048, 4096, bs, 4096).has_value());  // a larger target is fine
    BOOST_TEST((blk::VolumeCopier::create({}).error() == blk::CopyError::no_backend));

    Rig rig{8, false};
    Key weak{};  // equal halves
    BOOST_TEST((rig.copier->load_keys(weak, rig.to).error() == blk::CopyKeyError::rejected));
    BOOST_TEST((rig.copier->state() == blk::CopyState::waiting_for_keys));
    rig.start();
    BOOST_TEST((rig.copier->load_keys(rig.from, rig.to).error() == blk::CopyKeyError::occupied));
}

BOOST_AUTO_TEST_CASE(copies_a_local_volume_file) {
    // The local side as conversion opens it: a FileBackend.
    std::string tmpl = (std::filesystem::temp_directory_path() / "copier-XXXXXX").string();
    BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    const std::filesystem::path dir{tmpl};
    const blk::VolumeMetadata m{.volume_id = 5,
                                .owner_vm = 6,
                                .capacity_sectors = 64,
                                .logical_block_size = bs,
                                .wrapped_key = Bytes(32, std::byte{1}),
                                .image = std::nullopt};
    const Key from = key_of(3);
    const Key to = key_of(9);
    {
        auto f = blk::FileBackend::create(dir / "src.akv", m);
        BOOST_REQUIRE(f.has_value());
        auto c = blk::XtsCipher::create(from, bs);
        for (const std::uint64_t lba : {2U, 33U}) {
            auto b = plain_block(lba);
            BOOST_REQUIRE(c->encrypt(lba, b, b).has_value());
            BOOST_REQUIRE((*f)->write(lba * bs, b).has_value());
        }
    }
    auto src = blk::FileBackend::open(dir / "src.akv");
    BOOST_REQUIRE(src.has_value());
    auto dst = std::make_unique<MemBackend>(64 * bs, true);
    MemBackend* target = dst.get();
    auto copier = blk::VolumeCopier::create({.source = std::move(*src),
                                             .target = std::move(dst),
                                             .logical_block_size = bs,
                                             .region_bytes = region,
                                             .max_in_flight = 2,
                                             .mib_per_s = 0,
                                             .max_tries = 1,
                                             .retry_backoff = 1s,
                                             .clock = {}});
    BOOST_REQUIRE(copier.has_value());
    BOOST_REQUIRE((*copier)->load_keys(from, to).has_value());
    for (int i = 0; i < 100 && (*copier)->state() != blk::CopyState::completed; ++i) {
        static_cast<void>((*copier)->poll());
    }
    BOOST_TEST_REQUIRE(((*copier)->state() == blk::CopyState::completed));
    BOOST_TEST((read_plain(*target, to, 2) == plain_block(2)));
    BOOST_TEST((read_plain(*target, to, 33) == plain_block(33)));
    BOOST_TEST(!read_plain(*target, to, 3).has_value());
    BOOST_TEST((*copier)->progress().written_bytes == 2U * bs);
    copier->reset();
    std::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
