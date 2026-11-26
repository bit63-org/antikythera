// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 5: one hold replica on disk. The
// meta header and intent codecs (vectors; fuzz/fuzz_replica_meta.cpp
// fuzzes them), the store's data path, hydration, changed chunks and
// reflink detection, and crash consistency (Requirement 1.5): over
// MemFiles, a scenario is cut at every file operation and the unsynced
// writes are dropped or torn at random, then the replica reopens and
//
//   - the header is valid and its epoch is one that was set;
//   - every acknowledged write's data is there;
//   - a block reported bad lies inside an extent intents() returns, and a
//     block reported good holds data some write (or hydration) put there;
//   - every chunk written since the last freeze is still marked changed;
//   - a block an acknowledged write covered is no longer unhydrated;
//   - the replica takes new writes.

#define BOOST_TEST_MODULE hold_store_test
#include <boost/test/unit_test.hpp>

#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <map>
#include <optional>
#include <ostream>
#include <random>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "common/crc32c.hpp"
#include "hold/store/file_layer.hpp"
#include "hold/store/replica_meta.hpp"
#include "hold/store/replica_store.hpp"
#include "test_support.hpp"

namespace ak::hold::store {
auto operator<<(std::ostream& os, StoreError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, MetaError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, ChunkState s) -> std::ostream& {
    return os << static_cast<int>(s);
}
}  // namespace ak::hold::store

namespace {

namespace proto = ak::proto;
using namespace ak::hold::store;
using Bytes = std::vector<std::byte>;
namespace utf = boost::unit_test;

const std::filesystem::path root{"/srv/hold"};
const std::filesystem::path vdir = root / "vol-7.1";

auto make_meta(std::uint64_t blocks, std::uint32_t bs = proto::block_size_512,
               std::uint8_t shift = min_chunk_shift,
               proto::SourceKind kind = proto::SourceKind::none) -> ReplicaMeta {
    ReplicaMeta m;
    m.volume_id = 7;
    m.lineage_id = 9;
    m.replica_gen = 1;
    m.epoch = 1;
    m.role = proto::ReplicaRole::primary;
    m.capacity_blocks = blocks;
    m.block_size = bs;
    m.chunk_shift = shift;
    if (kind != proto::SourceKind::none) {
        m.source.kind = kind;
        m.source.store_id = 3;
        m.source.hydrate_mib_per_s = 50;
        m.source.manifest_name[0] = std::byte{'s'};
    }
    return m;
}

// `blocks` blocks of pseudo-random, never all-zero content.
auto content(std::uint64_t tag, std::uint32_t bs, std::uint64_t blocks = 1) -> Bytes {
    std::minstd_rand rng{static_cast<std::minstd_rand::result_type>((tag * 2654435761U) | 1U)};
    Bytes b(bs * blocks);
    for (auto& x : b) {
        x = static_cast<std::byte>(rng() & 0xFFU);
    }
    for (std::uint64_t i = 0; i < blocks; ++i) {
        b[i * bs] = std::byte{0x5A};
    }
    return b;
}

auto crcs_of(std::span<const std::byte> data, std::uint32_t bs) -> std::vector<std::uint32_t> {
    std::vector<std::uint32_t> out;
    for (std::size_t at = 0; at + bs <= data.size(); at += bs) {
        out.push_back(ak::crc32c::of(data.subspan(at, bs)));
    }
    return out;
}

auto block_of(const Bytes& b, std::uint32_t bs, std::uint64_t i) -> Bytes {
    return {b.begin() + static_cast<std::ptrdiff_t>(i * bs),
            b.begin() + static_cast<std::ptrdiff_t>((i + 1) * bs)};
}

auto block_range(const Bytes& b, std::uint32_t bs, std::uint64_t first, std::uint64_t n) -> Bytes {
    return {b.begin() + static_cast<std::ptrdiff_t>(first * bs),
            b.begin() + static_cast<std::ptrdiff_t>((first + n) * bs)};
}

// Holds the bytes a batch of ReplicaStore::Write spans points at.
class Batch {
public:
    explicit Batch(std::uint32_t bs) : _bs{bs} {}
    auto add(std::uint64_t seq, std::uint64_t lba, Bytes data, bool hydrate = false) -> Batch& {
        _data.push_back(std::move(data));
        _crcs.push_back(crcs_of(_data.back(), _bs));
        _writes.push_back({.seq = seq,
                           .lba = lba,
                           .data = _data.back(),
                           .crcs = _crcs.back(),
                           .hydrate = hydrate});
        return *this;
    }
    [[nodiscard]] auto writes() const -> std::span<const ReplicaStore::Write> { return _writes; }
    auto crcs(std::size_t i) -> std::vector<std::uint32_t>& { return _crcs[i]; }

private:
    std::uint32_t _bs;
    std::deque<Bytes> _data;
    std::deque<std::vector<std::uint32_t>> _crcs;
    std::vector<ReplicaStore::Write> _writes;
};

auto write_one(ReplicaStore& s, std::uint64_t seq, std::uint64_t lba, const Bytes& data)
    -> std::expected<void, StoreError> {
    Batch b{s.meta().block_size};
    b.add(seq, lba, data);
    return s.write(b.writes());
}

struct ReadResult {
    Bytes data;
    std::vector<std::uint32_t> crcs;
    std::vector<std::uint64_t> bad;
};

auto read_blocks(ReplicaStore& s, std::uint64_t lba, std::uint64_t blocks)
    -> std::expected<ReadResult, StoreError> {
    ReadResult r;
    r.data.resize(blocks * s.meta().block_size);
    r.crcs.resize(blocks);
    auto bad = s.read(lba, r.data, r.crcs);
    if (!bad) {
        return std::unexpected(bad.error());
    }
    r.bad = std::move(*bad);
    return r;
}

auto create(FileLayer& files, const ReplicaMeta& m) -> std::unique_ptr<ReplicaStore> {
    auto s = ReplicaStore::create(files, vdir, m);
    BOOST_TEST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto reopen(FileLayer& files) -> std::unique_ptr<ReplicaStore> {
    auto s = ReplicaStore::open(files, vdir);
    BOOST_TEST_REQUIRE(s.has_value());
    return std::move(*s);
}

}  // namespace

// ---- meta codec ------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(meta_codec)

BOOST_AUTO_TEST_CASE(round_trips, *utf::timeout(ak::test::unit_timeout_seconds)) {
    auto m = make_meta(1000, proto::block_size_4096, 22, proto::SourceKind::snapshot);
    m.epoch = 42;
    m.role = proto::ReplicaRole::joining;
    m.header_seq = 17;
    m.replica_gen = 5;
    m.source_blocks = 600;  // grown from 600 blocks
    const auto slot = encode_replica_meta(m);
    BOOST_TEST_REQUIRE(slot.has_value());
    BOOST_TEST(std::to_integer<int>((*slot)[0]) == 'A');
    BOOST_TEST(std::string(reinterpret_cast<const char*>(slot->data()), 8) == "AKREPLIC");
    const auto back = decode_replica_meta(*slot);
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((*back == m));
}

BOOST_AUTO_TEST_CASE(refuses_bad_fields, *utf::timeout(ak::test::unit_timeout_seconds)) {
    const auto good = make_meta(64);
    auto bad = [&](auto mutate) {
        auto m = good;
        mutate(m);
        const auto r = encode_replica_meta(m);
        return !r && r.error() == MetaError::bad_field;
    };
    BOOST_TEST(bad([](ReplicaMeta& m) { m.volume_id = 0; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.lineage_id = 0; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.replica_gen = 0; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.header_seq = 0; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.capacity_blocks = 0; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.capacity_blocks = max_capacity_blocks + 1; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.block_size = 1024; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.chunk_shift = min_chunk_shift - 1; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.chunk_shift = max_chunk_shift + 1; }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.role = static_cast<proto::ReplicaRole>(0); }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.role = static_cast<proto::ReplicaRole>(5); }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.source.kind = static_cast<proto::SourceKind>(3); }));
    BOOST_TEST(bad([](ReplicaMeta& m) { m.source.store_id = 1; }));  // with kind none
    BOOST_TEST(bad([](ReplicaMeta& m) { m.source_blocks = 8; }));    // with kind none
    const auto sourced = make_meta(64, proto::block_size_512, 12, proto::SourceKind::image);
    auto limit = [&](std::uint64_t n) {
        auto m = sourced;
        m.source_blocks = n;
        return encode_replica_meta(m).has_value();
    };
    BOOST_TEST(limit(0));
    BOOST_TEST(limit(63));
    BOOST_TEST(!limit(64));  // a source that covers everything is recorded as 0
    BOOST_TEST(encode_replica_meta(good).has_value());
}

BOOST_AUTO_TEST_CASE(decode_is_strict, *utf::timeout(ak::test::unit_timeout_seconds)) {
    const auto slot = *encode_replica_meta(make_meta(64));
    auto with = [&](std::size_t at, std::byte v) {
        auto s = slot;
        s[at] = v;
        return decode_replica_meta(s);
    };
    BOOST_TEST(decode_replica_meta(std::span{slot}.first(100)).error() == MetaError::truncated);
    BOOST_TEST(with(0, std::byte{0}).error() == MetaError::bad_magic);
    BOOST_TEST(with(8, std::byte{2}).error() == MetaError::bad_version);
    BOOST_TEST(with(0x10, std::byte{8}).error() == MetaError::bad_digest);  // volume_id
    BOOST_TEST(with(0xE0, std::byte{0}).error() == MetaError::bad_digest);  // the digest
    BOOST_TEST(with(0x100, std::byte{1}).error() == MetaError::nonzero_reserved);
    BOOST_TEST(with(meta_slot_size - 1, std::byte{1}).error() == MetaError::nonzero_reserved);
}

BOOST_AUTO_TEST_CASE(slots_pick_the_newest_valid, *utf::timeout(ak::test::unit_timeout_seconds)) {
    auto m1 = make_meta(64);
    auto m2 = m1;
    m2.header_seq = 2;
    m2.epoch = 9;
    Bytes both(2 * meta_slot_size);
    std::ranges::copy(*encode_replica_meta(m1), both.begin());
    std::ranges::copy(*encode_replica_meta(m2),
                      both.begin() + static_cast<std::ptrdiff_t>(meta_slot_size));
    BOOST_TEST(decode_meta_slots(both)->epoch == 9U);
    both[meta_slot_size + 0x20] ^= std::byte{1};  // a torn B
    BOOST_TEST(decode_meta_slots(both)->epoch == 1U);
    both[0x20] ^= std::byte{1};  // and A
    BOOST_TEST(!decode_meta_slots(both).has_value());
    BOOST_TEST(decode_meta_slots(std::span{both}.first(meta_slot_size)).error() ==
               MetaError::truncated);
}

BOOST_AUTO_TEST_CASE(layout_is_aligned, *utf::timeout(ak::test::unit_timeout_seconds)) {
    const auto l = layout(make_meta(10000, proto::block_size_512, 20));
    BOOST_TEST(l.checksums == 2 * meta_slot_size);
    BOOST_TEST(l.unhydrated == l.checksums + 40960);  // 10000 x 4 bytes, aligned
    BOOST_TEST(l.changed == l.unhydrated + 4096);
    BOOST_TEST(l.chunks == 5U);  // 5,120,000 bytes in MiB chunks
    BOOST_TEST(l.intents == l.changed + 4096);
    BOOST_TEST(l.end == l.intents + intent_ring_entries * intent_entry_size);
    for (const auto at : {l.checksums, l.unhydrated, l.changed, l.intents}) {
        BOOST_TEST(at % meta_align == 0U);
    }
    const auto big = layout(make_meta(max_capacity_blocks, proto::block_size_512, 30));
    BOOST_TEST(big.chunks == 16384U);  // 16 TiB in GiB chunks
}

BOOST_AUTO_TEST_CASE(intents_round_trip, *utf::timeout(ak::test::unit_timeout_seconds)) {
    const Intent i{.seq = 4097, .lba = 30, .blocks = 2};
    const auto e = encode_intent(i);
    BOOST_TEST((decode_intent(e, 32).value() == i));
    BOOST_TEST(decode_intent(std::span{e}.first(31), 32).error() == MetaError::truncated);
    BOOST_TEST(decode_intent(e, 31).error() == MetaError::bad_field);  // past the end
    auto torn = e;
    torn[9] ^= std::byte{1};
    BOOST_TEST(decode_intent(torn, 32).error() == MetaError::bad_digest);
    const Bytes empty(intent_entry_size);
    BOOST_TEST(decode_intent(empty, 32).error() == MetaError::bad_digest);
    BOOST_TEST(decode_intent(encode_intent({.seq = 0, .lba = 0, .blocks = 1}), 32).error() ==
               MetaError::bad_field);
    BOOST_TEST(decode_intent(encode_intent({.seq = 1, .lba = 0, .blocks = 0}), 32).error() ==
               MetaError::bad_field);
    BOOST_TEST(decode_intent(encode_intent({.seq = 1, .lba = ~0ULL, .blocks = 2}), 32).error() ==
               MetaError::bad_field);
    // Flag bit 0 marks a hydrate write; every other bit is reserved.
    const Intent hyd{.seq = 9, .lba = 4, .blocks = 2, .hydrate = true};
    BOOST_TEST((decode_intent(encode_intent(hyd), 32).value() == hyd));
    BOOST_TEST(!decode_intent(e, 32).value().hydrate);
    auto rsvd = e;
    rsvd[20] = std::byte{2};
    const auto crc = ak::crc32c::of(std::span{rsvd}.first(28));
    for (std::size_t k = 0; k < 4; ++k) {
        rsvd[28 + k] = static_cast<std::byte>((crc >> (8U * k)) & 0xFFU);
    }
    BOOST_TEST(decode_intent(rsvd, 32).error() == MetaError::nonzero_reserved);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- the store -------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(store)

BOOST_AUTO_TEST_CASE(creates_and_reopens, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    BOOST_TEST(replica_dir_name(7, 1) == "vol-7.1");
    const auto m = make_meta(64);
    {
        auto s = create(files, m);
        BOOST_TEST((s->meta() == m));
        BOOST_TEST(s->last_seq() == 0U);
        BOOST_TEST(s->intents().empty());
    }
    BOOST_TEST(files.contents(vdir / "data").size() == 64U * 512U);
    BOOST_TEST(files.contents(vdir / "meta").size() == layout(m).end);
    BOOST_TEST(ReplicaStore::create(files, vdir, m).error() == StoreError::exists);
    auto s = reopen(files);
    BOOST_TEST((s->meta() == m));
    BOOST_TEST(ReplicaStore::open(files, root / "vol-8.1").error() == StoreError::bad_meta);
    auto bad = m;
    bad.block_size = 1000;
    BOOST_TEST(ReplicaStore::create(files, root / "vol-7.2", bad).error() ==
               StoreError::bad_request);
}

BOOST_AUTO_TEST_CASE(refuses_files_of_the_wrong_size,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    create(files, make_meta(64));
    auto data = files.open(vdir / "data", false);
    BOOST_TEST_REQUIRE(data.has_value());
    BOOST_TEST_REQUIRE((*data)->truncate(63 * 512).has_value());
    BOOST_TEST(ReplicaStore::open(files, vdir).error() == StoreError::bad_meta);
    BOOST_TEST_REQUIRE((*data)->truncate(64 * 512).has_value());
    auto meta = files.open(vdir / "meta", false);
    BOOST_TEST_REQUIRE((*meta)->pwrite(0, Bytes(2 * meta_slot_size)).has_value());
    BOOST_TEST(ReplicaStore::open(files, vdir).error() == StoreError::bad_meta);
}

BOOST_AUTO_TEST_CASE(writes_and_reads, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    const auto a = content(1, 512, 3);
    const auto b = content(2, 512, 1);
    Batch batch{512};
    batch.add(1, 10, a).add(2, 11, b);
    BOOST_TEST_REQUIRE(s->write(batch.writes()).has_value());
    BOOST_TEST(s->last_seq() == 2U);
    const auto r = read_blocks(*s, 9, 5);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->bad.empty());
    BOOST_TEST((block_of(r->data, 512, 0) == Bytes(512)));  // never written: zeros
    BOOST_TEST(r->crcs[0] == 0U);
    BOOST_TEST((block_of(r->data, 512, 1) == block_of(a, 512, 0)));
    BOOST_TEST((block_of(r->data, 512, 2) == b));  // the later write wins
    BOOST_TEST((block_of(r->data, 512, 3) == block_of(a, 512, 2)));
    BOOST_TEST(r->crcs[2] == ak::crc32c::of(b));
    // Durable across a clean reopen.
    s.reset();
    s = reopen(files);
    BOOST_TEST(s->last_seq() == 2U);
    BOOST_TEST((read_blocks(*s, 11, 1)->data == b));
}

BOOST_AUTO_TEST_CASE(reports_corrupt_blocks, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    BOOST_TEST_REQUIRE(write_one(*s, 1, 4, content(1, 512, 4)).has_value());
    auto data = files.open(vdir / "data", false);
    BOOST_TEST_REQUIRE((*data)->pwrite((6 * 512) + 100, Bytes{std::byte{0xEE}}).has_value());
    BOOST_TEST_REQUIRE((*data)->pwrite(20 * 512, Bytes{std::byte{1}}).has_value());  // unwritten
    BOOST_TEST((read_blocks(*s, 0, 64)->bad == std::vector<std::uint64_t>{6, 20}));
}

BOOST_AUTO_TEST_CASE(refuses_bad_writes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    const auto two = content(1, 512, 2);
    auto refused = [&](std::uint64_t seq, std::uint64_t lba, const Bytes& d) {
        return write_one(*s, seq, lba, d).error();
    };
    BOOST_TEST(refused(1, 63, two) == StoreError::bad_request);
    BOOST_TEST(refused(1, 64, content(1, 512)) == StoreError::bad_request);
    BOOST_TEST(refused(1, ~0ULL, content(1, 512)) == StoreError::bad_request);
    BOOST_TEST(refused(1, 0, Bytes(100)) == StoreError::bad_request);
    BOOST_TEST(refused(1, 0, Bytes{}) == StoreError::bad_request);
    {
        const auto crcs = crcs_of(two, 512);
        const ReplicaStore::Write w{
            .seq = 1, .lba = 0, .data = two, .crcs = std::span{crcs}.first(1)};
        BOOST_TEST(s->write(std::span{&w, 1}).error() == StoreError::bad_request);
    }
    {
        Batch b{512};
        b.add(1, 0, two);
        b.crcs(0)[1] ^= 1U;
        BOOST_TEST(s->write(b.writes()).error() == StoreError::bad_crc);
    }
    BOOST_TEST(refused(0, 0, two) == StoreError::bad_seq);
    BOOST_TEST_REQUIRE(write_one(*s, 5, 0, two).has_value());
    BOOST_TEST(refused(5, 0, two) == StoreError::bad_seq);
    BOOST_TEST(refused(4, 0, two) == StoreError::bad_seq);
    {
        Batch b{512};
        b.add(7, 0, two).add(6, 2, two);
        BOOST_TEST(s->write(b.writes()).error() == StoreError::bad_seq);
    }
    // Nothing refused reached the disk.
    BOOST_TEST(s->last_seq() == 5U);
    BOOST_TEST((read_blocks(*s, 0, 2)->data == two));
    BOOST_TEST(s->intents().size() == 1U);
}

BOOST_AUTO_TEST_CASE(seqs_run_at_most_a_ring_ahead_of_commit,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    const auto d = content(1, 512);
    BOOST_TEST(write_one(*s, intent_ring_entries + 1, 0, d).error() == StoreError::ring_full);
    BOOST_TEST_REQUIRE(write_one(*s, intent_ring_entries, 0, d).has_value());
    BOOST_TEST(write_one(*s, intent_ring_entries + 1, 0, d).error() == StoreError::ring_full);
    s->set_commit(1);
    BOOST_TEST_REQUIRE(write_one(*s, intent_ring_entries + 1, 0, d).has_value());
    // set_commit never runs past what was written, nor goes back.
    s->set_commit(1'000'000);
    BOOST_TEST(s->commit_seq() == intent_ring_entries + 1);
    s->set_commit(3);
    BOOST_TEST(s->commit_seq() == intent_ring_entries + 1);
    BOOST_TEST(s->intents().empty());
}

BOOST_AUTO_TEST_CASE(reopen_waits_for_the_commit_point,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    for (std::uint64_t seq = 1; seq <= 5000; ++seq) {
        BOOST_TEST_REQUIRE(write_one(*s, seq, seq % 60, content(seq, 512, 2)).has_value());
        s->set_commit(seq - 1);
    }
    BOOST_TEST((s->intents() == std::vector<Intent>{{.seq = 5000, .lba = 20, .blocks = 2}}));
    s.reset();
    s = reopen(files);
    BOOST_TEST(s->last_seq() == 5000U);
    BOOST_TEST(s->commit_seq() == 0U);
    const auto torn = s->intents();
    BOOST_TEST(torn.size() == intent_ring_entries);  // every slot holds a write
    BOOST_TEST(torn.front().seq == 5000 - intent_ring_entries + 1);
    BOOST_TEST(torn.back().seq == 5000U);
    BOOST_TEST(write_one(*s, 5001, 0, content(1, 512)).error() == StoreError::ring_full);
    s->set_commit(4999);
    BOOST_TEST(s->intents().size() == 1U);
    BOOST_TEST_REQUIRE(write_one(*s, 5001, 0, content(1, 512)).has_value());
}

BOOST_AUTO_TEST_CASE(rewrites_writes_still_in_the_ring,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    const auto a = content(1, 512, 2);
    const auto b = content(2, 512, 1);
    BOOST_TEST_REQUIRE(write_one(*s, 1, 4, a).has_value());
    BOOST_TEST_REQUIRE(write_one(*s, 2, 8, b).has_value());
    s->set_commit(1);
    // A crash tore seq 2: its data and its checksum are both gone.
    auto data = files.open(vdir / "data", false);
    BOOST_TEST_REQUIRE((*data)->pwrite(8 * 512, Bytes(512)).has_value());
    BOOST_TEST((read_blocks(*s, 8, 1)->bad == std::vector<std::uint64_t>{8}));

    auto refused = [&](std::uint64_t seq, std::uint64_t lba, const Bytes& d) {
        Batch batch{512};
        batch.add(seq, lba, d);
        return s->rewrite(batch.writes()).error();
    };
    BOOST_TEST(refused(1, 4, a) == StoreError::bad_seq);  // committed
    BOOST_TEST(refused(3, 8, b) == StoreError::bad_seq);  // never written
    BOOST_TEST(refused(2, 9, b) == StoreError::bad_seq);  // not where the ring says
    BOOST_TEST(refused(2, 8, a) == StoreError::bad_seq);  // nor its length
    BOOST_TEST(refused(2, 64, b) == StoreError::bad_request);
    {
        Batch batch{512};
        batch.add(2, 8, b);
        batch.crcs(0)[0] ^= 1U;
        BOOST_TEST(s->rewrite(batch.writes()).error() == StoreError::bad_crc);
    }
    BOOST_TEST((read_blocks(*s, 8, 1)->bad == std::vector<std::uint64_t>{8}));

    Batch again{512};
    again.add(2, 8, b);
    BOOST_TEST_REQUIRE(s->rewrite(again.writes()).has_value());
    const auto r = read_blocks(*s, 8, 1);
    BOOST_TEST(r->bad.empty());
    BOOST_TEST((r->data == b));
    // No new intent, and the seqs stand.
    BOOST_TEST(s->last_seq() == 2U);
    BOOST_TEST((s->intents() == std::vector<Intent>{{.seq = 2, .lba = 8, .blocks = 1}}));
    // Durable: a crash now loses nothing.
    s.reset();
    files.crash(1);
    s = reopen(files);
    BOOST_TEST(read_blocks(*s, 8, 1)->bad.empty());
    BOOST_TEST((read_blocks(*s, 8, 1)->data == b));
}

BOOST_AUTO_TEST_CASE(copies_blocks_as_another_replica_holds_them,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    BOOST_TEST(!*s->written(0, 64));
    const auto good = content(1, 512, 2);
    auto crcs = crcs_of(good, 512);
    crcs[1] ^= 1U;  // the source's second block is bad: it stays bad here
    BOOST_TEST_REQUIRE(s->copy(10, good, crcs).has_value());
    BOOST_TEST((read_blocks(*s, 10, 2)->data == good));
    BOOST_TEST((read_blocks(*s, 10, 2)->bad == std::vector<std::uint64_t>{11}));
    BOOST_TEST(*s->written(8, 4));
    BOOST_TEST(!*s->written(0, 10));
    BOOST_TEST(!*s->written(12, 52));
    // Never-written blocks copy as such.
    BOOST_TEST_REQUIRE(s->copy(20, Bytes(512), std::vector<std::uint32_t>{0}).has_value());
    BOOST_TEST(read_blocks(*s, 20, 1)->bad.empty());
    BOOST_TEST(!*s->written(20, 1));
    BOOST_TEST(s->last_seq() == 0U);  // no intent, no seq
    BOOST_TEST(s->copy(63, good, crcs_of(good, 512)).error() == StoreError::bad_request);
    BOOST_TEST(s->written(64, 1).error() == StoreError::bad_request);
    BOOST_TEST(s->written(0, 0).error() == StoreError::bad_request);
    // Durable: a crash keeps it.
    s.reset();
    files.crash(3);
    s = reopen(files);
    BOOST_TEST((read_blocks(*s, 10, 1)->data == block_of(good, 512, 0)));
}

BOOST_AUTO_TEST_CASE(rebases_onto_a_new_stream, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    for (std::uint64_t seq = 1; seq <= 50; ++seq) {
        BOOST_TEST_REQUIRE(write_one(*s, seq, seq % 60, content(seq, 512)).has_value());
    }
    s->set_commit(40);
    BOOST_TEST(s->intents().size() == 10U);
    // A new primary's stream is at 7.
    BOOST_TEST_REQUIRE(s->rebase(7).has_value());
    BOOST_TEST(s->last_seq() == 7U);
    BOOST_TEST(s->commit_seq() == 7U);
    BOOST_TEST(s->intents().empty());
    BOOST_TEST_REQUIRE(write_one(*s, 8, 0, content(99, 512)).has_value());
    BOOST_TEST((read_blocks(*s, 50, 1)->data == content(50, 512)));  // data stays
    // The emptied ring is durable: only seq 8 comes back.
    s.reset();
    files.crash(5);
    s = reopen(files);
    BOOST_TEST(s->last_seq() == 8U);
    BOOST_TEST((s->intents() == std::vector<Intent>{{.seq = 8, .lba = 0, .blocks = 1}}));
}

BOOST_AUTO_TEST_CASE(records_epochs_in_alternate_slots,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64));
    BOOST_TEST_REQUIRE(s->set_epoch(2, proto::ReplicaRole::secondary).has_value());
    BOOST_TEST_REQUIRE(s->set_epoch(3, proto::ReplicaRole::leaving).has_value());
    BOOST_TEST(s->meta().header_seq == 3U);
    const auto meta = files.contents(vdir / "meta");
    const auto a = decode_replica_meta(std::span{meta}.first(meta_slot_size));
    const auto b = decode_replica_meta(std::span{meta}.subspan(meta_slot_size, meta_slot_size));
    BOOST_TEST_REQUIRE((a.has_value() && b.has_value()));
    BOOST_TEST(a->epoch == 3U);
    BOOST_TEST(b->epoch == 2U);
    s.reset();
    s = reopen(files);
    BOOST_TEST(s->meta().epoch == 3U);
    BOOST_TEST((s->meta().role == proto::ReplicaRole::leaving));
    BOOST_TEST_REQUIRE(s->set_epoch(4, proto::ReplicaRole::primary).has_value());
    s.reset();
    BOOST_TEST(reopen(files)->meta().epoch == 4U);
}

BOOST_AUTO_TEST_CASE(tracks_changed_chunks, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64, proto::block_size_512, 12));  // 8 blocks a chunk
    BOOST_TEST(s->changed_chunks()->empty());
    BOOST_TEST_REQUIRE(write_one(*s, 1, 7, content(1, 512, 2)).has_value());   // chunks 0, 1
    BOOST_TEST_REQUIRE(write_one(*s, 2, 63, content(2, 512, 1)).has_value());  // chunk 7
    BOOST_TEST((s->changed_chunks().value() == std::vector<std::uint64_t>{0, 1, 7}));
    BOOST_TEST_REQUIRE(s->flush().has_value());
    s.reset();
    s = reopen(files);
    BOOST_TEST((s->changed_chunks().value() == std::vector<std::uint64_t>{0, 1, 7}));
    s->set_commit(2);
    BOOST_TEST_REQUIRE(s->clear_changed().has_value());
    BOOST_TEST(s->changed_chunks()->empty());
    BOOST_TEST_REQUIRE(write_one(*s, 3, 40, content(3, 512, 1)).has_value());
    BOOST_TEST((s->changed_chunks().value() == std::vector<std::uint64_t>{5}));
}

BOOST_AUTO_TEST_CASE(hydrates_restored_blocks, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    // 21 blocks, 8 a chunk: chunks 0 and 1 full, chunk 2 holds 5.
    auto s = create(files, make_meta(21, proto::block_size_512, 12, proto::SourceKind::snapshot));
    for (std::uint64_t c = 0; c < 3; ++c) {
        BOOST_TEST(s->chunk_state(c).value() == ChunkState::unhydrated);
    }
    BOOST_TEST(s->chunk_state(3).error() == StoreError::bad_request);
    BOOST_TEST(s->unhydrated(20).value());
    BOOST_TEST(s->unhydrated(21).error() == StoreError::bad_request);
    BOOST_TEST(read_blocks(*s, 0, 1).error() == StoreError::not_hydrated);
    BOOST_TEST(s->unhydrated_blocks() == 21U);

    const auto src = content(100, 512, 21);
    const auto part = [&](std::uint64_t lba, std::uint64_t n) {
        return Bytes{src.begin() + static_cast<std::ptrdiff_t>(lba * 512),
                     src.begin() + static_cast<std::ptrdiff_t>((lba + n) * 512)};
    };
    // An ordinary write hydrates the blocks it covers.
    const auto w = content(1, 512, 2);
    BOOST_TEST_REQUIRE(write_one(*s, 1, 2, w).has_value());
    BOOST_TEST(s->chunk_state(0).value() == ChunkState::partial);
    BOOST_TEST(!s->unhydrated(2).value());
    // HYDRATE_FILL fills only what still awaits hydration.
    BOOST_TEST(s->hydrate(0, part(0, 8), crcs_of(part(0, 8), 512)).value() == 6U);
    BOOST_TEST(s->chunk_state(0).value() == ChunkState::hydrated);
    BOOST_TEST(s->hydrate(0, part(0, 8), crcs_of(part(0, 8), 512)).value() == 0U);
    const auto r = read_blocks(*s, 0, 8);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->bad.empty());
    BOOST_TEST((block_of(r->data, 512, 1) == block_of(src, 512, 1)));
    BOOST_TEST((block_of(r->data, 512, 2) == block_of(w, 512, 0)));  // the write stays
    // The short tail chunk.
    BOOST_TEST(s->hydrate(18, part(18, 2), crcs_of(part(18, 2), 512)).value() == 2U);
    BOOST_TEST(s->chunk_state(2).value() == ChunkState::partial);
    BOOST_TEST(s->hydrate(16, part(16, 5), crcs_of(part(16, 5), 512)).value() == 3U);
    BOOST_TEST(s->chunk_state(2).value() == ChunkState::hydrated);
    BOOST_TEST(s->chunk_state(1).value() == ChunkState::unhydrated);
    BOOST_TEST(s->unhydrated_blocks() == 8U);  // chunk 1 alone
    // Bad input changes nothing.
    auto crcs = crcs_of(part(8, 1), 512);
    crcs[0] ^= 1U;
    BOOST_TEST(s->hydrate(8, part(8, 1), crcs).error() == StoreError::bad_crc);
    BOOST_TEST(s->hydrate(20, part(19, 2), crcs_of(part(19, 2), 512)).error() ==
               StoreError::bad_request);
    BOOST_TEST(s->unhydrated(8).value());
    BOOST_TEST(s->unhydrated_blocks() == 8U);
    // The count survives a reopen (counted from the bitmap).
    BOOST_TEST_REQUIRE(s->flush().has_value());
    s.reset();
    s = reopen(files);
    BOOST_TEST(s->unhydrated_blocks() == 8U);
    // Hydration is not a write: chunks stay unchanged.
    BOOST_TEST((s->changed_chunks().value() == std::vector<std::uint64_t>{0}));
    // A volume without a source has nothing to hydrate.
    MemFiles plain;
    auto p = create(plain, make_meta(21));
    BOOST_TEST(p->hydrate(0, part(0, 2), crcs_of(part(0, 2), 512)).value() == 0U);
    BOOST_TEST(p->chunk_state(0).value() == ChunkState::hydrated);
    BOOST_TEST(!p->unhydrated(0).value());
    BOOST_TEST(p->unhydrated_blocks() == 0U);
}

BOOST_AUTO_TEST_CASE(hydrate_writes_fill_only_unwritten_blocks,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(24, proto::block_size_512, 12, proto::SourceKind::image));
    const auto src = content(100, 512, 24);
    const auto w1 = content(1, 512, 1);
    const auto w3 = content(3, 512, 1);
    // One batch: a write to block 1, a hydrate write of 0-3, then a write
    // to block 2. The hydrate write stores blocks 0, 2 and 3 (block 1 was
    // written before it); the later write still wins block 2.
    Batch b{512};
    b.add(1, 1, w1);
    b.add(2, 0, block_range(src, 512, 0, 4), true);
    b.add(3, 2, w3);
    BOOST_TEST_REQUIRE(s->write(b.writes()).has_value());
    BOOST_TEST(s->last_seq() == 3U);
    const auto r = read_blocks(*s, 0, 4);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->bad.empty());
    BOOST_TEST((block_of(r->data, 512, 0) == block_of(src, 512, 0)));
    BOOST_TEST((block_of(r->data, 512, 1) == w1));
    BOOST_TEST((block_of(r->data, 512, 2) == w3));
    BOOST_TEST((block_of(r->data, 512, 3) == block_of(src, 512, 3)));
    // Logged like any write, flagged as a hydrate write.
    const auto in = s->intents();
    BOOST_TEST_REQUIRE(in.size() == 3U);
    BOOST_TEST(in[1].hydrate);
    BOOST_TEST(!in[0].hydrate);
    // Hydrating again stores nothing over the guest's later writes.
    const auto w5 = content(5, 512, 1);
    BOOST_TEST_REQUIRE(write_one(*s, 4, 3, w5).has_value());
    Batch again{512};
    again.add(5, 0, block_range(src, 512, 0, 8), true);
    BOOST_TEST_REQUIRE(s->write(again.writes()).has_value());
    BOOST_TEST((read_blocks(*s, 3, 1)->data == w5));
    BOOST_TEST((read_blocks(*s, 7, 1)->data == block_of(src, 512, 7)));
    BOOST_TEST(s->unhydrated(8).value());
    // Hydration changes no chunk; the guest's writes do (chunk 0).
    BOOST_TEST((s->changed_chunks().value() == std::vector<std::uint64_t>{0}));
    // On a volume without a source a hydrate write stores nothing.
    MemFiles plain;
    auto p = create(plain, make_meta(24));
    Batch hp{512};
    hp.add(1, 0, block_range(src, 512, 0, 2), true);
    BOOST_TEST_REQUIRE(p->write(hp.writes()).has_value());
    BOOST_TEST((read_blocks(*p, 0, 2)->data == Bytes(1024)));
}

BOOST_AUTO_TEST_CASE(reopens_a_hydrate_write_that_lost_its_checksums,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    const auto src = content(100, 512, 24);
    const auto w = content(1, 512, 1);
    std::size_t lost = 0;
    for (std::uint64_t seed = 1; seed <= 40; ++seed) {
        BOOST_TEST_INFO("seed " << seed);
        MemFiles files;
        auto s = create(files, make_meta(24, proto::block_size_512, 12, proto::SourceKind::image));
        // Block 9 written by the guest, then a hydrate write of 8-11;
        // nothing syncs meta after it, so a crash may lose its checksums
        // and cleared bits.
        BOOST_TEST_REQUIRE(write_one(*s, 1, 9, w).has_value());
        Batch b{512};
        b.add(2, 8, block_range(src, 512, 8, 4), true);
        BOOST_TEST_REQUIRE(s->write(b.writes()).has_value());
        s.reset();
        files.crash(seed);
        auto o = ReplicaStore::open(files, vdir);
        BOOST_TEST_REQUIRE(o.has_value());
        s = std::move(*o);
        // The guest's block counts as written (its intent says so); a
        // hydrated block with no checksum awaits hydration again.
        BOOST_TEST(!s->unhydrated(9).value());
        for (const std::uint64_t lba : {8U, 10U, 11U}) {
            lost += s->unhydrated(lba).value() ? 1U : 0U;
        }
        // The resend stores what awaits hydration again; a block whose
        // checksum tore reads bad, for a peer to repair.
        s->set_commit(1);
        BOOST_TEST_REQUIRE(s->rewrite(b.writes()).has_value());
        for (const std::uint64_t lba : {8U, 10U, 11U}) {
            BOOST_TEST_INFO("block " << lba);
            BOOST_TEST(!s->unhydrated(lba).value());
            const auto r = read_blocks(*s, lba, 1);
            BOOST_TEST_REQUIRE(r.has_value());
            if (r->bad.empty()) {
                BOOST_TEST((r->data == block_of(src, 512, lba)));
            }
        }
        const auto g = read_blocks(*s, 9, 1);
        BOOST_TEST_REQUIRE(g.has_value());
        if (g->bad.empty()) {
            BOOST_TEST((g->data == w));  // never the image's copy
        }
    }
    BOOST_TEST(lost > 0U);  // some crash lost a hydrated block's checksum
}

BOOST_AUTO_TEST_CASE(grows_in_place, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(64, proto::block_size_512, 12));  // 8 blocks a chunk
    const auto a = content(1, 512, 2);
    const auto b = content(2, 512, 1);
    BOOST_TEST_REQUIRE(write_one(*s, 1, 7, a).has_value());      // chunks 0, 1
    BOOST_TEST_REQUIRE(write_one(*s, 2, 63, b).has_value());     // chunk 7, the last
    s->set_commit(1);                                            // seq 2 stays an intent
    BOOST_TEST(s->grow(32).error() == StoreError::bad_request);  // never shrinks
    BOOST_TEST(s->grow(max_capacity_blocks + 1).error() == StoreError::bad_request);
    BOOST_TEST_REQUIRE(s->grow(64).has_value());  // the same: no-op
    BOOST_TEST_REQUIRE(s->grow(200).has_value());
    BOOST_TEST(s->meta().capacity_blocks == 200U);
    BOOST_TEST(s->meta().header_seq == 2U);
    BOOST_TEST(!files.exists(vdir / "meta.new"));
    BOOST_TEST(files.contents(vdir / "data").size() == 200U * 512U);
    BOOST_TEST(files.contents(vdir / "meta").size() == layout(s->meta()).end);
    const auto check = [&](ReplicaStore& r) {
        const auto old = read_blocks(r, 6, 3);
        BOOST_TEST_REQUIRE(old.has_value());
        BOOST_TEST(old->bad.empty());
        BOOST_TEST((block_of(old->data, 512, 1) == block_of(a, 512, 0)));
        BOOST_TEST((read_blocks(r, 63, 1)->data == b));
        const auto fresh = read_blocks(r, 64, 136);  // the new blocks: never written
        BOOST_TEST_REQUIRE(fresh.has_value());
        BOOST_TEST(fresh->bad.empty());
        BOOST_TEST((fresh->data == Bytes(136 * 512)));
        BOOST_TEST((r.changed_chunks().value() == std::vector<std::uint64_t>{0, 1, 7}));
    };
    check(*s);
    BOOST_TEST((s->intents() == std::vector<Intent>{{.seq = 2, .lba = 63, .blocks = 1}}));
    // The new capacity takes writes, and everything survives a reopen.
    const auto c = content(3, 512, 1);
    BOOST_TEST_REQUIRE(write_one(*s, 3, 199, c).has_value());
    BOOST_TEST(write_one(*s, 4, 200, c).error() == StoreError::bad_request);
    BOOST_TEST_REQUIRE(s->flush().has_value());
    s.reset();
    s = reopen(files);
    BOOST_TEST(s->meta().capacity_blocks == 200U);
    BOOST_TEST((read_blocks(*s, 199, 1)->data == c));
    BOOST_TEST(s->last_seq() == 3U);
    BOOST_TEST((s->changed_chunks().value() == std::vector<std::uint64_t>{0, 1, 7, 24}));
}

BOOST_AUTO_TEST_CASE(grows_a_restored_volume, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    auto s = create(files, make_meta(21, proto::block_size_512, 12, proto::SourceKind::snapshot));
    const auto src = content(100, 512, 8);
    BOOST_TEST(s->hydrate(0, src, crcs_of(src, 512)).value() == 8U);
    BOOST_TEST_REQUIRE(s->grow(40).has_value());
    BOOST_TEST(s->meta().source_blocks == 21U);
    BOOST_TEST_REQUIRE(s->grow(50).has_value());
    BOOST_TEST(s->meta().source_blocks == 21U);  // still where the source ends
    BOOST_TEST(!s->past_source(20));
    BOOST_TEST(s->past_source(21));
    // What awaited hydration still does; the added blocks are past the
    // source, so they read as never written rather than unhydrated.
    BOOST_TEST(!s->unhydrated(7).value());
    BOOST_TEST(s->unhydrated(8).value());
    BOOST_TEST(s->unhydrated(20).value());
    BOOST_TEST(!s->unhydrated(21).value());
    BOOST_TEST(s->unhydrated_blocks() == 13U);                     // a grow adds nothing to fill
    BOOST_TEST(s->chunk_state(2).value() == ChunkState::partial);  // blocks 16-20 of 16-23
    BOOST_TEST(s->chunk_state(4).value() == ChunkState::hydrated);
    BOOST_TEST((read_blocks(*s, 0, 8)->data == src));
    const auto tail = read_blocks(*s, 21, 29);
    BOOST_TEST_REQUIRE(tail.has_value());
    BOOST_TEST(tail->bad.empty());
    BOOST_TEST(read_blocks(*s, 20, 1).error() == StoreError::not_hydrated);
    // A hydrated block of the source with zeros and no checksum is torn,
    // not unwritten: the zeros past the source do not change that.
    auto data = files.open(vdir / "data", false);
    BOOST_TEST_REQUIRE((*data)->pwrite(0, Bytes(512)).has_value());
    auto meta = files.open(vdir / "meta", false);
    BOOST_TEST_REQUIRE((*meta)->pwrite(layout(s->meta()).checksums, Bytes(4)).has_value());
    BOOST_TEST((read_blocks(*s, 0, 1)->bad == std::vector<std::uint64_t>{0}));
}

BOOST_AUTO_TEST_CASE(grows_on_a_real_filesystem, *utf::timeout(ak::test::unit_timeout_seconds)) {
    PosixFiles files;
    const auto dir =
        std::filesystem::temp_directory_path() / ("ak-hold-grow-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto rdir = dir / "vol-7.1";
    {
        auto s = ReplicaStore::create(files, rdir, make_meta(64, proto::block_size_4096));
        BOOST_TEST_REQUIRE(s.has_value());
        BOOST_TEST_REQUIRE(write_one(**s, 1, 63, content(1, 4096, 1)).has_value());
        BOOST_TEST_REQUIRE((*s)->grow(1000).has_value());
        BOOST_TEST(!std::filesystem::exists(rdir / "meta.new"));
        BOOST_TEST(std::filesystem::file_size(rdir / "data") == 1000U * 4096U);
    }
    auto s = ReplicaStore::open(files, rdir);
    BOOST_TEST_REQUIRE(s.has_value());
    BOOST_TEST((*s)->meta().capacity_blocks == 1000U);
    BOOST_TEST((read_blocks(**s, 63, 1)->data == content(1, 4096, 1)));
    std::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(detects_reflinks, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles with{true};
    BOOST_TEST(create(with, make_meta(8))->reflink());
    BOOST_TEST(!with.exists(vdir / ".reflink-probe"));
    BOOST_TEST(reopen(with)->reflink());
    MemFiles without{false};
    BOOST_TEST(!create(without, make_meta(8))->reflink());
}

BOOST_AUTO_TEST_CASE(destroys_the_directory, *utf::timeout(ak::test::unit_timeout_seconds)) {
    MemFiles files;
    create(files, make_meta(8));
    BOOST_TEST(files.exists(vdir / "data"));
    BOOST_TEST_REQUIRE(ReplicaStore::destroy(files, vdir).has_value());
    BOOST_TEST(!files.exists(vdir));
    BOOST_TEST(!files.exists(vdir / "meta"));
    BOOST_TEST(ReplicaStore::open(files, vdir).error() == StoreError::bad_meta);
}

BOOST_AUTO_TEST_CASE(runs_on_a_real_filesystem, *utf::timeout(ak::test::unit_timeout_seconds)) {
    const auto base =
        std::filesystem::temp_directory_path() / ("ak-hold-store-" + std::to_string(::getpid()));
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    const auto dir = base / replica_dir_name(7, 1);
    PosixFiles files;
    const auto d = content(1, 4096, 3);
    {
        auto s = ReplicaStore::create(files, dir, make_meta(256, proto::block_size_4096, 16));
        BOOST_TEST_REQUIRE(s.has_value());
        BOOST_TEST(!std::filesystem::exists(dir / ".reflink-probe"));
        BOOST_TEST(std::filesystem::file_size(dir / "data") == 256U * 4096U);
        BOOST_TEST(ReplicaStore::create(files, dir, make_meta(256)).error() == StoreError::exists);
        BOOST_TEST_REQUIRE(write_one(**s, 1, 100, d).has_value());
        BOOST_TEST_REQUIRE((*s)->set_epoch(2, proto::ReplicaRole::secondary).has_value());
    }
    {
        auto s = ReplicaStore::open(files, dir);
        BOOST_TEST_REQUIRE(s.has_value());
        BOOST_TEST((*s)->meta().epoch == 2U);
        const auto r = read_blocks(**s, 99, 5);
        BOOST_TEST_REQUIRE(r.has_value());
        BOOST_TEST(r->bad.empty());
        BOOST_TEST((Bytes{r->data.begin() + 4096, r->data.begin() + (4 * 4096)} == d));
    }
    BOOST_TEST_REQUIRE(ReplicaStore::destroy(files, dir).has_value());
    BOOST_TEST(!std::filesystem::exists(dir));
    std::filesystem::remove_all(base);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- crash consistency -----------------------------------------------------

namespace {

struct Op {
    enum class Kind : std::uint8_t {
        write,
        epoch,
        flush,
        clear,
        hydrate
    };
    struct W {
        std::uint64_t seq;
        std::uint64_t lba;
        Bytes data;
        bool hydrate{false};  // the source's blocks, as oar-blk sends them
    };
    Kind kind{Kind::write};
    std::vector<W> writes;  // write
    std::uint64_t lba{0};   // hydrate
    std::uint64_t blocks{0};
};

// What the replica must, or may, hold after a crash.
class Model {
public:
    Model(const ReplicaMeta& m, Bytes source)
        : _bs{m.block_size},
          _blocks{m.capacity_blocks},
          _chunk_blocks{(1ULL << m.chunk_shift) / m.block_size},
          _source{std::move(source)},
          _written(m.capacity_blocks),
          _hydrate_tried(m.capacity_blocks),
          _epoch{m.epoch} {}

    [[nodiscard]] auto source_block(std::uint64_t b) const -> Bytes {
        return block_of(_source, _bs, b);
    }

    auto begin(const Op& op) -> void {
        _inflight.clear();
        _inflight_epoch.reset();
        switch (op.kind) {
            case Op::Kind::write:
                for (const auto& w : op.writes) {
                    for (std::uint64_t i = 0; i < w.data.size() / _bs; ++i) {
                        if (w.hydrate) {
                            _hydrate_tried[w.lba + i] = true;  // the source, if unwritten
                        } else {
                            _inflight[w.lba + i].push_back(block_of(w.data, _bs, i));
                        }
                    }
                }
                break;
            case Op::Kind::epoch:
                _inflight_epoch = _epoch + 1;
                break;
            case Op::Kind::clear:
                _changed.clear();  // may already have taken effect
                break;
            case Op::Kind::hydrate:
                for (std::uint64_t b = op.lba; b < op.lba + op.blocks; ++b) {
                    _hydrate_tried[b] = true;
                }
                break;
            case Op::Kind::flush:
                break;
        }
    }

    auto acked(const Op& op) -> void {
        if (op.kind == Op::Kind::write) {
            for (const auto& w : op.writes) {
                if (w.hydrate) {
                    _last_seq = w.seq;  // stores only blocks no write stored
                    continue;
                }
                for (std::uint64_t i = 0; i < w.data.size() / _bs; ++i) {
                    _written[w.lba + i] = block_of(w.data, _bs, i);
                }
                const auto blocks = w.data.size() / _bs;
                for (auto c = w.lba / _chunk_blocks; c <= (w.lba + blocks - 1) / _chunk_blocks;
                     ++c) {
                    _changed.insert(c);
                }
                _last_seq = w.seq;
            }
        }
        if (op.kind == Op::Kind::epoch) {
            ++_epoch;
        }
        _inflight.clear();
        _inflight_epoch.reset();
    }

    auto check(ReplicaStore& s, std::uint64_t k, std::uint64_t seed) const -> void {
        BOOST_TEST_INFO("crash at op " << k << ", seed " << seed);
        BOOST_TEST((s.meta().epoch == _epoch || s.meta().epoch == _inflight_epoch));
        BOOST_TEST(s.last_seq() >= _last_seq);
        std::vector<bool> ring(_blocks);
        for (const auto& i : s.intents()) {
            for (std::uint64_t b = i.lba; b < i.lba + i.blocks; ++b) {
                ring[b] = true;
            }
        }
        const auto in_ring = [&](std::uint64_t b) { return ring[b]; };
        const bool sourced = s.meta().source.kind != proto::SourceKind::none;
        for (std::uint64_t b = 0; b < _blocks; ++b) {
            BOOST_TEST_INFO("block " << b);
            const auto pending = s.unhydrated(b);
            BOOST_TEST_REQUIRE(pending.has_value());
            if (*pending) {
                BOOST_TEST(!_written[b].has_value());  // an acked write hydrates
                BOOST_TEST(read_blocks(s, b, 1).error() == StoreError::not_hydrated);
                continue;
            }
            const auto r = read_blocks(s, b, 1);
            BOOST_TEST_REQUIRE(r.has_value());
            const auto fl = _inflight.find(b);
            const bool inflight = fl != _inflight.end();
            std::vector<Bytes> allowed = inflight ? fl->second : std::vector<Bytes>{};
            if (_written[b]) {
                allowed.push_back(*_written[b]);
            } else if (!sourced) {
                allowed.emplace_back(_bs);  // zeros
            }
            if (_hydrate_tried[b] && !_written[b]) {
                allowed.push_back(source_block(b));
            }
            if (_written[b] && !inflight) {
                BOOST_TEST((r->data == *_written[b]));  // acknowledged: durable
            }
            if (r->bad.empty()) {
                BOOST_TEST((std::ranges::find(allowed, r->data) != allowed.end()));
            } else {
                BOOST_TEST(in_ring(b));  // a torn write the primary will resync
            }
        }
        const auto changed = s.changed_chunks();
        BOOST_TEST_REQUIRE(changed.has_value());
        for (const auto c : _changed) {
            BOOST_TEST((std::ranges::find(*changed, c) != changed->end()));
        }
    }

    [[nodiscard]] auto last_seq() const noexcept -> std::uint64_t { return _last_seq; }

private:
    std::uint32_t _bs;
    std::uint64_t _blocks;
    std::uint64_t _chunk_blocks;
    Bytes _source;
    std::vector<std::optional<Bytes>> _written;
    std::vector<bool> _hydrate_tried;
    std::map<std::uint64_t, std::vector<Bytes>> _inflight;  // blocks the failed op wrote
    std::set<std::uint64_t> _changed;                       // since the last freeze begun
    std::uint64_t _epoch;
    std::optional<std::uint64_t> _inflight_epoch;
    std::uint64_t _last_seq{0};
};

auto scenario(const ReplicaMeta& m, const Bytes& source, std::uint64_t seed, std::size_t ops)
    -> std::vector<Op> {
    std::minstd_rand rng{static_cast<std::minstd_rand::result_type>(seed)};
    const bool sourced = m.source.kind != proto::SourceKind::none;
    const std::uint64_t cap = m.capacity_blocks;
    std::vector<Op> out;
    std::uint64_t seq = 0;
    for (std::size_t n = 0; n < ops; ++n) {
        Op op;
        const auto pick = rng() % 10;
        if (pick == 0) {
            op.kind = Op::Kind::epoch;
        } else if (pick == 1) {
            op.kind = Op::Kind::flush;
        } else if (pick == 2) {
            op.kind = Op::Kind::clear;
        } else if (sourced && pick <= 5) {
            op.kind = Op::Kind::hydrate;
            op.lba = rng() % cap;
            op.blocks = 1 + (rng() % std::min<std::uint64_t>(10, cap - op.lba));
        } else {
            const auto writes = 1 + (rng() % 3);
            for (std::uint64_t i = 0; i < writes; ++i) {
                const std::uint64_t lba = rng() % cap;
                const std::uint64_t blocks = 1 + (rng() % std::min<std::uint64_t>(4, cap - lba));
                ++seq;
                if (sourced && rng() % 3 == 0) {
                    // A hydrate write (oar-blk's foreign-key restore).
                    op.writes.push_back({.seq = seq,
                                         .lba = lba,
                                         .data = block_range(source, m.block_size, lba, blocks),
                                         .hydrate = true});
                    continue;
                }
                op.writes.push_back(
                    {.seq = seq, .lba = lba, .data = content(seq, m.block_size, blocks)});
            }
        }
        out.push_back(std::move(op));
    }
    return out;
}

// Runs ops until one fails; the Model learns what was acknowledged.
auto run(ReplicaStore& s, const std::vector<Op>& ops, Model& model) -> void {
    const std::uint32_t bs = s.meta().block_size;
    for (const auto& op : ops) {
        model.begin(op);
        bool ok = false;
        switch (op.kind) {
            case Op::Kind::write: {
                Batch b{bs};
                for (const auto& w : op.writes) {
                    b.add(w.seq, w.lba, w.data, w.hydrate);
                }
                ok = s.write(b.writes()).has_value();
                if (ok) {
                    s.set_commit(op.writes.back().seq);  // the primary acks at once
                }
                break;
            }
            case Op::Kind::epoch:
                ok = s.set_epoch(s.meta().epoch + 1, proto::ReplicaRole::primary).has_value();
                break;
            case Op::Kind::flush:
                ok = s.flush().has_value();
                break;
            case Op::Kind::clear:
                ok = s.clear_changed().has_value();
                break;
            case Op::Kind::hydrate: {
                Bytes data;
                for (std::uint64_t b = op.lba; b < op.lba + op.blocks; ++b) {
                    const auto blk = model.source_block(b);
                    data.insert(data.end(), blk.begin(), blk.end());
                }
                ok = s.hydrate(op.lba, data, crcs_of(data, bs)).has_value();
                break;
            }
        }
        if (!ok) {
            return;
        }
        model.acked(op);
    }
}

// The fill-progress count the store keeps agrees with its bitmap.
auto check_unhydrated_count(ReplicaStore& s) -> void {
    std::uint64_t n = 0;
    for (std::uint64_t lba = 0; lba < s.meta().capacity_blocks; ++lba) {
        n += s.unhydrated(lba).value() ? 1U : 0U;
    }
    BOOST_TEST(s.unhydrated_blocks() == n);
}

auto crash_and_check(MemFiles& files, const Model& model, std::uint64_t k, std::uint64_t seed)
    -> void {
    files.crash(seed);
    auto s = ReplicaStore::open(files, vdir);
    BOOST_TEST_INFO("crash at op " << k << ", seed " << seed);
    BOOST_TEST_REQUIRE(s.has_value());
    model.check(**s, k, seed);
    check_unhydrated_count(**s);
    // Still a working replica once the primary publishes its commit point.
    const auto next = (*s)->last_seq() + 1;
    (*s)->set_commit(next - 1);
    const auto d = content(next + 999, (*s)->meta().block_size);
    BOOST_TEST_REQUIRE(write_one(**s, next, 0, d).has_value());
    BOOST_TEST((read_blocks(**s, 0, 1)->data == d));
}

auto sweep(const ReplicaMeta& m, std::uint64_t scenario_seed, std::size_t n_ops) -> void {
    const auto source = content(7777, m.block_size, m.capacity_blocks);
    const auto ops = scenario(m, source, scenario_seed, n_ops);
    std::uint64_t total = 0;
    {
        MemFiles files;
        auto s = create(files, m);
        const auto before = files.ops();
        Model model{m, source};
        run(*s, ops, model);
        BOOST_TEST_REQUIRE(model.last_seq() > 0U);
        total = files.ops() - before;
        check_unhydrated_count(*s);
    }
    for (std::uint64_t k = 1; k <= total + 1; ++k) {
        for (std::uint64_t seed = 1; seed <= 3; ++seed) {
            MemFiles files;
            Model model{m, source};
            {
                auto s = create(files, m);
                files.fail_after(k);
                run(*s, ops, model);
            }
            crash_and_check(files, model, k, (k * 1000) + seed);
        }
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(crash)

BOOST_AUTO_TEST_CASE(at_every_step_with_sector_blocks, *utf::timeout(120)) {
    sweep(make_meta(40, proto::block_size_512, 12), 11, 40);
}

BOOST_AUTO_TEST_CASE(at_every_step_with_4k_blocks, *utf::timeout(120)) {
    // A 4 KiB block can tear inside itself: such a block must read bad.
    sweep(make_meta(16, proto::block_size_4096, 14), 12, 30);
}

BOOST_AUTO_TEST_CASE(at_every_step_while_hydrating, *utf::timeout(120)) {
    sweep(make_meta(40, proto::block_size_512, 12, proto::SourceKind::snapshot), 13, 40);
}

BOOST_AUTO_TEST_CASE(during_create, *utf::timeout(ak::test::unit_timeout_seconds)) {
    const auto m = make_meta(40, proto::block_size_512, 12, proto::SourceKind::image);
    std::uint64_t total = 0;
    {
        MemFiles files;
        create(files, m);
        total = files.ops();
    }
    for (std::uint64_t k = 1; k <= total; ++k) {
        for (std::uint64_t seed = 1; seed <= 3; ++seed) {
            MemFiles files;
            files.fail_after(k);
            static_cast<void>(ReplicaStore::create(files, vdir, m));
            files.crash(seed);
            // Either no replica, or a whole one.
            auto s = ReplicaStore::open(files, vdir);
            BOOST_TEST_INFO("crash at op " << k << ", seed " << seed);
            if (!s) {
                BOOST_TEST(s.error() == StoreError::bad_meta);
                continue;
            }
            BOOST_TEST(((*s)->meta() == m));
            for (std::uint64_t b = 0; b < m.capacity_blocks; ++b) {
                BOOST_TEST((*s)->unhydrated(b).value());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(during_grow, *utf::timeout(120)) {
    const auto m = make_meta(40, proto::block_size_512, 12, proto::SourceKind::image);
    const auto a = content(1, 512, 3);
    const auto prepare = [&](MemFiles& files) {
        auto s = create(files, m);
        BOOST_TEST_REQUIRE(write_one(*s, 1, 5, a).has_value());
        BOOST_TEST_REQUIRE(s->flush().has_value());
        return s;
    };
    std::uint64_t base = 0;
    std::uint64_t total = 0;
    {
        MemFiles files;
        auto s = prepare(files);
        base = files.ops();
        BOOST_TEST_REQUIRE(s->grow(100).has_value());
        total = files.ops() - base;
    }
    for (std::uint64_t k = 1; k <= total + 1; ++k) {
        for (std::uint64_t seed = 1; seed <= 3; ++seed) {
            MemFiles files;
            auto s = prepare(files);
            files.fail_after(k);
            const bool grew = s->grow(100).has_value();
            s.reset();
            files.crash(seed);
            BOOST_TEST_INFO("crash at grow op " << k << ", seed " << seed);
            // The old replica or the grown one, whole either way.
            auto r = ReplicaStore::open(files, vdir);
            BOOST_TEST_REQUIRE(r.has_value());
            const auto cap = (*r)->meta().capacity_blocks;
            BOOST_TEST((cap == 40U || cap == 100U));
            if (grew) {
                BOOST_TEST(cap == 100U);
            }
            BOOST_TEST(!files.exists(vdir / "meta.new"));
            BOOST_TEST(files.contents(vdir / "data").size() == cap * 512U);
            BOOST_TEST((read_blocks(**r, 5, 3)->data == a));
            BOOST_TEST((*r)->unhydrated(4).value());
            BOOST_TEST((*r)->unhydrated(39).value());
            if (cap == 100U) {
                BOOST_TEST(!(*r)->unhydrated(40).value());
                BOOST_TEST(read_blocks(**r, 40, 60)->bad.empty());
            }
            BOOST_TEST((*r)->grow(100).has_value());  // and it grows again
        }
    }
}

BOOST_AUTO_TEST_CASE(after_the_ring_wraps, *utf::timeout(120)) {
    // Slots are reused: a write that leaves the ring must have its checksums
    // durable first, so blocks outside the ring always read good.
    // Enough blocks that most lie outside the ring's extents.
    const auto m = make_meta(16384, proto::block_size_512, 12);
    std::vector<Op> ops;
    std::minstd_rand rng{21};
    for (std::uint64_t seq = 1; seq <= 2 * intent_ring_entries + 500; ++seq) {
        Op op;
        const std::uint64_t lba = rng() % (m.capacity_blocks - 1);
        op.writes.push_back({.seq = seq, .lba = lba, .data = content(seq, 512, 1 + (seq % 2))});
        if (seq % 1000 == 0) {
            ops.push_back({.kind = Op::Kind::flush, .writes = {}, .lba = 0, .blocks = 0});
        }
        ops.push_back(std::move(op));
    }
    std::uint64_t start = 0;
    std::uint64_t total = 0;
    {
        MemFiles files;
        auto s = create(files, m);
        start = files.ops();
        Model model{m, {}};
        run(*s, ops, model);
        total = files.ops() - start;
    }
    std::minstd_rand pick{5};
    for (int n = 0; n < 4; ++n) {
        const std::uint64_t k = (total / 2) + (pick() % (total / 2));
        MemFiles files;
        Model model{m, {}};
        {
            auto s = create(files, m);
            files.fail_after(k);
            run(*s, ops, model);
        }
        crash_and_check(files, model, k, k);
    }
}

BOOST_AUTO_TEST_CASE(when_a_batch_wraps_onto_the_last, *utf::timeout(120)) {
    // A batch whose seqs reuse the slots of the batch before it, whose
    // checksums are not yet durable: they must be before its intents go.
    const auto m = make_meta(1024, proto::block_size_512, 12);
    Op first;
    for (std::uint64_t seq = 1; seq <= 8; ++seq) {
        first.writes.push_back({.seq = seq, .lba = seq - 1, .data = content(seq, 512)});
    }
    Op second;
    for (std::uint64_t seq = 9; seq <= 8 + intent_ring_entries; ++seq) {
        second.writes.push_back({.seq = seq, .lba = 8 + (seq % 1000), .data = content(seq, 512)});
    }
    const std::vector<Op> ops{first, second};
    std::uint64_t base = 0;
    {
        MemFiles files;
        auto s = create(files, m);
        const auto before = files.ops();
        Model model{m, {}};
        run(*s, {first}, model);
        base = files.ops() - before;
    }
    for (const std::uint64_t j : {1U, 2U, 9U, 4000U, 4097U, 4098U}) {
        for (std::uint64_t seed = 1; seed <= 6; ++seed) {
            MemFiles files;
            Model model{m, {}};
            {
                auto s = create(files, m);
                files.fail_after(base + j);
                run(*s, ops, model);
            }
            crash_and_check(files, model, base + j, seed);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
