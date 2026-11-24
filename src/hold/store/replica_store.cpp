// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/store/replica_store.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <utility>

#include "common/crc32c.hpp"

namespace ak::hold::store {

namespace {

constexpr std::size_t crc_size = sizeof(std::uint32_t);
constexpr std::size_t fill_chunk = 64 * 1024;
constexpr char data_name[] = "data";
constexpr char meta_name[] = "meta";
constexpr char meta_new_name[] = "meta.new";  // grow(): the next meta, until renamed
constexpr char probe_name[] = ".reflink-probe";

auto le32_at(std::span<const std::byte> b, std::size_t i) noexcept -> std::uint32_t {
    std::uint32_t v = 0;
    for (std::size_t k = 0; k < crc_size; ++k) {
        v |= std::to_integer<std::uint32_t>(b[(i * crc_size) + k]) << (8U * k);
    }
    return v;
}

auto put_le32(std::span<std::byte> b, std::size_t i, std::uint32_t v) noexcept -> void {
    for (std::size_t k = 0; k < crc_size; ++k) {
        b[(i * crc_size) + k] = static_cast<std::byte>((v >> (8U * k)) & 0xFFU);
    }
}

auto bit(std::span<const std::byte> bytes, std::uint64_t i) noexcept -> bool {
    return (std::to_integer<unsigned>(bytes[i / 8]) & (1U << (i % 8))) != 0;
}

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto detect_reflink(FileLayer& files, const std::filesystem::path& dir) -> bool {
    const auto probe = dir / probe_name;
    const bool ok = files.clone(dir / data_name, probe).has_value();
    if (ok) {
        static_cast<void>(files.remove_all(probe));
    }
    return ok;
}

}  // namespace

auto to_string(StoreError e) noexcept -> const char* {
    switch (e) {
        case StoreError::io:
            return "io";
        case StoreError::exists:
            return "exists";
        case StoreError::bad_meta:
            return "bad_meta";
        case StoreError::bad_request:
            return "bad_request";
        case StoreError::bad_crc:
            return "bad_crc";
        case StoreError::bad_seq:
            return "bad_seq";
        case StoreError::ring_full:
            return "ring_full";
        case StoreError::not_hydrated:
            return "not_hydrated";
    }
    return "unknown";
}

auto replica_dir_name(std::uint64_t volume_id, std::uint32_t replica_gen) -> std::string {
    return "vol-" + std::to_string(volume_id) + "." + std::to_string(replica_gen);
}

ReplicaStore::ReplicaStore(FileLayer& files, std::filesystem::path dir, ReplicaMeta meta,
                           std::unique_ptr<File> data, std::unique_ptr<File> meta_file) noexcept
    : _files{&files},
      _dir{std::move(dir)},
      _meta{meta},
      _layout{layout(meta)},
      _data{std::move(data)},
      _meta_file{std::move(meta_file)},
      _ring(intent_ring_entries) {}

// ---- lifecycle -------------------------------------------------------------

auto ReplicaStore::create(FileLayer& files, const std::filesystem::path& dir, ReplicaMeta meta)
    -> std::expected<std::unique_ptr<ReplicaStore>, StoreError> {
    meta.header_seq = 1;
    const auto slot = encode_replica_meta(meta);
    if (!slot) {
        return std::unexpected(StoreError::bad_request);
    }
    if (files.exists(dir)) {
        return std::unexpected(StoreError::exists);
    }
    if (auto r = files.make_dir(dir); !r) {
        return std::unexpected(r.error() == EEXIST ? StoreError::exists : StoreError::io);
    }
    const MetaLayout l = layout(meta);
    auto data = files.open(dir / data_name, true);
    auto mf = files.open(dir / meta_name, true);
    if (!data || !mf || !(*data)->truncate(meta.capacity_blocks * meta.block_size) ||
        !(*mf)->truncate(l.end)) {
        return std::unexpected(StoreError::io);
    }
    if (meta.source.kind != proto::SourceKind::none) {
        // Every block awaits hydration: set the bitmap's bits, no more.
        const std::uint64_t full = meta.capacity_blocks / 8;
        std::vector<std::byte> ones(fill_chunk, std::byte{0xFF});
        for (std::uint64_t at = 0; at < full; at += fill_chunk) {
            const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(fill_chunk, full - at));
            if (!(*mf)->pwrite(l.unhydrated + at, std::span{ones}.first(n))) {
                return std::unexpected(StoreError::io);
            }
        }
        if (const auto tail = meta.capacity_blocks % 8; tail != 0) {
            const std::array<std::byte, 1> last{static_cast<std::byte>((1U << tail) - 1)};
            if (!(*mf)->pwrite(l.unhydrated + full, last)) {
                return std::unexpected(StoreError::io);
            }
        }
    }
    // The sizes and bits first, then the header: a replica with a valid
    // header is a whole one.
    if (!(*mf)->sync() || !(*data)->sync() || !(*mf)->pwrite(0, *slot) || !(*mf)->sync() ||
        !files.sync_dir(dir) || !files.sync_dir(dir.parent_path())) {
        return std::unexpected(StoreError::io);
    }
    std::unique_ptr<ReplicaStore> s{
        new ReplicaStore(files, dir, meta, std::move(*data), std::move(*mf))};
    s->_reflink = detect_reflink(files, dir);
    return s;
}

auto ReplicaStore::open(FileLayer& files, const std::filesystem::path& dir)
    -> std::expected<std::unique_ptr<ReplicaStore>, StoreError> {
    // A grow that did not reach its rename: the old meta stands.
    if (files.exists(dir / meta_new_name) &&
        (!files.remove_all(dir / meta_new_name) || !files.sync_dir(dir))) {
        return std::unexpected(StoreError::io);
    }
    auto data = files.open(dir / data_name, false);
    auto mf = files.open(dir / meta_name, false);
    if (!data || !mf) {
        return std::unexpected(StoreError::bad_meta);
    }
    std::array<std::byte, 2 * meta_slot_size> head{};
    if (!(*mf)->pread(0, head)) {
        return std::unexpected(StoreError::io);
    }
    const auto meta = decode_meta_slots(head);
    if (!meta) {
        return std::unexpected(StoreError::bad_meta);
    }
    const auto msize = (*mf)->size();
    const auto dsize = (*data)->size();
    const std::uint64_t want = meta->capacity_blocks * meta->block_size;
    if (!msize || !dsize || *msize < layout(*meta).end || *dsize < want) {
        return std::unexpected(StoreError::bad_meta);
    }
    // Extended by a grow that did not reach its rename: nothing past the
    // old capacity was ever written, so the tail goes.
    if (*dsize > want && (!(*data)->truncate(want) || !(*data)->sync())) {
        return std::unexpected(StoreError::io);
    }
    std::unique_ptr<ReplicaStore> s{
        new ReplicaStore(files, dir, *meta, std::move(*data), std::move(*mf))};
    if (auto r = s->recover(); !r) {
        return std::unexpected(r.error());
    }
    s->_reflink = detect_reflink(files, dir);
    return s;
}

auto ReplicaStore::destroy(FileLayer& files, const std::filesystem::path& dir)
    -> std::expected<void, StoreError> {
    if (!files.remove_all(dir) || !files.sync_dir(dir.parent_path())) {
        return std::unexpected(StoreError::io);
    }
    return {};
}

auto ReplicaStore::recover() -> std::expected<void, StoreError> {
    std::vector<std::byte> ring(intent_ring_entries * intent_entry_size);
    if (!_meta_file->pread(_layout.intents, ring)) {
        return std::unexpected(StoreError::io);
    }
    for (std::size_t slot = 0; slot < intent_ring_entries; ++slot) {
        const auto i =
            decode_intent(std::span{ring}.subspan(slot * intent_entry_size, intent_entry_size),
                          _meta.capacity_blocks);
        if (i && i->seq % intent_ring_entries == slot) {
            _ring[slot] = *i;
            _last_seq = std::max(_last_seq, i->seq);
        }
    }
    // Bits a crash may have lost for writes still in the ring.
    for (const auto& i : _ring) {
        if (i.seq != 0) {
            if (auto r = mark_written(i.lba, i.blocks); !r) {
                return r;
            }
        }
    }
    if (auto r = sync_meta(); !r) {
        return r;
    }
    _meta_synced_seq = _last_seq;
    _commit_seq = 0;  // unknown until the primary says
    return {};
}

// ---- header ----------------------------------------------------------------

auto ReplicaStore::write_header(ReplicaMeta next) -> std::expected<void, StoreError> {
    const auto slot = encode_replica_meta(next);
    if (!slot) {
        return std::unexpected(StoreError::bad_request);
    }
    // Alternate slots: odd header_seq in A, even in B.
    const std::uint64_t at = ((next.header_seq - 1) % 2) * meta_slot_size;
    if (!_meta_file->pwrite(at, *slot)) {
        return std::unexpected(StoreError::io);
    }
    if (auto r = sync_meta(); !r) {
        return r;
    }
    _meta = next;
    return {};
}

auto ReplicaStore::set_epoch(std::uint64_t epoch, proto::ReplicaRole role)
    -> std::expected<void, StoreError> {
    ReplicaMeta next = _meta;
    next.epoch = epoch;
    next.role = role;
    ++next.header_seq;
    return write_header(next);
}

auto ReplicaStore::set_commit(std::uint64_t seq) noexcept -> void {
    _commit_seq = std::max(_commit_seq, std::min(seq, _last_seq));
}

auto ReplicaStore::intents() const -> std::vector<Intent> {
    std::vector<Intent> out;
    for (const auto& i : _ring) {
        if (i.seq != 0 && i.seq > _commit_seq) {
            out.push_back(i);
        }
    }
    std::ranges::sort(out, {}, &Intent::seq);
    return out;
}

// ---- helpers ---------------------------------------------------------------

auto ReplicaStore::sync_meta() -> std::expected<void, StoreError> {
    if (!_meta_file->sync()) {
        return std::unexpected(StoreError::io);
    }
    return {};
}

auto ReplicaStore::check_range(std::uint64_t lba, std::size_t bytes) const noexcept -> bool {
    const std::uint64_t blocks = bytes / _meta.block_size;
    return bytes != 0 && bytes % _meta.block_size == 0 && lba <= _meta.capacity_blocks &&
           blocks <= _meta.capacity_blocks - lba;
}

auto ReplicaStore::set_bits(std::uint64_t region, std::uint64_t first, std::uint64_t count,
                            bool value) -> std::expected<void, StoreError> {
    if (count == 0) {
        return {};
    }
    const std::uint64_t lo = first / 8;
    const std::uint64_t hi = (first + count - 1) / 8;
    std::vector<std::byte> bytes(hi - lo + 1);
    if (!_meta_file->pread(region + lo, bytes)) {
        return std::unexpected(StoreError::io);
    }
    for (std::uint64_t i = first; i < first + count; ++i) {
        auto& b = bytes[(i / 8) - lo];
        const auto mask = static_cast<std::byte>(1U << (i % 8));
        b = value ? (b | mask) : (b & ~mask);
    }
    if (!_meta_file->pwrite(region + lo, bytes)) {
        return std::unexpected(StoreError::io);
    }
    return {};
}

auto ReplicaStore::count_bits(std::uint64_t region, std::uint64_t first, std::uint64_t count)
    -> std::expected<std::uint64_t, StoreError> {
    if (count == 0) {
        return 0;
    }
    const std::uint64_t lo = first / 8;
    const std::uint64_t hi = (first + count - 1) / 8;
    std::vector<std::byte> bytes(hi - lo + 1);
    if (!_meta_file->pread(region + lo, bytes)) {
        return std::unexpected(StoreError::io);
    }
    std::uint64_t n = 0;
    for (std::uint64_t i = first; i < first + count; ++i) {
        n += bit(bytes, i - (lo * 8)) ? 1U : 0U;
    }
    return n;
}

auto ReplicaStore::any_bit(std::uint64_t region, std::uint64_t first, std::uint64_t count)
    -> std::expected<bool, StoreError> {
    auto n = count_bits(region, first, count);
    if (!n) {
        return std::unexpected(n.error());
    }
    return *n != 0;
}

auto ReplicaStore::write_checksums(std::uint64_t lba, std::span<const std::uint32_t> crcs)
    -> std::expected<void, StoreError> {
    std::vector<std::byte> bytes(crcs.size() * crc_size);
    for (std::size_t i = 0; i < crcs.size(); ++i) {
        put_le32(bytes, i, crcs[i]);
    }
    if (!_meta_file->pwrite(_layout.checksums + (lba * crc_size), bytes)) {
        return std::unexpected(StoreError::io);
    }
    return {};
}

auto ReplicaStore::mark_written(std::uint64_t lba, std::uint64_t blocks)
    -> std::expected<void, StoreError> {
    if (_meta.source.kind != proto::SourceKind::none) {
        if (auto r = set_bits(_layout.unhydrated, lba, blocks, false); !r) {
            return r;
        }
    }
    const std::uint64_t first = (lba * _meta.block_size) >> _meta.chunk_shift;
    const std::uint64_t last = (((lba + blocks) * _meta.block_size) - 1) >> _meta.chunk_shift;
    return set_bits(_layout.changed, first, last - first + 1, true);
}

// ---- data path -------------------------------------------------------------

auto ReplicaStore::write(std::span<const Write> batch) -> std::expected<void, StoreError> {
    if (batch.empty()) {
        return {};
    }
    const std::uint32_t bs = _meta.block_size;
    std::uint64_t prev = _last_seq;
    bool must_sync = false;
    for (const auto& w : batch) {
        if (!check_range(w.lba, w.data.size()) || w.crcs.size() != w.data.size() / bs) {
            return std::unexpected(StoreError::bad_request);
        }
        if (w.seq <= prev) {
            return std::unexpected(StoreError::bad_seq);
        }
        if (w.seq - _commit_seq > intent_ring_entries) {
            return std::unexpected(StoreError::ring_full);
        }
        for (std::size_t b = 0; b < w.crcs.size(); ++b) {
            if (crc32c::of(w.data.subspan(b * bs, bs)) != w.crcs[b]) {
                return std::unexpected(StoreError::bad_crc);
            }
        }
        const Intent& old = _ring[w.seq % intent_ring_entries];
        must_sync = must_sync || (old.seq != 0 && old.seq > _meta_synced_seq);
        prev = w.seq;
    }
    // Reusing a slot whose write may not have durable checksums yet: make
    // them durable before its intent goes.
    if (must_sync) {
        if (auto r = sync_meta(); !r) {
            return r;
        }
        _meta_synced_seq = _last_seq;
    }
    // 1. Intents, durable before any of the data.
    for (const auto& w : batch) {
        const Intent i{
            .seq = w.seq, .lba = w.lba, .blocks = static_cast<std::uint32_t>(w.data.size() / bs)};
        const auto slot = w.seq % intent_ring_entries;
        if (!_meta_file->pwrite(_layout.intents + (slot * intent_entry_size), encode_intent(i))) {
            return std::unexpected(StoreError::io);
        }
        _ring[slot] = i;
    }
    if (auto r = sync_meta(); !r) {
        return r;
    }
    _meta_synced_seq = _last_seq;  // that sync carried earlier batches' checksums
    // 2. Data.
    for (const auto& w : batch) {
        if (!_data->pwrite(w.lba * bs, w.data)) {
            return std::unexpected(StoreError::io);
        }
    }
    if (!_data->sync()) {
        return std::unexpected(StoreError::io);
    }
    // 3. Checksums and bits, durable with the next sync of meta.
    for (const auto& w : batch) {
        if (auto r = write_checksums(w.lba, w.crcs); !r) {
            return r;
        }
        if (auto r = mark_written(w.lba, w.crcs.size()); !r) {
            return r;
        }
    }
    _last_seq = batch.back().seq;
    return {};
}

auto ReplicaStore::read(std::uint64_t lba, std::span<std::byte> out, std::span<std::uint32_t> crcs)
    -> std::expected<std::vector<std::uint64_t>, StoreError> {
    const std::uint32_t bs = _meta.block_size;
    if (!check_range(lba, out.size()) || crcs.size() != out.size() / bs) {
        return std::unexpected(StoreError::bad_request);
    }
    if (_meta.source.kind != proto::SourceKind::none) {
        auto pending = any_bit(_layout.unhydrated, lba, crcs.size());
        if (!pending) {
            return std::unexpected(pending.error());
        }
        if (*pending) {
            return std::unexpected(StoreError::not_hydrated);
        }
    }
    std::vector<std::byte> stored(crcs.size() * crc_size);
    if (!_data->pread(lba * bs, out) ||
        !_meta_file->pread(_layout.checksums + (lba * crc_size), stored)) {
        return std::unexpected(StoreError::io);
    }
    std::vector<std::uint64_t> bad;
    for (std::size_t b = 0; b < crcs.size(); ++b) {
        crcs[b] = le32_at(stored, b);
        const auto block = out.subspan(b * bs, bs);
        const bool unwritten = crcs[b] == 0 && past_source(lba + b) && all_zero(block);
        if (crc32c::of(block) != crcs[b] && !unwritten) {
            bad.push_back(lba + b);
        }
    }
    return bad;
}

auto ReplicaStore::hydrate(std::uint64_t lba, std::span<const std::byte> data,
                           std::span<const std::uint32_t> crcs)
    -> std::expected<std::uint64_t, StoreError> {
    const std::uint32_t bs = _meta.block_size;
    if (!check_range(lba, data.size()) || crcs.size() != data.size() / bs) {
        return std::unexpected(StoreError::bad_request);
    }
    for (std::size_t b = 0; b < crcs.size(); ++b) {
        if (crc32c::of(data.subspan(b * bs, bs)) != crcs[b]) {
            return std::unexpected(StoreError::bad_crc);
        }
    }
    if (_meta.source.kind == proto::SourceKind::none) {
        return 0;  // nothing ever awaits hydration
    }
    const std::uint64_t lo = lba / 8;
    const std::uint64_t hi = (lba + crcs.size() - 1) / 8;
    std::vector<std::byte> bits(hi - lo + 1);
    if (!_meta_file->pread(_layout.unhydrated + lo, bits)) {
        return std::unexpected(StoreError::io);
    }
    std::vector<std::size_t> fill;
    for (std::size_t b = 0; b < crcs.size(); ++b) {
        if (bit(bits, lba + b - (lo * 8))) {
            fill.push_back(b);
        }
    }
    if (fill.empty()) {
        return 0;
    }
    for (const auto b : fill) {
        if (!_data->pwrite((lba + b) * bs, data.subspan(b * bs, bs))) {
            return std::unexpected(StoreError::io);
        }
    }
    if (!_data->sync()) {
        return std::unexpected(StoreError::io);
    }
    for (const auto b : fill) {
        if (auto r = write_checksums(lba + b, crcs.subspan(b, 1)); !r) {
            return std::unexpected(r.error());
        }
    }
    if (auto r = sync_meta(); !r) {
        return std::unexpected(r.error());
    }
    for (const auto b : fill) {
        if (auto r = set_bits(_layout.unhydrated, lba + b, 1, false); !r) {
            return std::unexpected(r.error());
        }
    }
    return fill.size();
}

auto ReplicaStore::rewrite(std::span<const Write> batch) -> std::expected<void, StoreError> {
    const std::uint32_t bs = _meta.block_size;
    for (const auto& w : batch) {
        if (!check_range(w.lba, w.data.size()) || w.crcs.size() != w.data.size() / bs) {
            return std::unexpected(StoreError::bad_request);
        }
        if (w.seq <= _commit_seq || w.seq > _last_seq ||
            std::ranges::none_of(_ring, [&](const Intent& i) {
                return i.seq == w.seq && i.lba == w.lba && i.blocks == w.crcs.size();
            })) {
            return std::unexpected(StoreError::bad_seq);
        }
        for (std::size_t b = 0; b < w.crcs.size(); ++b) {
            if (crc32c::of(w.data.subspan(b * bs, bs)) != w.crcs[b]) {
                return std::unexpected(StoreError::bad_crc);
            }
        }
    }
    for (const auto& w : batch) {
        if (!_data->pwrite(w.lba * bs, w.data)) {
            return std::unexpected(StoreError::io);
        }
    }
    if (!_data->sync()) {
        return std::unexpected(StoreError::io);
    }
    for (const auto& w : batch) {
        if (auto r = write_checksums(w.lba, w.crcs); !r) {
            return r;
        }
        if (auto r = mark_written(w.lba, w.crcs.size()); !r) {
            return r;
        }
    }
    return sync_meta();
}

auto ReplicaStore::repair(std::uint64_t lba, std::span<const std::byte> block, std::uint32_t crc)
    -> std::expected<void, StoreError> {
    const std::uint32_t bs = _meta.block_size;
    if (!check_range(lba, block.size()) || block.size() != bs) {
        return std::unexpected(StoreError::bad_request);
    }
    const bool unwritten = crc == 0 && past_source(lba) && all_zero(block);
    if (!unwritten && crc32c::of(block) != crc) {
        return std::unexpected(StoreError::bad_crc);
    }
    if (!_data->pwrite(lba * bs, block) || !_data->sync()) {
        return std::unexpected(StoreError::io);
    }
    const std::array<std::uint32_t, 1> crcs{crc};
    if (auto r = write_checksums(lba, crcs); !r) {
        return std::unexpected(r.error());
    }
    return sync_meta();
}

auto ReplicaStore::copy(std::uint64_t lba, std::span<const std::byte> data,
                        std::span<const std::uint32_t> crcs) -> std::expected<void, StoreError> {
    const std::uint32_t bs = _meta.block_size;
    if (!check_range(lba, data.size()) || crcs.size() != data.size() / bs) {
        return std::unexpected(StoreError::bad_request);
    }
    if (!_data->pwrite(lba * bs, data) || !_data->sync()) {
        return std::unexpected(StoreError::io);
    }
    if (auto r = write_checksums(lba, crcs); !r) {
        return r;
    }
    if (auto r = mark_written(lba, crcs.size()); !r) {
        return r;
    }
    return sync_meta();
}

auto ReplicaStore::written(std::uint64_t lba, std::uint64_t blocks)
    -> std::expected<bool, StoreError> {
    if (blocks == 0 || lba >= _meta.capacity_blocks || blocks > _meta.capacity_blocks - lba) {
        return std::unexpected(StoreError::bad_request);
    }
    std::vector<std::byte> stored(blocks * crc_size);
    if (!_meta_file->pread(_layout.checksums + (lba * crc_size), stored)) {
        return std::unexpected(StoreError::io);
    }
    return !all_zero(stored);
}

auto ReplicaStore::rebase(std::uint64_t seq) -> std::expected<void, StoreError> {
    const std::vector<std::byte> empty(intent_ring_entries * intent_entry_size);
    if (!_meta_file->pwrite(_layout.intents, empty)) {
        return std::unexpected(StoreError::io);
    }
    if (auto r = sync_meta(); !r) {
        return r;
    }
    std::ranges::fill(_ring, Intent{});
    _last_seq = seq;
    _commit_seq = seq;
    _meta_synced_seq = seq;
    return {};
}

auto ReplicaStore::unhydrated(std::uint64_t lba) -> std::expected<bool, StoreError> {
    if (lba >= _meta.capacity_blocks) {
        return std::unexpected(StoreError::bad_request);
    }
    if (_meta.source.kind == proto::SourceKind::none) {
        return false;
    }
    return any_bit(_layout.unhydrated, lba, 1);
}

auto ReplicaStore::chunk_state(std::uint64_t chunk) -> std::expected<ChunkState, StoreError> {
    if (chunk >= _layout.chunks) {
        return std::unexpected(StoreError::bad_request);
    }
    if (_meta.source.kind == proto::SourceKind::none) {
        return ChunkState::hydrated;
    }
    const std::uint64_t per_chunk = (1ULL << _meta.chunk_shift) / _meta.block_size;
    const std::uint64_t first = chunk * per_chunk;
    const std::uint64_t count = std::min(per_chunk, _meta.capacity_blocks - first);
    const auto n = count_bits(_layout.unhydrated, first, count);
    if (!n) {
        return std::unexpected(n.error());
    }
    if (*n == 0) {
        return ChunkState::hydrated;
    }
    return *n == count ? ChunkState::unhydrated : ChunkState::partial;
}

auto ReplicaStore::changed_chunks() -> std::expected<std::vector<std::uint64_t>, StoreError> {
    std::vector<std::byte> bits((_layout.chunks + 7) / 8);
    if (!_meta_file->pread(_layout.changed, bits)) {
        return std::unexpected(StoreError::io);
    }
    std::vector<std::uint64_t> out;
    for (std::uint64_t c = 0; c < _layout.chunks; ++c) {
        if (bit(bits, c)) {
            out.push_back(c);
        }
    }
    return out;
}

auto ReplicaStore::clear_changed() -> std::expected<void, StoreError> {
    const std::vector<std::byte> zeros((_layout.chunks + 7) / 8);
    if (!_meta_file->pwrite(_layout.changed, zeros)) {
        return std::unexpected(StoreError::io);
    }
    return sync_meta();
}

auto ReplicaStore::flush() -> std::expected<void, StoreError> {
    if (auto r = sync_meta(); !r) {
        return r;
    }
    _meta_synced_seq = _last_seq;
    return {};
}

auto ReplicaStore::past_source(std::uint64_t lba) const noexcept -> bool {
    return _meta.source.kind == proto::SourceKind::none ||
           (_meta.source_blocks != 0 && lba >= _meta.source_blocks);
}

auto ReplicaStore::grow(std::uint64_t capacity_blocks) -> std::expected<void, StoreError> {
    if (capacity_blocks == _meta.capacity_blocks) {
        return {};
    }
    ReplicaMeta next = _meta;
    next.capacity_blocks = capacity_blocks;
    if (_meta.source.kind != proto::SourceKind::none && _meta.source_blocks == 0) {
        next.source_blocks = _meta.capacity_blocks;  // the source ends where it did
    }
    ++next.header_seq;
    const auto slot = encode_replica_meta(next);
    if (capacity_blocks < _meta.capacity_blocks || !slot) {
        return std::unexpected(StoreError::bad_request);
    }
    const MetaLayout to = layout(next);
    const auto path = _dir / meta_new_name;
    if (_files->exists(path) && !_files->remove_all(path)) {
        return std::unexpected(StoreError::io);
    }
    auto mf = _files->open(path, true);
    if (!mf || !(*mf)->truncate(to.end)) {
        return std::unexpected(StoreError::io);
    }
    // Each region to its new place; the new file is sparse, so runs of
    // zeros (never written, not awaiting hydration, unchanged) are skipped.
    std::vector<std::byte> buf(fill_chunk);
    const auto move = [&](std::uint64_t from, std::uint64_t at, std::uint64_t bytes) -> bool {
        for (std::uint64_t done = 0; done < bytes; done += buf.size()) {
            const auto n =
                static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), bytes - done));
            const auto part = std::span{buf}.first(n);
            if (!_meta_file->pread(from + done, part)) {
                return false;
            }
            if (!all_zero(part) && !(*mf)->pwrite(at + done, part)) {
                return false;
            }
        }
        return true;
    };
    const std::uint64_t old_blocks = _meta.capacity_blocks;
    if (!move(_layout.checksums, to.checksums, old_blocks * crc_size) ||
        !move(_layout.unhydrated, to.unhydrated, (old_blocks + 7) / 8) ||
        !move(_layout.changed, to.changed, (_layout.chunks + 7) / 8) ||
        !move(_layout.intents, to.intents, intent_ring_entries * intent_entry_size)) {
        return std::unexpected(StoreError::io);
    }
    // The header in the slot its header_seq picks; the other stays zero.
    const std::uint64_t at = ((next.header_seq - 1) % 2) * meta_slot_size;
    if (!(*mf)->pwrite(at, *slot) || !(*mf)->sync()) {
        return std::unexpected(StoreError::io);
    }
    if (!_data->truncate(capacity_blocks * _meta.block_size) || !_data->sync()) {
        return std::unexpected(StoreError::io);
    }
    if (!_files->rename(path, _dir / meta_name) || !_files->sync_dir(_dir)) {
        return std::unexpected(StoreError::io);
    }
    _meta_file = std::move(*mf);
    _meta = next;
    _layout = to;
    _meta_synced_seq = _last_seq;  // the new file was synced whole
    return {};
}

}  // namespace ak::hold::store
