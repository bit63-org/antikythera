// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// One hold replica on disk (.kiro/specs/block-volume-service/ design
// "ReplicaStore", task 5): the directory `vol-<id>.<replica_gen>/` with a
// sparse `data` file of ciphertext at its logical offsets and a `meta`
// file (replica_meta.hpp) with the header, a CRC32C per block, the
// unhydrated-block and changed-chunk bitmaps and the intent ring.
//
// Writes are group-committed: write() takes a batch, and returns only
// once the batch is durable (Requirement 1.5), in this order:
//
//   1. the batch's intents (seq, lba, blocks) into the ring, then sync;
//   2. the data, then sync;
//   3. the checksums, the changed-chunk bits and the cleared unhydrated
//      bits, not synced: the next sync of `meta` carries them, and before
//      an intent slot is reused for a newer write, `meta` is synced if the
//      write it held may still have unsynced checksums.
//
// So after a crash, checksums can disagree with data only inside extents
// still in the ring: open() returns those extents (intents()) for the
// primary to resync, re-marks their chunks changed and their blocks
// hydrated (bits that may have been lost), and a read reports any
// mismatch as bad blocks to repair, never as silently good data.
//
// A seq must exceed every seq before it, and may run at most 4096 ahead
// of the commit point the primary has published (set_commit), or the
// ring would overwrite an intent that may still be needed (ring_full).
// After open() the commit point is unknown, so writes wait for
// set_commit() (the primary's REPL_WRITE carries commit_seq).
//
// hydrate() fills blocks still marked unhydrated (a snapshot restore's
// chunks, HYDRATE_FILL): data, sync, checksums, sync, then the bits, so a
// cleared bit always has its checksum. Ordinary writes clear the bits of
// the blocks they write.
//
// reflink() reports whether `data` can be cloned (FICLONE) for snapshot
// freezes and clones, detected at create and open. Not thread-safe: the
// replica's owner serializes calls.
//
// grow() raises the capacity (task 19, design "QoS and elasticity").
// The meta regions after the checksums move with the capacity, so it
// builds the new `meta` aside as `meta.new` (the header with the new
// capacity, every region copied to its new place, the new blocks neither
// written nor awaiting hydration, and source_blocks recording where a
// source ends), syncs it, extends `data` and syncs it,
// then renames `meta.new` over `meta` and syncs the directory. A crash
// before the rename leaves the old replica whole: open() removes a
// leftover `meta.new` and cuts `data` back to the old capacity (nothing
// was ever written past it). It copies the checksum array, so it costs a
// read of 4 bytes per block (1 GiB for a 1 TiB volume of 4 KiB blocks),
// skipping what was never written when writing.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "hold/store/file_layer.hpp"
#include "hold/store/replica_meta.hpp"

namespace ak::hold::store {

enum class StoreError : std::uint8_t {
    io,            // the file layer failed; the replica must be reopened
    exists,        // create: the directory is already there
    bad_meta,      // open: no valid header, or files of the wrong size
    bad_request,   // a range outside the volume, a length that is not whole blocks
    bad_crc,       // a block's data does not match the CRC32C it came with
    bad_seq,       // a seq not above every earlier one
    ring_full,     // a seq more than 4096 ahead of the commit point
    not_hydrated,  // a read touches a block that awaits hydration
};

[[nodiscard]] auto to_string(StoreError e) noexcept -> const char*;

// `vol-<volume_id>.<replica_gen>`
[[nodiscard]] auto replica_dir_name(std::uint64_t volume_id, std::uint32_t replica_gen)
    -> std::string;

enum class ChunkState : std::uint8_t {
    hydrated,
    partial,
    unhydrated,
};

class ReplicaStore {
public:
    struct Write {
        std::uint64_t seq{0};
        std::uint64_t lba{0};
        std::span<const std::byte> data;      // whole blocks
        std::span<const std::uint32_t> crcs;  // one per block
    };

    // A new, empty replica in `dir` (which must not exist). With a source,
    // every block starts unhydrated.
    [[nodiscard]] static auto create(FileLayer& files, const std::filesystem::path& dir,
                                     ReplicaMeta meta)
        -> std::expected<std::unique_ptr<ReplicaStore>, StoreError>;
    [[nodiscard]] static auto open(FileLayer& files, const std::filesystem::path& dir)
        -> std::expected<std::unique_ptr<ReplicaStore>, StoreError>;
    // delete_replica: the directory and everything in it.
    [[nodiscard]] static auto destroy(FileLayer& files, const std::filesystem::path& dir)
        -> std::expected<void, StoreError>;

    ReplicaStore(const ReplicaStore&) = delete;
    auto operator=(const ReplicaStore&) -> ReplicaStore& = delete;
    ReplicaStore(ReplicaStore&&) = delete;
    auto operator=(ReplicaStore&&) -> ReplicaStore& = delete;
    ~ReplicaStore() = default;

    [[nodiscard]] auto meta() const noexcept -> const ReplicaMeta& { return _meta; }
    [[nodiscard]] auto reflink() const noexcept -> bool { return _reflink; }
    [[nodiscard]] auto last_seq() const noexcept -> std::uint64_t { return _last_seq; }
    [[nodiscard]] auto commit_seq() const noexcept -> std::uint64_t { return _commit_seq; }
    // The ring's extents above the commit point, by seq: what may be torn.
    [[nodiscard]] auto intents() const -> std::vector<Intent>;

    // Records a new epoch and role in the header (durable on return).
    [[nodiscard]] auto set_epoch(std::uint64_t epoch, proto::ReplicaRole role)
        -> std::expected<void, StoreError>;
    // The primary acknowledged everything up to `seq`.
    auto set_commit(std::uint64_t seq) noexcept -> void;

    // A group commit; durable when it returns.
    [[nodiscard]] auto write(std::span<const Write> batch) -> std::expected<void, StoreError>;
    // Writes again what writes already in the ring and above the commit
    // point hold (a member's resend after a crash, which may have torn
    // them): data, sync, checksums, sync, with no new intents, so a crash
    // here leaves them in the ring still. Each seq must be one of
    // intents().
    [[nodiscard]] auto rewrite(std::span<const Write> batch) -> std::expected<void, StoreError>;
    // Reads blocks [lba, lba + out/block_size) and their stored CRC32Cs;
    // returns the LBAs whose data does not match (empty: all good). A block
    // never written reads as zeros with a stored CRC of 0, which is not a
    // mismatch (the CRC32C of a zero block is not 0). On a volume with a
    // source that holds only past the source (past_source); a block the
    // source covers is unhydrated until a write or hydration stores its
    // checksum, so zeros with CRC 0 there are a torn write.
    [[nodiscard]] auto read(std::uint64_t lba, std::span<std::byte> out,
                            std::span<std::uint32_t> crcs)
        -> std::expected<std::vector<std::uint64_t>, StoreError>;
    // Fills the blocks of [lba, ...) still unhydrated; returns how many.
    [[nodiscard]] auto hydrate(std::uint64_t lba, std::span<const std::byte> data,
                               std::span<const std::uint32_t> crcs)
        -> std::expected<std::uint64_t, StoreError>;
    // Replaces one block a read found bad with a good copy from another
    // replica (checksum repair, Requirement 5.4): data, sync, checksum,
    // sync. No intent: a crash in between leaves a block that is still
    // bad, or already good, and the next read repairs it again. A
    // never-written copy (zeros with CRC 0) is accepted past the source.
    [[nodiscard]] auto repair(std::uint64_t lba, std::span<const std::byte> block,
                              std::uint32_t crc) -> std::expected<void, StoreError>;
    // Resync and rebuild (task 11). copy() stores blocks as another
    // replica holds them, checksums included, bad ones too (a read finds
    // and repairs those): data, sync, checksums, sync, no intent. A crash
    // in between leaves a region the copy sends again.
    [[nodiscard]] auto copy(std::uint64_t lba, std::span<const std::byte> data,
                            std::span<const std::uint32_t> crcs) -> std::expected<void, StoreError>;
    // Whether any block of [lba, lba + blocks) was ever written (has a
    // checksum): what a rebuild copies.
    [[nodiscard]] auto written(std::uint64_t lba, std::uint64_t blocks)
        -> std::expected<bool, StoreError>;
    // A rebuilt replica takes up a primary's stream at `seq`: the intent
    // ring is emptied (durably) and the sequence restarts there, so writes
    // numbered below what this replica held before are taken, not
    // mistaken for resends. Its old intents must already be in the copy.
    [[nodiscard]] auto rebase(std::uint64_t seq) -> std::expected<void, StoreError>;
    [[nodiscard]] auto unhydrated(std::uint64_t lba) -> std::expected<bool, StoreError>;
    [[nodiscard]] auto chunk_state(std::uint64_t chunk) -> std::expected<ChunkState, StoreError>;
    // Chunks written since the last clear_changed (a snapshot freeze).
    [[nodiscard]] auto changed_chunks() -> std::expected<std::vector<std::uint64_t>, StoreError>;
    [[nodiscard]] auto clear_changed() -> std::expected<void, StoreError>;
    // Makes everything written so far durable (FLUSH, close).
    [[nodiscard]] auto flush() -> std::expected<void, StoreError>;
    // Whether a never-written block may sit at `lba`: always without a
    // source, and in the capacity a grow() added past one.
    [[nodiscard]] auto past_source(std::uint64_t lba) const noexcept -> bool;
    // Raises the capacity to `capacity_blocks` (see above); the same
    // capacity again is a no-op, a smaller one bad_request.
    [[nodiscard]] auto grow(std::uint64_t capacity_blocks) -> std::expected<void, StoreError>;

private:
    ReplicaStore(FileLayer& files, std::filesystem::path dir, ReplicaMeta meta,
                 std::unique_ptr<File> data, std::unique_ptr<File> meta_file) noexcept;

    [[nodiscard]] auto write_header(ReplicaMeta next) -> std::expected<void, StoreError>;
    [[nodiscard]] auto check_range(std::uint64_t lba, std::size_t bytes) const noexcept -> bool;
    [[nodiscard]] auto set_bits(std::uint64_t region, std::uint64_t first, std::uint64_t count,
                                bool value) -> std::expected<void, StoreError>;
    [[nodiscard]] auto any_bit(std::uint64_t region, std::uint64_t first, std::uint64_t count)
        -> std::expected<bool, StoreError>;
    [[nodiscard]] auto count_bits(std::uint64_t region, std::uint64_t first, std::uint64_t count)
        -> std::expected<std::uint64_t, StoreError>;
    [[nodiscard]] auto write_checksums(std::uint64_t lba, std::span<const std::uint32_t> crcs)
        -> std::expected<void, StoreError>;
    [[nodiscard]] auto mark_written(std::uint64_t lba, std::uint64_t blocks)
        -> std::expected<void, StoreError>;
    [[nodiscard]] auto recover() -> std::expected<void, StoreError>;
    [[nodiscard]] auto sync_meta() -> std::expected<void, StoreError>;

    FileLayer* _files;
    std::filesystem::path _dir;
    ReplicaMeta _meta;
    MetaLayout _layout;
    std::unique_ptr<File> _data;
    std::unique_ptr<File> _meta_file;
    bool _reflink{false};
    std::uint64_t _last_seq{0};
    std::uint64_t _commit_seq{0};
    std::uint64_t _meta_synced_seq{0};  // writes up to here have durable checksums
    std::vector<Intent> _ring;          // by slot; seq 0 empty
};

}  // namespace ak::hold::store
