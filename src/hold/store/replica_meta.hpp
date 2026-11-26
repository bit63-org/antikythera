// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The `meta` file of a hold replica (.kiro/specs/block-volume-service/
// design "ReplicaStore"): what a replica is, and where its per-block
// state lives. Little-endian, decoded strictly with ak::wire and fuzzed
// (fuzz/fuzz_replica_meta.cpp): it is read back from a disk an attacker
// with the storage board may have written.
//
// The header is kept twice, in 4 KiB slots A and B; an update writes the
// slot not holding the newest valid copy with header_seq + 1, so a torn
// header write leaves the other copy. Each slot:
//
//   0x00 magic "AKREPLIC" (le64)      0x08 version u16 = 1, role u8,
//   0x0B source kind u8               0x0C block_size u32 (512 | 4096)
//   0x10 volume_id u64                0x18 lineage_id u64
//   0x20 epoch u64 (last applied)     0x28 capacity_blocks u64
//   0x30 header_seq u64               0x38 replica_gen u32
//   0x3C chunk_shift u8, rsvd[3]      0x40 source store_id u32,
//   0x44 hydrate_mib_per_s u32        0x48 manifest_name [32]
//   0x68 source_blocks u64            0x70 reserved, zero, to 0xE0
//   0xE0 SHA-256 over [0, 0xE0)
//
// source_blocks is 0 unless a volume with a source grew (grow() in
// replica_store.hpp): then the blocks the source covers, below the
// capacity. Blocks from there on never await hydration, so one that was
// never written reads as zeros there, as on a volume without a source.
//   0x100 zero to the end of the slot
//
// After the slots, each region 4 KiB-aligned (layout() computes them):
//   checksums   CRC32C per block, le32;
//   unhydrated  one bit per block, set while the block awaits hydration;
//   changed     one bit per chunk written since the last snapshot freeze;
//   intents     a ring of 4096 entries of 32 bytes, slot = seq % 4096:
//               seq u64 (0: empty), lba u64, blocks u32, flags u64
//               (bit 0: a hydrate write; the rest zero), le32 CRC32C
//               over the first 28 bytes.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "proto/replica_config.hpp"

namespace ak::hold::store {

inline constexpr std::uint64_t meta_magic = 0x4349'4C50'4552'4B41;  // "AKREPLIC"
inline constexpr std::uint16_t meta_version = 1;
inline constexpr std::size_t meta_slot_size = 4096;
inline constexpr std::size_t meta_fields_size = 0xE0;
inline constexpr std::size_t meta_digest_size = 32;
inline constexpr std::size_t intent_entry_size = 32;
inline constexpr std::size_t intent_ring_entries = 4096;
inline constexpr std::uint64_t intent_flag_hydrate = 1;
inline constexpr std::size_t meta_align = 4096;
inline constexpr std::uint8_t min_chunk_shift = 12;  // 4 KiB
inline constexpr std::uint8_t max_chunk_shift = 30;  // 1 GiB
// 16 TiB at 512-byte blocks (Requirement 1.4's top size).
inline constexpr std::uint64_t max_capacity_blocks = 1ULL << 35U;

struct ReplicaMeta {
    std::uint64_t volume_id{0};
    std::uint64_t lineage_id{0};
    std::uint32_t replica_gen{0};
    std::uint64_t epoch{0};
    proto::ReplicaRole role{proto::ReplicaRole::secondary};
    std::uint64_t capacity_blocks{0};
    std::uint32_t block_size{proto::block_size_4096};
    std::uint8_t chunk_shift{20};  // 1 MiB: hydration and changed-chunk granularity
    proto::VolumeSource source{};
    std::uint64_t header_seq{1};
    std::uint64_t source_blocks{0};  // 0: the source covers the whole capacity
    friend auto operator==(const ReplicaMeta&, const ReplicaMeta&) -> bool = default;
};

enum class MetaError : std::uint8_t {
    truncated,
    bad_magic,
    bad_version,
    bad_digest,
    bad_field,  // an ID of 0, an unknown role or source, a bad size
    nonzero_reserved,
    crypto,  // SHA-256 unavailable
};

[[nodiscard]] auto to_string(MetaError e) noexcept -> const char*;

struct MetaLayout {
    std::uint64_t checksums{0};
    std::uint64_t unhydrated{0};
    std::uint64_t changed{0};
    std::uint64_t intents{0};
    std::uint64_t end{0};  // the meta file's size
    std::uint64_t chunks{0};
};

// Only for a ReplicaMeta that decode accepts (or encode would).
[[nodiscard]] auto layout(const ReplicaMeta& m) noexcept -> MetaLayout;

[[nodiscard]] auto encode_replica_meta(const ReplicaMeta& m)
    -> std::expected<std::array<std::byte, meta_slot_size>, MetaError>;
[[nodiscard]] auto decode_replica_meta(std::span<const std::byte> slot)
    -> std::expected<ReplicaMeta, MetaError>;
// The newest valid of the two slots ([0, 8 KiB) of the file).
[[nodiscard]] auto decode_meta_slots(std::span<const std::byte> both)
    -> std::expected<ReplicaMeta, MetaError>;

struct Intent {
    std::uint64_t seq{0};
    std::uint64_t lba{0};
    std::uint32_t blocks{0};
    bool hydrate{false};  // stored only the blocks still unhydrated
    friend auto operator==(const Intent&, const Intent&) -> bool = default;
};

[[nodiscard]] auto encode_intent(const Intent& i) -> std::array<std::byte, intent_entry_size>;
// Refuses an empty (seq 0), torn or corrupt entry (bad_digest), or one
// outside `capacity_blocks` (bad_field).
[[nodiscard]] auto decode_intent(std::span<const std::byte> entry, std::uint64_t capacity_blocks)
    -> std::expected<Intent, MetaError>;

}  // namespace ak::hold::store
