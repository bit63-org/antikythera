// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/store/replica_meta.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"

namespace ak::hold::store {

namespace {

constexpr std::size_t intent_crc_offset = 28;
constexpr std::size_t reserved_after_chunk_shift = 3;
constexpr std::size_t reserved_fields = meta_fields_size - 0x68;

auto sha256(std::span<const std::byte> in, std::span<std::byte, meta_digest_size> out) -> bool {
    unsigned int len = 0;
    return EVP_Digest(in.data(), in.size(), reinterpret_cast<unsigned char*>(out.data()), &len,
                      EVP_sha256(), nullptr) == 1 &&
           len == meta_digest_size;
}

auto align_up(std::uint64_t n) noexcept -> std::uint64_t {
    return (n + meta_align - 1) / meta_align * meta_align;
}

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto valid_fields(const ReplicaMeta& m) noexcept -> bool {
    const bool role_ok =
        m.role >= proto::ReplicaRole::primary && m.role <= proto::ReplicaRole::leaving;
    const bool source_ok = m.source.kind == proto::SourceKind::none
                               ? m.source == proto::VolumeSource{}
                               : (m.source.kind == proto::SourceKind::snapshot ||
                                  m.source.kind == proto::SourceKind::image);
    const bool block_ok =
        m.block_size == proto::block_size_512 || m.block_size == proto::block_size_4096;
    return m.volume_id != 0 && m.lineage_id != 0 && m.replica_gen != 0 && m.header_seq != 0 &&
           role_ok && source_ok && block_ok && m.capacity_blocks != 0 &&
           m.capacity_blocks <= max_capacity_blocks && m.chunk_shift >= min_chunk_shift &&
           m.chunk_shift <= max_chunk_shift && (1ULL << m.chunk_shift) >= m.block_size;
}

}  // namespace

auto to_string(MetaError e) noexcept -> const char* {
    switch (e) {
        case MetaError::truncated:
            return "truncated";
        case MetaError::bad_magic:
            return "bad_magic";
        case MetaError::bad_version:
            return "bad_version";
        case MetaError::bad_digest:
            return "bad_digest";
        case MetaError::bad_field:
            return "bad_field";
        case MetaError::nonzero_reserved:
            return "nonzero_reserved";
        case MetaError::crypto:
            return "crypto";
    }
    return "unknown";
}

auto layout(const ReplicaMeta& m) noexcept -> MetaLayout {
    MetaLayout l;
    const std::uint64_t bytes = m.capacity_blocks * m.block_size;
    l.chunks = (bytes + (1ULL << m.chunk_shift) - 1) >> m.chunk_shift;
    l.checksums = 2 * meta_slot_size;
    l.unhydrated = l.checksums + align_up(m.capacity_blocks * sizeof(std::uint32_t));
    l.changed = l.unhydrated + align_up((m.capacity_blocks + 7) / 8);
    l.intents = l.changed + align_up((l.chunks + 7) / 8);
    l.end = l.intents + (intent_ring_entries * intent_entry_size);
    return l;
}

auto encode_replica_meta(const ReplicaMeta& m)
    -> std::expected<std::array<std::byte, meta_slot_size>, MetaError> {
    if (!valid_fields(m)) {
        return std::unexpected(MetaError::bad_field);
    }
    std::vector<std::byte> v;
    wire::Writer w{v};
    w.le64(meta_magic);
    w.le16(meta_version);
    w.u8(static_cast<std::uint8_t>(m.role));
    w.u8(static_cast<std::uint8_t>(m.source.kind));
    w.le32(m.block_size);
    w.le64(m.volume_id);
    w.le64(m.lineage_id);
    w.le64(m.epoch);
    w.le64(m.capacity_blocks);
    w.le64(m.header_seq);
    w.le32(m.replica_gen);
    w.u8(m.chunk_shift);
    for (std::size_t i = 0; i < reserved_after_chunk_shift; ++i) {
        w.u8(0);
    }
    w.le32(m.source.store_id);
    w.le32(m.source.hydrate_mib_per_s);
    w.bytes(m.source.manifest_name);
    v.resize(meta_fields_size);
    std::array<std::byte, meta_slot_size> out{};
    std::ranges::copy(v, out.begin());
    if (!sha256(std::span{out}.first(meta_fields_size),
                std::span{out}.subspan<meta_fields_size, meta_digest_size>())) {
        return std::unexpected(MetaError::crypto);
    }
    return out;
}

auto decode_replica_meta(std::span<const std::byte> slot) -> std::expected<ReplicaMeta, MetaError> {
    if (slot.size() != meta_slot_size) {
        return std::unexpected(MetaError::truncated);
    }
    wire::Reader r{slot};
    // The reads below cannot run short: the slot is 4 KiB.
    if (r.le64().value_or(0) != meta_magic) {
        return std::unexpected(MetaError::bad_magic);
    }
    if (r.le16().value_or(0) != meta_version) {
        return std::unexpected(MetaError::bad_version);
    }
    std::array<std::byte, meta_digest_size> digest{};
    if (!sha256(slot.first(meta_fields_size), digest)) {
        return std::unexpected(MetaError::crypto);
    }
    if (!std::ranges::equal(digest, slot.subspan(meta_fields_size, meta_digest_size))) {
        return std::unexpected(MetaError::bad_digest);
    }
    ReplicaMeta m;
    m.role = static_cast<proto::ReplicaRole>(r.u8().value_or(0));
    m.source.kind = static_cast<proto::SourceKind>(r.u8().value_or(0xFF));
    m.block_size = r.le32().value_or(0);
    m.volume_id = r.le64().value_or(0);
    m.lineage_id = r.le64().value_or(0);
    m.epoch = r.le64().value_or(0);
    m.capacity_blocks = r.le64().value_or(0);
    m.header_seq = r.le64().value_or(0);
    m.replica_gen = r.le32().value_or(0);
    m.chunk_shift = r.u8().value_or(0);
    const auto rsvd1 = r.bytes(reserved_after_chunk_shift).value_or(std::span<const std::byte>{});
    m.source.store_id = r.le32().value_or(0);
    m.source.hydrate_mib_per_s = r.le32().value_or(0);
    const auto name = r.bytes(proto::manifest_name_size).value_or(std::span<const std::byte>{});
    std::ranges::copy(name, m.source.manifest_name.begin());
    const auto rsvd2 = r.bytes(reserved_fields).value_or(std::span<const std::byte>{});
    if (!all_zero(rsvd1) || !all_zero(rsvd2) ||
        !all_zero(slot.subspan(meta_fields_size + meta_digest_size))) {
        return std::unexpected(MetaError::nonzero_reserved);
    }
    if (!valid_fields(m)) {
        return std::unexpected(MetaError::bad_field);
    }
    return m;
}

auto decode_meta_slots(std::span<const std::byte> both) -> std::expected<ReplicaMeta, MetaError> {
    if (both.size() < 2 * meta_slot_size) {
        return std::unexpected(MetaError::truncated);
    }
    auto a = decode_replica_meta(both.first(meta_slot_size));
    auto b = decode_replica_meta(both.subspan(meta_slot_size, meta_slot_size));
    if (a && b) {
        return a->header_seq >= b->header_seq ? *a : *b;
    }
    if (a) {
        return a;
    }
    return b;  // b's value, or b's error when neither decodes
}

auto encode_intent(const Intent& i) -> std::array<std::byte, intent_entry_size> {
    std::vector<std::byte> v;
    wire::Writer w{v};
    w.le64(i.seq);
    w.le64(i.lba);
    w.le32(i.blocks);
    w.le64(0);
    w.le32(crc32c::of(v));
    std::array<std::byte, intent_entry_size> out{};
    std::ranges::copy(v, out.begin());
    return out;
}

auto decode_intent(std::span<const std::byte> entry, std::uint64_t capacity_blocks)
    -> std::expected<Intent, MetaError> {
    if (entry.size() != intent_entry_size) {
        return std::unexpected(MetaError::truncated);
    }
    wire::Reader r{entry};
    Intent i;
    i.seq = r.le64().value_or(0);
    i.lba = r.le64().value_or(0);
    i.blocks = r.le32().value_or(0);
    const std::uint64_t rsvd = r.le64().value_or(1);
    const std::uint32_t crc = r.le32().value_or(0);
    if (crc != crc32c::of(entry.first(intent_crc_offset))) {
        return std::unexpected(MetaError::bad_digest);
    }
    if (rsvd != 0) {
        return std::unexpected(MetaError::nonzero_reserved);
    }
    if (i.seq == 0 || i.blocks == 0 || i.lba > capacity_blocks ||
        i.blocks > capacity_blocks - i.lba) {
        return std::unexpected(MetaError::bad_field);
    }
    return i;
}

}  // namespace ak::hold::store
