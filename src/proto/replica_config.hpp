// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ReplicaConfig: the controller's signed, full description of one network
// volume's replica set at one epoch (.kiro/specs/block-volume-service/
// Requirement 6, design "Protocols" and "Epochs, leases and fencing").
// helm verifies it with the controller keys it holds for MapUpdate and
// hands it to the hold role (members) or oar-blk (attachments) on its
// server.
//
// Like MapUpdate it is a snapshot, not a delta: applying one is idempotent
// and a role that missed epochs catches up from the newest alone. Roles
// refuse an epoch lower than the newest they applied; that ordering check
// is theirs, not the decoder's. One frame per recipient server, whose
// server_id is inside the signed bytes, so a config cannot be replayed to
// another server.
//
// Layout (little-endian):
//   0x00  magic             [8]  "AKRCFG\0\0"
//   0x08  version           u16  frame format version (1)
//   0x0A  key_id            u16  controller key that signed it; non-zero
//   0x0C  member_count      u8   1 to max_replica_members
//   0x0D  attachment_count  u8   at most max_volume_attachments
//   0x0E  reserved          u16  zero
//   0x10  server_id         u64  recipient server; non-zero
//   0x18  volume_id         u64  non-zero
//   0x20  epoch             u64  per volume, starts at 1
//   0x28  lineage_id        u64  key lineage (volume, snapshots, clones); non-zero
//   0x30  capacity_blocks   u64  non-zero
//   0x38  block_size        u32  512 or 4096
//   0x3C  flags             u32  ReplicaFlags; other bits zero
//   0x40  qos               iops u32 | mib_per_s u32 | burst_iops u32 | burst_mib u32
//   0x50  lease_ms          u32  non-zero
//   0x54  resync_window_s   u32
//   0x58  source            kind u8 | reserved [3] | store_id u32 |
//                           hydrate_mib_per_s u32 | reserved u32 |
//                           manifest_name [32]
//   0x88  members           member_count x 32, server IDs strictly ascending:
//           +0x00 server_id u64 | +0x08 endpoint [16] (IPv6, network order)
//           +0x18 port u16 | +0x1A role u8 | +0x1B reserved u8
//           +0x1C replica_gen u32
//   then  attachments       attachment_count x 24, IDs strictly ascending:
//           +0x00 attachment_id u64 | +0x08 server_id u64
//           +0x10 generation u32 | +0x14 mode u8 | +0x15 reserved [3]
//   then  signature         64 bytes, Ed25519 over every byte before it
//
// Rules the decoder checks beyond reserved bytes and known enum values:
// exactly one primary unless io_suspended (then at most one); joining and
// leaving members are never primary (the role enum makes that structural);
// every member has a non-zero server ID, a unicast endpoint, a port and a
// replica_gen; every attachment has non-zero IDs and generation; more than
// one read-write attachment only with multi_attach; QoS limits non-zero
// with each burst at least its baseline; a source of kind none is all zero
// and any other kind names a store, a manifest and a hydration rate.
//
// Whether server_id appears among the members or attachments is not
// checked: a server dropped from a volume may still be sent the epoch that
// removes it. Endpoints are IPv6; an IPv4 storage segment uses
// IPv4-mapped addresses (::ffff:a.b.c.d).

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint64_t replica_config_magic =
    0x0000'4746'4352'4B41;  // "AKRCFG\0\0" as little-endian bytes
inline constexpr std::uint16_t replica_config_version = 1;
inline constexpr std::size_t replica_config_header_size = 0x88;
inline constexpr std::size_t replica_member_size = 32;
inline constexpr std::size_t volume_attachment_size = 24;
inline constexpr std::size_t max_replica_members = 5;
inline constexpr std::size_t max_volume_attachments = 16;
inline constexpr std::size_t manifest_name_size = 32;  // SHA-256 of the manifest
inline constexpr std::uint32_t block_size_512 = 512;
inline constexpr std::uint32_t block_size_4096 = 4096;

using ManifestName = std::array<std::byte, manifest_name_size>;
using StorageEndpoint = Ipv6Address;  // checked with detail::unicast

// Bits of ReplicaConfig::flags.
namespace replica_flags {
inline constexpr std::uint32_t multi_attach = 0x1;  // more than one read-write attachment allowed
inline constexpr std::uint32_t io_suspended = 0x2;  // no in-sync replica; initiators fail I/O
inline constexpr std::uint32_t impaired = 0x4;      // reported to the tenant (Requirement 6.8)
inline constexpr std::uint32_t draining = 0x8;      // being moved off a draining server
inline constexpr std::uint32_t all = multi_attach | io_suspended | impaired | draining;
}  // namespace replica_flags

// Values are part of the wire protocol: never renumber.
enum class ReplicaRole : std::uint8_t {
    primary = 1,
    secondary = 2,
    joining = 3,  // being rebuilt: receives writes, not yet in sync
    leaving = 4,  // planned handover away from this member
};

enum class AttachMode : std::uint8_t {
    rw = 1,
    ro = 2,
};

enum class SourceKind : std::uint8_t {
    none = 0,      // starts empty
    snapshot = 1,  // same-lineage snapshot: hold hydrates (design "Restore")
    image = 2,     // foreign-key image: oar-blk hydrates
};

struct VolumeQos {
    std::uint32_t iops{0};
    std::uint32_t mib_per_s{0};
    std::uint32_t burst_iops{0};
    std::uint32_t burst_mib{0};
    friend auto operator==(const VolumeQos&, const VolumeQos&) -> bool = default;
};

struct ReplicaMember {
    std::uint64_t server_id{0};
    StorageEndpoint endpoint{};
    std::uint16_t port{0};
    ReplicaRole role{ReplicaRole::secondary};
    std::uint32_t replica_gen{0};
    friend auto operator==(const ReplicaMember&, const ReplicaMember&) -> bool = default;
};

struct VolumeAttachment {
    std::uint64_t attachment_id{0};
    std::uint64_t server_id{0};
    std::uint32_t generation{0};
    AttachMode mode{AttachMode::rw};
    friend auto operator==(const VolumeAttachment&, const VolumeAttachment&) -> bool = default;
};

struct VolumeSource {
    SourceKind kind{SourceKind::none};
    std::uint32_t store_id{0};
    std::uint32_t hydrate_mib_per_s{0};
    ManifestName manifest_name{};
    friend auto operator==(const VolumeSource&, const VolumeSource&) -> bool = default;
};

struct ReplicaConfig {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t lineage_id{0};
    std::uint64_t capacity_blocks{0};
    std::uint32_t block_size{block_size_4096};
    std::uint32_t flags{0};
    VolumeQos qos{};
    std::uint32_t lease_ms{0};
    std::uint32_t resync_window_s{0};
    VolumeSource source{};
    std::vector<ReplicaMember> members;         // server IDs strictly ascending
    std::vector<VolumeAttachment> attachments;  // attachment IDs strictly ascending
    Ed25519Signature signature{};

    friend auto operator==(const ReplicaConfig&, const ReplicaConfig&) -> bool = default;
};

[[nodiscard]] inline constexpr auto replica_config_size(std::size_t members,
                                                        std::size_t attachments) noexcept
    -> std::size_t {
    return replica_config_header_size + (members * replica_member_size) +
           (attachments * volume_attachment_size) + ed25519_signature_size;
}

inline constexpr std::size_t max_replica_config_size =
    replica_config_size(max_replica_members, max_volume_attachments);

// The bytes a ReplicaConfig signature covers: all but the trailing 64.
[[nodiscard]] inline auto replica_config_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return map_update_signed_bytes(frame);
}

// Writes `signature` over the trailing 64 bytes of an encoded frame.
inline auto set_replica_config_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    set_map_update_signature(frame, signature);
}

// The member with role primary, or nullptr (only while io_suspended).
[[nodiscard]] inline auto primary_member(const ReplicaConfig& c) noexcept -> const ReplicaMember* {
    const auto it = std::ranges::find(c.members, ReplicaRole::primary, &ReplicaMember::role);
    return it == c.members.end() ? nullptr : &*it;
}

namespace detail {

[[nodiscard]] constexpr auto known(ReplicaRole r) noexcept -> bool {
    return r >= ReplicaRole::primary && r <= ReplicaRole::leaving;
}
[[nodiscard]] constexpr auto known(AttachMode m) noexcept -> bool {
    return m == AttachMode::rw || m == AttachMode::ro;
}
[[nodiscard]] constexpr auto known(SourceKind k) noexcept -> bool {
    return k <= SourceKind::image;
}

[[nodiscard]] inline auto check_replica_config(const ReplicaConfig& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (c.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (c.volume_id == 0 || c.lineage_id == 0 || c.capacity_blocks == 0 || c.lease_ms == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (c.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    if (c.block_size != block_size_512 && c.block_size != block_size_4096) {
        return std::unexpected(DecodeError::bad_block_size);
    }
    if ((c.flags & ~replica_flags::all) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (c.qos.iops == 0 || c.qos.mib_per_s == 0 || c.qos.burst_iops < c.qos.iops ||
        c.qos.burst_mib < c.qos.mib_per_s) {
        return std::unexpected(DecodeError::bad_qos);
    }
    if (!known(c.source.kind)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    const bool named = !all_zero(c.source.manifest_name);
    if (c.source.kind == SourceKind::none
            ? (c.source.store_id != 0 || c.source.hydrate_mib_per_s != 0 || named)
            : (c.source.store_id == 0 || c.source.hydrate_mib_per_s == 0 || !named)) {
        return std::unexpected(DecodeError::bad_source);
    }

    if (c.members.empty() || c.members.size() > max_replica_members) {
        return std::unexpected(DecodeError::too_many_members);
    }
    std::size_t primaries = 0;
    for (const auto& m : c.members) {
        if (!known(m.role)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (m.server_id == 0) {
            return std::unexpected(DecodeError::bad_server_id);
        }
        if (!unicast(m.endpoint) || m.port == 0 || m.replica_gen == 0) {
            return std::unexpected(DecodeError::bad_member);
        }
        primaries += m.role == ReplicaRole::primary ? 1 : 0;
    }
    if (std::ranges::adjacent_find(c.members, std::ranges::greater_equal{},
                                   &ReplicaMember::server_id) != c.members.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    const bool suspended = (c.flags & replica_flags::io_suspended) != 0;
    if (primaries > 1 || (primaries == 0 && !suspended)) {
        return std::unexpected(DecodeError::bad_roles);
    }

    if (c.attachments.size() > max_volume_attachments) {
        return std::unexpected(DecodeError::too_many_attachments);
    }
    std::size_t writers = 0;
    for (const auto& a : c.attachments) {
        if (!known(a.mode)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (a.attachment_id == 0 || a.generation == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (a.server_id == 0) {
            return std::unexpected(DecodeError::bad_server_id);
        }
        writers += a.mode == AttachMode::rw ? 1 : 0;
    }
    if (std::ranges::adjacent_find(c.attachments, std::ranges::greater_equal{},
                                   &VolumeAttachment::attachment_id) != c.attachments.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    if (writers > 1 && (c.flags & replica_flags::multi_attach) == 0) {
        return std::unexpected(DecodeError::bad_attachment_mode);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// replica_config_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_replica_config(std::span<const std::byte> bytes)
    -> std::expected<ReplicaConfig, DecodeError> {
    if (bytes.size() < replica_config_header_size) {
        return std::unexpected(DecodeError::truncated);
    }
    // The header is present, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le64().value_or(0);
    const auto version = r.le16().value_or(0);
    ReplicaConfig c;
    c.key_id = r.le16().value_or(0);
    const std::size_t member_count = r.u8().value_or(0);
    const std::size_t attachment_count = r.u8().value_or(0);
    bool zero = r.le16().value_or(1) == 0;
    c.server_id = r.le64().value_or(0);
    c.volume_id = r.le64().value_or(0);
    c.epoch = r.le64().value_or(0);
    c.lineage_id = r.le64().value_or(0);
    c.capacity_blocks = r.le64().value_or(0);
    c.block_size = r.le32().value_or(0);
    c.flags = r.le32().value_or(0);
    c.qos.iops = r.le32().value_or(0);
    c.qos.mib_per_s = r.le32().value_or(0);
    c.qos.burst_iops = r.le32().value_or(0);
    c.qos.burst_mib = r.le32().value_or(0);
    c.lease_ms = r.le32().value_or(0);
    c.resync_window_s = r.le32().value_or(0);
    c.source.kind = static_cast<SourceKind>(r.u8().value_or(0));
    zero = detail::all_zero(r.bytes(3).value_or(std::span<const std::byte>{})) && zero;
    c.source.store_id = r.le32().value_or(0);
    c.source.hydrate_mib_per_s = r.le32().value_or(0);
    zero = r.le32().value_or(1) == 0 && zero;
    std::ranges::copy(r.bytes(manifest_name_size).value_or(std::span<const std::byte>{}),
                      c.source.manifest_name.begin());

    if (magic != replica_config_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != replica_config_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (member_count == 0 || member_count > max_replica_members) {
        return std::unexpected(DecodeError::too_many_members);
    }
    if (attachment_count > max_volume_attachments) {
        return std::unexpected(DecodeError::too_many_attachments);
    }
    // The exact length is known before anything is allocated.
    const std::size_t want = replica_config_size(member_count, attachment_count);
    if (bytes.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }

    c.members.resize(member_count);
    for (auto& m : c.members) {
        m.server_id = r.le64().value_or(0);
        std::ranges::copy(r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{}),
                          m.endpoint.begin());
        m.port = r.le16().value_or(0);
        m.role = static_cast<ReplicaRole>(r.u8().value_or(0));
        zero = r.u8().value_or(1) == 0 && zero;
        m.replica_gen = r.le32().value_or(0);
    }
    c.attachments.resize(attachment_count);
    for (auto& a : c.attachments) {
        a.attachment_id = r.le64().value_or(0);
        a.server_id = r.le64().value_or(0);
        a.generation = r.le32().value_or(0);
        a.mode = static_cast<AttachMode>(r.u8().value_or(0));
        zero = detail::all_zero(r.bytes(3).value_or(std::span<const std::byte>{})) && zero;
    }
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      c.signature.begin());
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_replica_config(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

// Encodes a ReplicaConfig (with whatever is in `signature`), enforcing
// every rule decode_replica_config checks.
[[nodiscard]] inline auto encode_replica_config(const ReplicaConfig& c)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_replica_config(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(replica_config_size(c.members.size(), c.attachments.size()));
    wire::Writer w{out};
    w.le64(replica_config_magic);
    w.le16(replica_config_version);
    w.le16(c.key_id);
    w.u8(static_cast<std::uint8_t>(c.members.size()));
    w.u8(static_cast<std::uint8_t>(c.attachments.size()));
    w.le16(0);
    w.le64(c.server_id);
    w.le64(c.volume_id);
    w.le64(c.epoch);
    w.le64(c.lineage_id);
    w.le64(c.capacity_blocks);
    w.le32(c.block_size);
    w.le32(c.flags);
    w.le32(c.qos.iops);
    w.le32(c.qos.mib_per_s);
    w.le32(c.qos.burst_iops);
    w.le32(c.qos.burst_mib);
    w.le32(c.lease_ms);
    w.le32(c.resync_window_s);
    w.u8(static_cast<std::uint8_t>(c.source.kind));
    w.bytes(std::array<std::byte, 3>{});
    w.le32(c.source.store_id);
    w.le32(c.source.hydrate_mib_per_s);
    w.le32(0);
    w.bytes(c.source.manifest_name);
    for (const auto& m : c.members) {
        w.le64(m.server_id);
        w.bytes(m.endpoint);
        w.le16(m.port);
        w.u8(static_cast<std::uint8_t>(m.role));
        w.u8(0);
        w.le32(m.replica_gen);
    }
    for (const auto& a : c.attachments) {
        w.le64(a.attachment_id);
        w.le64(a.server_id);
        w.le32(a.generation);
        w.u8(static_cast<std::uint8_t>(a.mode));
        w.bytes(std::array<std::byte, 3>{});
    }
    w.bytes(c.signature);
    return out;
}

}  // namespace ak::proto
