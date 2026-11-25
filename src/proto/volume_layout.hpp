// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VolumeLayout: the controller's signed, full description of one khold
// volume at one layout epoch (kythira .kiro/specs/khold-block-service/
// design "Layouts, authority and fencing", Requirements 3, 5, 6 and 11.5):
// its striping, the members of each stripe group and their kinds, the
// gateways of a split layout, the attachments and their generations, QoS,
// timings and an in-progress mirror migration. helm relays it byte for
// byte, as it relays ReplicaConfig; the khold node verifies the signature
// itself with the controller keys it was started with, and the initiator
// (oar-blk) seeds its group-to-leader map from it and follows a hold v2
// redirect only to a member of the group named here.
//
// Like ReplicaConfig it is a snapshot, not a delta: applying one is
// idempotent, and a node refuses an epoch lower than the newest its group
// has committed (that ordering check is the receiver's, not the
// decoder's). One frame per recipient server, whose server_id is signed,
// so a layout cannot be replayed to another server.
//
// Layout (little-endian):
//   0x00  magic             [8]  "AKVLAY\0\0"
//   0x08  version           u16  frame format version (1)
//   0x0A  key_id            u16  controller key that signed it; non-zero
//   0x0C  stripe_width      u16  stripe groups, 1 to max_stripe_width
//   0x0E  gateway_count     u8   at most max_layout_gateways (0: co-located)
//   0x0F  attachment_count  u8   at most max_volume_attachments
//   0x10  server_id         u64  recipient server; non-zero
//   0x18  volume_id         u64  non-zero
//   0x20  epoch             u64  per volume, starts at 1
//   0x28  lineage_id        u64  key lineage; non-zero
//   0x30  capacity_blocks   u64  non-zero
//   0x38  block_size        u32  512 or 4096
//   0x3C  stripe_unit       u32  bytes; a power of two, 64 KiB to 4 MiB
//   0x40  flags             u32  layout_flags; other bits zero
//   0x44  commit_rule       u8   CommitRule
//   0x45  group_skew_pct    u8   per-group QoS skew allowance, 0 to 100
//   0x46  reserved          u16  zero
//   0x48  qos               iops u32 | mib_per_s u32 | burst_iops u32 | burst_mib u32
//   0x58  timings           member_deadline_ms u32 | election_min_ms u32 |
//                           resync_window_s u32 | reserved u32
//   0x68  mirror            peer_backend u8 | phase u8 | reserved [6] | peer_volume u64
//   0x78  groups            stripe_width entries, in stripe order (group i holds
//                           stripe units i, i + G, i + 2G, ...):
//           +0x00 group_id u64 | +0x08 member_count u8 | +0x09 reserved [7]
//           +0x10 members  member_count x 32, server IDs strictly ascending:
//                   +0x00 server_id u64 | +0x08 endpoint [16] (IPv6, network order)
//                   +0x18 port u16 | +0x1A kind u8 | +0x1B drive u8 | +0x1C reserved u32
//   then  gateways          gateway_count x 32, server IDs strictly ascending:
//           +0x00 server_id u64 | +0x08 endpoint [16] | +0x18 port u16 | +0x1A reserved [6]
//   then  attachments       attachment_count x 24, IDs strictly ascending (as ReplicaConfig):
//           +0x00 attachment_id u64 | +0x08 server_id u64
//           +0x10 generation u32 | +0x14 mode u8 | +0x15 reserved [3]
//   then  signature         64 bytes, Ed25519 over every byte before it
//
// Rules the decoder checks beyond reserved bytes and known enum values:
// stripe width 1 to 64 and a valid stripe unit; group IDs non-zero and
// unique; each group has 1 to max_group_members members on distinct
// servers (strictly ascending server IDs), at least one data member and at
// most one witness; every member and gateway has a non-zero server ID, a
// unicast endpoint and a port; attachments as in ReplicaConfig (non-zero
// IDs and generation, more than one read-write attachment only with
// multi_attach); QoS limits non-zero with each burst at least its
// baseline and the skew at most 100 %; member_deadline_ms and
// election_min_ms non-zero; mirror_source and mirror_target never both
// set, and a peer backend and peer volume exactly when one is.
//
// Failure-domain spread, which drive a member's replica lives on, and
// whether server_id appears in the layout are the controller's and the
// receiver's business, not the decoder's. The phase 2 `source` (snapshot
// or image hydration) is not in format 1; it arrives with a new version.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/hold_wire_v2.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"

namespace ak::proto {

inline constexpr std::uint64_t volume_layout_magic =
    0x0000'5941'4C56'4B41;  // "AKVLAY\0\0" as little-endian bytes
inline constexpr std::uint16_t volume_layout_version = 1;
inline constexpr std::size_t volume_layout_header_size = 0x78;
inline constexpr std::size_t layout_group_fixed_size = 16;
inline constexpr std::size_t layout_member_size = 32;
inline constexpr std::size_t layout_gateway_size = 32;
inline constexpr std::size_t max_group_members = 5;
inline constexpr std::size_t max_layout_gateways = 16;
inline constexpr std::uint8_t max_group_skew_pct = 100;

// Bits of VolumeLayout::flags.
namespace layout_flags {
inline constexpr std::uint32_t multi_attach = 0x1;       // more than one rw attachment allowed
inline constexpr std::uint32_t io_suspended = 0x2;       // initiators fail I/O
inline constexpr std::uint32_t impaired = 0x4;           // reported to the tenant
inline constexpr std::uint32_t mirror_source = 0x8;      // this volume is a migration's source
inline constexpr std::uint32_t mirror_target = 0x10;     // this volume is a migration's target
inline constexpr std::uint32_t no_space_warning = 0x20;  // an overcommitted drive is near full
inline constexpr std::uint32_t all =
    multi_attach | io_suspended | impaired | mirror_source | mirror_target | no_space_warning;
}  // namespace layout_flags

// Values are part of the wire protocol: never renumber.
enum class CommitRule : std::uint8_t {
    all_in_sync = 1,  // majority, every non-lagging data replica, at least one data replica
    majority = 2,     // majority of voters, at least one data replica
};

enum class MemberKind : std::uint8_t {
    data = 1,     // votes, stores blocks, may lead
    witness = 2,  // votes, stores entry descriptors only, never leads
    learner = 3,  // being rebuilt: receives entries, does not vote
};

enum class MirrorBackend : std::uint8_t {
    none = 0,
    hold = 1,
    khold = 2,
};

enum class MirrorPhase : std::uint8_t {
    none = 0,
    prepare = 1,  // target created, fenced to the copier and the attachments
    mirror = 2,   // writes go to both backends
    copy = 3,     // the copier fills the target with hydrate writes
};

struct LayoutTimings {
    std::uint32_t member_deadline_ms{0};
    std::uint32_t election_min_ms{0};
    std::uint32_t resync_window_s{0};
    friend auto operator==(const LayoutTimings&, const LayoutTimings&) -> bool = default;
};

struct LayoutMirror {
    MirrorBackend peer_backend{MirrorBackend::none};
    MirrorPhase phase{MirrorPhase::none};
    std::uint64_t peer_volume{0};
    friend auto operator==(const LayoutMirror&, const LayoutMirror&) -> bool = default;
};

struct LayoutMember {
    std::uint64_t server_id{0};
    StorageEndpoint endpoint{};
    std::uint16_t port{0};
    MemberKind kind{MemberKind::data};
    std::uint8_t drive{0};
    friend auto operator==(const LayoutMember&, const LayoutMember&) -> bool = default;
};

struct StripeGroup {
    std::uint64_t group_id{0};
    std::vector<LayoutMember> members;  // server IDs strictly ascending
    friend auto operator==(const StripeGroup&, const StripeGroup&) -> bool = default;
};

struct LayoutGateway {
    std::uint64_t server_id{0};
    StorageEndpoint endpoint{};
    std::uint16_t port{0};
    friend auto operator==(const LayoutGateway&, const LayoutGateway&) -> bool = default;
};

struct VolumeLayout {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t lineage_id{0};
    std::uint64_t capacity_blocks{0};
    std::uint32_t block_size{block_size_4096};
    std::uint32_t stripe_unit{std::uint32_t{1} << 20U};
    std::uint32_t flags{0};
    CommitRule commit_rule{CommitRule::all_in_sync};
    std::uint8_t group_skew_pct{0};
    VolumeQos qos{};
    LayoutTimings timings{};
    LayoutMirror mirror{};
    std::vector<StripeGroup> groups;            // stripe order
    std::vector<LayoutGateway> gateways;        // server IDs strictly ascending
    std::vector<VolumeAttachment> attachments;  // attachment IDs strictly ascending
    Ed25519Signature signature{};

    friend auto operator==(const VolumeLayout&, const VolumeLayout&) -> bool = default;
};

[[nodiscard]] inline auto volume_layout_size(const VolumeLayout& l) noexcept -> std::size_t {
    std::size_t n = volume_layout_header_size;
    for (const auto& g : l.groups) {
        n += layout_group_fixed_size + (g.members.size() * layout_member_size);
    }
    return n + (l.gateways.size() * layout_gateway_size) +
           (l.attachments.size() * volume_attachment_size) + ed25519_signature_size;
}

inline constexpr std::size_t max_volume_layout_size =
    volume_layout_header_size +
    (max_stripe_width * (layout_group_fixed_size + (max_group_members * layout_member_size))) +
    (max_layout_gateways * layout_gateway_size) +
    (max_volume_attachments * volume_attachment_size) + ed25519_signature_size;

// The bytes a VolumeLayout signature covers: all but the trailing 64.
[[nodiscard]] inline auto volume_layout_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return map_update_signed_bytes(frame);
}

// Writes `signature` over the trailing 64 bytes of an encoded frame.
inline auto set_volume_layout_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    set_map_update_signature(frame, signature);
}

// The stripe group holding volume block `lba` (stripe order index), or
// stripe_width when the block is past the capacity.
[[nodiscard]] inline auto group_index_of(const VolumeLayout& l, std::uint64_t lba) noexcept
    -> std::size_t {
    if (lba >= l.capacity_blocks || l.groups.empty()) {
        return l.groups.size();
    }
    const std::uint64_t unit_blocks = l.stripe_unit / l.block_size;
    return static_cast<std::size_t>((lba / unit_blocks) % l.groups.size());
}

// The member of `group_id` running on `server_id`, or nullptr. The
// initiator follows a redirect only when this finds the named leader.
[[nodiscard]] inline auto find_member(const VolumeLayout& l, std::uint64_t group_id,
                                      std::uint64_t server_id) noexcept -> const LayoutMember* {
    const auto g = std::ranges::find(l.groups, group_id, &StripeGroup::group_id);
    if (g == l.groups.end()) {
        return nullptr;
    }
    const auto m = std::ranges::find(g->members, server_id, &LayoutMember::server_id);
    return m == g->members.end() ? nullptr : &*m;
}

namespace detail {

[[nodiscard]] constexpr auto known(CommitRule r) noexcept -> bool {
    return r == CommitRule::all_in_sync || r == CommitRule::majority;
}
[[nodiscard]] constexpr auto known(MemberKind k) noexcept -> bool {
    return k >= MemberKind::data && k <= MemberKind::learner;
}
[[nodiscard]] constexpr auto known(MirrorBackend b) noexcept -> bool {
    return b <= MirrorBackend::khold;
}
[[nodiscard]] constexpr auto known(MirrorPhase p) noexcept -> bool {
    return p <= MirrorPhase::copy;
}

[[nodiscard]] inline auto check_endpoint(std::uint64_t server_id, const StorageEndpoint& endpoint,
                                         std::uint16_t port) noexcept
    -> std::expected<void, DecodeError> {
    if (server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (!unicast(endpoint) || port == 0) {
        return std::unexpected(DecodeError::bad_member);
    }
    return {};
}

[[nodiscard]] inline auto check_group(const StripeGroup& g) noexcept
    -> std::expected<void, DecodeError> {
    if (g.group_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (g.members.empty() || g.members.size() > max_group_members) {
        return std::unexpected(DecodeError::too_many_members);
    }
    std::size_t data = 0;
    std::size_t witnesses = 0;
    for (const auto& m : g.members) {
        if (!known(m.kind)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (auto ok = check_endpoint(m.server_id, m.endpoint, m.port); !ok) {
            return ok;
        }
        data += m.kind == MemberKind::data ? 1 : 0;
        witnesses += m.kind == MemberKind::witness ? 1 : 0;
    }
    if (std::ranges::adjacent_find(g.members, std::ranges::greater_equal{},
                                   &LayoutMember::server_id) != g.members.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    if (data == 0 || witnesses > 1) {
        return std::unexpected(DecodeError::bad_group_members);
    }
    return {};
}

[[nodiscard]] inline auto check_volume_layout(const VolumeLayout& l)
    -> std::expected<void, DecodeError> {
    if (l.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (l.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (l.volume_id == 0 || l.lineage_id == 0 || l.capacity_blocks == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (l.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    if (l.block_size != block_size_512 && l.block_size != block_size_4096) {
        return std::unexpected(DecodeError::bad_block_size);
    }
    if (!valid_stripe_unit(l.stripe_unit) || l.groups.empty() ||
        l.groups.size() > max_stripe_width) {
        return std::unexpected(DecodeError::bad_stripe);
    }
    if ((l.flags & ~layout_flags::all) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (!known(l.commit_rule) || !known(l.mirror.peer_backend) || !known(l.mirror.phase)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (l.qos.iops == 0 || l.qos.mib_per_s == 0 || l.qos.burst_iops < l.qos.iops ||
        l.qos.burst_mib < l.qos.mib_per_s || l.group_skew_pct > max_group_skew_pct) {
        return std::unexpected(DecodeError::bad_qos);
    }
    if (l.timings.member_deadline_ms == 0 || l.timings.election_min_ms == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    const bool source = (l.flags & layout_flags::mirror_source) != 0;
    const bool target = (l.flags & layout_flags::mirror_target) != 0;
    const bool mirroring = source || target;
    if ((source && target) ||
        (mirroring ? (l.mirror.peer_backend == MirrorBackend::none || l.mirror.peer_volume == 0 ||
                      l.mirror.phase == MirrorPhase::none)
                   : (l.mirror.peer_backend != MirrorBackend::none || l.mirror.peer_volume != 0 ||
                      l.mirror.phase != MirrorPhase::none))) {
        return std::unexpected(DecodeError::bad_mirror);
    }

    for (const auto& g : l.groups) {
        if (auto ok = check_group(g); !ok) {
            return ok;
        }
    }
    std::vector<std::uint64_t> ids;
    ids.reserve(l.groups.size());
    for (const auto& g : l.groups) {
        ids.push_back(g.group_id);
    }
    std::ranges::sort(ids);
    if (std::ranges::adjacent_find(ids) != ids.end()) {
        return std::unexpected(DecodeError::bad_id);
    }

    if (l.gateways.size() > max_layout_gateways) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& gw : l.gateways) {
        if (auto ok = check_endpoint(gw.server_id, gw.endpoint, gw.port); !ok) {
            return ok;
        }
    }
    if (std::ranges::adjacent_find(l.gateways, std::ranges::greater_equal{},
                                   &LayoutGateway::server_id) != l.gateways.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }

    if (l.attachments.size() > max_volume_attachments) {
        return std::unexpected(DecodeError::too_many_attachments);
    }
    std::size_t writers = 0;
    for (const auto& a : l.attachments) {
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
    if (std::ranges::adjacent_find(l.attachments, std::ranges::greater_equal{},
                                   &VolumeAttachment::attachment_id) != l.attachments.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    if (writers > 1 && (l.flags & layout_flags::multi_attach) == 0) {
        return std::unexpected(DecodeError::bad_attachment_mode);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// volume_layout_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_volume_layout(std::span<const std::byte> bytes)
    -> std::expected<VolumeLayout, DecodeError> {
    if (bytes.size() < volume_layout_header_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > max_volume_layout_size) {
        return std::unexpected(DecodeError::record_too_large);
    }
    // The header is present, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le64().value_or(0);
    const auto version = r.le16().value_or(0);
    VolumeLayout l;
    l.key_id = r.le16().value_or(0);
    const std::size_t width = r.le16().value_or(0);
    const std::size_t gateway_count = r.u8().value_or(0);
    const std::size_t attachment_count = r.u8().value_or(0);
    l.server_id = r.le64().value_or(0);
    l.volume_id = r.le64().value_or(0);
    l.epoch = r.le64().value_or(0);
    l.lineage_id = r.le64().value_or(0);
    l.capacity_blocks = r.le64().value_or(0);
    l.block_size = r.le32().value_or(0);
    l.stripe_unit = r.le32().value_or(0);
    l.flags = r.le32().value_or(0);
    l.commit_rule = static_cast<CommitRule>(r.u8().value_or(0));
    l.group_skew_pct = r.u8().value_or(0);
    bool zero = r.le16().value_or(1) == 0;
    l.qos.iops = r.le32().value_or(0);
    l.qos.mib_per_s = r.le32().value_or(0);
    l.qos.burst_iops = r.le32().value_or(0);
    l.qos.burst_mib = r.le32().value_or(0);
    l.timings.member_deadline_ms = r.le32().value_or(0);
    l.timings.election_min_ms = r.le32().value_or(0);
    l.timings.resync_window_s = r.le32().value_or(0);
    zero = r.le32().value_or(1) == 0 && zero;
    l.mirror.peer_backend = static_cast<MirrorBackend>(r.u8().value_or(0));
    l.mirror.phase = static_cast<MirrorPhase>(r.u8().value_or(0));
    zero = detail::all_zero(r.bytes(6).value_or(std::span<const std::byte>{})) && zero;
    l.mirror.peer_volume = r.le64().value_or(0);

    if (magic != volume_layout_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != volume_layout_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (width == 0 || width > max_stripe_width) {
        return std::unexpected(DecodeError::bad_stripe);
    }
    if (gateway_count > max_layout_gateways) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    if (attachment_count > max_volume_attachments) {
        return std::unexpected(DecodeError::too_many_attachments);
    }

    // Groups have their own member counts, so each length is checked as it
    // is read; the frame is bounded by max_volume_layout_size above.
    l.groups.resize(width);
    for (auto& g : l.groups) {
        auto group_id = r.le64();
        auto count = r.u8();
        auto pad = r.bytes(7);
        if (!group_id || !count || !pad) {
            return std::unexpected(DecodeError::truncated);
        }
        if (!detail::all_zero(*pad)) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        if (*count == 0 || *count > max_group_members) {
            return std::unexpected(DecodeError::too_many_members);
        }
        if (r.remaining() < std::size_t{*count} * layout_member_size) {
            return std::unexpected(DecodeError::truncated);
        }
        g.group_id = *group_id;
        g.members.resize(*count);
        for (auto& m : g.members) {
            m.server_id = r.le64().value_or(0);
            std::ranges::copy(r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{}),
                              m.endpoint.begin());
            m.port = r.le16().value_or(0);
            m.kind = static_cast<MemberKind>(r.u8().value_or(0));
            m.drive = r.u8().value_or(0);
            zero = r.le32().value_or(1) == 0 && zero;
        }
    }
    const std::size_t want = (gateway_count * layout_gateway_size) +
                             (attachment_count * volume_attachment_size) + ed25519_signature_size;
    if (r.remaining() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    l.gateways.resize(gateway_count);
    for (auto& gw : l.gateways) {
        gw.server_id = r.le64().value_or(0);
        std::ranges::copy(r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{}),
                          gw.endpoint.begin());
        gw.port = r.le16().value_or(0);
        zero = detail::all_zero(r.bytes(6).value_or(std::span<const std::byte>{})) && zero;
    }
    l.attachments.resize(attachment_count);
    for (auto& a : l.attachments) {
        a.attachment_id = r.le64().value_or(0);
        a.server_id = r.le64().value_or(0);
        a.generation = r.le32().value_or(0);
        a.mode = static_cast<AttachMode>(r.u8().value_or(0));
        zero = detail::all_zero(r.bytes(3).value_or(std::span<const std::byte>{})) && zero;
    }
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      l.signature.begin());
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_volume_layout(l); !ok) {
        return std::unexpected(ok.error());
    }
    return l;
}

// Encodes a VolumeLayout (with whatever is in `signature`), enforcing
// every rule decode_volume_layout checks.
[[nodiscard]] inline auto encode_volume_layout(const VolumeLayout& l)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_volume_layout(l); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(volume_layout_size(l));
    wire::Writer w{out};
    w.le64(volume_layout_magic);
    w.le16(volume_layout_version);
    w.le16(l.key_id);
    w.le16(static_cast<std::uint16_t>(l.groups.size()));
    w.u8(static_cast<std::uint8_t>(l.gateways.size()));
    w.u8(static_cast<std::uint8_t>(l.attachments.size()));
    w.le64(l.server_id);
    w.le64(l.volume_id);
    w.le64(l.epoch);
    w.le64(l.lineage_id);
    w.le64(l.capacity_blocks);
    w.le32(l.block_size);
    w.le32(l.stripe_unit);
    w.le32(l.flags);
    w.u8(static_cast<std::uint8_t>(l.commit_rule));
    w.u8(l.group_skew_pct);
    w.le16(0);
    w.le32(l.qos.iops);
    w.le32(l.qos.mib_per_s);
    w.le32(l.qos.burst_iops);
    w.le32(l.qos.burst_mib);
    w.le32(l.timings.member_deadline_ms);
    w.le32(l.timings.election_min_ms);
    w.le32(l.timings.resync_window_s);
    w.le32(0);
    w.u8(static_cast<std::uint8_t>(l.mirror.peer_backend));
    w.u8(static_cast<std::uint8_t>(l.mirror.phase));
    w.bytes(std::array<std::byte, 6>{});
    w.le64(l.mirror.peer_volume);
    for (const auto& g : l.groups) {
        w.le64(g.group_id);
        w.u8(static_cast<std::uint8_t>(g.members.size()));
        w.bytes(std::array<std::byte, 7>{});
        for (const auto& m : g.members) {
            w.le64(m.server_id);
            w.bytes(m.endpoint);
            w.le16(m.port);
            w.u8(static_cast<std::uint8_t>(m.kind));
            w.u8(m.drive);
            w.le32(0);
        }
    }
    for (const auto& gw : l.gateways) {
        w.le64(gw.server_id);
        w.bytes(gw.endpoint);
        w.le16(gw.port);
        w.bytes(std::array<std::byte, 6>{});
    }
    for (const auto& a : l.attachments) {
        w.le64(a.attachment_id);
        w.le64(a.server_id);
        w.le32(a.generation);
        w.u8(static_cast<std::uint8_t>(a.mode));
        w.bytes(std::array<std::byte, 3>{});
    }
    w.bytes(l.signature);
    return out;
}

}  // namespace ak::proto
