// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VolumeOp: a signed one-shot operation on a network volume that is not a
// membership change (.kiro/specs/block-volume-service/ design "VolumeOp",
// "Snapshots", "Restore, hydration and clones"). The controller sends it
// to a hold role through helm; the role executes an op_id at most once and
// reports its outcome (report.hpp op_outcome), so the controller can
// resend freely.
//
// Layout (little-endian, fixed 0xA0 bytes):
//   0x00  magic      u32  'AKVO'
//   0x04  version    u16  frame format version (1)
//   0x06  key_id     u16  controller key that signed it; non-zero
//   0x08  server_id  u64  recipient server; non-zero
//   0x10  volume_id  u64  non-zero
//   0x18  epoch      u64  epoch the op was issued in; non-zero
//   0x20  op_id      u64  controller operation ID; non-zero
//   0x28  kind       u8   VolumeOpKind
//   0x29  reserved   [7]  zero
//   0x30  args       [48] per kind, unused bytes zero:
//     snapshot_prepare  cut_id u64 | timeout_ms u32
//     snapshot_commit   cut_id u64 | uploader u64 (server that uploads)
//     snapshot_abort    cut_id u64
//     snapshot_upload   cut_id u64 | store_id u32 | reserved u32 |
//                       parent_manifest [32] (zero: no parent, upload every chunk)
//     clone             cut_id u64 | new_volume_id u64 | new_replica_gen u32
//     scrub             mib_per_s u32
//     delete_replica    replica_gen u32
//   0x60  signature  64 bytes, Ed25519 over bytes [0x00, 0x60)
//
// Every ID, timeout and rate named above is non-zero. A cut ID names one
// consistent cut across the volumes of a (multi-volume) snapshot or clone;
// it is the controller's, and every op of one cut carries it.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"

namespace ak::proto {

inline constexpr std::uint32_t volume_op_magic = 0x4F56'4B41;  // "AKVO" as little-endian bytes
inline constexpr std::uint16_t volume_op_version = 1;
inline constexpr std::size_t volume_op_args_offset = 0x30;
inline constexpr std::size_t volume_op_args_size = 0x30;
inline constexpr std::size_t volume_op_size =
    volume_op_args_offset + volume_op_args_size + ed25519_signature_size;

// Values are part of the wire protocol: never renumber.
enum class VolumeOpKind : std::uint8_t {
    snapshot_prepare = 1,
    snapshot_commit = 2,
    snapshot_abort = 3,
    snapshot_upload = 4,
    clone = 5,
    scrub = 6,
    delete_replica = 7,
};

// Primary: stop acknowledging new writes (keep persisting them) and report
// the cut sequence; release them on commit or abort, or after timeout_ms.
struct SnapshotPrepare {
    std::uint64_t cut_id{0};
    std::uint32_t timeout_ms{0};
    friend auto operator==(const SnapshotPrepare&, const SnapshotPrepare&) -> bool = default;
};

// Every member freezes at the cut; `uploader` keeps its frozen clone for
// snapshot_upload.
struct SnapshotCommit {
    std::uint64_t cut_id{0};
    std::uint64_t uploader{0};
    friend auto operator==(const SnapshotCommit&, const SnapshotCommit&) -> bool = default;
};

struct SnapshotAbort {
    std::uint64_t cut_id{0};
    friend auto operator==(const SnapshotAbort&, const SnapshotAbort&) -> bool = default;
};

struct SnapshotUpload {
    std::uint64_t cut_id{0};
    std::uint32_t store_id{0};
    ManifestName parent_manifest{};  // zero: first snapshot of the lineage
    friend auto operator==(const SnapshotUpload&, const SnapshotUpload&) -> bool = default;
};

struct CloneVolume {
    std::uint64_t cut_id{0};
    std::uint64_t new_volume_id{0};
    std::uint32_t new_replica_gen{0};
    friend auto operator==(const CloneVolume&, const CloneVolume&) -> bool = default;
};

struct ScrubVolume {
    std::uint32_t mib_per_s{0};
    friend auto operator==(const ScrubVolume&, const ScrubVolume&) -> bool = default;
};

struct DeleteReplica {
    std::uint32_t replica_gen{0};
    friend auto operator==(const DeleteReplica&, const DeleteReplica&) -> bool = default;
};

using VolumeOpArgs = std::variant<SnapshotPrepare, SnapshotCommit, SnapshotAbort, SnapshotUpload,
                                  CloneVolume, ScrubVolume, DeleteReplica>;

struct VolumeOp {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t op_id{0};
    VolumeOpArgs args;
    Ed25519Signature signature{};
    friend auto operator==(const VolumeOp&, const VolumeOp&) -> bool = default;
};

// The variant's alternatives are in VolumeOpKind order, starting at 1.
[[nodiscard]] inline auto volume_op_kind(const VolumeOpArgs& args) noexcept -> VolumeOpKind {
    return static_cast<VolumeOpKind>(args.index() + 1);
}

// The bytes a VolumeOp signature covers: all but the trailing 64.
[[nodiscard]] inline auto volume_op_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return map_update_signed_bytes(frame);
}

inline auto set_volume_op_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    set_map_update_signature(frame, signature);
}

namespace detail {

[[nodiscard]] constexpr auto known(VolumeOpKind k) noexcept -> bool {
    return k >= VolumeOpKind::snapshot_prepare && k <= VolumeOpKind::delete_replica;
}

[[nodiscard]] inline auto check_args(const VolumeOpArgs& args) noexcept -> bool {
    return std::visit(
        []<typename T>(const T& a) {
            if constexpr (std::is_same_v<T, SnapshotPrepare>) {
                return a.cut_id != 0 && a.timeout_ms != 0;
            } else if constexpr (std::is_same_v<T, SnapshotCommit>) {
                return a.cut_id != 0 && a.uploader != 0;
            } else if constexpr (std::is_same_v<T, SnapshotAbort>) {
                return a.cut_id != 0;
            } else if constexpr (std::is_same_v<T, SnapshotUpload>) {
                return a.cut_id != 0 && a.store_id != 0;
            } else if constexpr (std::is_same_v<T, CloneVolume>) {
                return a.cut_id != 0 && a.new_volume_id != 0 && a.new_replica_gen != 0;
            } else if constexpr (std::is_same_v<T, ScrubVolume>) {
                return a.mib_per_s != 0;
            } else {
                static_assert(std::is_same_v<T, DeleteReplica>);
                return a.replica_gen != 0;
            }
        },
        args);
}

[[nodiscard]] inline auto check_volume_op(const VolumeOp& op) noexcept
    -> std::expected<void, DecodeError> {
    if (op.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (op.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (op.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    if (op.volume_id == 0 || op.op_id == 0 || !check_args(op.args)) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

inline auto write_args(wire::Writer& w, const VolumeOpArgs& args) -> void {
    std::visit(
        [&w]<typename T>(const T& a) {
            if constexpr (std::is_same_v<T, SnapshotPrepare>) {
                w.le64(a.cut_id);
                w.le32(a.timeout_ms);
            } else if constexpr (std::is_same_v<T, SnapshotCommit>) {
                w.le64(a.cut_id);
                w.le64(a.uploader);
            } else if constexpr (std::is_same_v<T, SnapshotAbort>) {
                w.le64(a.cut_id);
            } else if constexpr (std::is_same_v<T, SnapshotUpload>) {
                w.le64(a.cut_id);
                w.le32(a.store_id);
                w.le32(0);
                w.bytes(a.parent_manifest);
            } else if constexpr (std::is_same_v<T, CloneVolume>) {
                w.le64(a.cut_id);
                w.le64(a.new_volume_id);
                w.le32(a.new_replica_gen);
            } else if constexpr (std::is_same_v<T, ScrubVolume>) {
                w.le32(a.mib_per_s);
            } else {
                static_assert(std::is_same_v<T, DeleteReplica>);
                w.le32(a.replica_gen);
            }
        },
        args);
}

// Reads the args of `kind` from the 48-byte area; the bytes a kind does
// not use must be zero.
[[nodiscard]] inline auto read_args(VolumeOpKind kind, std::span<const std::byte> area)
    -> std::expected<VolumeOpArgs, DecodeError> {
    wire::Reader r{area};
    VolumeOpArgs args;
    // area is volume_op_args_size bytes, more than any kind reads.
    switch (kind) {
        case VolumeOpKind::snapshot_prepare:
            args =
                SnapshotPrepare{.cut_id = r.le64().value_or(0), .timeout_ms = r.le32().value_or(0)};
            break;
        case VolumeOpKind::snapshot_commit:
            args = SnapshotCommit{.cut_id = r.le64().value_or(0), .uploader = r.le64().value_or(0)};
            break;
        case VolumeOpKind::snapshot_abort:
            args = SnapshotAbort{.cut_id = r.le64().value_or(0)};
            break;
        case VolumeOpKind::snapshot_upload: {
            SnapshotUpload u{.cut_id = r.le64().value_or(0), .store_id = r.le32().value_or(0)};
            if (r.le32().value_or(1) != 0) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            std::ranges::copy(r.bytes(manifest_name_size).value_or(std::span<const std::byte>{}),
                              u.parent_manifest.begin());
            args = u;
            break;
        }
        case VolumeOpKind::clone:
            args = CloneVolume{.cut_id = r.le64().value_or(0),
                               .new_volume_id = r.le64().value_or(0),
                               .new_replica_gen = r.le32().value_or(0)};
            break;
        case VolumeOpKind::scrub:
            args = ScrubVolume{.mib_per_s = r.le32().value_or(0)};
            break;
        case VolumeOpKind::delete_replica:
            args = DeleteReplica{.replica_gen = r.le32().value_or(0)};
            break;
        default:
            return std::unexpected(DecodeError::unknown_value);
    }
    if (!all_zero(r.rest())) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    return args;
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// volume_op_signed_bytes(frame) against `signature` under `key_id` first.
[[nodiscard]] inline auto decode_volume_op(std::span<const std::byte> bytes)
    -> std::expected<VolumeOp, DecodeError> {
    if (bytes.size() < volume_op_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > volume_op_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    VolumeOp op;
    op.key_id = r.le16().value_or(0);
    op.server_id = r.le64().value_or(0);
    op.volume_id = r.le64().value_or(0);
    op.epoch = r.le64().value_or(0);
    op.op_id = r.le64().value_or(0);
    const auto kind = static_cast<VolumeOpKind>(r.u8().value_or(0));
    const bool zero = detail::all_zero(r.bytes(7).value_or(std::span<const std::byte>{}));
    const auto area = r.bytes(volume_op_args_size).value_or(std::span<const std::byte>{});
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      op.signature.begin());
    if (magic != volume_op_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != volume_op_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (!detail::known(kind)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    auto args = detail::read_args(kind, area);
    if (!args) {
        return std::unexpected(args.error());
    }
    op.args = *args;
    if (auto ok = detail::check_volume_op(op); !ok) {
        return std::unexpected(ok.error());
    }
    return op;
}

// Encodes a VolumeOp (with whatever is in `signature`), enforcing every
// rule decode_volume_op checks.
[[nodiscard]] inline auto encode_volume_op(const VolumeOp& op)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_volume_op(op); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> args;
    args.reserve(volume_op_args_size);
    wire::Writer aw{args};
    detail::write_args(aw, op.args);
    args.resize(volume_op_args_size);

    std::vector<std::byte> out;
    out.reserve(volume_op_size);
    wire::Writer w{out};
    w.le32(volume_op_magic);
    w.le16(volume_op_version);
    w.le16(op.key_id);
    w.le64(op.server_id);
    w.le64(op.volume_id);
    w.le64(op.epoch);
    w.le64(op.op_id);
    w.u8(static_cast<std::uint8_t>(volume_op_kind(op.args)));
    w.bytes(std::array<std::byte, 7>{});
    w.bytes(args);
    w.bytes(op.signature);
    return out;
}

}  // namespace ak::proto
