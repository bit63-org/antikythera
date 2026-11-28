// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// FrameNotice: the controller's word that a signed frame is waiting in a
// frame store, for a network role to fetch over its bulk channel
// (.kiro/specs/fleet-scale-networking/ Requirement 6.2, design "Bulk
// channel", task 11).
//
// A notice names the frame (its kind, its VNI or other scope, and its
// sequence or version), its exact size and its SHA-256 digest. The role
// fetches the bytes by digest, checks the digest, then decodes the frame
// and checks the frame's own signature, so neither the frame store, the
// path, nor the notice needs to be trusted: a wrong notice costs a failed
// fetch, never a wrong frame. The notice is therefore unsigned, like
// lease_grant.
//
// FrameNotice layout (little-endian, 56 bytes; OarLink vendor type 0x33
// carries exactly this):
//   0x00  kind                 u8   FrameKind
//   0x01  reserved             [3]  zero
//   0x04  vni_or_scope         u32  the VNI for vpc_stream (1..2^24-1);
//                                   the kind's own scope otherwise
//   0x08  sequence_or_version  u64  non-zero
//   0x10  size                 u32  the frame's length, 1..max_notice_frame_size
//   0x14  reserved             u32  zero
//   0x18  sha256               [32] of the frame's bytes
//
// Link record 33 (frame_notice, controller -> helm) is the server it is
// for, then the notice:
//   0x00  server_id  u64  non-zero; checked against the session
//   0x08  notice     [56]
// helm strips the server ID and passes the notice to its network roles.
// The design's struct had no server ID; every other per-server record
// names its server, so a record routed to the wrong session is refused
// the same way.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"

namespace ak::proto {

inline constexpr std::size_t frame_notice_size = 56;
inline constexpr std::size_t frame_notice_record_size = 8 + frame_notice_size;
inline constexpr std::size_t frame_digest_size = 32;
// Largest frame a notice may announce: a full VPC stream snapshot, with
// room to spare (design "VPC streams").
inline constexpr std::uint32_t max_notice_frame_size = 64U * 1024U * 1024U;
inline constexpr std::uint32_t max_notice_vni = (1U << 24U) - 1U;

// Values are part of the wire protocol: never renumber.
enum class FrameKind : std::uint8_t {
    vpc_stream = 1,
    edge_mapping = 2,
    security_policy = 3,
};

struct FrameNotice {
    FrameKind kind{FrameKind::vpc_stream};
    std::uint32_t vni_or_scope{0};
    std::uint64_t sequence_or_version{0};
    std::uint32_t size{0};
    std::array<std::byte, frame_digest_size> sha256{};
    friend auto operator==(const FrameNotice&, const FrameNotice&) -> bool = default;
};

struct FrameNoticeRecord {
    std::uint64_t server_id{0};
    FrameNotice notice;
    friend auto operator==(const FrameNoticeRecord&, const FrameNoticeRecord&) -> bool = default;
};

[[nodiscard]] constexpr auto known(FrameKind k) noexcept -> bool {
    return k >= FrameKind::vpc_stream && k <= FrameKind::security_policy;
}

[[nodiscard]] inline auto check_frame_notice(const FrameNotice& n) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(n.kind)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (n.kind == FrameKind::vpc_stream &&
        (n.vni_or_scope == 0 || n.vni_or_scope > max_notice_vni)) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (n.sequence_or_version == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (n.size == 0 || n.size > max_notice_frame_size) {
        return std::unexpected(DecodeError::bad_frame_size);
    }
    return {};
}

namespace detail {

inline auto write_frame_notice(wire::Writer& w, const FrameNotice& n) -> void {
    w.u8(static_cast<std::uint8_t>(n.kind));
    w.u8(0);
    w.le16(0);
    w.le32(n.vni_or_scope);
    w.le64(n.sequence_or_version);
    w.le32(n.size);
    w.le32(0);
    w.bytes(n.sha256);
}

[[nodiscard]] inline auto read_frame_notice(wire::Reader& r) noexcept
    -> std::expected<FrameNotice, DecodeError> {
    auto kind = r.u8();
    auto reserved1 = r.u8();
    auto reserved2 = r.le16();
    auto scope = r.le32();
    auto sequence = r.le64();
    auto size = r.le32();
    auto reserved3 = r.le32();
    auto digest = r.bytes(frame_digest_size);
    if (!kind || !reserved1 || !reserved2 || !scope || !sequence || !size || !reserved3 ||
        !digest) {
        return std::unexpected(DecodeError::truncated);
    }
    FrameNotice n{};
    std::ranges::copy(*digest, n.sha256.begin());
    if (*reserved1 != 0 || *reserved2 != 0 || *reserved3 != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    n.kind = static_cast<FrameKind>(*kind);
    n.vni_or_scope = *scope;
    n.sequence_or_version = *sequence;
    n.size = *size;
    if (auto ok = check_frame_notice(n); !ok) {
        return std::unexpected(ok.error());
    }
    return n;
}

}  // namespace detail

[[nodiscard]] inline auto encode_frame_notice(const FrameNotice& n)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = check_frame_notice(n); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(frame_notice_size);
    wire::Writer w{out};
    detail::write_frame_notice(w, n);
    return out;
}

[[nodiscard]] inline auto decode_frame_notice(std::span<const std::byte> bytes) noexcept
    -> std::expected<FrameNotice, DecodeError> {
    wire::Reader r{bytes};
    auto n = detail::read_frame_notice(r);
    if (!n) {
        return n;
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    return n;
}

[[nodiscard]] inline auto encode_frame_notice_record(const FrameNoticeRecord& rec)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (rec.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (auto ok = check_frame_notice(rec.notice); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(frame_notice_record_size);
    wire::Writer w{out};
    w.le64(rec.server_id);
    detail::write_frame_notice(w, rec.notice);
    return out;
}

[[nodiscard]] inline auto decode_frame_notice_record(std::span<const std::byte> bytes) noexcept
    -> std::expected<FrameNoticeRecord, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    if (!server_id) {
        return std::unexpected(DecodeError::truncated);
    }
    auto n = detail::read_frame_notice(r);
    if (!n) {
        return std::unexpected(n.error());
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    return FrameNoticeRecord{.server_id = *server_id, .notice = *n};
}

}  // namespace ak::proto
