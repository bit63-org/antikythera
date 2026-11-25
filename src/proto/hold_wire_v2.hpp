// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Hold wire protocol version 2: frames between an initiator (oar-blk) or a
// khold gateway and the khold node leading a stripe group
// (kythira .kiro/specs/khold-block-service/ design "Hold wire protocol
// version 2", Requirement 11). Version 1 (hold_wire.hpp) is unchanged and
// keeps serving hold; both versions share the magic and put the version
// byte at the same offset, so a server peeks it (hold_frame_version) and
// hands the frame to the matching decoder. Each decoder refuses the other
// version with bad_version.
//
// Version 2 keeps version 1's discipline: a fixed header with its own
// CRC32C, strict payloads, block data as CRCs then blocks (the BlockData of
// hold_wire.hpp, decoded without copies). It drops version 1's
// hold-to-hold opcodes (khold members talk Raft, not hold wire) and adds a
// stripe group ID and the sender's last known term to the header, a
// REDIRECT that names the group's leader, and the not_leader, no_space,
// repairing and unknown_group statuses.
//
// Header (little-endian, 88 bytes):
//   0x00  magic          u32  'AKHW'
//   0x04  version        u8   2
//   0x05  opcode         u8   HoldV2Opcode
//   0x06  flags          u16  hold_flags (response, hydrate); other bits zero
//   0x08  payload_len    u32  at most max_hold_v2_payload
//   0x0C  status         u16  HoldV2Status; ok unless the response flag is set
//   0x0E  reserved       u16  zero
//   0x10  request_id     u64  sender's ID, echoed in the response
//   0x18  volume_id      u64  non-zero
//   0x20  epoch          u64  layout epoch; non-zero. A stale_epoch response
//                             carries the receiver's newer epoch here.
//   0x28  attachment_id  u64  the attachment the request is for; 0 for a copier
//   0x30  generation     u32  non-zero exactly when attachment_id is
//   0x34  blocks         u32  1 to max_hold_blocks for block opcodes, else 0
//   0x38  lba            u64  first block, volume-relative, for block opcodes, else 0
//   0x40  group_id       u64  the stripe group; non-zero for block opcodes and
//                             redirect, 0 or a group for the others
//   0x48  term           u64  requests: the sender's last known leader term for
//                             the group (0: none); responses: the responder's
//   0x50  reserved       u32  zero
//   0x54  header_crc32c  u32  CRC32C of bytes [0x00, 0x54)
//
// Opcodes ("R" is the response flag; a response echoes request_id, lba,
// blocks and group_id):
//   hello         ->  role u8 | reserved [7]
//                     initiator: attachment_id and generation set
//                     gateway, copier: attachment_id 0
//   hello_ok  R   <-  block_size u32 | reserved u32 | capacity_blocks u64 |
//                     stripe_unit u32 | stripe_width u16 | reserved u16
//   read          ->  empty;  R: block data
//   write         ->  block data (flag hydrate: fill only blocks whose written
//                     bit is clear; the mirror copier and phase 2 hydration);
//                     R: empty
//   write_zeroes  ->  empty;  R: empty (the store punches whole fs blocks)
//   discard       ->  empty;  R: empty (likewise)
//   flush         ->  empty;  R: empty (every acknowledged write is already
//                     durable on the group's in-sync replicas; kept for the
//                     guest's FLUSH)
//   ping          ->  empty;  R: empty
//   redirect  R   <-  leader_server u64 | endpoint [16] | port u16 |
//                     reserved [6] | leader_term u64
//                     sent by a member that does not lead the group, with
//                     status not_leader; leader_server 0 means unknown (then
//                     endpoint, port and leader_term are zero)
//
// Opcode values match version 1 where the operation is the same; version
// 1's hold-to-hold opcodes (repl_write .. hydrate_fill) are not version 2
// opcodes. A response with a status other than ok has an empty payload,
// except redirect, which always carries its own.
//
// The initiator follows a redirect only to a member of the group in its
// current signed VolumeLayout (volume_layout.hpp); that check, the epoch,
// generation and term fencing and who may open a session are the
// receiver's job, not this decoder's.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/hold_wire.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"

namespace ak::proto {

inline constexpr std::uint8_t hold_v2_version = 2;
inline constexpr std::size_t hold_v2_header_size = 88;
inline constexpr std::size_t hold_v2_header_crc_offset = 0x54;
inline constexpr std::size_t hold_v2_hello_size = 8;
inline constexpr std::size_t hold_v2_hello_ok_size = 24;
inline constexpr std::size_t hold_v2_redirect_size = 40;
inline constexpr std::size_t hold_version_offset = 4;
inline constexpr std::size_t max_hold_v2_payload =
    (max_hold_blocks * hold_block_crc_size) + max_hold_data_bytes;

// Striping bounds (khold Requirement 3.1), shared with volume_layout.hpp:
// the stripe unit is a power of two from 64 KiB to 4 MiB, the stripe width
// (stripe groups per volume) 1 to 64.
inline constexpr std::uint32_t min_stripe_unit = std::uint32_t{64} << 10U;
inline constexpr std::uint32_t max_stripe_unit = std::uint32_t{4} << 20U;
inline constexpr std::uint16_t max_stripe_width = 64;

[[nodiscard]] constexpr auto valid_stripe_unit(std::uint32_t su) noexcept -> bool {
    return su >= min_stripe_unit && su <= max_stripe_unit && (su & (su - 1)) == 0;
}

// Values are part of the wire protocol: never renumber.
enum class HoldV2Opcode : std::uint8_t {
    hello = 1,
    hello_ok = 2,
    read = 3,
    write = 4,
    write_zeroes = 5,
    discard = 6,
    flush = 7,
    ping = 13,
    redirect = 14,
};

// Values are part of the wire protocol: never renumber. 0 to 12 mean what
// they mean in version 1, with not_primary renamed not_leader.
enum class HoldV2Status : std::uint16_t {
    ok = 0,
    stale_epoch = 1,   // the request's layout epoch is not the receiver's
    fenced = 2,        // the attachment generation is retired
    not_leader = 3,    // see the redirect payload
    read_only = 4,     // a write from a read-only attachment
    not_hydrated = 5,  // foreign-key restore: oar-blk must hydrate first
    throttled = 6,     // over the attachment's or group's QoS limit
    checksum = 7,      // a block's CRC32C did not match its data
    io_suspended = 8,  // the group cannot commit (no up-to-date data replica)
    range = 9,         // past the volume's capacity, or not inside group_id's stripes
    io_error = 10,     // media error that could not be repaired
    bad_request = 11,  // well-formed but not acceptable in this session
    unknown_volume = 12,
    no_space = 13,       // the write needs space an overcommitted drive lacks
    repairing = 14,      // the range is being reconciled after an election; retry shortly
    unknown_group = 15,  // the receiver holds no member of group_id
};

enum class HoldV2Role : std::uint8_t {
    initiator = 1,  // oar-blk, for one attachment
    gateway = 2,    // a khold gateway forwarding parts to the group leader
    copier = 3,     // the mirror copier (hydrate writes only)
};

struct HoldV2Header {
    HoldV2Opcode opcode{HoldV2Opcode::ping};
    std::uint16_t flags{0};
    std::uint32_t payload_len{0};  // set by encode_hold_v2_frame
    HoldV2Status status{HoldV2Status::ok};
    std::uint64_t request_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t attachment_id{0};
    std::uint32_t generation{0};
    std::uint32_t blocks{0};
    std::uint64_t lba{0};
    std::uint64_t group_id{0};
    std::uint64_t term{0};
    friend auto operator==(const HoldV2Header&, const HoldV2Header&) -> bool = default;
};

struct HoldV2Hello {
    HoldV2Role role{HoldV2Role::initiator};
    friend auto operator==(const HoldV2Hello&, const HoldV2Hello&) -> bool = default;
};

struct HoldV2HelloOk {
    std::uint32_t block_size{block_size_4096};
    std::uint64_t capacity_blocks{0};
    std::uint32_t stripe_unit{0};   // bytes; see volume_layout.hpp
    std::uint16_t stripe_width{0};  // stripe groups
    friend auto operator==(const HoldV2HelloOk&, const HoldV2HelloOk&) -> bool = default;
};

struct HoldV2Redirect {
    std::uint64_t leader_server{0};  // 0: leader unknown
    StorageEndpoint endpoint{};
    std::uint16_t port{0};
    std::uint64_t leader_term{0};
    friend auto operator==(const HoldV2Redirect&, const HoldV2Redirect&) -> bool = default;
};

using HoldV2Payload =
    std::variant<std::monostate, HoldV2Hello, HoldV2HelloOk, BlockData, HoldV2Redirect>;

struct HoldV2Frame {
    HoldV2Header header;
    HoldV2Payload payload;
    friend auto operator==(const HoldV2Frame&, const HoldV2Frame&) -> bool = default;
};

[[nodiscard]] constexpr auto is_response(const HoldV2Header& h) noexcept -> bool {
    return (h.flags & hold_flags::response) != 0;
}

[[nodiscard]] constexpr auto is_block_opcode(HoldV2Opcode op) noexcept -> bool {
    switch (op) {
        case HoldV2Opcode::read:
        case HoldV2Opcode::write:
        case HoldV2Opcode::write_zeroes:
        case HoldV2Opcode::discard:
            return true;
        default:
            return false;
    }
}

// The version byte of a hold frame whose first bytes are in `bytes`, after
// checking the magic: 1, 2, or an error (truncated, bad_magic). Nothing
// else is checked; the matching decoder does the rest.
[[nodiscard]] inline auto hold_frame_version(std::span<const std::byte> bytes) noexcept
    -> std::expected<std::uint8_t, DecodeError> {
    wire::Reader r{bytes};
    const auto magic = r.le32();
    const auto version = r.u8();
    if (!magic || !version) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != hold_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    return *version;
}

namespace detail {

[[nodiscard]] constexpr auto known(HoldV2Opcode op) noexcept -> bool {
    return (op >= HoldV2Opcode::hello && op <= HoldV2Opcode::flush) || op == HoldV2Opcode::ping ||
           op == HoldV2Opcode::redirect;
}
[[nodiscard]] constexpr auto known(HoldV2Status s) noexcept -> bool {
    return s <= HoldV2Status::unknown_group;
}
[[nodiscard]] constexpr auto known(HoldV2Role r) noexcept -> bool {
    return r >= HoldV2Role::initiator && r <= HoldV2Role::copier;
}

// The version 1 header fields of a version 2 header, for the block data
// helpers, which look only at blocks.
[[nodiscard]] constexpr auto v1_view(const HoldV2Header& h) noexcept -> HoldHeader {
    HoldHeader v1;
    v1.blocks = h.blocks;
    return v1;
}

[[nodiscard]] inline auto check_hold_v2_header(const HoldV2Header& h) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(h.opcode) || !known(h.status)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if ((h.flags & ~(hold_flags::response | hold_flags::hydrate)) != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (h.payload_len > max_hold_v2_payload) {
        return std::unexpected(DecodeError::record_too_large);
    }
    if (h.volume_id == 0 || (h.attachment_id == 0) != (h.generation == 0)) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (h.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    if (h.group_id == 0 && (is_block_opcode(h.opcode) || h.opcode == HoldV2Opcode::redirect)) {
        return std::unexpected(DecodeError::bad_id);
    }
    const bool resp = is_response(h);
    const bool must_respond =
        h.opcode == HoldV2Opcode::hello_ok || h.opcode == HoldV2Opcode::redirect;
    const bool must_request = h.opcode == HoldV2Opcode::hello;
    if ((must_respond && !resp) || (must_request && resp) ||
        (!resp && h.status != HoldV2Status::ok)) {
        return std::unexpected(DecodeError::bad_hold_direction);
    }
    if (h.opcode == HoldV2Opcode::redirect && h.status != HoldV2Status::not_leader) {
        return std::unexpected(DecodeError::bad_hold_direction);
    }
    if ((h.flags & hold_flags::hydrate) != 0 && (resp || h.opcode != HoldV2Opcode::write)) {
        return std::unexpected(DecodeError::bad_hold_direction);
    }
    if (is_block_opcode(h.opcode)) {
        if (h.blocks == 0 || h.blocks > max_hold_blocks || h.lba > UINT64_MAX - h.blocks) {
            return std::unexpected(DecodeError::bad_block_range);
        }
    } else if (h.blocks != 0 || h.lba != 0) {
        return std::unexpected(DecodeError::bad_block_range);
    }
    return {};
}

enum class ShapeV2 : std::uint8_t {
    empty,
    hello,
    hello_ok,
    blocks,
    redirect,
};

[[nodiscard]] constexpr auto shape_of(const HoldV2Header& h) noexcept -> ShapeV2 {
    const bool resp = is_response(h);
    if (h.opcode == HoldV2Opcode::redirect) {
        return ShapeV2::redirect;
    }
    if (resp && h.status != HoldV2Status::ok) {
        return ShapeV2::empty;
    }
    switch (h.opcode) {
        case HoldV2Opcode::hello:
            return ShapeV2::hello;
        case HoldV2Opcode::hello_ok:
            return ShapeV2::hello_ok;
        case HoldV2Opcode::read:
            return resp ? ShapeV2::blocks : ShapeV2::empty;
        case HoldV2Opcode::write:
            return resp ? ShapeV2::empty : ShapeV2::blocks;
        default:
            return ShapeV2::empty;
    }
}

[[nodiscard]] constexpr auto shape_of(const HoldV2Payload& p) noexcept -> ShapeV2 {
    // HoldV2Payload's alternatives are in ShapeV2 order.
    return static_cast<ShapeV2>(p.index());
}

[[nodiscard]] inline auto check_payload(const HoldV2Header& h, const HoldV2Payload& p)
    -> std::expected<void, DecodeError> {
    if (shape_of(p) != shape_of(h)) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    if (const auto* hello = std::get_if<HoldV2Hello>(&p)) {
        if (!known(hello->role)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if ((hello->role == HoldV2Role::initiator) != (h.attachment_id != 0)) {
            return std::unexpected(DecodeError::bad_id);
        }
    } else if (const auto* ok = std::get_if<HoldV2HelloOk>(&p)) {
        if (ok->block_size != block_size_512 && ok->block_size != block_size_4096) {
            return std::unexpected(DecodeError::bad_block_size);
        }
        if (ok->capacity_blocks == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (!valid_stripe_unit(ok->stripe_unit) || ok->stripe_width == 0 ||
            ok->stripe_width > max_stripe_width) {
            return std::unexpected(DecodeError::bad_stripe);
        }
    } else if (const auto* d = std::get_if<BlockData>(&p)) {
        return check_block_data(v1_view(h), *d);
    } else if (const auto* rd = std::get_if<HoldV2Redirect>(&p)) {
        const bool known_leader = rd->leader_server != 0;
        if (known_leader ? (!unicast(rd->endpoint) || rd->port == 0 || rd->leader_term == 0)
                         : (!all_zero(rd->endpoint) || rd->port != 0 || rd->leader_term != 0)) {
            return std::unexpected(DecodeError::bad_redirect);
        }
    }
    return {};
}

[[nodiscard]] inline auto payload_size(const HoldV2Payload& p) noexcept -> std::size_t {
    return std::visit(
        []<typename T>(const T& v) -> std::size_t {
            if constexpr (std::is_same_v<T, std::monostate>) {
                return 0;
            } else if constexpr (std::is_same_v<T, HoldV2Hello>) {
                return hold_v2_hello_size;
            } else if constexpr (std::is_same_v<T, HoldV2HelloOk>) {
                return hold_v2_hello_ok_size;
            } else if constexpr (std::is_same_v<T, BlockData>) {
                return v.crcs.size() + v.data.size();
            } else {
                static_assert(std::is_same_v<T, HoldV2Redirect>);
                return hold_v2_redirect_size;
            }
        },
        p);
}

}  // namespace detail

// Decodes and checks a version 2 header: magic, version, CRC, reserved
// bytes and the header rules above. `bytes` is exactly the 88 header bytes.
[[nodiscard]] inline auto decode_hold_v2_header(std::span<const std::byte> bytes)
    -> std::expected<HoldV2Header, DecodeError> {
    if (bytes.size() < hold_v2_header_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > hold_v2_header_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.u8().value_or(0);
    HoldV2Header h;
    h.opcode = static_cast<HoldV2Opcode>(r.u8().value_or(0));
    h.flags = r.le16().value_or(0);
    h.payload_len = r.le32().value_or(0);
    h.status = static_cast<HoldV2Status>(r.le16().value_or(0));
    bool zero = r.le16().value_or(1) == 0;
    h.request_id = r.le64().value_or(0);
    h.volume_id = r.le64().value_or(0);
    h.epoch = r.le64().value_or(0);
    h.attachment_id = r.le64().value_or(0);
    h.generation = r.le32().value_or(0);
    h.blocks = r.le32().value_or(0);
    h.lba = r.le64().value_or(0);
    h.group_id = r.le64().value_or(0);
    h.term = r.le64().value_or(0);
    zero = r.le32().value_or(1) == 0 && zero;
    const auto crc = r.le32().value_or(0);
    if (magic != hold_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != hold_v2_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    // The checksum before anything else in the header is believed.
    if (crc32c::of(bytes.first(hold_v2_header_crc_offset)) != crc) {
        return std::unexpected(DecodeError::bad_header_crc);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_hold_v2_header(h); !ok) {
        return std::unexpected(ok.error());
    }
    return h;
}

// Decodes the payload that follows `header` (which decode_hold_v2_header
// accepted). `bytes` must be exactly header.payload_len bytes; block data
// in the result points into it.
[[nodiscard]] inline auto decode_hold_v2_payload(const HoldV2Header& header,
                                                 std::span<const std::byte> bytes)
    -> std::expected<HoldV2Payload, DecodeError> {
    if (bytes.size() != header.payload_len) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    wire::Reader r{bytes};
    const auto exact = [&](std::size_t n) -> std::expected<void, DecodeError> {
        if (bytes.size() != n) {
            return std::unexpected(DecodeError::bad_payload_size);
        }
        return {};
    };
    HoldV2Payload out;
    switch (detail::shape_of(header)) {
        case detail::ShapeV2::empty:
            if (auto ok = exact(0); !ok) {
                return std::unexpected(ok.error());
            }
            break;
        case detail::ShapeV2::hello: {
            if (auto ok = exact(hold_v2_hello_size); !ok) {
                return std::unexpected(ok.error());
            }
            const HoldV2Hello hello{.role = static_cast<HoldV2Role>(r.u8().value_or(0))};
            if (!detail::all_zero(r.bytes(7).value_or(std::span<const std::byte>{}))) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            out = hello;
            break;
        }
        case detail::ShapeV2::hello_ok: {
            if (auto ok = exact(hold_v2_hello_ok_size); !ok) {
                return std::unexpected(ok.error());
            }
            HoldV2HelloOk hok{.block_size = r.le32().value_or(0)};
            bool zero = r.le32().value_or(1) == 0;
            hok.capacity_blocks = r.le64().value_or(0);
            hok.stripe_unit = r.le32().value_or(0);
            hok.stripe_width = r.le16().value_or(0);
            zero = r.le16().value_or(1) == 0 && zero;
            if (!zero) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            out = hok;
            break;
        }
        case detail::ShapeV2::blocks: {
            auto d = detail::read_block_data(detail::v1_view(header), bytes);
            if (!d) {
                return std::unexpected(d.error());
            }
            out = *d;
            break;
        }
        case detail::ShapeV2::redirect: {
            if (auto ok = exact(hold_v2_redirect_size); !ok) {
                return std::unexpected(ok.error());
            }
            HoldV2Redirect rd{.leader_server = r.le64().value_or(0)};
            std::ranges::copy(r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{}),
                              rd.endpoint.begin());
            rd.port = r.le16().value_or(0);
            const bool zero = detail::all_zero(r.bytes(6).value_or(std::span<const std::byte>{}));
            rd.leader_term = r.le64().value_or(0);
            if (!zero) {
                return std::unexpected(DecodeError::reserved_not_zero);
            }
            out = rd;
            break;
        }
    }
    if (auto ok = detail::check_payload(header, out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Decodes one whole version 2 frame (header and payload in one buffer).
[[nodiscard]] inline auto decode_hold_v2_frame(std::span<const std::byte> bytes)
    -> std::expected<HoldV2Frame, DecodeError> {
    if (bytes.size() < hold_v2_header_size) {
        return std::unexpected(DecodeError::truncated);
    }
    auto h = decode_hold_v2_header(bytes.first(hold_v2_header_size));
    if (!h) {
        return std::unexpected(h.error());
    }
    const auto rest = bytes.subspan(hold_v2_header_size);
    if (rest.size() < h->payload_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (rest.size() > h->payload_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    auto p = decode_hold_v2_payload(*h, rest);
    if (!p) {
        return std::unexpected(p.error());
    }
    return HoldV2Frame{.header = *h, .payload = std::move(*p)};
}

// Encodes a version 2 header with the given payload length and its CRC,
// for a sender that writes the payload separately (no copy of block data).
// Checks the header rules, not the payload.
[[nodiscard]] inline auto encode_hold_v2_header(HoldV2Header h, std::size_t payload_len)
    -> std::expected<std::array<std::byte, hold_v2_header_size>, DecodeError> {
    if (payload_len > max_hold_v2_payload) {
        return std::unexpected(DecodeError::record_too_large);
    }
    h.payload_len = static_cast<std::uint32_t>(payload_len);
    if (auto ok = detail::check_hold_v2_header(h); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> buf;
    buf.reserve(hold_v2_header_size);
    wire::Writer w{buf};
    w.le32(hold_magic);
    w.u8(hold_v2_version);
    w.u8(static_cast<std::uint8_t>(h.opcode));
    w.le16(h.flags);
    w.le32(h.payload_len);
    w.le16(static_cast<std::uint16_t>(h.status));
    w.le16(0);
    w.le64(h.request_id);
    w.le64(h.volume_id);
    w.le64(h.epoch);
    w.le64(h.attachment_id);
    w.le32(h.generation);
    w.le32(h.blocks);
    w.le64(h.lba);
    w.le64(h.group_id);
    w.le64(h.term);
    w.le32(0);
    w.le32(crc32c::of(buf));
    std::array<std::byte, hold_v2_header_size> out{};
    std::ranges::copy(buf, out.begin());
    return out;
}

// Encodes a whole version 2 frame, enforcing every rule the decoders
// check. The header's payload_len is ignored and computed from the payload.
[[nodiscard]] inline auto encode_hold_v2_frame(const HoldV2Frame& f)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    const std::size_t len = detail::payload_size(f.payload);
    auto header = encode_hold_v2_header(f.header, len);
    if (!header) {
        return std::unexpected(header.error());
    }
    auto h = f.header;
    h.payload_len = static_cast<std::uint32_t>(len);
    if (auto ok = detail::check_payload(h, f.payload); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(hold_v2_header_size + len);
    wire::Writer w{out};
    w.bytes(*header);
    std::visit(
        [&]<typename T>(const T& v) {
            if constexpr (std::is_same_v<T, HoldV2Hello>) {
                w.u8(static_cast<std::uint8_t>(v.role));
                w.bytes(std::array<std::byte, 7>{});
            } else if constexpr (std::is_same_v<T, HoldV2HelloOk>) {
                w.le32(v.block_size);
                w.le32(0);
                w.le64(v.capacity_blocks);
                w.le32(v.stripe_unit);
                w.le16(v.stripe_width);
                w.le16(0);
            } else if constexpr (std::is_same_v<T, BlockData>) {
                w.bytes(v.crcs);
                w.bytes(v.data);
            } else if constexpr (std::is_same_v<T, HoldV2Redirect>) {
                w.le64(v.leader_server);
                w.bytes(v.endpoint);
                w.le16(v.port);
                w.bytes(std::array<std::byte, 6>{});
                w.le64(v.leader_term);
            }
        },
        f.payload);
    return out;
}

}  // namespace ak::proto
