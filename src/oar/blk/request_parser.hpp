// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// virtio-blk request parsing (virtio 1.2 section 5.2.6), the guest-facing
// trust boundary of the storage data plane
// (.kiro/specs/oar-blk-data-plane/ Requirement 6).
//
// A request is one descriptor chain. Its device-readable bytes, taken as
// one stream, are the 16-byte header followed (for writes) by the data; its
// device-writable bytes are the data to fill (for reads and GET_ID)
// followed by one status byte. VIRTIO_F_ANY_LAYOUT is mandatory for virtio
// 1.x, so nothing here assumes how the guest split that stream into
// descriptors: the header may span descriptors and may share one with data.
//
//   struct virtio_blk_req {
//       le32 type;
//       le32 reserved;
//       le64 sector;     // always in 512-byte units, whatever blk_size is
//       u8   data[];
//       u8   status;     // written by the device
//   };
//
// The parser validates everything before any I/O and copies the header out
// once, so a guest rewriting it afterwards changes nothing:
//
//   - the chain must have room for the status byte, or there is no way to
//     report anything (ParseError::no_status_byte);
//   - the type must be one oar-blk implements (IN, OUT, FLUSH, GET_ID, and
//     DISCARD and WRITE_ZEROES when the geometry offers them);
//   - each type must have exactly the readable/writable shape it implies;
//   - read/write lengths must be a non-zero multiple of the logical block
//     size, start on a logical block boundary, and lie entirely inside the
//     volume, computed without overflow, so an out-of-range sector fails
//     the request and never wraps (Requirement 6.1);
//   - segment counts and transfer size are capped so one request cannot
//     make the device do unbounded work;
//   - DISCARD and WRITE_ZEROES carry exactly one 16-byte range (the device
//     offers max_discard_seg = max_write_zeroes_seg = 1), copied out of
//     guest memory once:
//
//       struct virtio_blk_discard_write_zeroes {
//           le64 sector;       // 512-byte units
//           le32 num_sectors;
//           le32 flags;        // bit 0: unmap; the rest reserved
//       };
//
//     The range must be whole logical blocks inside the volume and at most
//     max_trim_sectors long. A DISCARD with unmap set, or either type with
//     a reserved flag bit, completes with UNSUPP (virtio 1.2 5.2.6.2); the
//     header's sector field is ignored, as for FLUSH.
//
// The chain itself (descriptor flags, guest addresses, readable-before-
// writable ordering) has already been validated by the shared virtqueue;
// this layer takes the resulting buffers as spans and does not depend on it.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace ak::oar::blk {

inline constexpr std::size_t sector_size = 512;  // unit of virtio_blk_req.sector
inline constexpr std::size_t header_size = 16;
inline constexpr std::size_t status_size = 1;
inline constexpr std::size_t id_bytes = 20;         // VIRTIO_BLK_ID_BYTES
inline constexpr std::size_t trim_range_size = 16;  // virtio_blk_discard_write_zeroes
inline constexpr std::uint32_t trim_flag_unmap = 0x1;

// virtio_blk_req.type values (virtio 1.2 5.2.6).
enum class RequestType : std::uint32_t {
    in = 0,             // VIRTIO_BLK_T_IN: read
    out = 1,            // VIRTIO_BLK_T_OUT: write
    flush = 4,          // VIRTIO_BLK_T_FLUSH
    get_id = 8,         // VIRTIO_BLK_T_GET_ID: up to 20 bytes of serial
    get_lifetime = 10,  // VIRTIO_BLK_T_GET_LIFETIME (not offered)
    discard = 11,       // VIRTIO_BLK_T_DISCARD (when VolumeGeometry::trim)
    write_zeroes = 13,  // VIRTIO_BLK_T_WRITE_ZEROES (when VolumeGeometry::trim)
    secure_erase = 14,  // VIRTIO_BLK_T_SECURE_ERASE (not offered)
};

// The status byte the device writes back.
enum class Status : std::uint8_t {
    ok = 0,      // VIRTIO_BLK_S_OK
    ioerr = 1,   // VIRTIO_BLK_S_IOERR
    unsupp = 2,  // VIRTIO_BLK_S_UNSUPP
};

// What the device advertises for one attachment, fixed while it is
// attached except for the capacity, which an online grow raises
// (RequestParser::grow).
struct VolumeGeometry {
    std::uint64_t capacity_sectors{0};      // virtio_blk_config.capacity, 512-byte units
    std::uint32_t logical_block_size{512};  // virtio_blk_config.blk_size: 512 or 4096
    bool read_only{false};                  // VIRTIO_BLK_F_RO offered
    std::uint32_t seg_max{128};             // virtio_blk_config.seg_max: data segments per request
    std::uint32_t max_transfer_bytes{1U << 20U};  // largest IN/OUT the device accepts
    // DISCARD and WRITE_ZEROES (VIRTIO_BLK_F_DISCARD and _WRITE_ZEROES),
    // offered only for backends that free space (khold volumes), and the
    // longest range either may name, in 512-byte sectors.
    bool trim{false};
    std::uint32_t max_trim_sectors{0};
};

enum class GeometryError : std::uint8_t {
    bad_block_size,      // not 512 or 4096 (the XTS data unit sizes)
    capacity_unaligned,  // capacity is not a whole number of logical blocks
    bad_seg_max,         // zero
    bad_max_transfer,    // zero or not a multiple of the logical block size
    bad_max_trim,        // trim offered with max_trim_sectors zero or not whole blocks
};

[[nodiscard]] auto to_string(GeometryError e) noexcept -> const char*;

enum class ParseError : std::uint8_t {
    no_status_byte,     // no writable byte at all: nothing can be reported
    header_truncated,   // fewer than 16 readable bytes
    unsupported_type,   // a type oar-blk does not implement
    unexpected_data,    // bytes the type has no use for (e.g. writable data on OUT)
    missing_data,       // GET_ID with no room for the ID
    bad_length,         // IN/OUT data length 0 or not a multiple of the block size
    misaligned_sector,  // IN/OUT sector not on a logical block boundary
    out_of_range,       // IN/OUT runs past the end of the volume
    read_only,          // OUT on a read-only volume
    too_many_segments,  // more data segments than seg_max
    too_large,          // IN/OUT longer than max_transfer_bytes, or a range past max_trim_sectors
    bad_flags,          // DISCARD with unmap, or a reserved range flag (UNSUPP)
};

[[nodiscard]] auto to_string(ParseError e) noexcept -> const char*;

// The status a rejected request completes with: UNSUPP for an unknown or
// unimplemented type or a range flag the device does not take, IOERR for
// everything else (virtio 1.2 5.2.6.1).
// Meaningless for no_status_byte, which cannot be completed normally.
[[nodiscard]] auto status_for(ParseError e) noexcept -> Status;

// A validated request. All spans alias the chain's buffers (guest memory).
struct Request {
    RequestType type{RequestType::in};
    std::uint64_t sector{0};        // first 512-byte sector (IN/OUT/DISCARD/WRITE_ZEROES)
    std::uint64_t sector_count{0};  // 512-byte sectors moved or trimmed (likewise; else 0)
    bool unmap{false};              // WRITE_ZEROES: the device may free the range
    std::uint64_t data_bytes{0};    // bytes in `out_data` or `in_data`

    // OUT: the data to write, in order. Empty for every other type.
    std::vector<std::span<const std::byte>> out_data;
    // IN and GET_ID: where to put the data, in order. Empty otherwise.
    std::vector<std::span<std::byte>> in_data;
    // The status byte; always exactly one byte.
    std::span<std::byte> status;
};

// A rejected request. `status` is the byte to write status_for(error) into,
// or empty when error is no_status_byte.
struct Rejection {
    ParseError error{ParseError::no_status_byte};
    std::span<std::byte> status;
};

// Writes `s` into a status span of exactly one byte; no-op on an empty span.
auto complete(std::span<std::byte> status, Status s) noexcept -> void;

class RequestParser {
public:
    [[nodiscard]] static auto create(const VolumeGeometry& geometry)
        -> std::expected<RequestParser, GeometryError>;

    // Parses one request from a chain's readable and writable buffers, in
    // chain order. Never reads or writes any byte of the buffers past the
    // header; the caller writes the status byte.
    [[nodiscard]] auto parse(std::span<const std::span<const std::byte>> readable,
                             std::span<const std::span<std::byte>> writable) const
        -> std::expected<Request, Rejection>;

    [[nodiscard]] auto geometry() const noexcept -> const VolumeGeometry& { return _geometry; }

    // An online grow (.kiro/specs/block-volume-service/ Requirement 10.3):
    // requests up to `capacity_sectors` pass from now on. A smaller
    // capacity, or one not a whole number of logical blocks, is refused
    // and changes nothing.
    [[nodiscard]] auto grow(std::uint64_t capacity_sectors) noexcept
        -> std::expected<void, GeometryError>;

private:
    explicit RequestParser(const VolumeGeometry& geometry) noexcept : _geometry{geometry} {}

    // DISCARD and WRITE_ZEROES, after the header (above).
    [[nodiscard]] auto parse_trim(RequestType type, Request req, std::uint64_t readable_data,
                                  std::uint64_t writable_data) const
        -> std::expected<Request, Rejection>;

    VolumeGeometry _geometry;
};

}  // namespace ak::oar::blk
