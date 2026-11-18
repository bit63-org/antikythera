// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/request_parser.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "common/wire.hpp"

namespace ak::oar::blk {

namespace {

constexpr std::uint32_t block_size_512 = 512;
constexpr std::uint32_t block_size_4k = 4096;

// The readable stream after the header, as non-empty segments. Returns
// false if the stream is shorter than the header.
auto split_readable(std::span<const std::span<const std::byte>> readable,
                    std::array<std::byte, header_size>& header,
                    std::vector<std::span<const std::byte>>& data) -> bool {
    std::size_t have = 0;
    for (auto seg : readable) {
        if (have < header_size) {
            const std::size_t take = std::min(seg.size(), header_size - have);
            if (take != 0) {
                std::memcpy(header.data() + have, seg.data(), take);
            }
            have += take;
            seg = seg.subspan(take);
        }
        if (!seg.empty()) {
            data.push_back(seg);
        }
    }
    return have == header_size;
}

// The writable stream minus its final byte, as non-empty segments, and that
// final byte. Returns an empty status span if there are no writable bytes.
auto split_writable(std::span<const std::span<std::byte>> writable,
                    std::vector<std::span<std::byte>>& data) -> std::span<std::byte> {
    for (auto seg : writable) {
        if (!seg.empty()) {
            data.push_back(seg);
        }
    }
    if (data.empty()) {
        return {};
    }
    auto& last = data.back();
    auto status = last.last(status_size);
    last = last.first(last.size() - status_size);
    if (last.empty()) {
        data.pop_back();
    }
    return status;
}

template<typename Span> auto total_bytes(const std::vector<Span>& segs) noexcept -> std::uint64_t {
    std::uint64_t n = 0;
    for (const auto& s : segs) {
        n += s.size();
    }
    return n;
}

}  // namespace

auto to_string(GeometryError e) noexcept -> const char* {
    switch (e) {
        case GeometryError::bad_block_size:
            return "bad_block_size";
        case GeometryError::capacity_unaligned:
            return "capacity_unaligned";
        case GeometryError::bad_seg_max:
            return "bad_seg_max";
        case GeometryError::bad_max_transfer:
            return "bad_max_transfer";
    }
    return "unknown";
}

auto to_string(ParseError e) noexcept -> const char* {
    switch (e) {
        case ParseError::no_status_byte:
            return "no_status_byte";
        case ParseError::header_truncated:
            return "header_truncated";
        case ParseError::unsupported_type:
            return "unsupported_type";
        case ParseError::unexpected_data:
            return "unexpected_data";
        case ParseError::missing_data:
            return "missing_data";
        case ParseError::bad_length:
            return "bad_length";
        case ParseError::misaligned_sector:
            return "misaligned_sector";
        case ParseError::out_of_range:
            return "out_of_range";
        case ParseError::read_only:
            return "read_only";
        case ParseError::too_many_segments:
            return "too_many_segments";
        case ParseError::too_large:
            return "too_large";
    }
    return "unknown";
}

auto status_for(ParseError e) noexcept -> Status {
    return e == ParseError::unsupported_type ? Status::unsupp : Status::ioerr;
}

auto complete(std::span<std::byte> status, Status s) noexcept -> void {
    if (status.size() == status_size) {
        status[0] = static_cast<std::byte>(s);
    }
}

auto RequestParser::create(const VolumeGeometry& geometry)
    -> std::expected<RequestParser, GeometryError> {
    const std::uint32_t lbs = geometry.logical_block_size;
    if (lbs != block_size_512 && lbs != block_size_4k) {
        return std::unexpected(GeometryError::bad_block_size);
    }
    const std::uint64_t sectors_per_block = lbs / sector_size;
    if (geometry.capacity_sectors % sectors_per_block != 0) {
        return std::unexpected(GeometryError::capacity_unaligned);
    }
    if (geometry.seg_max == 0) {
        return std::unexpected(GeometryError::bad_seg_max);
    }
    if (geometry.max_transfer_bytes == 0 || geometry.max_transfer_bytes % lbs != 0) {
        return std::unexpected(GeometryError::bad_max_transfer);
    }
    return RequestParser{geometry};
}

auto RequestParser::parse(std::span<const std::span<const std::byte>> readable,
                          std::span<const std::span<std::byte>> writable) const
    -> std::expected<Request, Rejection> {
    Request req;

    // The status byte first: without it no other error can be reported.
    req.status = split_writable(writable, req.in_data);
    if (req.status.empty()) {
        return std::unexpected(Rejection{.error = ParseError::no_status_byte, .status = {}});
    }
    auto reject = [&req](ParseError e) {
        return std::unexpected(Rejection{.error = e, .status = req.status});
    };

    // Copy the header out of guest memory once, then decode the copy.
    std::array<std::byte, header_size> header{};
    if (!split_readable(readable, header, req.out_data)) {
        return reject(ParseError::header_truncated);
    }
    wire::Reader r{header};
    const auto type = r.le32();
    const auto reserved = r.le32();
    const auto sector = r.le64();
    if (!type || !reserved || !sector) {
        return reject(ParseError::header_truncated);  // unreachable: header is 16 bytes
    }
    // `reserved` is ignored, as the spec requires of devices (it held the
    // legacy ioprio field).

    const std::uint64_t readable_data = total_bytes(req.out_data);
    const std::uint64_t writable_data = total_bytes(req.in_data);

    switch (static_cast<RequestType>(*type)) {
        case RequestType::in:
            if (readable_data != 0) {
                return reject(ParseError::unexpected_data);
            }
            req.type = RequestType::in;
            req.out_data.clear();
            req.data_bytes = writable_data;
            break;
        case RequestType::out:
            if (_geometry.read_only) {
                return reject(ParseError::read_only);
            }
            if (writable_data != 0) {
                return reject(ParseError::unexpected_data);
            }
            req.type = RequestType::out;
            req.in_data.clear();
            req.data_bytes = readable_data;
            break;
        case RequestType::flush:
            // The sector field is ignored: drivers must send 0, and legacy
            // drivers sent garbage.
            if (readable_data != 0 || writable_data != 0) {
                return reject(ParseError::unexpected_data);
            }
            req.type = RequestType::flush;
            return req;
        case RequestType::get_id:
            if (readable_data != 0) {
                return reject(ParseError::unexpected_data);
            }
            if (writable_data == 0) {
                return reject(ParseError::missing_data);
            }
            if (req.in_data.size() > _geometry.seg_max) {
                return reject(ParseError::too_many_segments);
            }
            req.type = RequestType::get_id;
            req.data_bytes = writable_data;
            return req;
        case RequestType::get_lifetime:
        case RequestType::discard:
        case RequestType::write_zeroes:
        case RequestType::secure_erase:
        default:
            return reject(ParseError::unsupported_type);
    }

    // IN and OUT: shape, length, alignment and range, in that order.
    const std::size_t segments =
        req.type == RequestType::in ? req.in_data.size() : req.out_data.size();
    if (segments > _geometry.seg_max) {
        return reject(ParseError::too_many_segments);
    }
    const std::uint32_t lbs = _geometry.logical_block_size;
    if (req.data_bytes == 0 || req.data_bytes % lbs != 0) {
        return reject(ParseError::bad_length);
    }
    if (req.data_bytes > _geometry.max_transfer_bytes) {
        return reject(ParseError::too_large);
    }
    const std::uint64_t sectors_per_block = lbs / sector_size;
    if (*sector % sectors_per_block != 0) {
        return reject(ParseError::misaligned_sector);
    }
    const std::uint64_t count = req.data_bytes / sector_size;
    const std::uint64_t capacity = _geometry.capacity_sectors;
    // sector + count <= capacity, written so that it cannot wrap.
    if (count > capacity || *sector > capacity - count) {
        return reject(ParseError::out_of_range);
    }
    req.sector = *sector;
    req.sector_count = count;
    return req;
}

}  // namespace ak::oar::blk
