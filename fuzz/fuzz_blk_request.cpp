// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the virtio-blk request parser over arbitrary chain layouts and
// volume geometries, and checks its guarantees on every input: accepted
// I/O lies inside the volume, every returned span lies inside the chain's
// buffers and covers exactly the data, and parsing never writes.
//
// Input: 6 control bytes, then the readable stream.
//   [0]   geometry: bit 0 = 4 KiB blocks, bit 1 = read-only, bits 2-7 = seg_max - 1
//   [1]   capacity in logical blocks (0-255)
//   [2]   readable segment count (low 3 bits); the stream is cut evenly
//   [3]   writable segment count (low 3 bits)
//   [4-5] writable bytes per segment, little-endian, capped at 9 KiB

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "oar/blk/request_parser.hpp"

namespace {

namespace blk = ak::oar::blk;

constexpr std::size_t control_bytes = 6;
constexpr std::uint8_t flag_4k = 0x01;
constexpr std::uint8_t flag_ro = 0x02;
constexpr unsigned seg_max_shift = 2;
constexpr std::uint8_t count_mask = 0x07;
constexpr unsigned byte_bits = 8;
constexpr std::size_t max_writable_segment = 9 * 1024;
constexpr std::uint32_t block_4k = 4096;
constexpr std::uint32_t block_512 = 512;
constexpr std::uint32_t max_transfer = 64 * 1024;
constexpr std::byte pattern{0xC3};

template<typename Span, typename Buf> auto inside(Span s, const std::vector<Buf>& bufs) -> bool {
    return std::ranges::any_of(bufs, [&](const Buf& b) {
        const auto* lo = reinterpret_cast<const std::byte*>(b.data());
        const auto* p = reinterpret_cast<const std::byte*>(s.data());
        return p >= lo && p + s.size() <= lo + b.size();
    });
}

auto check(bool ok) -> void {
    if (!ok) {
        std::abort();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < control_bytes) {
        return 0;
    }
    const std::uint8_t g = data[0];
    const std::uint32_t lbs = (g & flag_4k) != 0 ? block_4k : block_512;
    const blk::VolumeGeometry geometry{
        .capacity_sectors = std::uint64_t{data[1]} * (lbs / blk::sector_size),
        .logical_block_size = lbs,
        .read_only = (g & flag_ro) != 0,
        .seg_max = static_cast<std::uint32_t>(g >> seg_max_shift) + 1,
        .max_transfer_bytes = max_transfer,
    };
    auto parser = blk::RequestParser::create(geometry);
    check(parser.has_value());

    const std::size_t nr = data[2] & count_mask;
    const std::size_t nw = data[3] & count_mask;
    const std::size_t wlen =
        std::min<std::size_t>(data[4] | (std::size_t{data[5]} << byte_bits), max_writable_segment);

    // Readable stream, cut into nr nearly equal segments (owned copies).
    const std::span<const std::uint8_t> stream{data + control_bytes, size - control_bytes};
    std::vector<std::vector<std::byte>> rbufs;
    for (std::size_t i = 0, off = 0; i < nr; ++i) {
        const std::size_t len = (i + 1 == nr) ? stream.size() - off : stream.size() / nr;
        const auto* p = reinterpret_cast<const std::byte*>(stream.data() + off);
        rbufs.emplace_back(p, p + len);
        off += len;
    }
    std::vector<std::vector<std::byte>> wbufs(nw, std::vector<std::byte>(wlen, pattern));

    std::vector<std::span<const std::byte>> rs(rbufs.begin(), rbufs.end());
    std::vector<std::span<std::byte>> ws(wbufs.begin(), wbufs.end());
    auto req = parser->parse(rs, ws);

    // Parsing never writes guest memory.
    for (const auto& b : wbufs) {
        check(std::ranges::all_of(b, [](std::byte x) { return x == pattern; }));
    }

    if (!req) {
        const auto& rej = req.error();
        check((rej.error == blk::ParseError::no_status_byte) == rej.status.empty());
        check(rej.status.empty() || (rej.status.size() == 1 && inside(rej.status, wbufs)));
        return 0;
    }

    check(req->status.size() == 1 && inside(req->status, wbufs));
    // The status byte is the last writable byte of the chain.
    const auto last = std::ranges::find_if(wbufs.rbegin(), wbufs.rend(),
                                           [](const auto& b) { return !b.empty(); });
    check(last != wbufs.rend() && req->status.data() == &last->back());

    std::uint64_t total = 0;
    for (auto s : req->out_data) {
        check(!s.empty() && inside(s, rbufs));
        total += s.size();
    }
    for (auto s : req->in_data) {
        check(!s.empty() && inside(s, wbufs));
        check(s.data() + s.size() <= req->status.data() || s.data() > req->status.data());
        total += s.size();
    }
    check(total == req->data_bytes);

    switch (req->type) {
        case blk::RequestType::in:
        case blk::RequestType::out: {
            check(req->data_bytes != 0 && req->data_bytes % lbs == 0);
            check(req->data_bytes <= max_transfer);
            check(req->sector % (lbs / blk::sector_size) == 0);
            check(req->sector_count * blk::sector_size == req->data_bytes);
            check(req->sector_count <= geometry.capacity_sectors &&
                  req->sector <= geometry.capacity_sectors - req->sector_count);
            const auto segs =
                req->type == blk::RequestType::in ? req->in_data.size() : req->out_data.size();
            check(segs <= geometry.seg_max);
            check(req->type == blk::RequestType::in || !geometry.read_only);
            break;
        }
        case blk::RequestType::flush:
            check(req->data_bytes == 0);
            break;
        case blk::RequestType::get_id:
            check(req->data_bytes != 0 && req->out_data.empty());
            break;
        default:
            std::abort();  // parse accepted a type it does not implement
    }
    return 0;
}
