// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirement 6.1, design "RequestParser":
// header, descriptor-chain shape, length, alignment and sector range are
// validated before any I/O, and out-of-range sectors fail without wrapping.

#define BOOST_TEST_MODULE request_parser_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "oar/blk/request_parser.hpp"
#include "test_support.hpp"

// Lets BOOST_TEST print the enums when a comparison fails.
namespace ak::oar::blk {
auto operator<<(std::ostream& os, ParseError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, GeometryError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, RequestType t) -> std::ostream& {
    return os << static_cast<std::uint32_t>(t);
}
auto operator<<(std::ostream& os, Status s) -> std::ostream& {
    return os << static_cast<unsigned>(s);
}
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;
using blk::ParseError;
using blk::RequestParser;
using blk::RequestType;
using blk::Status;
using blk::VolumeGeometry;

namespace {

constexpr std::uint64_t volume_sectors = 2048;  // 1 MiB
constexpr std::size_t one_sector = blk::sector_size;
constexpr std::size_t two_sectors = 2 * blk::sector_size;
constexpr std::uint32_t block_4k = 4096;
constexpr std::uint64_t sectors_per_4k = block_4k / blk::sector_size;
constexpr std::uint32_t small_seg_max = 2;
constexpr std::uint32_t small_max_transfer = 2 * blk::sector_size;
constexpr std::uint32_t unknown_type = 0xDEAD;
constexpr std::uint32_t garbage_reserved = 0xFFFF'FFFF;
constexpr std::uint64_t garbage_sector = 0x1234'5678;
constexpr std::uint64_t max_u64 = std::numeric_limits<std::uint64_t>::max();
constexpr std::size_t header_split = 5;  // header cut mid-field
constexpr std::byte status_canary{0xAA};

auto header(std::uint32_t type, std::uint64_t sector, std::uint32_t reserved = 0)
    -> std::vector<std::byte> {
    std::vector<std::byte> out;
    ak::wire::Writer w{out};
    w.le32(type);
    w.le32(reserved);
    w.le64(sector);
    return out;
}

auto header(RequestType type, std::uint64_t sector) -> std::vector<std::byte> {
    return header(static_cast<std::uint32_t>(type), sector);
}

// Owns the buffers of one descriptor chain and hands out spans over them.
struct Chain {
    std::vector<std::vector<std::byte>> r;
    std::vector<std::vector<std::byte>> w;

    auto readable(std::vector<std::byte> b) -> Chain& {
        r.push_back(std::move(b));
        return *this;
    }
    auto writable(std::size_t n) -> Chain& {
        w.emplace_back(n, status_canary);
        return *this;
    }

    [[nodiscard]] auto parse(const RequestParser& p)
        -> std::expected<blk::Request, blk::Rejection> {
        _rs.clear();
        _ws.clear();
        for (const auto& b : r) {
            _rs.emplace_back(b);
        }
        for (auto& b : w) {
            _ws.emplace_back(b);
        }
        return p.parse(_rs, _ws);
    }

private:
    std::vector<std::span<const std::byte>> _rs;
    std::vector<std::span<std::byte>> _ws;
};

auto parser(VolumeGeometry g = {.capacity_sectors = volume_sectors}) -> RequestParser {
    auto p = RequestParser::create(g);
    BOOST_TEST_REQUIRE(p.has_value());
    return *p;
}

auto data(std::size_t n) -> std::vector<std::byte> {
    return std::vector<std::byte>(n, std::byte{0x5A});
}

auto error_of(const std::expected<blk::Request, blk::Rejection>& r) -> ParseError {
    BOOST_TEST_REQUIRE(!r.has_value());
    return r.error().error;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(geometry)

BOOST_AUTO_TEST_CASE(accepts_512_and_4k, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(RequestParser::create({.capacity_sectors = volume_sectors}).has_value());
    BOOST_TEST(
        RequestParser::create({.capacity_sectors = volume_sectors, .logical_block_size = block_4k})
            .has_value());
}

BOOST_AUTO_TEST_CASE(rejects_bad_geometry, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using blk::GeometryError;
    constexpr std::uint32_t block_1k = 1024;
    BOOST_TEST(
        RequestParser::create({.capacity_sectors = volume_sectors, .logical_block_size = block_1k})
            .error() == GeometryError::bad_block_size);
    BOOST_TEST(RequestParser::create(
                   {.capacity_sectors = volume_sectors + 1, .logical_block_size = block_4k})
                   .error() == GeometryError::capacity_unaligned);
    BOOST_TEST(RequestParser::create({.capacity_sectors = volume_sectors, .seg_max = 0}).error() ==
               GeometryError::bad_seg_max);
    BOOST_TEST(RequestParser::create({.capacity_sectors = volume_sectors, .max_transfer_bytes = 0})
                   .error() == GeometryError::bad_max_transfer);
    BOOST_TEST(RequestParser::create({.capacity_sectors = volume_sectors,
                                      .logical_block_size = block_4k,
                                      .max_transfer_bytes = small_max_transfer})
                   .error() == GeometryError::bad_max_transfer);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(well_formed)

BOOST_AUTO_TEST_CASE(read_two_sectors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::uint64_t sector = 10;
    Chain c;
    c.readable(header(RequestType::in, sector)).writable(two_sectors).writable(1);
    auto r = c.parse(parser());
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->type == RequestType::in);
    BOOST_TEST(r->sector == sector);
    BOOST_TEST(r->sector_count == 2U);
    BOOST_TEST(r->data_bytes == two_sectors);
    BOOST_TEST(r->out_data.empty());
    BOOST_TEST_REQUIRE(r->in_data.size() == 1U);
    BOOST_TEST(r->in_data[0].data() == c.w[0].data());
    BOOST_TEST(r->in_data[0].size() == two_sectors);
    BOOST_TEST_REQUIRE(r->status.size() == 1U);
    BOOST_TEST(r->status.data() == c.w[1].data());
}

BOOST_AUTO_TEST_CASE(write_two_sectors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::uint64_t sector = 7;
    Chain c;
    c.readable(header(RequestType::out, sector))
        .readable(data(one_sector))
        .readable(data(one_sector))
        .writable(1);
    auto r = c.parse(parser());
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->type == RequestType::out);
    BOOST_TEST(r->sector == sector);
    BOOST_TEST(r->sector_count == 2U);
    BOOST_TEST(r->in_data.empty());
    BOOST_TEST_REQUIRE(r->out_data.size() == 2U);
    BOOST_TEST(r->out_data[0].data() == c.r[1].data());
    BOOST_TEST(r->out_data[1].data() == c.r[2].data());
}

// VIRTIO_F_ANY_LAYOUT: header split across descriptors and sharing one with
// data; status sharing a descriptor with read data.
BOOST_AUTO_TEST_CASE(any_layout, *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::uint64_t sector = 3;
    auto h = header(RequestType::out, sector);
    std::vector<std::byte> first(h.begin(), h.begin() + header_split);
    std::vector<std::byte> second(h.begin() + header_split, h.end());
    auto payload = data(one_sector);
    second.insert(second.end(), payload.begin(), payload.end());

    Chain w;
    w.readable(first).readable(second).writable(1);
    auto wr = w.parse(parser());
    BOOST_TEST_REQUIRE(wr.has_value());
    BOOST_TEST(wr->sector == sector);
    BOOST_TEST(wr->data_bytes == one_sector);
    BOOST_TEST_REQUIRE(wr->out_data.size() == 1U);
    BOOST_TEST(wr->out_data[0].data() == w.r[1].data() + (blk::header_size - header_split));

    Chain rd;
    rd.readable(header(RequestType::in, sector)).writable(one_sector + 1);
    auto rr = rd.parse(parser());
    BOOST_TEST_REQUIRE(rr.has_value());
    BOOST_TEST_REQUIRE(rr->in_data.size() == 1U);
    BOOST_TEST(rr->in_data[0].size() == one_sector);
    BOOST_TEST(rr->status.data() == rd.w[0].data() + one_sector);
}

BOOST_AUTO_TEST_CASE(zero_length_descriptors_are_skipped,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::in, 0))
        .readable({})
        .writable(one_sector)
        .writable(0)
        .writable(1)
        .writable(0);
    auto r = c.parse(parser());
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->in_data.size() == 1U);
    BOOST_TEST(r->status.data() == c.w[2].data());
}

BOOST_AUTO_TEST_CASE(last_sector_is_in_range, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::in, volume_sectors - 1)).writable(one_sector).writable(1);
    BOOST_TEST(c.parse(parser()).has_value());
}

BOOST_AUTO_TEST_CASE(flush_ignores_sector_and_reserved,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(
         header(static_cast<std::uint32_t>(RequestType::flush), garbage_sector, garbage_reserved))
        .writable(1);
    auto r = c.parse(parser());
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->type == RequestType::flush);
    BOOST_TEST(r->sector == 0U);
    BOOST_TEST(r->data_bytes == 0U);
}

BOOST_AUTO_TEST_CASE(get_id, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::get_id, 0)).writable(blk::id_bytes).writable(1);
    auto r = c.parse(parser());
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->type == RequestType::get_id);
    BOOST_TEST(r->data_bytes == blk::id_bytes);
}

BOOST_AUTO_TEST_CASE(read_only_volume_still_reads,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::in, 0)).writable(one_sector).writable(1);
    BOOST_TEST(
        c.parse(parser({.capacity_sectors = volume_sectors, .read_only = true})).has_value());
}

BOOST_AUTO_TEST_CASE(header_is_copied_once, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Rewriting the header after parse (the guest racing us) changes nothing.
    constexpr std::uint64_t sector = 4;
    Chain c;
    c.readable(header(RequestType::in, sector)).writable(one_sector).writable(1);
    auto r = c.parse(parser());
    BOOST_TEST_REQUIRE(r.has_value());
    c.r[0] = header(RequestType::in, max_u64);
    BOOST_TEST(r->sector == sector);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(rejected)

BOOST_AUTO_TEST_CASE(no_writable_byte, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::flush, 0)).writable(0);
    auto r = c.parse(parser());
    BOOST_TEST(error_of(r) == ParseError::no_status_byte);
    BOOST_TEST(r.error().status.empty());
}

BOOST_AUTO_TEST_CASE(short_header, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto h = header(RequestType::flush, 0);
    h.pop_back();
    Chain c;
    c.readable(h).writable(1);
    auto r = c.parse(parser());
    BOOST_TEST(error_of(r) == ParseError::header_truncated);
    BOOST_TEST(r.error().status.data() == c.w[0].data());
    BOOST_TEST(blk::status_for(r.error().error) == Status::ioerr);
}

BOOST_AUTO_TEST_CASE(unsupported_types_get_unsupp,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (auto t : {static_cast<std::uint32_t>(RequestType::discard),
                   static_cast<std::uint32_t>(RequestType::write_zeroes),
                   static_cast<std::uint32_t>(RequestType::secure_erase),
                   static_cast<std::uint32_t>(RequestType::get_lifetime), unknown_type}) {
        Chain c;
        c.readable(header(t, 0)).writable(1);
        auto r = c.parse(parser());
        BOOST_TEST(error_of(r) == ParseError::unsupported_type);
        BOOST_TEST(blk::status_for(r.error().error) == Status::unsupp);
    }
}

BOOST_AUTO_TEST_CASE(wrong_shape, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain read_with_payload;
    read_with_payload.readable(header(RequestType::in, 0))
        .readable(data(one_sector))
        .writable(one_sector + 1);
    BOOST_TEST(error_of(read_with_payload.parse(parser())) == ParseError::unexpected_data);

    Chain write_with_room;
    write_with_room.readable(header(RequestType::out, 0))
        .readable(data(one_sector))
        .writable(one_sector + 1);
    BOOST_TEST(error_of(write_with_room.parse(parser())) == ParseError::unexpected_data);

    Chain flush_with_data;
    flush_with_data.readable(header(RequestType::flush, 0)).writable(one_sector + 1);
    BOOST_TEST(error_of(flush_with_data.parse(parser())) == ParseError::unexpected_data);

    Chain id_no_room;
    id_no_room.readable(header(RequestType::get_id, 0)).writable(1);
    BOOST_TEST(error_of(id_no_room.parse(parser())) == ParseError::missing_data);
}

BOOST_AUTO_TEST_CASE(bad_lengths, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain empty;
    empty.readable(header(RequestType::in, 0)).writable(1);
    BOOST_TEST(error_of(empty.parse(parser())) == ParseError::bad_length);

    Chain partial;
    partial.readable(header(RequestType::out, 0)).readable(data(one_sector - 1)).writable(1);
    BOOST_TEST(error_of(partial.parse(parser())) == ParseError::bad_length);

    Chain sub_block;
    sub_block.readable(header(RequestType::in, 0)).writable(one_sector).writable(1);
    BOOST_TEST(error_of(sub_block.parse(
                   parser({.capacity_sectors = volume_sectors, .logical_block_size = block_4k}))) ==
               ParseError::bad_length);
}

BOOST_AUTO_TEST_CASE(misaligned_for_4k_blocks, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto p = parser({.capacity_sectors = volume_sectors, .logical_block_size = block_4k});
    Chain aligned;
    aligned.readable(header(RequestType::in, sectors_per_4k)).writable(block_4k).writable(1);
    BOOST_TEST(aligned.parse(p).has_value());

    Chain off;
    off.readable(header(RequestType::in, sectors_per_4k + 1)).writable(block_4k).writable(1);
    BOOST_TEST(error_of(off.parse(p)) == ParseError::misaligned_sector);
}

BOOST_AUTO_TEST_CASE(out_of_range_never_wraps, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // One past the end, straddling the end, and sectors chosen so that
    // sector + count (or sector * 512) would wrap to a small number.
    for (std::uint64_t sector : {volume_sectors, volume_sectors - 1, max_u64, max_u64 - 1,
                                 max_u64 / blk::sector_size + 1}) {
        Chain c;
        c.readable(header(RequestType::in, sector)).writable(two_sectors).writable(1);
        BOOST_TEST(error_of(c.parse(parser())) == ParseError::out_of_range, "sector " << sector);
    }
    Chain past_empty;
    past_empty.readable(header(RequestType::in, 0)).writable(one_sector).writable(1);
    BOOST_TEST(error_of(past_empty.parse(parser({.capacity_sectors = 0}))) ==
               ParseError::out_of_range);
}

BOOST_AUTO_TEST_CASE(write_to_read_only, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::out, 0)).readable(data(one_sector)).writable(1);
    BOOST_TEST(error_of(c.parse(parser({.capacity_sectors = volume_sectors, .read_only = true}))) ==
               ParseError::read_only);
}

BOOST_AUTO_TEST_CASE(limits, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto p = parser({.capacity_sectors = volume_sectors,
                           .seg_max = small_seg_max,
                           .max_transfer_bytes = small_max_transfer});
    Chain three_segs;
    three_segs.readable(header(RequestType::in, 0))
        .writable(one_sector)
        .writable(one_sector)
        .writable(one_sector)
        .writable(1);
    BOOST_TEST(error_of(three_segs.parse(p)) == ParseError::too_many_segments);

    Chain big;
    big.readable(header(RequestType::out, 0)).readable(data(3 * one_sector)).writable(1);
    BOOST_TEST(error_of(big.parse(p)) == ParseError::too_large);

    Chain at_limit;
    at_limit.readable(header(RequestType::out, 0))
        .readable(data(one_sector))
        .readable(data(one_sector))
        .writable(1);
    BOOST_TEST(at_limit.parse(p).has_value());
}

BOOST_AUTO_TEST_CASE(parse_never_writes, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Chain c;
    c.readable(header(RequestType::in, max_u64)).writable(one_sector).writable(1);
    (void)c.parse(parser());
    for (const auto& b : c.w) {
        for (auto x : b) {
            BOOST_TEST((x == status_canary));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(complete_writes_one_byte, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> buf(2, status_canary);
    blk::complete(std::span{buf}.first(1), Status::unsupp);
    BOOST_TEST((buf[0] == std::byte{2}));
    BOOST_TEST((buf[1] == status_canary));
    blk::complete(std::span{buf}, Status::ok);  // wrong size: ignored
    BOOST_TEST((buf[0] == std::byte{2}));
    blk::complete({}, Status::ok);
}
