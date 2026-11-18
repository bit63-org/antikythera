// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE wire_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <vector>

#include "common/wire.hpp"
#include "test_support.hpp"

using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using ak::wire::Order;
using ak::wire::Reader;
using ak::wire::SpanWriter;
using ak::wire::WireError;
using ak::wire::Writer;

namespace {

constexpr std::uint8_t byte_a = 0x12;
constexpr std::uint8_t byte_b = 0x34;
constexpr std::uint8_t byte_c = 0x56;
constexpr std::uint8_t byte_d = 0x78;
constexpr std::uint32_t abcd_big_endian = 0x12345678u;
constexpr std::uint32_t abcd_little_endian = 0x78563412u;
constexpr std::uint16_t ab_big_endian = 0x1234u;
constexpr std::uint16_t cd_little_endian = 0x7856u;

constexpr std::size_t three_bytes = 3;
constexpr std::size_t two_bytes = 2;

constexpr std::uint16_t sample_u16 = 0xBEEF;
constexpr std::uint64_t sample_u64 = 0x0102030405060708ull;
constexpr std::uint8_t sample_u8 = 0x7F;
constexpr std::size_t sample_encoded_size =
    sizeof(sample_u16) + sizeof(sample_u64) + sizeof(sample_u8);

constexpr std::uint16_t first_word = 0xAABB;
constexpr std::uint16_t second_word = 0xCCDD;
constexpr std::byte first_word_hi{0xAA};
constexpr std::byte first_word_lo{0xBB};

}  // namespace

BOOST_AUTO_TEST_CASE(reads_big_and_little_endian,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto buf = bytes_of(byte_a, byte_b, byte_c, byte_d);
    Reader be{buf};
    BOOST_TEST(*be.be32() == abcd_big_endian);
    Reader le{buf};
    BOOST_TEST(*le.le32() == abcd_little_endian);
    Reader mixed{buf};
    BOOST_TEST(*mixed.be16() == ab_big_endian);
    BOOST_TEST(*mixed.le16() == cd_little_endian);
}

BOOST_AUTO_TEST_CASE(truncated_read_fails_without_advancing,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto buf = bytes_of(byte_a, byte_b, byte_c);
    Reader r{buf};
    auto v = r.be32();
    BOOST_TEST(!v.has_value());
    BOOST_TEST((v.error() == WireError::truncated));
    BOOST_TEST(r.position() == 0u);
    BOOST_TEST(*r.u8() == byte_a);
    BOOST_TEST(!r.bytes(three_bytes).has_value());
    BOOST_TEST(r.bytes(two_bytes)->size() == two_bytes);
    BOOST_TEST(r.remaining() == 0u);
    BOOST_TEST(!r.skip(1).has_value());
}

BOOST_AUTO_TEST_CASE(writer_round_trips_through_reader,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> out;
    Writer w{out};
    w.be16(sample_u16);
    w.le64(sample_u64);
    w.u8(sample_u8);
    BOOST_TEST(out.size() == sample_encoded_size);
    Reader r{out};
    BOOST_TEST(*r.be16() == sample_u16);
    BOOST_TEST(*r.le64() == sample_u64);
    BOOST_TEST(*r.u8() == sample_u8);
}

BOOST_AUTO_TEST_CASE(span_writer_refuses_overflow,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::array<std::byte, three_bytes> buf{};
    SpanWriter w{buf};
    BOOST_TEST(w.write(first_word, Order::big).has_value());
    auto r = w.write(second_word, Order::big);
    BOOST_TEST(!r.has_value());
    BOOST_TEST((r.error() == WireError::overflow));
    BOOST_TEST(w.written() == sizeof(first_word));
    BOOST_TEST((buf[0] == first_word_hi));
    BOOST_TEST((buf[1] == first_word_lo));
}
