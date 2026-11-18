// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE wire_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <vector>

#include "common/wire.hpp"

using ak::wire::Order;
using ak::wire::Reader;
using ak::wire::SpanWriter;
using ak::wire::WireError;
using ak::wire::Writer;

namespace {
template <typename... B>
std::vector<std::byte> bytes(B... b) {
    return {static_cast<std::byte>(b)...};
}
}  // namespace

BOOST_AUTO_TEST_CASE(reads_big_and_little_endian) {
    const auto buf = bytes(0x12, 0x34, 0x56, 0x78);
    Reader be{buf};
    BOOST_TEST(*be.be32() == 0x12345678u);
    Reader le{buf};
    BOOST_TEST(*le.le32() == 0x78563412u);
    Reader be16{buf};
    BOOST_TEST(*be16.be16() == 0x1234u);
    BOOST_TEST(*be16.le16() == 0x7856u);
}

BOOST_AUTO_TEST_CASE(truncated_read_fails_without_advancing) {
    const auto buf = bytes(0x01, 0x02, 0x03);
    Reader r{buf};
    auto v = r.be32();
    BOOST_TEST(!v.has_value());
    BOOST_TEST((v.error() == WireError::truncated));
    BOOST_TEST(r.position() == 0u);
    BOOST_TEST(*r.u8() == 0x01u);
    BOOST_TEST(!r.bytes(3).has_value());
    BOOST_TEST(r.bytes(2)->size() == 2u);
    BOOST_TEST(r.remaining() == 0u);
    BOOST_TEST(!r.skip(1).has_value());
}

BOOST_AUTO_TEST_CASE(writer_round_trips_through_reader) {
    std::vector<std::byte> out;
    Writer w{out};
    w.be16(0xBEEF);
    w.le64(0x0102030405060708ull);
    w.u8(0x7F);
    BOOST_TEST(out.size() == 11u);
    Reader r{out};
    BOOST_TEST(*r.be16() == 0xBEEFu);
    BOOST_TEST(*r.le64() == 0x0102030405060708ull);
    BOOST_TEST(*r.u8() == 0x7Fu);
}

BOOST_AUTO_TEST_CASE(span_writer_refuses_overflow) {
    std::array<std::byte, 3> buf{};
    SpanWriter w{buf};
    BOOST_TEST(w.write(std::uint16_t{0xAABB}, Order::big).has_value());
    auto r = w.write(std::uint16_t{0xCCDD}, Order::big);
    BOOST_TEST(!r.has_value());
    BOOST_TEST((r.error() == WireError::overflow));
    BOOST_TEST(w.written() == 2u);
    BOOST_TEST((buf[0] == std::byte{0xAA}));
    BOOST_TEST((buf[1] == std::byte{0xBB}));
}
