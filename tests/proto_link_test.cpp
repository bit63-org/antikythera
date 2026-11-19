// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 2, design "ControllerLink":
// record framing on the controller <-> helm stream and the report ack.

#define BOOST_TEST_MODULE proto_link_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <optional>
#include <span>
#include <vector>

#include "proto/link.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using proto::RecordType;

namespace {

auto framed(RecordType t, const std::vector<std::byte>& payload) -> std::vector<std::byte> {
    auto b = proto::encode_record(t, payload);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto drain(proto::RecordDecoder& d) -> std::vector<proto::Record> {
    std::vector<proto::Record> out;
    for (;;) {
        auto r = d.next();
        BOOST_REQUIRE(r.has_value());
        if (!r->has_value()) {
            return out;
        }
        out.push_back(std::move(**r));
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(records, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(record_header_layout) {
    const auto b = framed(RecordType::report, bytes_of(0xAA, 0xBB, 0xCC));
    BOOST_TEST((b == bytes_of(3, 0, 0, 0, 3, 0, 0, 0, 0xAA, 0xBB, 0xCC)));
    static_assert(proto::max_record_payload == proto::max_map_update_size);
    static_assert(proto::max_record_payload >= proto::max_report_size);
}

BOOST_AUTO_TEST_CASE(records_split_at_every_byte_reassemble) {
    std::vector<std::byte> stream;
    const std::vector<proto::Record> want{
        {.type = RecordType::envelope, .payload = bytes_of(1, 2, 3, 4)},
        {.type = RecordType::report_ack, .payload = {}},
        {.type = RecordType::map_update, .payload = std::vector<std::byte>(300, std::byte{7})},
    };
    for (const auto& r : want) {
        const auto b = framed(r.type, r.payload);
        stream.insert(stream.end(), b.begin(), b.end());
    }
    for (std::size_t chunk = 1; chunk <= stream.size(); ++chunk) {
        proto::RecordDecoder d;
        std::vector<proto::Record> got;
        for (std::size_t i = 0; i < stream.size(); i += chunk) {
            d.feed(std::span{stream}.subspan(i, std::min(chunk, stream.size() - i)));
            auto more = drain(d);
            got.insert(got.end(), more.begin(), more.end());
        }
        BOOST_TEST((got == want), "chunk " << chunk);
        BOOST_TEST(d.buffered() == 0U);
    }
}

BOOST_AUTO_TEST_CASE(oversized_record_fails_before_its_payload_arrives) {
    proto::RecordDecoder d;
    const auto too_big = static_cast<std::uint32_t>(proto::max_record_payload + 1);
    d.feed(bytes_of(too_big & 0xFF, (too_big >> 8) & 0xFF, (too_big >> 16) & 0xFF,
                    (too_big >> 24) & 0xFF, 1, 0, 0, 0));
    auto r = d.next();
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error() == DecodeError::record_too_large));
    // Sticky: the stream is out of sync.
    d.feed(framed(RecordType::envelope, bytes_of(1)));
    auto again = d.next();
    BOOST_REQUIRE(!again.has_value());
    BOOST_TEST((again.error() == DecodeError::record_too_large));
    BOOST_TEST(d.buffered() == 0U);
}

BOOST_AUTO_TEST_CASE(bad_type_and_reserved_break_the_stream) {
    for (const auto& [bytes, want] :
         {std::pair{bytes_of(0, 0, 0, 0, 0, 0, 0, 0), DecodeError::bad_record_type},
          std::pair{bytes_of(0, 0, 0, 0, 7, 0, 0, 0), DecodeError::bad_record_type},
          std::pair{bytes_of(0, 0, 0, 0, 1, 0, 0, 1), DecodeError::reserved_not_zero}}) {
        proto::RecordDecoder d;
        d.feed(bytes);
        auto r = d.next();
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == want));
    }
}

BOOST_AUTO_TEST_CASE(encode_refuses_what_decode_would) {
    auto bad_type = proto::encode_record(static_cast<RecordType>(9), {});
    BOOST_REQUIRE(!bad_type.has_value());
    BOOST_TEST((bad_type.error() == DecodeError::bad_record_type));
    const std::vector<std::byte> huge(proto::max_record_payload + 1);
    auto too_big = proto::encode_record(RecordType::report, huge);
    BOOST_REQUIRE(!too_big.has_value());
    BOOST_TEST((too_big.error() == DecodeError::record_too_large));
    const std::vector<std::byte> max(proto::max_record_payload);
    BOOST_TEST(proto::encode_record(RecordType::report, max).has_value());
}

BOOST_AUTO_TEST_CASE(report_ack_round_trips_and_is_strict) {
    const proto::ReportAck ack{.server_id = 0x0102'0304'0506'0708, .report_seq = 9};
    auto b = proto::encode_report_ack(ack);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::report_ack_size);
    auto back = proto::decode_report_ack(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == ack));

    for (std::size_t n = 0; n < b->size(); ++n) {
        auto r = proto::decode_report_ack(std::span{*b}.first(n));
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_report_ack(longer).error() == DecodeError::trailing_bytes));
    BOOST_TEST((proto::decode_report_ack(std::vector<std::byte>(16)).error() ==
                DecodeError::bad_server_id));
    BOOST_TEST((proto::encode_report_ack({.server_id = 1, .report_seq = 0}).error() ==
                DecodeError::bad_report_seq));
    BOOST_TEST((proto::encode_report_ack({.server_id = 0, .report_seq = 1}).error() ==
                DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_CASE(hello_round_trips_and_is_strict) {
    const proto::Hello hello{.server_id = 0x0102'0304'0506'0708, .boot_id = 0xB007};
    auto b = proto::encode_hello(hello);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::hello_size);
    auto back = proto::decode_hello(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == hello));
    for (std::size_t n = 0; n < b->size(); ++n) {
        BOOST_TEST((proto::decode_hello(std::span{*b}.first(n)).error() == DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_hello(longer).error() == DecodeError::trailing_bytes));
    auto zero_boot = *b;
    std::ranges::fill(std::span{zero_boot}.subspan(8), std::byte{0});
    BOOST_TEST((proto::decode_hello(zero_boot).error() == DecodeError::bad_boot_id));
    BOOST_TEST(
        (proto::decode_hello(std::vector<std::byte>(16)).error() == DecodeError::bad_server_id));
    BOOST_TEST(
        (proto::encode_hello({.server_id = 1, .boot_id = 0}).error() == DecodeError::bad_boot_id));
    BOOST_TEST((proto::encode_hello({.server_id = 0, .boot_id = 1}).error() ==
                DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_SUITE_END()
