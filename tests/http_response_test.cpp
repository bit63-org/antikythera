// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 8.9 and 8.11: the strict
// HTTP/1.1 response head parser S3ObjectStore uses on untrusted responses.

#define BOOST_TEST_MODULE http_response_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <ostream>
#include <span>
#include <string>
#include <string_view>

#include "objstore/http_response.hpp"
#include "test_support.hpp"

namespace ak::objstore {
auto operator<<(std::ostream& os, HttpError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::objstore

namespace objstore = ak::objstore;
using ak::test::unit_timeout_seconds;
using objstore::HttpError;

namespace {
auto parse(std::string_view s) {
    return objstore::parse_response_head(std::as_bytes(std::span{s.data(), s.size()}));
}
auto error_of(std::string_view s) -> objstore::HttpError {
    const auto r = parse(s);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}
}  // namespace

BOOST_AUTO_TEST_CASE(partial_content, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::string head =
        "HTTP/1.1 206 Partial Content\r\n"
        "Content-Range: bytes 100-199/1000\r\n"
        "content-length:   100 \r\n"
        "ETag: \"abc\"\r\n"
        "\r\n";
    const auto r = parse(head + "BODY...");
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(r->status == 206U);
    BOOST_TEST(*r->content_length == 100U);
    BOOST_TEST(
        (*r->content_range == objstore::ContentRange{.first = 100, .last = 199, .total = 1000}));
    BOOST_TEST(!r->close);
    BOOST_TEST(r->head_bytes == head.size());
}

BOOST_AUTO_TEST_CASE(status_and_connection, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto r = parse("HTTP/1.1 404\r\nConnection: Close\r\n\r\n");
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(r->status == 404U);
    BOOST_TEST(r->close);
    BOOST_TEST(!r->content_length.has_value());
    r = parse("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(r->close);  // HTTP/1.0 closes
    BOOST_TEST(error_of("HTTP/2 200 OK\r\n\r\n") == objstore::HttpError::bad_status_line);
    BOOST_TEST(error_of("HTTP/1.1 20 OK\r\n\r\n") == objstore::HttpError::bad_status_line);
    BOOST_TEST(error_of("HTTP/1.1 2000 OK\r\n\r\n") == objstore::HttpError::bad_status_line);
    BOOST_TEST(error_of("HTTP/1.1 099 x\r\n\r\n") == objstore::HttpError::bad_status_line);
    BOOST_TEST(error_of("HTTP/1.1 2x0 OK\r\n\r\n") == objstore::HttpError::bad_status_line);
}

BOOST_AUTO_TEST_CASE(incomplete_and_oversized, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(error_of("") == objstore::HttpError::incomplete);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n") ==
               objstore::HttpError::incomplete);
    std::string big = "HTTP/1.1 200 OK\r\nX: ";
    big.append(objstore::max_response_head, 'a');
    BOOST_TEST(error_of(big) == objstore::HttpError::too_large);
}

BOOST_AUTO_TEST_CASE(refuses_malformed_headers, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nNoColon\r\n\r\n") == objstore::HttpError::bad_header);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\n: v\r\n\r\n") == objstore::HttpError::bad_header);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n") ==
               objstore::HttpError::bad_header);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nA: b\r\n folded\r\n\r\n") ==
               objstore::HttpError::bad_header);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nA: b\nC: d\r\n\r\n") ==
               objstore::HttpError::bad_header);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nA: b\rC: d\r\n\r\n") ==
               objstore::HttpError::bad_header);
}

BOOST_AUTO_TEST_CASE(content_length_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n") ==
               objstore::HttpError::bad_content_length);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nContent-Length: 1e3\r\n\r\n") ==
               objstore::HttpError::bad_content_length);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n") ==
               objstore::HttpError::bad_content_length);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n") ==
               objstore::HttpError::bad_content_length);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n") ==
               objstore::HttpError::bad_content_length);
    const auto same = parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
    BOOST_REQUIRE(same.has_value());
    BOOST_TEST(*same->content_length == 5U);
    BOOST_TEST(error_of("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") ==
               objstore::HttpError::transfer_encoding);
}

BOOST_AUTO_TEST_CASE(content_range_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto star = objstore::parse_content_range("bytes 0-0/*");
    BOOST_REQUIRE(star.has_value());
    BOOST_TEST(!star->total.has_value());
    for (const char* bad : {"bytes 5-4/10", "bytes 0-10/10", "bits 0-1/2", "bytes 0-1",
                            "bytes -1/2", "bytes 0-1/x", "bytes a-1/2", "bytes 1/2-3"}) {
        BOOST_TEST_CONTEXT(bad) {
            BOOST_TEST(objstore::parse_content_range(bad).error() ==
                       objstore::HttpError::bad_content_range);
        }
    }
    BOOST_TEST(error_of("HTTP/1.1 206 x\r\nContent-Range: bytes 0-1/2\r\n"
                        "Content-Range: bytes 0-1/2\r\n\r\n") ==
               objstore::HttpError::bad_content_range);
}
