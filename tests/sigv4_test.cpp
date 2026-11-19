// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirement 8.9: AWS Signature V4 for S3
// GETs, checked against the worked example in AWS's S3 documentation
// ("Signature Calculations for the Authorization Header", GET object with
// a Range header), plus the date format and path encoding.

#define BOOST_TEST_MODULE sigv4_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <ostream>
#include <string>

#include "oar/blk/sigv4.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, SigV4Error e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;

BOOST_AUTO_TEST_CASE(aws_documented_get_object_example,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const blk::SigV4Credentials creds{.access_key = "AKIAIOSFODNN7EXAMPLE",
                                      .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      .session_token = ""};
    const auto auth = blk::sigv4_authorization(
        {.method = "GET",
         .canonical_uri = "/test.txt",
         .headers = {{"x-amz-date", "20130524T000000Z"},
                     {"range", "bytes=0-9"},
                     {"host", "examplebucket.s3.amazonaws.com"},
                     {"x-amz-content-sha256", std::string{blk::empty_payload_sha256}}},
         .payload_hash = blk::empty_payload_sha256,
         .amz_date = "20130524T000000Z",
         .region = "us-east-1"},
        creds);
    BOOST_REQUIRE(auth.has_value());
    BOOST_TEST(*auth ==
               "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/"
               "aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
               "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
}

BOOST_AUTO_TEST_CASE(refuses_incomplete_requests,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const blk::SigV4Credentials creds{.access_key = "a", .secret_key = "b", .session_token = ""};
    blk::SigV4Request r{.method = "GET",
                        .canonical_uri = "/x",
                        .headers = {{"host", "h"}, {"x-amz-content-sha256", "e"}},
                        .payload_hash = blk::empty_payload_sha256,
                        .amz_date = "20130524T000000Z",
                        .region = "us-east-1"};
    BOOST_TEST(blk::sigv4_authorization(r, creds).error() == blk::SigV4Error::bad_request);
    r.headers.emplace_back("x-amz-date", "20130524T000000Z");
    BOOST_TEST(blk::sigv4_authorization(r, creds).has_value());
    r.headers.emplace_back("Range", "bytes=0-1");  // names must be lowercase
    BOOST_TEST(blk::sigv4_authorization(r, creds).error() == blk::SigV4Error::bad_request);
    r.headers.pop_back();
    r.amz_date = "20130524";
    BOOST_TEST(blk::sigv4_authorization(r, creds).error() == blk::SigV4Error::bad_request);
    r.amz_date = "20130524T000000Z";
    BOOST_TEST(
        blk::sigv4_authorization(r, {.access_key = "", .secret_key = "b", .session_token = ""})
            .error() == blk::SigV4Error::bad_request);
}

BOOST_AUTO_TEST_CASE(dates_hashes_and_paths, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using namespace std::chrono;
    const auto t = sys_days{year{2013} / May / 24} + hours{1} + minutes{2} + seconds{3};
    BOOST_TEST(blk::amz_date(t) == "20130524T010203Z");
    BOOST_TEST(*blk::sha256_hex("") == std::string{blk::empty_payload_sha256});
    BOOST_TEST(blk::s3_uri_encode_path("/bucket/images/ab12/data") == "/bucket/images/ab12/data");
    BOOST_TEST(blk::s3_uri_encode_path("/b/a b+c%d~e_f.g-h") == "/b/a%20b%2Bc%25d~e_f.g-h");
    BOOST_TEST(blk::s3_uri_encode_path("/\xC3\xA9") == "/%C3%A9");
}
