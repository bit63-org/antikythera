// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 4.1: the signed host image
// descriptor. Layout, rules both ways, strict decoding and object keys.

#define BOOST_TEST_MODULE proto_host_image_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ed25519_test_support.hpp"
#include "proto/host_image.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::from_hex;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

auto sample() -> proto::HostImage {
    proto::HostImage h{.key_id = 2,
                       .image_version = 7,
                       .size = 4096,
                       .kind = proto::HostImageKind::hull,
                       .digest = {},
                       .signature = {}};
    h.digest.fill(std::byte{0xAB});
    h.signature.fill(std::byte{0x11});
    return h;
}

auto encoded(const proto::HostImage& h) -> std::vector<std::byte> {
    auto b = proto::encode_host_image(h);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto error(std::span<const std::byte> b) -> DecodeError {
    auto h = proto::decode_host_image(b);
    BOOST_REQUIRE(!h.has_value());
    return h.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(host_image, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_and_is_pinned) {
    const auto b = encoded(sample());
    BOOST_TEST(b.size() == proto::host_image_size);
    BOOST_TEST(std::ranges::equal(std::span{b}.first(0x20), from_hex("414b484901000200"
                                                                     "0700000000000000"
                                                                     "0010000000000000"
                                                                     "0100000000000000")));
    auto d = proto::decode_host_image(b);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((*d == sample()));
    BOOST_TEST(proto::host_image_signed_bytes(b).size() == 0x40U);
}

BOOST_AUTO_TEST_CASE(encode_refuses_what_decode_refuses) {
    auto h = sample();
    h.key_id = 0;
    BOOST_TEST((proto::encode_host_image(h).error() == DecodeError::bad_key_id));
    h = sample();
    h.image_version = 0;
    BOOST_TEST((proto::encode_host_image(h).error() == DecodeError::bad_generation));
    h = sample();
    h.size = 0;
    BOOST_TEST((proto::encode_host_image(h).error() == DecodeError::bad_payload_size));
    h.size = proto::max_host_image_size + 1;
    BOOST_TEST((proto::encode_host_image(h).error() == DecodeError::bad_payload_size));
    h = sample();
    h.kind = static_cast<proto::HostImageKind>(5);
    BOOST_TEST((proto::encode_host_image(h).error() == DecodeError::unknown_value));
    h = sample();
    h.digest = {};
    BOOST_TEST((proto::encode_host_image(h).error() == DecodeError::bad_id));
}

BOOST_AUTO_TEST_CASE(decode_is_strict) {
    const auto good = encoded(sample());
    auto b = good;
    b[1] ^= std::byte{1};
    BOOST_TEST((error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((error(b) == DecodeError::bad_version));
    b = good;
    b[0x1F] = std::byte{1};
    BOOST_TEST((error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[0x18] = std::byte{0};
    BOOST_TEST((error(b) == DecodeError::unknown_value));
    BOOST_TEST((error(std::span{good}.first(0x7F)) == DecodeError::truncated));
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((error(b) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(object_keys_name_the_digest) {
    proto::ImageDigest d{};
    d[0] = std::byte{0x0F};
    d[31] = std::byte{0xA0};
    const std::string hex = "0f" + std::string(60, '0') + "a0";
    BOOST_TEST(proto::digest_hex(d) == hex);
    BOOST_TEST(proto::host_image_descriptor_key(d) == "v1/images/" + hex + "/descriptor");
    BOOST_TEST(proto::host_image_data_key(d) == "v1/images/" + hex + "/data");
}

BOOST_AUTO_TEST_SUITE_END()
