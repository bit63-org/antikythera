// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 2.1: the controller's boot_image
// assignment. Layout, the embedded descriptor, rules both ways and strict
// decoding.

#define BOOST_TEST_MODULE proto_boot_image_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ed25519_test_support.hpp"
#include "proto/boot_image.hpp"
#include "proto/link.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::from_hex;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

auto sample() -> proto::BootImage {
    proto::BootImage b{
        .key_id = 3, .server_id = 9, .assignment_version = 4, .image = {}, .signature = {}};
    b.image = proto::HostImage{.key_id = 2,
                               .image_version = 7,
                               .size = 4096,
                               .kind = proto::HostImageKind::hull,
                               .digest = {},
                               .signature = {}};
    b.image.digest.fill(std::byte{0xAB});
    b.image.signature.fill(std::byte{0x11});
    b.signature.fill(std::byte{0x22});
    return b;
}

auto encoded(const proto::BootImage& b) -> std::vector<std::byte> {
    auto f = proto::encode_boot_image(b);
    BOOST_REQUIRE(f.has_value());
    return *f;
}

auto error(std::span<const std::byte> b) -> DecodeError {
    auto f = proto::decode_boot_image(b);
    BOOST_REQUIRE(!f.has_value());
    return f.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(boot_image, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_and_is_pinned) {
    const auto b = encoded(sample());
    BOOST_TEST(b.size() == proto::boot_image_size);
    BOOST_TEST(b.size() == 0xE0U);
    BOOST_TEST(std::ranges::equal(std::span{b}.first(0x20), from_hex("414b424901000300"
                                                                     "0900000000000000"
                                                                     "0400000000000000"
                                                                     "0000000000000000")));
    // The descriptor sits whole at 0x20, exactly as encode_host_image
    // writes it, so the image key's signature checks over those bytes.
    const auto descriptor = proto::encode_host_image(sample().image);
    BOOST_REQUIRE(descriptor.has_value());
    BOOST_TEST(std::ranges::equal(proto::boot_image_descriptor(b), *descriptor));
    auto d = proto::decode_boot_image(b);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((*d == sample()));
    BOOST_TEST(proto::boot_image_signed_bytes(b).size() == 0xA0U);
    BOOST_TEST(proto::boot_image_descriptor(std::span{b}.first(0x9F)).empty());
}

BOOST_AUTO_TEST_CASE(encode_refuses_what_decode_refuses) {
    auto b = sample();
    b.key_id = 0;
    BOOST_TEST((proto::encode_boot_image(b).error() == DecodeError::bad_key_id));
    b = sample();
    b.server_id = 0;
    BOOST_TEST((proto::encode_boot_image(b).error() == DecodeError::bad_server_id));
    b = sample();
    b.assignment_version = 0;
    BOOST_TEST((proto::encode_boot_image(b).error() == DecodeError::bad_id));
    b = sample();
    b.image.kind = proto::HostImageKind::discovery;  // not something helm boots
    BOOST_TEST((proto::encode_boot_image(b).error() == DecodeError::unknown_value));
    b = sample();
    b.image.digest = {};
    BOOST_TEST((proto::encode_boot_image(b).error() == DecodeError::bad_id));
}

BOOST_AUTO_TEST_CASE(decode_is_strict) {
    const auto good = encoded(sample());
    auto b = good;
    b[3] ^= std::byte{1};
    BOOST_TEST((error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((error(b) == DecodeError::bad_version));
    b = good;
    b[0x1F] = std::byte{1};
    BOOST_TEST((error(b) == DecodeError::reserved_not_zero));
    // A bad embedded descriptor fails as the descriptor does.
    b = good;
    b[0x20] ^= std::byte{1};
    BOOST_TEST((error(b) == DecodeError::bad_magic));
    b = good;
    b[0x20 + 0x18] = std::byte{2};  // kythira_host
    BOOST_TEST((error(b) == DecodeError::unknown_value));
    BOOST_TEST((error(std::span{good}.first(0xDF)) == DecodeError::truncated));
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((error(b) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(travels_as_link_record_25) {
    const auto b = encoded(sample());
    BOOST_TEST(static_cast<int>(proto::RecordType::boot_image) == 25);
    auto rec = proto::encode_record(proto::RecordType::boot_image, b);
    BOOST_REQUIRE(rec.has_value());
    BOOST_TEST(proto::max_record_payload >= proto::boot_image_size);
}

BOOST_AUTO_TEST_SUITE_END()
