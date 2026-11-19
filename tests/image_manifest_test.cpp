// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 8.3 and 8.11: the image
// manifest. It round-trips, pins itself to the image name and every chunk
// to its digest, and refuses every malformed field before trusting it.

#define BOOST_TEST_MODULE image_manifest_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include "oar/blk/image_manifest.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, ManifestError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;
using blk::ImageManifest;
using blk::ManifestError;

namespace {

constexpr std::uint64_t kib64 = 64ULL * 1024;

// A three-chunk image at 64 KiB chunks: two full chunks, a short last one,
// the middle one a hole.
auto sample_data() -> std::vector<std::byte> {
    std::vector<std::byte> data((2 * kib64) + 4096);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 7) + 3);
    }
    std::fill_n(data.begin() + static_cast<std::ptrdiff_t>(kib64), kib64, std::byte{0});
    return data;
}

auto sample_manifest(const std::vector<std::byte>& data) -> ImageManifest {
    ImageManifest m;
    m.chunk_shift = blk::min_chunk_shift;
    m.image_bytes = data.size();
    const std::span all{data};
    m.chunks.push_back(*blk::sha256_digest(all.first(kib64)));
    m.chunks.push_back(blk::ImageDigest{});  // hole
    m.chunks.push_back(*blk::sha256_digest(all.subspan(2 * kib64)));
    return m;
}

auto encoded(const ImageManifest& m) -> std::vector<std::byte> {
    auto e = blk::encode_manifest(m);
    BOOST_REQUIRE(e.has_value());
    return *e;
}

auto decode_error(const std::vector<std::byte>& bytes) -> ManifestError {
    const auto d = blk::decode_manifest(bytes);
    BOOST_REQUIRE(!d.has_value());
    return d.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(round_trip_and_geometry, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto m = sample_manifest(data);
    const auto bytes = encoded(m);
    BOOST_TEST(bytes.size() == blk::manifest_header_size + (3 * blk::image_digest_size));
    const auto d = blk::decode_manifest(bytes);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((*d == m));
    BOOST_TEST(d->chunk_size() == kib64);
    BOOST_TEST(d->chunk_count() == 3U);
    BOOST_TEST(d->chunk_offset(2) == 2 * kib64);
    BOOST_TEST(d->chunk_length(0) == kib64);
    BOOST_TEST(d->chunk_length(2) == 4096U);
    BOOST_TEST(d->chunk_length(3) == 0U);
    BOOST_TEST(!d->is_hole(0));
    BOOST_TEST(d->is_hole(1));
    BOOST_TEST(!d->is_hole(3));
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto bytes = encoded(sample_manifest(data));
    const std::string magic{reinterpret_cast<const char*>(bytes.data()), 7};
    BOOST_TEST(magic == "AKIMAGE");
    BOOST_TEST(std::to_integer<int>(bytes[7]) == 0);
    BOOST_TEST(std::to_integer<int>(bytes[8]) == 1);    // version
    BOOST_TEST(std::to_integer<int>(bytes[13]) == 2);   // 512 = 0x0200
    BOOST_TEST(std::to_integer<int>(bytes[16]) == 16);  // chunk shift
    BOOST_TEST(std::to_integer<int>(bytes[24]) == 0x00);
    BOOST_TEST(std::to_integer<int>(bytes[26]) == 0x02);  // 0x21000 bytes
    BOOST_TEST(std::to_integer<int>(bytes[32]) == 3);     // chunk count
}

BOOST_AUTO_TEST_CASE(name_pins_the_manifest, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    auto bytes = encoded(sample_manifest(data));
    const auto name = blk::sha256_digest(bytes);
    BOOST_REQUIRE(name.has_value());
    BOOST_TEST(blk::decode_named_manifest(bytes, *name).has_value());
    // One flipped bit in a chunk digest is still a valid manifest, but not
    // this image.
    bytes.back() ^= std::byte{1};
    BOOST_TEST(blk::decode_manifest(bytes).has_value());
    const auto d = blk::decode_named_manifest(bytes, *name);
    BOOST_REQUIRE(!d.has_value());
    BOOST_TEST(d.error() == ManifestError::name_mismatch);
}

BOOST_AUTO_TEST_CASE(chunks_match_their_digests, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto m = sample_manifest(data);
    const std::span all{data};
    BOOST_TEST(blk::chunk_matches(m, 0, all.first(kib64)));
    BOOST_TEST(blk::chunk_matches(m, 2, all.subspan(2 * kib64)));
    // Holes are never fetched, so nothing matches them.
    BOOST_TEST(!blk::chunk_matches(m, 1, all.subspan(kib64, kib64)));
    // Wrong chunk, wrong length, damaged data, out of range.
    BOOST_TEST(!blk::chunk_matches(m, 2, all.subspan(1, 4096)));
    BOOST_TEST(!blk::chunk_matches(m, 0, all.first(kib64 - 1)));
    auto damaged = std::vector<std::byte>(all.begin(), all.begin() + kib64);
    damaged[100] ^= std::byte{0x80};
    BOOST_TEST(!blk::chunk_matches(m, 0, damaged));
    BOOST_TEST(!blk::chunk_matches(m, 3, all.first(kib64)));
}

BOOST_AUTO_TEST_CASE(encrypted_images_need_a_key_id,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    auto m = sample_manifest(data);
    m.encrypted = true;
    BOOST_TEST(blk::encode_manifest(m).error() == ManifestError::bad_key_id);
    m.key_id[15] = std::byte{9};
    const auto bytes = encoded(m);
    BOOST_TEST(std::to_integer<int>(bytes[10]) == 1);  // flags
    const auto d = blk::decode_manifest(bytes);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->encrypted);
    BOOST_TEST(std::to_integer<int>(d->key_id[15]) == 9);
    m.encrypted = false;
    BOOST_TEST(blk::encode_manifest(m).error() == ManifestError::bad_key_id);
}

BOOST_AUTO_TEST_CASE(refuses_malformed_manifests,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto good = encoded(sample_manifest(data));
    auto with = [&](std::size_t at, std::uint8_t v) {
        auto b = good;
        b[at] = static_cast<std::byte>(v);
        return b;
    };
    BOOST_TEST(decode_error({}) == ManifestError::truncated);
    BOOST_TEST(decode_error(std::vector<std::byte>(good.begin(), good.begin() + 40)) ==
               ManifestError::truncated);
    BOOST_TEST(decode_error(std::vector<std::byte>(good.begin(), good.end() - 1)) ==
               ManifestError::truncated);
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST(decode_error(longer) == ManifestError::wrong_size);
    BOOST_TEST(decode_error(with(0, 'X')) == ManifestError::bad_magic);
    BOOST_TEST(decode_error(with(8, 2)) == ManifestError::unsupported_version);
    BOOST_TEST(decode_error(with(10, 2)) == ManifestError::bad_flags);
    BOOST_TEST(decode_error(with(13, 4)) == ManifestError::bad_block_size);  // 1024
    BOOST_TEST(decode_error(with(16, 15)) == ManifestError::bad_chunk_shift);
    BOOST_TEST(decode_error(with(16, 23)) == ManifestError::bad_chunk_shift);
    BOOST_TEST(decode_error(with(17, 1)) == ManifestError::nonzero_reserved);
    BOOST_TEST(decode_error(with(36, 1)) == ManifestError::nonzero_reserved);
    BOOST_TEST(decode_error(with(24, 1)) == ManifestError::bad_image_size);  // not whole blocks
    // A count that disagrees with the image size (and the table length).
    BOOST_TEST(decode_error(with(32, 0)) == ManifestError::bad_chunk_count);
    // Chunk shift 17 makes the same image two chunks, not three.
    auto shift17 = with(16, 17);
    BOOST_TEST(decode_error(shift17) == ManifestError::bad_chunk_count);
    BOOST_TEST(decode_error(with(40, 1)) == ManifestError::bad_key_id);
    // A huge count is refused before any allocation.
    auto huge = good;
    huge[32] = std::byte{0xFF};
    huge[33] = std::byte{0xFF};
    huge[34] = std::byte{0xFF};
    huge[35] = std::byte{0xFF};
    BOOST_TEST(decode_error(huge) == ManifestError::bad_chunk_count);
}

BOOST_AUTO_TEST_CASE(encode_checks_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    auto m = sample_manifest(data);
    m.image_bytes = 0;
    BOOST_TEST(blk::encode_manifest(m).error() == ManifestError::bad_image_size);
    m = sample_manifest(data);
    m.chunks.pop_back();
    BOOST_TEST(blk::encode_manifest(m).error() == ManifestError::bad_chunk_count);
    m = sample_manifest(data);
    m.logical_block_size = 4096;  // 0x21000 is whole 4 KiB blocks
    BOOST_TEST(blk::encode_manifest(m).has_value());
    m.image_bytes -= 512;
    BOOST_TEST(blk::encode_manifest(m).error() == ManifestError::bad_image_size);
}

BOOST_AUTO_TEST_CASE(image_names_in_hex, *boost::unit_test::timeout(unit_timeout_seconds)) {
    blk::ImageDigest d{};
    for (std::size_t i = 0; i < d.size(); ++i) {
        d[i] = static_cast<std::byte>(i * 9);
    }
    const auto hex = blk::image_name_hex(d);
    BOOST_TEST(hex.size() == 64U);
    BOOST_TEST(hex.substr(0, 8) == "0009121b");
    const auto back = blk::parse_image_name(hex);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == d));
    BOOST_TEST(!blk::parse_image_name(hex.substr(1)).has_value());
    auto upper = hex;
    upper[2] = 'A';
    BOOST_TEST(!blk::parse_image_name(upper).has_value());
    auto junk = hex;
    junk[5] = 'g';
    BOOST_TEST(!blk::parse_image_name(junk).has_value());
}
