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

#include "objstore/image_manifest.hpp"
#include "objstore/object_store.hpp"
#include "test_support.hpp"

namespace ak::objstore {
auto operator<<(std::ostream& os, ManifestError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::objstore

namespace objstore = ak::objstore;
using ak::test::unit_timeout_seconds;
using objstore::ImageManifest;
using objstore::ManifestError;

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

auto sample_manifest(const std::vector<std::byte>& data) -> objstore::ImageManifest {
    objstore::ImageManifest m;
    m.chunk_shift = objstore::min_chunk_shift;
    m.image_bytes = data.size();
    const std::span all{data};
    m.chunks.push_back(*objstore::sha256_digest(all.first(kib64)));
    m.chunks.push_back(objstore::ImageDigest{});  // hole
    m.chunks.push_back(*objstore::sha256_digest(all.subspan(2 * kib64)));
    return m;
}

constexpr std::uint64_t lineage = 0x0123'4567'89AB'CDEF;

// sample_manifest as a snapshot: chunked, encrypted, in `lineage`, with a
// parent.
auto sample_snapshot(const std::vector<std::byte>& data) -> objstore::ImageManifest {
    auto m = sample_manifest(data);
    m.encrypted = true;
    m.key_id.fill(std::byte{0x11});
    m.chunked = true;
    m.lineage_id = lineage;
    m.parent.fill(std::byte{0x22});
    return m;
}

auto encoded(const objstore::ImageManifest& m) -> std::vector<std::byte> {
    auto e = objstore::encode_manifest(m);
    BOOST_REQUIRE(e.has_value());
    return *e;
}

auto decode_error(const std::vector<std::byte>& bytes) -> objstore::ManifestError {
    const auto d = objstore::decode_manifest(bytes);
    BOOST_REQUIRE(!d.has_value());
    return d.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(round_trip_and_geometry, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto m = sample_manifest(data);
    const auto bytes = encoded(m);
    BOOST_TEST(bytes.size() == objstore::manifest_header_size + (3 * objstore::image_digest_size));
    const auto d = objstore::decode_manifest(bytes);
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
    const auto name = objstore::sha256_digest(bytes);
    BOOST_REQUIRE(name.has_value());
    BOOST_TEST(objstore::decode_named_manifest(bytes, *name).has_value());
    // One flipped bit in a chunk digest is still a valid manifest, but not
    // this image.
    bytes.back() ^= std::byte{1};
    BOOST_TEST(objstore::decode_manifest(bytes).has_value());
    const auto d = objstore::decode_named_manifest(bytes, *name);
    BOOST_REQUIRE(!d.has_value());
    BOOST_TEST(d.error() == objstore::ManifestError::name_mismatch);
}

BOOST_AUTO_TEST_CASE(chunks_match_their_digests, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto m = sample_manifest(data);
    const std::span all{data};
    BOOST_TEST(objstore::chunk_matches(m, 0, all.first(kib64)));
    BOOST_TEST(objstore::chunk_matches(m, 2, all.subspan(2 * kib64)));
    // Holes are never fetched, so nothing matches them.
    BOOST_TEST(!objstore::chunk_matches(m, 1, all.subspan(kib64, kib64)));
    // Wrong chunk, wrong length, damaged data, out of range.
    BOOST_TEST(!objstore::chunk_matches(m, 2, all.subspan(1, 4096)));
    BOOST_TEST(!objstore::chunk_matches(m, 0, all.first(kib64 - 1)));
    auto damaged = std::vector<std::byte>(all.begin(), all.begin() + kib64);
    damaged[100] ^= std::byte{0x80};
    BOOST_TEST(!objstore::chunk_matches(m, 0, damaged));
    BOOST_TEST(!objstore::chunk_matches(m, 3, all.first(kib64)));
}

BOOST_AUTO_TEST_CASE(encrypted_images_need_a_key_id,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    auto m = sample_manifest(data);
    m.encrypted = true;
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_key_id);
    m.key_id[15] = std::byte{9};
    const auto bytes = encoded(m);
    BOOST_TEST(std::to_integer<int>(bytes[10]) == 1);  // flags
    const auto d = objstore::decode_manifest(bytes);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->encrypted);
    BOOST_TEST(std::to_integer<int>(d->key_id[15]) == 9);
    m.encrypted = false;
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_key_id);
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
    BOOST_TEST(decode_error({}) == objstore::ManifestError::truncated);
    BOOST_TEST(decode_error(std::vector<std::byte>(good.begin(), good.begin() + 40)) ==
               objstore::ManifestError::truncated);
    BOOST_TEST(decode_error(std::vector<std::byte>(good.begin(), good.end() - 1)) ==
               objstore::ManifestError::truncated);
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST(decode_error(longer) == objstore::ManifestError::wrong_size);
    BOOST_TEST(decode_error(with(0, 'X')) == objstore::ManifestError::bad_magic);
    BOOST_TEST(decode_error(with(8, 3)) == objstore::ManifestError::unsupported_version);
    BOOST_TEST(decode_error(with(8, 0)) == objstore::ManifestError::unsupported_version);
    // Version 2 without the chunked flag, the flag on version 1.
    BOOST_TEST(decode_error(with(8, 2)) == objstore::ManifestError::bad_lineage);
    BOOST_TEST(decode_error(with(10, 2)) == objstore::ManifestError::bad_lineage);
    BOOST_TEST(decode_error(with(10, 4)) == objstore::ManifestError::bad_flags);
    BOOST_TEST(decode_error(with(13, 4)) == objstore::ManifestError::bad_block_size);  // 1024
    BOOST_TEST(decode_error(with(16, 15)) == objstore::ManifestError::bad_chunk_shift);
    BOOST_TEST(decode_error(with(16, 23)) == objstore::ManifestError::bad_chunk_shift);
    BOOST_TEST(decode_error(with(17, 1)) == objstore::ManifestError::nonzero_reserved);
    BOOST_TEST(decode_error(with(36, 1)) == objstore::ManifestError::nonzero_reserved);
    BOOST_TEST(decode_error(with(24, 1)) ==
               objstore::ManifestError::bad_image_size);  // not whole blocks
    // A count that disagrees with the image size (and the table length).
    BOOST_TEST(decode_error(with(32, 0)) == objstore::ManifestError::bad_chunk_count);
    // Chunk shift 17 makes the same image two chunks, not three.
    auto shift17 = with(16, 17);
    BOOST_TEST(decode_error(shift17) == objstore::ManifestError::bad_chunk_count);
    BOOST_TEST(decode_error(with(40, 1)) == objstore::ManifestError::bad_key_id);
    // A huge count is refused before any allocation.
    auto huge = good;
    huge[32] = std::byte{0xFF};
    huge[33] = std::byte{0xFF};
    huge[34] = std::byte{0xFF};
    huge[35] = std::byte{0xFF};
    BOOST_TEST(decode_error(huge) == objstore::ManifestError::bad_chunk_count);
}

BOOST_AUTO_TEST_CASE(version_2_round_trip_and_layout,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto m = sample_snapshot(data);
    BOOST_TEST(m.version() == 2U);
    BOOST_TEST(m.has_parent());
    const auto bytes = encoded(m);
    BOOST_REQUIRE(bytes.size() ==
                  objstore::manifest_header_size_chunked + (3 * objstore::image_digest_size));
    BOOST_TEST(std::to_integer<int>(bytes[8]) == 2);      // version
    BOOST_TEST(std::to_integer<int>(bytes[10]) == 0x03);  // encrypted | chunked
    BOOST_TEST(std::to_integer<int>(bytes[56]) == 0xEF);  // lineage, little-endian
    BOOST_TEST(std::to_integer<int>(bytes[63]) == 0x01);
    BOOST_TEST(std::to_integer<int>(bytes[64]) == 0x22);  // parent
    BOOST_TEST(std::to_integer<int>(bytes[95]) == 0x22);
    // The digest table starts after the longer header, and is unchanged.
    BOOST_TEST(std::equal(m.chunks[0].begin(), m.chunks[0].end(), bytes.begin() + 96));
    const auto d = objstore::decode_manifest(bytes);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((*d == m));
    // The name still pins it, and chunks still match their digests.
    const auto name = objstore::sha256_digest(bytes);
    BOOST_REQUIRE(name.has_value());
    BOOST_TEST(objstore::decode_named_manifest(bytes, *name).has_value());
    BOOST_TEST(objstore::chunk_matches(*d, 0, std::span{data}.first(kib64)));
    BOOST_TEST(d->is_hole(1));

    // A first snapshot has no parent.
    auto first = m;
    first.parent = {};
    const auto f = objstore::decode_manifest(encoded(first));
    BOOST_REQUIRE(f.has_value());
    BOOST_TEST(!f->has_parent());
}

BOOST_AUTO_TEST_CASE(version_2_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    const auto good = encoded(sample_snapshot(data));
    auto with = [&](std::size_t at, std::uint8_t v) {
        auto b = good;
        b[at] = static_cast<std::byte>(v);
        return b;
    };
    // Cut inside the lineage/parent fields, or the table.
    BOOST_TEST(decode_error(std::vector<std::byte>(good.begin(), good.begin() + 60)) ==
               objstore::ManifestError::truncated);
    BOOST_TEST(decode_error(std::vector<std::byte>(good.begin(), good.begin() + 96)) ==
               objstore::ManifestError::truncated);
    BOOST_TEST(decode_error(with(10, 0x02)) ==
               objstore::ManifestError::bad_key_id);  // plain, but a key ID
    BOOST_TEST(decode_error(with(10, 0x01)) == objstore::ManifestError::bad_lineage);  // no flag
    auto no_lineage = good;
    std::fill_n(no_lineage.begin() + 56, 8, std::byte{0});
    BOOST_TEST(decode_error(no_lineage) == objstore::ManifestError::bad_lineage);

    // encode holds the same rules.
    auto m = sample_snapshot(data);
    m.lineage_id = 0;
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_lineage);
    m = sample_snapshot(data);
    m.encrypted = false;
    m.key_id = {};
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_lineage);
    // Lineage and parent belong to version 2 only.
    m = sample_manifest(data);
    m.lineage_id = lineage;
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_lineage);
    m = sample_manifest(data);
    m.parent.fill(std::byte{1});
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_lineage);
}

BOOST_AUTO_TEST_CASE(snapshot_object_keys, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto chunks = objstore::lineage_chunks_prefix("vols", lineage);
    BOOST_TEST(chunks == "vols/lineage-0123456789abcdef/chunks");
    BOOST_TEST(objstore::lineage_chunks_prefix("", 1) == "lineage-0000000000000001/chunks");
    BOOST_TEST(objstore::chunk_key(chunks, "ab") == "vols/lineage-0123456789abcdef/chunks/ab");
    BOOST_TEST(objstore::snapshot_manifest_key("vols/", lineage, "cd") ==
               "vols/lineage-0123456789abcdef/snap-cd/manifest");
}

BOOST_AUTO_TEST_CASE(encode_checks_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = sample_data();
    auto m = sample_manifest(data);
    m.image_bytes = 0;
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_image_size);
    m = sample_manifest(data);
    m.chunks.pop_back();
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_chunk_count);
    m = sample_manifest(data);
    m.logical_block_size = 4096;  // 0x21000 is whole 4 KiB blocks
    BOOST_TEST(objstore::encode_manifest(m).has_value());
    m.image_bytes -= 512;
    BOOST_TEST(objstore::encode_manifest(m).error() == objstore::ManifestError::bad_image_size);
}

BOOST_AUTO_TEST_CASE(image_names_in_hex, *boost::unit_test::timeout(unit_timeout_seconds)) {
    objstore::ImageDigest d{};
    for (std::size_t i = 0; i < d.size(); ++i) {
        d[i] = static_cast<std::byte>(i * 9);
    }
    const auto hex = objstore::image_name_hex(d);
    BOOST_TEST(hex.size() == 64U);
    BOOST_TEST(hex.substr(0, 8) == "0009121b");
    const auto back = objstore::parse_image_name(hex);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == d));
    BOOST_TEST(!objstore::parse_image_name(hex.substr(1)).has_value());
    auto upper = hex;
    upper[2] = 'A';
    BOOST_TEST(!objstore::parse_image_name(upper).has_value());
    auto junk = hex;
    junk[5] = 'g';
    BOOST_TEST(!objstore::parse_image_name(junk).has_value());
}
