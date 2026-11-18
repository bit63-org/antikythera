// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 2.1 and 7.1, design
// "XtsCipher": IEEE 1619 XTS-AES-256 vectors, 4 KiB data units, multi-unit
// buffers, in-place operation and argument checks.
//
// Vectors. IEEE 1619-2007 Annex B vectors 10 to 14 share one 512-bit key
// and one plaintext (bytes 00..ff twice) and differ only in the data unit
// number. Vector 10's ciphertext is checked byte for byte, as published
// (and as the Linux kernel's crypto/testmgr.h carries it). For vectors 11
// to 14 the test checks the published first ciphertext block and the
// SHA-256 of the whole ciphertext; those digests, and the 4 KiB ones, come
// from a separate pure-Python XTS over pycryptodome's AES (no OpenSSL),
// which reproduces vector 10 exactly.

#define BOOST_TEST_MODULE xts_cipher_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"

// Lets BOOST_TEST print an XtsError when a comparison fails.
namespace ak::oar::blk {
auto operator<<(std::ostream& os, XtsError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;
using blk::XtsCipher;
using blk::XtsError;

namespace {

constexpr unsigned hex_digit_bits = 4;
constexpr int hex_letter_base = 10;

auto hex_nibble(char c) -> unsigned {
    if (c >= '0' && c <= '9') {
        return static_cast<unsigned>(c - '0');
    }
    BOOST_REQUIRE(c >= 'a' && c <= 'f');
    return static_cast<unsigned>(c - 'a' + hex_letter_base);
}

auto from_hex(std::string_view hex) -> std::vector<std::byte> {
    BOOST_REQUIRE(hex.size() % 2 == 0);
    std::vector<std::byte> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::byte>((hex_nibble(hex[2 * i]) << hex_digit_bits) |
                                        hex_nibble(hex[(2 * i) + 1]));
    }
    return out;
}

constexpr std::string_view ieee_key =
    "2718281828459045235360287471352662497757247093699959574966967627"
    "3141592653589793238462643383279502884197169399375105820974944592";

constexpr std::uint64_t vector10_unit = 0xff;
constexpr std::string_view vector10_ciphertext =
    "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
    "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
    "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
    "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
    "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
    "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
    "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
    "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
    "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
    "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
    "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
    "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
    "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
    "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
    "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
    "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";

struct DigestVector {
    std::uint64_t unit;
    std::string_view first_block;  // as published in IEEE 1619 Annex B
    std::string_view sha256;       // of the whole 512-byte ciphertext
};

constexpr std::array ieee_vectors_11_to_14{
    DigestVector{0xffff, "77a31251618a15e6b92d1d66dffe7b50",
                 "def4fad29e95dfe1a24b1ad4620f86d7be094cced5b19e0b121aa82d9e6baf98"},
    DigestVector{0xffffff, "e387aaa58ba483afa7e8eb469778317e",
                 "8bf44861a081dd660d91ce615b5cdfb4d5df9d72c3025c12e67cc0ae097fa5d5"},
    DigestVector{0xffffffff, "bf53d2dade78e822a4d949a9bc6766b0",
                 "c706140a11affda7402234f5e6331eacbfeb687d8e80d83962691823bb3636f0"},
    DigestVector{0xffffffffff, "64497e5a831e4a932c09be3e5393376d",
                 "afba71abc4e95b186d89a63a5437c1bafcfd1a18ca273970c534aba4f8d05282"},
};

// 4 KiB data units, plaintext bytes 00..ff sixteen times.
constexpr std::array vectors_4k{
    DigestVector{0xff, "1c3b3a102f770386e4836c99e370cf9b",
                 "d74aad83ceba041c9697f0cd1a0f94a1efd98cb9740ce630724e964be6b85436"},
    DigestVector{0x0123456789abcdef, "5efb5c1c85b22336959d5b7420126588",
                 "b016783c474eda27faaa95143e9d8dbd7c00856e60bd624e5ede3b6c49d374ca"},
};

constexpr std::size_t aes_block = 16;
constexpr std::size_t byte_values = 256;
constexpr std::uint64_t sample_unit = 41;
constexpr std::size_t sample_units = 3;
constexpr std::size_t half_key = blk::xts_key_size / 2;

auto key_bytes() -> std::vector<std::byte> {
    return from_hex(ieee_key);
}

auto key_span(const std::vector<std::byte>& k) -> blk::XtsKey {
    BOOST_REQUIRE_EQUAL(k.size(), blk::xts_key_size);
    return blk::XtsKey{k.data(), blk::xts_key_size};
}

// Bytes 00..ff repeated to fill `size`.
auto counting(std::size_t size) -> std::vector<std::byte> {
    std::vector<std::byte> v(size);
    for (std::size_t i = 0; i < size; ++i) {
        v[i] = static_cast<std::byte>(i % byte_values);
    }
    return v;
}

auto make_cipher(std::size_t unit) -> XtsCipher {
    const auto k = key_bytes();
    auto c = XtsCipher::create(key_span(k), unit);
    BOOST_REQUIRE(c.has_value());
    return std::move(*c);
}

auto sha256(std::span<const std::byte> data) -> std::vector<std::byte> {
    std::vector<std::byte> md(EVP_MAX_MD_SIZE);
    unsigned len = 0;
    BOOST_REQUIRE_EQUAL(
        EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char*>(md.data()), &len,
                   EVP_sha256(), nullptr),
        1);
    md.resize(len);
    return md;
}

auto equal(std::span<const std::byte> a, std::span<const std::byte> b) -> bool {
    return std::ranges::equal(a, b);
}

auto check_digest_vector(XtsCipher& c, const DigestVector& v, std::size_t size) -> void {
    BOOST_TEST_CONTEXT("data unit " << std::hex << v.unit) {
        const auto pt = counting(size);
        std::vector<std::byte> ct(size);
        BOOST_REQUIRE(c.encrypt(v.unit, pt, ct).has_value());
        BOOST_TEST(equal(std::span{ct}.first(aes_block), from_hex(v.first_block)));
        BOOST_TEST(equal(sha256(ct), from_hex(v.sha256)));
        std::vector<std::byte> back(size);
        BOOST_REQUIRE(c.decrypt(v.unit, ct, back).has_value());
        BOOST_TEST(equal(back, pt));
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(ieee1619_vector_10, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_512);
    const auto pt = counting(blk::data_unit_512);
    const auto expected = from_hex(vector10_ciphertext);
    std::vector<std::byte> ct(blk::data_unit_512);
    BOOST_REQUIRE(c.encrypt(vector10_unit, pt, ct).has_value());
    BOOST_TEST(equal(ct, expected));
    std::vector<std::byte> back(blk::data_unit_512);
    BOOST_REQUIRE(c.decrypt(vector10_unit, expected, back).has_value());
    BOOST_TEST(equal(back, pt));
}

BOOST_AUTO_TEST_CASE(ieee1619_vectors_11_to_14, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_512);
    for (const auto& v : ieee_vectors_11_to_14) {
        check_digest_vector(c, v, blk::data_unit_512);
    }
}

BOOST_AUTO_TEST_CASE(four_kib_data_units, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_4k);
    BOOST_TEST(c.data_unit_size() == blk::data_unit_4k);
    for (const auto& v : vectors_4k) {
        check_digest_vector(c, v, blk::data_unit_4k);
    }
}

// XTS block j of a unit uses tweak * alpha^j whatever the unit's length, so
// the first 512 bytes of a 4 KiB unit equal a 512-byte unit with the same
// number: vector 10 again, through the 4 KiB path.
BOOST_AUTO_TEST_CASE(four_kib_unit_starts_like_vector_10,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_4k);
    const auto pt = counting(blk::data_unit_4k);
    std::vector<std::byte> ct(blk::data_unit_4k);
    BOOST_REQUIRE(c.encrypt(vector10_unit, pt, ct).has_value());
    BOOST_TEST(equal(std::span{ct}.first(blk::data_unit_512), from_hex(vector10_ciphertext)));
}

BOOST_AUTO_TEST_CASE(multi_unit_buffer_numbers_units_consecutively,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::size_t unit : {blk::data_unit_512, blk::data_unit_4k}) {
        BOOST_TEST_CONTEXT("unit size " << unit) {
            auto c = make_cipher(unit);
            const auto pt = counting(unit * sample_units);
            std::vector<std::byte> whole(pt.size());
            BOOST_REQUIRE(c.encrypt(sample_unit, pt, whole).has_value());
            for (std::size_t i = 0; i < sample_units; ++i) {
                std::vector<std::byte> one(unit);
                BOOST_REQUIRE(c.encrypt(sample_unit + i, std::span{pt}.subspan(i * unit, unit), one)
                                  .has_value());
                BOOST_TEST(equal(std::span{whole}.subspan(i * unit, unit), one));
            }
            std::vector<std::byte> back(pt.size());
            BOOST_REQUIRE(c.decrypt(sample_unit, whole, back).has_value());
            BOOST_TEST(equal(back, pt));
        }
    }
}

BOOST_AUTO_TEST_CASE(in_place, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_512);
    auto buf = counting(blk::data_unit_512);
    BOOST_REQUIRE(c.encrypt(vector10_unit, buf, buf).has_value());
    BOOST_TEST(equal(buf, from_hex(vector10_ciphertext)));
    BOOST_REQUIRE(c.decrypt(vector10_unit, buf, buf).has_value());
    BOOST_TEST(equal(buf, counting(blk::data_unit_512)));
}

BOOST_AUTO_TEST_CASE(last_unit_number_may_be_max,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_512);
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    const auto pt = counting(blk::data_unit_512 * 2);
    std::vector<std::byte> ct(pt.size());
    BOOST_TEST(c.encrypt(max - 1, pt, ct).has_value());
    BOOST_TEST(c.encrypt(max, std::span{pt}.first(blk::data_unit_512),
                         std::span{ct}.first(blk::data_unit_512))
                   .has_value());
    BOOST_TEST(c.encrypt(max, pt, ct).error() == XtsError::unit_number_overflow);
    BOOST_TEST(c.decrypt(max, pt, ct).error() == XtsError::unit_number_overflow);
}

BOOST_AUTO_TEST_CASE(rejects_bad_data_unit_sizes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto k = key_bytes();
    for (const std::size_t unit :
         {std::size_t{0}, aes_block, std::size_t{1024}, std::size_t{8192}}) {
        BOOST_TEST_CONTEXT("unit size " << unit) {
            BOOST_TEST(XtsCipher::create(key_span(k), unit).error() ==
                       XtsError::bad_data_unit_size);
        }
    }
}

BOOST_AUTO_TEST_CASE(rejects_equal_key_halves, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto k = key_bytes();
    std::copy_n(k.begin(), half_key, k.begin() + half_key);
    BOOST_TEST(XtsCipher::create(key_span(k), blk::data_unit_512).error() == XtsError::weak_key);
    k.back() ^= std::byte{1};
    BOOST_TEST(XtsCipher::create(key_span(k), blk::data_unit_512).has_value());
}

BOOST_AUTO_TEST_CASE(rejects_partial_units, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_4k);
    for (const std::size_t size : {std::size_t{0}, blk::data_unit_512, blk::data_unit_4k - 1,
                                   blk::data_unit_4k + aes_block}) {
        BOOST_TEST_CONTEXT("size " << size) {
            const auto pt = counting(size);
            std::vector<std::byte> out(size);
            BOOST_TEST(c.encrypt(0, pt, out).error() == XtsError::bad_length);
            BOOST_TEST(c.decrypt(0, pt, out).error() == XtsError::bad_length);
        }
    }
}

BOOST_AUTO_TEST_CASE(rejects_bad_output_buffers, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make_cipher(blk::data_unit_512);
    auto buf = counting(blk::data_unit_512 * 2);
    const std::span<const std::byte> in = std::span{buf}.first(blk::data_unit_512);

    std::vector<std::byte> short_out(blk::data_unit_512 - 1);
    BOOST_TEST(c.encrypt(0, in, short_out).error() == XtsError::buffer_mismatch);
    std::vector<std::byte> long_out(blk::data_unit_512 * 2);
    BOOST_TEST(c.encrypt(0, in, long_out).error() == XtsError::buffer_mismatch);

    // Shifted by one AES block either way: overlapping but not in place.
    const auto ahead = std::span{buf}.subspan(aes_block, blk::data_unit_512);
    BOOST_TEST(c.encrypt(0, in, ahead).error() == XtsError::buffer_mismatch);
    BOOST_TEST(c.decrypt(0, ahead, std::span{buf}.first(blk::data_unit_512)).error() ==
               XtsError::buffer_mismatch);

    // Adjacent is disjoint, and fine.
    BOOST_TEST(c.encrypt(0, in, std::span{buf}.subspan(blk::data_unit_512)).has_value());
}

BOOST_AUTO_TEST_CASE(error_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(std::string_view{blk::to_string(XtsError::bad_data_unit_size)} ==
               "bad_data_unit_size");
    BOOST_TEST(std::string_view{blk::to_string(XtsError::weak_key)} == "weak_key");
    BOOST_TEST(std::string_view{blk::to_string(XtsError::bad_length)} == "bad_length");
    BOOST_TEST(std::string_view{blk::to_string(XtsError::buffer_mismatch)} == "buffer_mismatch");
    BOOST_TEST(std::string_view{blk::to_string(XtsError::unit_number_overflow)} ==
               "unit_number_overflow");
    BOOST_TEST(std::string_view{blk::to_string(XtsError::crypto_failure)} == "crypto_failure");
}
