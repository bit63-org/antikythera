// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// HPKE base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM
// (.kiro/specs/block-volume-service/ design "VolumeKey"): the CFRG test
// vector for this suite (draft-irtf-cfrg-hpke test-vectors.json, mode 0,
// kem 0x20, kdf 1, aead 2), and the ways an open must fail.

#define BOOST_TEST_MODULE hpke_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>
#include <string_view>
#include <vector>

#include "helm/hpke.hpp"

namespace ak::helm::hpke {
auto operator<<(std::ostream& os, Error e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::helm::hpke

namespace {

namespace hpke = ak::helm::hpke;
using Bytes = std::vector<std::byte>;

auto hex(std::string_view s) -> Bytes {
    const auto nibble = [](char c) -> unsigned {
        return c <= '9' ? static_cast<unsigned>(c - '0') : static_cast<unsigned>(c - 'a' + 10);
    };
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::byte>((nibble(s[i]) << 4U) | nibble(s[i + 1])));
    }
    return out;
}

template<std::size_t N> auto fixed(std::string_view s) -> std::array<std::byte, N> {
    const auto b = hex(s);
    BOOST_TEST_REQUIRE(b.size() == N);
    std::array<std::byte, N> out{};
    std::ranges::copy(b, out.begin());
    return out;
}

// The vector.
const auto info = hex("4f6465206f6e2061204772656369616e2055726e");
const auto ikm_e = fixed<32>("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9");
const auto pk_em = fixed<32>("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
const auto sk_em = fixed<32>("179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11");
const auto ikm_r = hex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee");
const auto pk_rm = fixed<32>("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
const auto sk_rm = fixed<32>("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d");
const auto aad0 = hex("436f756e742d30");
const auto pt = hex("4265617574792069732074727574682c20747275746820626561757479");
const auto ct0 = hex(
    "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a");

BOOST_AUTO_TEST_CASE(derive_key_pair_matches_the_vector) {
    const auto r = hpke::derive_key_pair(ikm_r);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((r->public_key == pk_rm));
    const auto rs = r->private_key.span();
    BOOST_TEST((Bytes(rs.begin(), rs.end()) == Bytes(sk_rm.begin(), sk_rm.end())));
    const auto e = hpke::derive_key_pair(ikm_e);
    BOOST_REQUIRE(e.has_value());
    BOOST_TEST((e->public_key == pk_em));
    const auto es = e->private_key.span();
    BOOST_TEST((Bytes(es.begin(), es.end()) == Bytes(sk_em.begin(), sk_em.end())));
}

BOOST_AUTO_TEST_CASE(seal_matches_the_vector) {
    const auto s = hpke::seal(pk_rm, info, aad0, pt, ikm_e);
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST((s->enc == pk_em));
    BOOST_TEST((s->ciphertext == ct0));
}

BOOST_AUTO_TEST_CASE(open_matches_the_vector) {
    Bytes out(pt.size());
    const auto r = hpke::open(sk_rm, pk_em, info, aad0, ct0, out);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((out == pt));
}

BOOST_AUTO_TEST_CASE(any_change_fails_to_open_and_leaves_no_plaintext) {
    Bytes out(pt.size(), std::byte{0x55});
    const auto zeroed = [&] {
        return std::ranges::all_of(out, [](std::byte b) { return b == std::byte{0}; });
    };
    auto bad_ct = ct0;
    bad_ct[3] ^= std::byte{1};
    BOOST_TEST(hpke::open(sk_rm, pk_em, info, aad0, bad_ct, out).error() ==
               hpke::Error::open_failed);
    BOOST_TEST(zeroed());
    auto bad_aad = aad0;
    bad_aad.back() = std::byte{'1'};
    BOOST_TEST(hpke::open(sk_rm, pk_em, info, bad_aad, ct0, out).error() ==
               hpke::Error::open_failed);
    BOOST_TEST(hpke::open(sk_rm, pk_em, {}, aad0, ct0, out).error() == hpke::Error::open_failed);
    auto other = sk_rm;
    other[0] ^= std::byte{0x40};
    BOOST_TEST(hpke::open(other, pk_em, info, aad0, ct0, out).error() == hpke::Error::open_failed);
    BOOST_TEST(hpke::open(sk_rm, pk_em, info, aad0, std::span{ct0}.first(10), out).error() ==
               hpke::Error::bad_size);
    // A low-order point as the ephemeral key: refused, not a zero secret.
    const std::array<std::byte, 32> zero_point{};
    BOOST_TEST(hpke::open(sk_rm, zero_point, info, aad0, ct0, out).error() ==
               hpke::Error::bad_public_key);
    BOOST_TEST(zeroed());
}

BOOST_AUTO_TEST_CASE(random_seals_round_trip_and_differ) {
    const auto a = hpke::seal(pk_rm, info, aad0, pt);
    const auto b = hpke::seal(pk_rm, info, aad0, pt);
    BOOST_REQUIRE((a.has_value() && b.has_value()));
    BOOST_TEST((a->enc != b->enc));
    Bytes out(pt.size());
    BOOST_REQUIRE(hpke::open(sk_rm, a->enc, info, aad0, a->ciphertext, out).has_value());
    BOOST_TEST((out == pt));
}

}  // namespace
