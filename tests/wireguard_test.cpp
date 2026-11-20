// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 5 (task 10): WireGuard message
// parsing, the primitives the handshake is built from, and the anti-replay
// window.

#define BOOST_TEST_MODULE wireguard_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "oar/net/wireguard.hpp"
#include "test_support.hpp"

namespace wg = ak::oar::net::wg;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::size_t transport_payload = 20;

auto message(wg::MessageType type, std::size_t size) -> std::vector<std::byte> {
    std::vector<std::byte> m(size, std::byte{0x11});
    m[0] = static_cast<std::byte>(type);
    m[1] = m[2] = m[3] = std::byte{0};
    return m;
}

auto hex(std::span<const std::byte> b) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (const auto x : b) {
        const auto v = std::to_integer<unsigned>(x);
        out += digits[v >> 4U];
        out += digits[v & 0xFU];
    }
    return out;
}

auto key_of(std::uint8_t fill) -> wg::Key {
    wg::Key k{};
    k.fill(std::byte{fill});
    return k;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(parse)

BOOST_AUTO_TEST_CASE(each_type_at_its_size, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto init = message(wg::MessageType::initiation, wg::initiation_size);
    init[4] = std::byte{0x78};
    init[7] = std::byte{0x12};
    const auto i = wg::parse(init);
    BOOST_REQUIRE(i.has_value());
    const auto& iv = std::get<wg::Initiation>(*i);
    BOOST_TEST(iv.sender == 0x1211'1178U);
    BOOST_TEST(iv.before_mac1.size() == wg::initiation_mac1_offset);
    BOOST_TEST(iv.mac2.data() == init.data() + wg::initiation_size - wg::mac_size);

    auto resp = message(wg::MessageType::response, wg::response_size);
    resp[8] = std::byte{0x01};
    resp[9] = resp[10] = resp[11] = std::byte{0};
    const auto r = wg::parse(resp);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(std::get<wg::Response>(*r).receiver == 1U);
    BOOST_TEST(std::get<wg::Response>(*r).before_mac1.size() == wg::response_mac1_offset);

    BOOST_TEST(
        wg::parse(message(wg::MessageType::cookie_reply, wg::cookie_reply_size)).has_value());

    auto t = message(wg::MessageType::transport, wg::transport_overhead + transport_payload);
    t[8] = std::byte{0x05};
    for (std::size_t b = 9; b < wg::transport_header_size; ++b) {
        t[b] = std::byte{0};
    }
    const auto tv = wg::parse(t);
    BOOST_REQUIRE(tv.has_value());
    BOOST_TEST(std::get<wg::Transport>(*tv).counter == 5U);
    BOOST_TEST(std::get<wg::Transport>(*tv).ciphertext.size() == transport_payload + wg::tag_size);
    // An empty transport message (a keepalive) is exactly the overhead.
    BOOST_TEST(wg::parse(message(wg::MessageType::transport, wg::transport_overhead)).has_value());
}

BOOST_AUTO_TEST_CASE(errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((wg::parse({}).error() == wg::ParseError::empty));
    auto bad = message(wg::MessageType::initiation, wg::initiation_size);
    bad[0] = std::byte{5};
    BOOST_TEST((wg::parse(bad).error() == wg::ParseError::unknown_type));
    bad[0] = std::byte{0};
    BOOST_TEST((wg::parse(bad).error() == wg::ParseError::unknown_type));
    bad = message(wg::MessageType::initiation, wg::initiation_size);
    bad[2] = std::byte{1};
    BOOST_TEST((wg::parse(bad).error() == wg::ParseError::reserved_not_zero));
    BOOST_TEST((wg::parse(message(wg::MessageType::initiation, wg::initiation_size - 1)).error() ==
                wg::ParseError::bad_length));
    BOOST_TEST((wg::parse(message(wg::MessageType::response, wg::response_size + 1)).error() ==
                wg::ParseError::bad_length));
    BOOST_TEST(
        (wg::parse(message(wg::MessageType::cookie_reply, wg::cookie_reply_size - 1)).error() ==
         wg::ParseError::bad_length));
    BOOST_TEST(
        (wg::parse(message(wg::MessageType::transport, wg::transport_overhead - 1)).error() ==
         wg::ParseError::bad_length));
    const std::array<std::byte, 2> stub{std::byte{4}, std::byte{0}};
    BOOST_TEST((wg::parse(stub).error() == wg::ParseError::bad_length));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(primitives)

BOOST_AUTO_TEST_CASE(hash_is_blake2s_256, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // BLAKE2s-256("") and ("abc"), RFC 7693 appendix B.
    BOOST_TEST(hex(wg::hash({})) ==
               "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    const std::string_view abc = "abc";
    BOOST_TEST(hex(wg::hash({std::as_bytes(std::span{abc})})) ==
               "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    // Parts are concatenated.
    const std::string_view a = "a";
    const std::string_view bc = "bc";
    BOOST_TEST((wg::hash({std::as_bytes(std::span{a}), std::as_bytes(std::span{bc})}) ==
                wg::hash({std::as_bytes(std::span{abc})})));
}

BOOST_AUTO_TEST_CASE(mac_is_keyed_and_16_bytes, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto k1 = key_of(1);
    const auto k2 = key_of(2);
    const std::string_view data = "mac me";
    const auto m1 = wg::mac(k1, std::as_bytes(std::span{data}));
    BOOST_TEST(m1.size() == wg::mac_size);
    BOOST_TEST((m1 != wg::mac(k2, std::as_bytes(std::span{data}))));
    BOOST_TEST((m1 == wg::mac(k1, std::as_bytes(std::span{data}))));
    BOOST_TEST((m1 != wg::Mac{}));
}

BOOST_AUTO_TEST_CASE(kdf_outputs_chain, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto key = key_of(7);
    const std::string_view input = "input";
    wg::Hash a{};
    wg::Hash b{};
    wg::Hash c{};
    wg::kdf(key, std::as_bytes(std::span{input}), {a, b, c});
    wg::Hash a1{};
    wg::kdf(key, std::as_bytes(std::span{input}), {a1});
    BOOST_TEST((a == a1));  // KDF1 is KDF3's first output
    BOOST_TEST((a != b));
    BOOST_TEST((b != c));
    // The key may also be the output (C = KDF1(C, x)).
    wg::Hash chain = key;
    wg::kdf(chain, std::as_bytes(std::span{input}), {chain});
    BOOST_TEST((chain == a));
}

BOOST_AUTO_TEST_CASE(x25519_rfc7748, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // RFC 7748 section 6.1: Alice's and Bob's keys and their shared secret.
    const auto parse_hex = [](std::string_view h) {
        wg::Key k{};
        for (std::size_t i = 0; i < k.size(); ++i) {
            k[i] = static_cast<std::byte>(std::stoul(std::string{h.substr(2 * i, 2)}, nullptr, 16));
        }
        return k;
    };
    const auto alice =
        parse_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto bob = parse_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const auto alice_pub = wg::public_key(alice);
    const auto bob_pub = wg::public_key(bob);
    BOOST_REQUIRE(alice_pub.has_value());
    BOOST_REQUIRE(bob_pub.has_value());
    BOOST_TEST(hex(*alice_pub) ==
               "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const auto s1 = wg::dh(alice, *bob_pub);
    const auto s2 = wg::dh(bob, *alice_pub);
    BOOST_REQUIRE(s1.has_value());
    BOOST_REQUIRE(s2.has_value());
    BOOST_TEST(hex(s1->span()) ==
               "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    BOOST_TEST(hex(s2->span()) == hex(s1->span()));

    // A low-order public key gives an all-zero secret, which is refused.
    wg::Key low_order{};
    low_order[0] = std::byte{1};
    BOOST_TEST(!wg::dh(alice, low_order).has_value());
    BOOST_TEST(!wg::dh(alice, wg::Key{}).has_value());

    const auto fresh = wg::generate_private_key();
    BOOST_REQUIRE(fresh.has_value());
    BOOST_TEST(wg::public_key(fresh->span()).has_value());
}

BOOST_AUTO_TEST_CASE(aead_round_trip_and_tamper, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto key = key_of(3);
    const std::string_view text = "geneve payload";
    const auto plain = std::as_bytes(std::span{text});
    const std::string_view ad_text = "hash";
    const auto ad = std::as_bytes(std::span{ad_text});
    std::vector<std::byte> sealed(plain.size() + wg::tag_size);
    BOOST_REQUIRE(wg::seal(key, 9, plain, ad, sealed));
    std::vector<std::byte> opened(plain.size());
    BOOST_REQUIRE(wg::open(key, 9, sealed, ad, opened));
    BOOST_TEST((std::vector<std::byte>(plain.begin(), plain.end()) == opened));

    BOOST_TEST(!wg::open(key, 10, sealed, ad, opened));  // wrong counter
    BOOST_TEST(!wg::open(key, 9, sealed, {}, opened));   // wrong ad
    BOOST_TEST(!wg::open(key_of(4), 9, sealed, ad, opened));
    sealed[0] ^= std::byte{1};
    BOOST_TEST(!wg::open(key, 9, sealed, ad, opened));
    BOOST_TEST((opened == std::vector<std::byte>(plain.size())));  // zeroed on failure

    // Wrong output sizes are refused, not overrun.
    std::vector<std::byte> small(plain.size());
    BOOST_TEST(!wg::seal(key, 0, plain, ad, small));
    std::array<std::byte, wg::tag_size - 1> short_ct{};
    BOOST_TEST(!wg::open(key, 0, short_ct, ad, {}));

    // An empty plaintext seals to a bare tag (the response's "empty").
    std::array<std::byte, wg::tag_size> tag{};
    BOOST_REQUIRE(wg::seal(key, 0, {}, ad, tag));
    BOOST_TEST(wg::open(key, 0, tag, ad, {}));
}

BOOST_AUTO_TEST_CASE(keyed_context_matches_one_shot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto key = key_of(5);
    auto enc = wg::Aead::create(key, true);
    auto dec = wg::Aead::create(key, false);
    BOOST_REQUIRE(enc.has_value());
    BOOST_REQUIRE(dec.has_value());
    const std::string_view text = "the same bytes every time";
    const auto plain = std::as_bytes(std::span{text});
    for (const std::uint64_t counter : {0ULL, 1ULL, 77ULL, 1ULL << 40U}) {
        std::vector<std::byte> a(plain.size() + wg::tag_size);
        std::vector<std::byte> b(plain.size() + wg::tag_size);
        BOOST_REQUIRE(enc->seal(counter, plain, a));
        BOOST_REQUIRE(wg::seal(key, counter, plain, {}, b));
        BOOST_TEST((a == b));  // the context kept its key across nonces
        std::vector<std::byte> out(plain.size());
        BOOST_REQUIRE(dec->open(counter, a, out));
        BOOST_TEST((std::vector<std::byte>(plain.begin(), plain.end()) == out));
        BOOST_TEST(!dec->open(counter + 1, a, out));
    }
    // A moved-to context still works; the moved-from one fails cleanly.
    wg::Aead moved = std::move(*enc);
    std::vector<std::byte> c(plain.size() + wg::tag_size);
    BOOST_TEST(moved.seal(3, plain, c));
    BOOST_TEST(
        !enc->seal(3, plain, c));  // NOLINT(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
}

BOOST_AUTO_TEST_CASE(tai64n_layout, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using namespace std::chrono;
    BOOST_TEST(hex(wg::tai64n(system_clock::time_point{})) == "400000000000000a00000000");
    // 1 s + 0.5 s: nanoseconds rounded down to a multiple of 2^24.
    const auto t = system_clock::time_point{
        duration_cast<system_clock::duration>(seconds{1} + nanoseconds{500'000'000})};
    const auto stamp = wg::tai64n(t);
    BOOST_TEST(hex(std::span{stamp}.first(8)) == "400000000000000b");
    constexpr std::uint32_t grain = 1U << 24U;
    constexpr std::uint32_t expect = 500'000'000U - (500'000'000U % grain);
    std::uint32_t ns = 0;
    for (std::size_t i = 8; i < wg::timestamp_size; ++i) {
        ns = (ns << 8U) | std::to_integer<std::uint32_t>(stamp[i]);
    }
    BOOST_TEST(ns == expect);
    // Later is greater, byte-wise, as the responder compares them.
    BOOST_TEST((wg::tai64n(t + seconds{1}) > stamp));
}

BOOST_AUTO_TEST_CASE(secret_wipes_when_moved, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto k = key_of(9);
    wg::SecretKey a{k};
    wg::SecretKey b = std::move(a);
    BOOST_TEST(wg::equal(b.span(), k));
    BOOST_TEST(wg::equal(
        a.span(), wg::Key{}));  // NOLINT(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    b.wipe();
    BOOST_TEST(wg::equal(b.span(), wg::Key{}));
    BOOST_TEST(!wg::equal(k, std::span{k}.first(4)));  // lengths differ
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(replay_window)

BOOST_AUTO_TEST_CASE(in_order_and_duplicates, *boost::unit_test::timeout(unit_timeout_seconds)) {
    wg::ReplayWindow w;
    for (std::uint64_t c = 0; c < 100; ++c) {
        BOOST_TEST(w.may_accept(c));
        BOOST_TEST(w.accept(c));
        BOOST_TEST(!w.may_accept(c));
        BOOST_TEST(!w.accept(c));
    }
}

BOOST_AUTO_TEST_CASE(out_of_order_within_window, *boost::unit_test::timeout(unit_timeout_seconds)) {
    wg::ReplayWindow w;
    BOOST_TEST(w.accept(10));
    BOOST_TEST(w.accept(5));
    BOOST_TEST(w.accept(0));
    BOOST_TEST(!w.accept(5));
    BOOST_TEST(w.accept(9));
    BOOST_TEST(w.accept(11));
    BOOST_TEST(!w.accept(10));
}

BOOST_AUTO_TEST_CASE(too_old_refused, *boost::unit_test::timeout(unit_timeout_seconds)) {
    wg::ReplayWindow w;
    const std::uint64_t top = 20'000;
    BOOST_TEST(w.accept(top));
    BOOST_TEST(w.may_accept(top - wg::ReplayWindow::window + 1));
    BOOST_TEST(w.accept(top - wg::ReplayWindow::window + 1));
    BOOST_TEST(!w.may_accept(top - wg::ReplayWindow::window - 2));
    BOOST_TEST(!w.accept(top - wg::ReplayWindow::window - 2));
    // A big jump clears the bitmap: old bits do not mark new counters seen.
    const std::uint64_t far = top + (4 * wg::ReplayWindow::bits_total);
    BOOST_TEST(w.accept(far));
    for (std::uint64_t c = far - 64; c < far; ++c) {
        BOOST_TEST(w.accept(c));
    }
    BOOST_TEST(!w.accept(top));
}

BOOST_AUTO_TEST_CASE(counter_limit, *boost::unit_test::timeout(unit_timeout_seconds)) {
    wg::ReplayWindow w;
    BOOST_TEST(!w.may_accept(~std::uint64_t{0}));
    BOOST_TEST(!w.accept(~std::uint64_t{0}));
}

BOOST_AUTO_TEST_SUITE_END()
