// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 8 and design "TunnelPeers":
// the TunnelPeers codec, its layout, its signed bytes, and its strict
// decode.

#define BOOST_TEST_MODULE proto_tunnel_peers_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "proto/tunnel_peers.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::size_t last = 15;

auto vtep(std::uint8_t tag) -> proto::VtepAddress {
    proto::VtepAddress a{};
    a[0] = std::byte{ula_prefix};
    a[last] = std::byte{tag};
    return a;
}

auto key(std::uint8_t fill) -> proto::TunnelPublicKey {
    proto::TunnelPublicKey k{};
    k.fill(std::byte{fill});
    return k;
}

auto sample() -> proto::TunnelPeers {
    proto::TunnelPeers t{.server_id = sample_server,
                         .key_id = 3,
                         .vtep = vtep(1),
                         .peers_version = 9,
                         .peers = {{.vtep = vtep(2), .public_key = key(0x22)},
                                   {.vtep = vtep(5), .public_key = key(0x55)}},
                         .signature = {}};
    t.signature.fill(std::byte{0x5A});
    return t;
}

auto encoded(const proto::TunnelPeers& t) -> std::vector<std::byte> {
    auto b = proto::encode_tunnel_peers(t);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto t = proto::decode_tunnel_peers(b);
    BOOST_REQUIRE(!t.has_value());
    return t.error();
}

auto le_at(const std::vector<std::byte>& b, std::size_t off, std::size_t n) -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        v |= std::to_integer<std::uint64_t>(b[off + i]) << (8 * i);
    }
    return v;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(tunnel_peers, *boost::unit_test::timeout(ak::test::unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips) {
    const auto t = sample();
    const auto b = encoded(t);
    BOOST_TEST(b.size() == proto::tunnel_peers_size(2));
    auto back = proto::decode_tunnel_peers(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == t));

    // An empty peer set is legal: the VTEP shares no VNI with anyone.
    auto none = t;
    none.peers.clear();
    const auto nb = encoded(none);
    BOOST_TEST(nb.size() == proto::tunnel_peers_header_size + proto::ed25519_signature_size);
    BOOST_TEST((proto::decode_tunnel_peers(nb).value() == none));
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian_with_peers_after_the_header) {
    const auto b = encoded(sample());
    BOOST_TEST(le_at(b, 0x00, 4) == proto::tunnel_peers_magic);
    BOOST_TEST((b[0] == std::byte{'A'}));
    BOOST_TEST((b[3] == std::byte{'P'}));
    BOOST_TEST(le_at(b, 0x04, 2) == proto::tunnel_peers_version);
    BOOST_TEST(le_at(b, 0x06, 2) == 3U);
    BOOST_TEST(le_at(b, 0x08, 8) == sample_server);
    BOOST_TEST((b[0x10] == std::byte{ula_prefix}));
    BOOST_TEST((b[0x10 + last] == std::byte{1}));
    BOOST_TEST(le_at(b, 0x20, 8) == 9U);
    BOOST_TEST(le_at(b, 0x28, 2) == 2U);
    BOOST_TEST(std::ranges::all_of(std::span{b}.subspan(0x2A, 6),
                                   [](std::byte x) { return x == std::byte{0}; }));
    // Peer 1 (vtep(5)) at 0x30 + 48: address, then key.
    const std::size_t p1 = proto::tunnel_peers_header_size + proto::tunnel_peer_size;
    BOOST_TEST((b[p1 + last] == std::byte{5}));
    BOOST_TEST((b[p1 + 16] == std::byte{0x55}));
    BOOST_TEST((b[p1 + 47] == std::byte{0x55}));
    BOOST_TEST((b[b.size() - 1] == std::byte{0x5A}));
}

BOOST_AUTO_TEST_CASE(signature_covers_every_byte_before_it) {
    auto b = encoded(sample());
    const auto signed_bytes = proto::tunnel_peers_signed_bytes(b);
    BOOST_TEST(signed_bytes.size() == b.size() - proto::ed25519_signature_size);
    BOOST_TEST(signed_bytes.data() == b.data());

    std::array<std::byte, proto::ed25519_signature_size> sig{};
    sig.fill(std::byte{0xC3});
    proto::set_tunnel_peers_signature(b, sig);
    auto back = proto::decode_tunnel_peers(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(std::ranges::equal(back->signature, sig));
}

BOOST_AUTO_TEST_CASE(rules_are_enforced_both_ways) {
    struct Case {
        void (*mutate)(proto::TunnelPeers&);
        DecodeError want;
    };
    const Case cases[] = {
        {[](proto::TunnelPeers& t) { t.key_id = proto::no_key_id; }, DecodeError::bad_key_id},
        {[](proto::TunnelPeers& t) { t.server_id = 0; }, DecodeError::bad_server_id},
        {[](proto::TunnelPeers& t) { t.vtep = {}; }, DecodeError::bad_vtep},
        {[](proto::TunnelPeers& t) { t.vtep[0] = std::byte{0xFF}; }, DecodeError::bad_vtep},
        {[](proto::TunnelPeers& t) { t.peers_version = 0; }, DecodeError::bad_peers_version},
        {[](proto::TunnelPeers& t) { t.peers[0].vtep = {}; }, DecodeError::bad_vtep},
        {[](proto::TunnelPeers& t) { t.peers[1].vtep[0] = std::byte{0xFF}; },
         DecodeError::bad_vtep},
        // A VTEP is never its own peer.
        {[](proto::TunnelPeers& t) { t.peers[0].vtep = t.vtep; }, DecodeError::bad_vtep},
        {[](proto::TunnelPeers& t) { std::swap(t.peers[0], t.peers[1]); },
         DecodeError::not_ascending},
        {[](proto::TunnelPeers& t) { t.peers[1].vtep = t.peers[0].vtep; },
         DecodeError::not_ascending},
        {[](proto::TunnelPeers& t) { t.peers[1].public_key = {}; }, DecodeError::bad_public_key},
        {[](proto::TunnelPeers& t) { t.peers[1].public_key = t.peers[0].public_key; },
         DecodeError::duplicate_public_key},
    };
    for (const auto& c : cases) {
        auto t = sample();
        c.mutate(t);
        auto refused = proto::encode_tunnel_peers(t);
        BOOST_REQUIRE(!refused.has_value());
        BOOST_TEST((refused.error() == c.want));
    }

    // The decoder enforces them on bytes the encoder would not make.
    const auto good = encoded(sample());
    auto b = good;
    std::ranges::fill(std::span{b}.subspan(0x10, 16), std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_vtep));
    b = good;
    const std::size_t p1_key = proto::tunnel_peers_header_size + proto::tunnel_peer_size + 16;
    std::ranges::fill(std::span{b}.subspan(p1_key, 32), std::byte{0x22});  // = peer 0's key
    BOOST_TEST((decode_error(b) == DecodeError::duplicate_public_key));
}

BOOST_AUTO_TEST_CASE(header_rules) {
    const auto good = encoded(sample());
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    for (std::size_t off = 0x2A; off < 0x30; ++off) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
}

BOOST_AUTO_TEST_CASE(every_short_length_is_truncated_and_long_is_trailing) {
    const auto good = encoded(sample());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated),
                   "length " << n);
    }
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((decode_error(longer) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(hostile_counts_cost_nothing) {
    auto b = encoded(sample());
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(0x28)};
    BOOST_REQUIRE(
        w.write(static_cast<std::uint16_t>(proto::max_tunnel_peers + 1), ak::wire::Order::little)
            .has_value());
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    ak::wire::SpanWriter w2{std::span<std::byte>{b}.subspan(0x28)};
    BOOST_REQUIRE(w2.write(std::uint16_t{3}, ak::wire::Order::little).has_value());
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(largest_set_round_trips) {
    auto t = sample();
    t.vtep = vtep(0xFE);
    t.peers.clear();
    for (std::size_t i = 0; i < proto::max_tunnel_peers; ++i) {
        proto::TunnelPeer p{.vtep = vtep(1), .public_key = key(1)};
        p.vtep[13] = std::byte{static_cast<std::uint8_t>(i >> 8U)};
        p.vtep[14] = std::byte{static_cast<std::uint8_t>(i & 0xFFU)};
        p.public_key[0] = p.vtep[13];
        p.public_key[1] = p.vtep[14];
        t.peers.push_back(p);
    }
    const auto b = encoded(t);
    BOOST_TEST(b.size() == proto::max_tunnel_peers_size);
    BOOST_TEST((proto::decode_tunnel_peers(b).value() == t));
    t.peers.push_back({.vtep = vtep(0xFF), .public_key = key(0xEE)});
    BOOST_TEST((proto::encode_tunnel_peers(t).error() == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_SUITE_END()
