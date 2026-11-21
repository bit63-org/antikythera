// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 5.2 and controller-interface
// Requirement 8: TunnelPeerSet checks a controller TunnelPeers frame
// (target, signature, version) and makes its peers the Tunnel's.

#define BOOST_TEST_MODULE tunnel_peers_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "oar/net/tunnel.hpp"
#include "oar/net/tunnel_peers.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/tunnel_peers.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using net::PeersResult;

namespace {

constexpr std::uint64_t server = 0x5E'0001;
constexpr proto::KeyId good_key = 7;
constexpr std::byte good_mark{0x5A};

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a.back() = std::byte{tail};
    return a;
}

class NullSender final : public net::DatagramSender {
public:
    auto send_to(const net::Ipv6Address& /*dst*/, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> /*payload*/)
        -> bool override {
        return true;
    }
};

// Stands in for Ed25519: a signature "verifies" when it is filled with
// good_mark and the key ID is good_key. The real check (hull's verifier
// over the same bytes) is exercised end to end in tunnel_keys_test.
auto fake_verifier(int& calls, std::size_t& signed_size) -> net::FrameVerifier {
    return [&calls, &signed_size](std::span<const std::byte> signed_bytes,
                                  std::span<const std::byte, net::frame_signature_size> sig,
                                  std::uint16_t key_id) {
        ++calls;
        signed_size = signed_bytes.size();
        return key_id == good_key &&
               std::ranges::all_of(sig, [](std::byte b) { return b == good_mark; });
    };
}

auto public_of(std::uint8_t seed) -> wg::Key {
    // Distinct, valid X25519 public keys from fixed private keys.
    wg::Key priv{};
    priv.fill(std::byte{seed});
    return wg::public_key(priv).value();
}

struct Frame {
    std::uint64_t to_server{server};
    net::Ipv6Address to_vtep{vtep(1)};
    std::uint64_t version{1};
    std::vector<proto::TunnelPeer> peers;
    proto::KeyId key_id{good_key};
    std::byte mark{good_mark};

    [[nodiscard]] auto bytes() const -> std::vector<std::byte> {
        proto::TunnelPeers t{.server_id = to_server,
                             .key_id = key_id,
                             .vtep = to_vtep,
                             .peers_version = version,
                             .peers = peers,
                             .signature = {}};
        t.signature.fill(mark);
        auto b = proto::encode_tunnel_peers(t);
        BOOST_REQUIRE(b.has_value());
        return *b;
    }
};

struct Fixture {
    NullSender sender;
    std::unique_ptr<net::Tunnel> tunnel{net::Tunnel::create(sender, {}).value()};
    int calls = 0;
    std::size_t signed_size = 0;
    net::TunnelPeerSet set{*tunnel, server, vtep(1), fake_verifier(calls, signed_size)};

    Fixture() {
        wg::Key own{};
        own.fill(std::byte{0x01});
        BOOST_REQUIRE(tunnel->set_private_key(own).has_value());
    }

    [[nodiscard]] auto peer_vteps() const -> std::vector<net::Ipv6Address> {
        std::vector<net::Ipv6Address> out;
        for (const auto& p : tunnel->peers()) {
            out.push_back(p.vtep);
        }
        std::ranges::sort(out);
        return out;
    }
    [[nodiscard]] auto key_of(const net::Ipv6Address& v) const -> wg::Key {
        for (const auto& p : tunnel->peers()) {
            if (p.vtep == v) {
                return p.public_key;
            }
        }
        return {};
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(tunnel_peer_set, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_FIXTURE_TEST_CASE(installs_and_replaces_the_peer_set, Fixture) {
    Frame f{
        .version = 1,
        .peers = {
            {.vtep = vtep(2), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(2)},
            {.vtep = vtep(3),
             .mode = proto::TunnelMode::wireguard,
             .spi = 0,
             .key = public_of(3)}}};
    const auto b1 = f.bytes();
    BOOST_TEST((set.apply(b1) == PeersResult::applied));
    BOOST_TEST(signed_size == b1.size() - proto::ed25519_signature_size);
    BOOST_TEST(set.version() == 1U);
    BOOST_TEST(set.size() == 2U);
    BOOST_TEST((peer_vteps() == std::vector{vtep(2), vtep(3)}));
    BOOST_TEST((key_of(vtep(3)) == public_of(3)));

    // Re-delivery of the same version changes nothing and is accepted.
    BOOST_TEST((set.apply(b1) == PeersResult::redelivered));
    BOOST_TEST(net::accepted(PeersResult::redelivered));

    // Version 2: vtep(2) leaves, vtep(3) is re-keyed, vtep(4) joins.
    f.version = 2;
    f.peers = {
        {.vtep = vtep(3), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(33)},
        {.vtep = vtep(4), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(4)}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::applied));
    BOOST_TEST((peer_vteps() == std::vector{vtep(3), vtep(4)}));
    BOOST_TEST((key_of(vtep(3)) == public_of(33)));
    BOOST_TEST(set.counters().peers_added == 4U);    // 2, 3, 3 again (re-keyed), 4
    BOOST_TEST(set.counters().peers_removed == 2U);  // 2 gone, 3 re-keyed

    // An older version is refused and leaves the peers alone.
    f.version = 1;
    f.peers = {};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::stale));
    BOOST_TEST(!net::accepted(PeersResult::stale));
    BOOST_TEST(set.version() == 2U);
    BOOST_TEST(set.size() == 2U);

    // An empty set removes every controller-managed peer.
    f.version = 3;
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::applied));
    BOOST_TEST(tunnel->peers().empty());
    BOOST_TEST(set.counters().applied == 3U);
    BOOST_TEST(set.counters().redelivered == 1U);
    BOOST_TEST(set.counters().stale == 1U);
}

BOOST_FIXTURE_TEST_CASE(a_key_can_move_between_vteps, Fixture) {
    Frame f{
        .version = 1,
        .peers = {
            {.vtep = vtep(2), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(2)},
            {.vtep = vtep(3),
             .mode = proto::TunnelMode::wireguard,
             .spi = 0,
             .key = public_of(3)}}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::applied));
    // The two VTEPs swap keys: the Tunnel never sees one key on two peers.
    f.version = 2;
    f.peers = {
        {.vtep = vtep(2), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(3)},
        {.vtep = vtep(3), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(2)}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::applied));
    BOOST_TEST((key_of(vtep(2)) == public_of(3)));
    BOOST_TEST((key_of(vtep(3)) == public_of(2)));
}

BOOST_FIXTURE_TEST_CASE(refusals_change_nothing, Fixture) {
    const Frame good{.version = 5,
                     .peers = {{.vtep = vtep(2),
                                .mode = proto::TunnelMode::wireguard,
                                .spi = 0,
                                .key = public_of(2)}}};
    auto f = good;
    f.to_server = server + 1;
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::wrong_target));
    f = good;
    f.to_vtep = vtep(9);
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::wrong_target));
    f = good;
    f.mark = std::byte{0};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::bad_signature));
    f = good;
    f.key_id = good_key + 1;
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::bad_signature));
    // Undecodable bytes never reach the verifier.
    const int before = calls;
    auto b = good.bytes();
    b[0] = std::byte{0};
    BOOST_TEST((set.apply(b) == PeersResult::undecodable));
    BOOST_TEST((set.apply({}) == PeersResult::undecodable));
    BOOST_TEST(calls == before);

    BOOST_TEST(set.version() == 0U);
    BOOST_TEST(tunnel->peers().empty());
    BOOST_TEST(set.counters().wrong_target == 2U);
    BOOST_TEST(set.counters().bad_signature == 2U);
    BOOST_TEST(set.counters().undecodable == 2U);

    // The good frame still applies afterwards.
    BOOST_TEST((set.apply(good.bytes()) == PeersResult::applied));
}

BOOST_FIXTURE_TEST_CASE(a_key_the_tunnel_refuses_is_rejected, Fixture) {
    // The role's own public key as a peer: the frame is well formed and
    // signed, but the Tunnel cannot use it.
    const auto own = tunnel->public_key().value();
    const Frame f{
        .version = 1,
        .peers = {
            {.vtep = vtep(2), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(2)},
            {.vtep = vtep(3), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = own}}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::rejected));
    BOOST_TEST(set.version() == 0U);  // can be sent again once fixed
    BOOST_TEST(set.counters().rejected == 1U);
}

BOOST_FIXTURE_TEST_CASE(psp_peers_are_unsupported, Fixture) {
    // The role advertises only WireGuard, so a PSP pair is a controller
    // error: the whole frame is refused before anything changes.
    const Frame f{
        .version = 1,
        .peers = {
            {.vtep = vtep(2), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = public_of(2)},
            {.vtep = vtep(3), .mode = proto::TunnelMode::psp, .spi = 9, .key = public_of(3)}}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::unsupported));
    BOOST_TEST(!net::accepted(PeersResult::unsupported));
    BOOST_TEST(tunnel->peers().empty());
    BOOST_TEST(set.version() == 0U);
    BOOST_TEST(set.counters().unsupported == 1U);
}

BOOST_FIXTURE_TEST_CASE(peers_added_by_hand_are_left_alone, Fixture) {
    wg::Key psk{};
    psk.fill(std::byte{0x33});
    BOOST_REQUIRE(tunnel->set_peer(vtep(8), public_of(8), psk).has_value());
    const Frame f{.version = 1,
                  .peers = {{.vtep = vtep(2),
                             .mode = proto::TunnelMode::wireguard,
                             .spi = 0,
                             .key = public_of(2)}}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::applied));
    auto empty = f;
    empty.version = 2;
    empty.peers = {};
    BOOST_TEST((set.apply(empty.bytes()) == PeersResult::applied));
    BOOST_TEST((peer_vteps() == std::vector{vtep(8)}));
}

BOOST_AUTO_TEST_CASE(no_verifier_trusts_nothing) {
    NullSender sender;
    auto tunnel = net::Tunnel::create(sender, {}).value();
    net::TunnelPeerSet set{*tunnel, server, vtep(1), {}};
    const Frame f{.version = 1, .peers = {}};
    BOOST_TEST((set.apply(f.bytes()) == PeersResult::bad_signature));
}

BOOST_AUTO_TEST_CASE(results_have_names) {
    for (auto r : {PeersResult::applied, PeersResult::redelivered, PeersResult::undecodable,
                   PeersResult::wrong_target, PeersResult::bad_signature, PeersResult::stale,
                   PeersResult::rejected, PeersResult::unsupported}) {
        BOOST_TEST(std::string_view{net::to_string(r)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
