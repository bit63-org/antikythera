// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 5.2 (task 10): helm delivers
// the network role's WireGuard keys over the sideband (OarLink ->
// OarEndpoint), and two roles keyed that way bring a tunnel up.
//
// controller-interface Requirement 8: the whole key distribution path.
// Each server's helm generates its VTEP's key pair (TunnelKeyring) and
// reports the public key; the controller signs each VTEP's peer set
// (TunnelPeers) and sends it as a ControllerLink record; helm forwards it
// unmodified (ControllerSession's dispatch is controller_session_test's;
// controller_link.hpp and oar_link.hpp cannot share a translation unit
// until helm main renames ControllerLink's LinkError); the role verifies it (TunnelPeerSet with
// hull's Ed25519 verifier) and installs the peers; the tunnel comes up.

#define BOOST_TEST_MODULE tunnel_keys_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <thread>
#include <vector>

#include "ed25519_test_support.hpp"
#include "helm/oar_link.hpp"
#include "helm/oar_protocol.hpp"
#include "helm/sideband_binding.hpp"
#include "helm/tunnel_keyring.hpp"
#include "hull/signature_verifier.hpp"
#include "oar/net/tunnel.hpp"
#include "oar/net/tunnel_peers.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/link.hpp"
#include "proto/report.hpp"
#include "proto/tunnel_peers.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;
namespace oar = ak::helm::oar;
using ak::helm::BindingError;
using ak::helm::InProcessBinding;
using ak::helm::LinkConfig;
using ak::helm::LinkErrc;
using ak::helm::OarEndpoint;
using ak::helm::OarHandler;
using ak::helm::OarLink;
using ak::test::unit_timeout_seconds;
using namespace std::chrono_literals;

namespace {

constexpr ak::helm::LinkAddress helm_side{
    .local_addr = 0x10, .peer_addr = 0x20, .local_eid = 8, .peer_eid = 9};

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a.back() = std::byte{tail};
    return a;
}

// Datagrams between the two roles' tunnels, delivered by hand.
struct Wire {
    struct Datagram {
        net::Ipv6Address from{};
        net::Ipv6Address to{};
        std::vector<std::byte> bytes;
    };
    std::deque<Datagram> queue;
};

class WireSender final : public net::DatagramSender {
public:
    WireSender(Wire& wire, const net::Ipv6Address& self) : _wire{&wire}, _self{self} {}
    auto send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool override {
        _wire->queue.push_back(
            {.from = _self, .to = dst, .bytes = {payload.begin(), payload.end()}});
        return true;
    }

private:
    Wire* _wire;
    net::Ipv6Address _self;
};

// The tunnel-key half of a network role: what task 11's NetRole will do
// with these requests.
class KeyRole final : public OarHandler {
public:
    explicit KeyRole(net::Tunnel& tunnel) : _tunnel{&tunnel} {}

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return std::unexpected(oar::Status::unsupported);
    }
    auto prepare_function(const oar::PrepareFunction& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto map_update(std::span<const std::byte> /*frame*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }

    auto set_tunnel_key(const oar::SetTunnelKey& r) -> oar::Status override {
        return _tunnel->set_private_key(r.private_key) ? oar::Status::ok : oar::Status::failed;
    }
    auto set_tunnel_peer(const oar::SetTunnelPeer& r) -> oar::Status override {
        return _tunnel->set_peer(r.vtep, r.public_key, r.psk) ? oar::Status::ok
                                                              : oar::Status::failed;
    }
    auto remove_tunnel_peer(const oar::RemoveTunnelPeer& r) -> oar::Status override {
        return _tunnel->remove_peer(r.vtep) ? oar::Status::ok : oar::Status::failed;
    }

private:
    net::Tunnel* _tunnel;
};

// One role: its tunnel, its sideband endpoint served on a thread, and
// helm's link to it.
struct Role {
    Role(Wire& wire, std::uint8_t tail)
        : addr{vtep(tail)},
          sender{wire, addr},
          tunnel{net::Tunnel::create(sender, {}).value()},
          handler{*tunnel},
          bindings{InProcessBinding::make_pair()},
          endpoint{*bindings.second,
                   LinkConfig{.address = helm_side.reversed(), .mtu = 64, .timeout = 5s}},
          link{*bindings.first, LinkConfig{.address = helm_side, .mtu = 64, .timeout = 5s}} {}

    auto serve() -> std::jthread {
        return std::jthread{[this](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint.serve_one(handler, 10ms);
                if (!r && r.error() != BindingError::timed_out) {
                    return;
                }
            }
        }};
    }

    net::Ipv6Address addr;
    WireSender sender;
    std::unique_ptr<net::Tunnel> tunnel;
    KeyRole handler;
    std::pair<std::unique_ptr<InProcessBinding>, std::unique_ptr<InProcessBinding>> bindings;
    OarEndpoint endpoint;
    OarLink link;
};

}  // namespace

BOOST_AUTO_TEST_CASE(helm_keys_two_roles, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Wire wire;
    Role one{wire, 1};
    Role two{wire, 2};

    // helm's side: a key per role and a PSK for the pair.
    auto k1 = wg::generate_private_key();
    auto k2 = wg::generate_private_key();
    BOOST_REQUIRE(k1.has_value());
    BOOST_REQUIRE(k2.has_value());
    const auto p1 = wg::public_key(k1->span());
    const auto p2 = wg::public_key(k2->span());
    BOOST_REQUIRE(p1.has_value());
    BOOST_REQUIRE(p2.has_value());
    std::array<std::byte, wg::key_size> psk{};
    psk.fill(std::byte{0x33});

    {
        const auto s1 = one.serve();
        const auto s2 = two.serve();
        BOOST_TEST(one.link.set_tunnel_key(k1->span()).has_value());
        BOOST_TEST(two.link.set_tunnel_key(k2->span()).has_value());
        BOOST_TEST(one.link.set_tunnel_peer({.vtep = two.addr, .public_key = *p2, .psk = psk})
                       .has_value());
        BOOST_TEST(two.link.set_tunnel_peer({.vtep = one.addr, .public_key = *p1, .psk = psk})
                       .has_value());

        // The role refuses keys the tunnel cannot use, and says so.
        wg::Key low_order{};
        low_order[0] = std::byte{1};
        const auto refused =
            one.link.set_tunnel_peer({.vtep = vtep(3), .public_key = low_order, .psk = psk});
        BOOST_REQUIRE(!refused.has_value());
        BOOST_TEST((refused.error().code == LinkErrc::refused));
        BOOST_TEST((refused.error().status == oar::Status::failed));
        // Invalid keys never reach the wire.
        const wg::Key zero{};
        BOOST_TEST((one.link.set_tunnel_key(zero).error().code == LinkErrc::bad_request));
        BOOST_TEST(
            (one.link.remove_tunnel_peer({.vtep = vtep(3)}).error().status == oar::Status::failed));
    }
    BOOST_TEST((one.tunnel->public_key() == *p1));
    BOOST_TEST((two.tunnel->public_key() == *p2));

    // The keyed tunnels negotiate and carry a payload.
    const std::array<std::byte, 3> payload{std::byte{1}, std::byte{2}, std::byte{3}};
    BOOST_TEST(!one.tunnel->send_to(two.addr, net::flow_port_base, net::flow_port_base, payload));
    std::vector<std::vector<std::byte>> out;
    const auto run = [&] {
        while (!wire.queue.empty()) {
            auto d = std::move(wire.queue.front());
            wire.queue.pop_front();
            Role& to = d.to == one.addr ? one : two;
            if (auto o = to.tunnel->receive(d.bytes, d.from)) {
                out.emplace_back(o->payload.begin(), o->payload.end());
            }
        }
    };
    run();
    BOOST_TEST(one.tunnel->send_to(two.addr, net::flow_port_base, net::flow_port_base, payload));
    run();
    BOOST_REQUIRE(out.size() == 1U);
    BOOST_TEST(std::ranges::equal(out[0], payload));

    // helm removes the peer: the role stops sending to it.
    {
        const auto s1 = one.serve();
        BOOST_TEST(one.link.remove_tunnel_peer({.vtep = two.addr}).has_value());
    }
    BOOST_TEST(!one.tunnel->send_to(two.addr, net::flow_port_base, net::flow_port_base, payload));
    BOOST_TEST(one.tunnel->counters().tx_no_peer == 1U);
}

namespace {

namespace proto = ak::proto;

constexpr proto::KeyId controller_key_id = 1;

// hull's verifier holds the controller key; the role's FrameVerifier wraps it.
auto controller_verifier() -> net::FrameVerifier {
    const std::array keys{ak::test::controller_key(controller_key_id, ak::test::rfc_test1_public)};
    auto v = std::make_shared<ak::hull::SignatureVerifier>(
        ak::hull::SignatureVerifier::create(keys).value());
    return [v](std::span<const std::byte> signed_bytes,
               std::span<const std::byte, net::frame_signature_size> sig,
               std::uint16_t key_id) { return v->verify(signed_bytes, sig, key_id).has_value(); };
}

// A network role that takes its private key from helm and its peers only
// from verified controller frames.
class PeerSetRole final : public OarHandler {
public:
    PeerSetRole(net::Tunnel& tunnel, std::uint64_t server_id, const net::Ipv6Address& vtep)
        : _tunnel{&tunnel}, peers{tunnel, server_id, vtep, controller_verifier()} {}

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return std::unexpected(oar::Status::unsupported);
    }
    auto prepare_function(const oar::PrepareFunction& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto map_update(std::span<const std::byte> /*frame*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto set_tunnel_key(const oar::SetTunnelKey& r) -> oar::Status override {
        return _tunnel->set_private_key(r.private_key) ? oar::Status::ok : oar::Status::failed;
    }
    auto tunnel_peers(std::span<const std::byte> frame) -> oar::Status override {
        return net::accepted(peers.apply(frame)) ? oar::Status::ok : oar::Status::failed;
    }

private:
    net::Tunnel* _tunnel;

public:
    net::TunnelPeerSet peers;
};

// helm's ControllerSink::on_tunnel_peers for one server: forwards each
// peer set to the VTEP's role through the keyring, as the daemon does.
class HelmSink {
public:
    HelmSink(ak::helm::TunnelKeyring& ring, OarLink& link) : _ring{&ring}, _link{&link} {}
    auto on_tunnel_peers(const proto::TunnelPeers& t, std::span<const std::byte> frame) -> void {
        if (_ring->store_peers(t, frame) == ak::helm::PeersOutcome::stored) {
            forwarded.push_back(_link->tunnel_peers(frame).has_value());
        }
    }
    std::vector<bool> forwarded;

private:
    ak::helm::TunnelKeyring* _ring;
    OarLink* _link;
};

// One server: its helm (keyring, controller session) and its network role.
struct Server {
    Server(Wire& wire, std::uint64_t id, std::uint8_t tail)
        : server_id{id},
          addr{vtep(tail)},
          sender{wire, addr},
          tunnel{net::Tunnel::create(sender, {}).value()},
          handler{*tunnel, id, addr},
          bindings{InProcessBinding::make_pair()},
          endpoint{*bindings.second,
                   LinkConfig{.address = helm_side.reversed(), .mtu = 64, .timeout = 5s}},
          link{*bindings.first, LinkConfig{.address = helm_side, .mtu = 64, .timeout = 5s}},
          sink{ring, link} {}

    auto serve() -> std::jthread {
        return std::jthread{[this](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint.serve_one(handler, 10ms);
                if (!r && r.error() != BindingError::timed_out) {
                    return;
                }
            }
        }};
    }

    // What the controller learns at registration: the VTEP's public key,
    // from the inventory report helm encodes.
    auto registered_key() -> proto::TunnelPublicKey {
        proto::Inventory inv;
        inv.boot_id = 1;
        inv.vteps = {addr};
        ring.fill(inv);
        const auto bytes = proto::encode_report(
            {.server_id = server_id, .report_seq = 1, .body = proto::ReportBody{inv}});
        BOOST_REQUIRE(bytes.has_value());
        auto report = proto::decode_report(*bytes);
        BOOST_REQUIRE(report.has_value());
        const auto& got = std::get<proto::Inventory>(report->body);
        BOOST_REQUIRE(got.tunnels.size() == 1U);
        BOOST_TEST(got.tunnels[0].modes == proto::tunnel_mode_bit(proto::TunnelMode::wireguard));
        return got.tunnels[0].public_key;
    }

    // A controller record arriving at helm: decoded and checked the way
    // ControllerSession does, then handed to the sink.
    auto deliver(const std::vector<std::byte>& record) -> bool {
        proto::RecordDecoder d;
        d.feed(record);
        auto rec = d.next();
        if (!rec || !rec->has_value() || (*rec)->type != proto::RecordType::tunnel_peers) {
            return false;
        }
        auto peers = proto::decode_tunnel_peers((*rec)->payload);
        if (!peers || peers->server_id != server_id) {
            return false;
        }
        sink.on_tunnel_peers(*peers, (*rec)->payload);
        return true;
    }

    std::uint64_t server_id;
    net::Ipv6Address addr;
    WireSender sender;
    std::unique_ptr<net::Tunnel> tunnel;
    PeerSetRole handler;
    std::pair<std::unique_ptr<InProcessBinding>, std::unique_ptr<InProcessBinding>> bindings;
    OarEndpoint endpoint;
    OarLink link;
    ak::helm::TunnelKeyring ring;
    HelmSink sink;
};

// The controller's TunnelPeers record for `to`, naming `peers`, signed
// with `secret` (RFC 8032 test key 1 is the one the roles trust).
auto peers_record(const Server& to, std::uint64_t version, std::vector<proto::TunnelPeer> peers,
                  std::string_view secret = ak::test::rfc_test1_secret) -> std::vector<std::byte> {
    proto::TunnelPeers t{.server_id = to.server_id,
                         .key_id = controller_key_id,
                         .vtep = to.addr,
                         .peers_version = version,
                         .peers = std::move(peers),
                         .signature = {}};
    auto frame = proto::encode_tunnel_peers(t).value();
    const ak::test::TestSigner signer{secret};
    proto::set_tunnel_peers_signature(frame, signer.sign(proto::tunnel_peers_signed_bytes(frame)));
    return proto::encode_record(proto::RecordType::tunnel_peers, frame).value();
}

}  // namespace

BOOST_AUTO_TEST_CASE(controller_distributes_vtep_keys,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Wire wire;
    Server a{wire, 0xA, 1};
    Server b{wire, 0xB, 2};

    // Each helm makes its VTEP's key pair when the role attaches, and
    // gives the role its private key.
    BOOST_REQUIRE(a.ring.ensure(a.addr, 0).has_value());
    BOOST_REQUIRE(b.ring.ensure(b.addr, 0).has_value());
    {
        const auto sa = a.serve();
        const auto sb = b.serve();
        BOOST_TEST(a.ring.provision(a.link, a.addr).has_value());
        BOOST_TEST(b.ring.provision(b.link, b.addr).has_value());
    }
    // The controller learns the public keys from the inventories.
    const auto key_a = a.registered_key();
    const auto key_b = b.registered_key();
    BOOST_TEST((key_a == a.tunnel->public_key().value()));
    BOOST_TEST((key_b == b.tunnel->public_key().value()));

    // Before any peer set, the VTEPs cannot reach each other.
    const std::array<std::byte, 3> payload{std::byte{1}, std::byte{2}, std::byte{3}};
    BOOST_TEST(!a.tunnel->send_to(b.addr, net::flow_port_base, net::flow_port_base, payload));
    BOOST_TEST(a.tunnel->counters().tx_no_peer == 1U);

    // The controller sends each VTEP the other's key; helm forwards it.
    {
        const auto sa = a.serve();
        const auto sb = b.serve();
        BOOST_TEST(a.deliver(peers_record(
            a, 1,
            {{.vtep = b.addr, .mode = proto::TunnelMode::wireguard, .spi = 0, .key = key_b}})));
        BOOST_TEST(b.deliver(peers_record(
            b, 1,
            {{.vtep = a.addr, .mode = proto::TunnelMode::wireguard, .spi = 0, .key = key_a}})));
    }
    BOOST_TEST((a.sink.forwarded == std::vector<bool>{true}));
    BOOST_TEST((b.sink.forwarded == std::vector<bool>{true}));
    BOOST_TEST(a.handler.peers.version() == 1U);

    // The tunnel negotiates and carries a payload.
    std::vector<std::vector<std::byte>> out;
    const auto run = [&] {
        while (!wire.queue.empty()) {
            auto d = std::move(wire.queue.front());
            wire.queue.pop_front();
            Server& to = d.to == a.addr ? a : b;
            if (auto o = to.tunnel->receive(d.bytes, d.from)) {
                out.emplace_back(o->payload.begin(), o->payload.end());
            }
        }
    };
    BOOST_TEST(!a.tunnel->send_to(b.addr, net::flow_port_base, net::flow_port_base, payload));
    run();
    BOOST_TEST(a.tunnel->send_to(b.addr, net::flow_port_base, net::flow_port_base, payload));
    run();
    BOOST_REQUIRE(out.size() == 1U);
    BOOST_TEST(std::ranges::equal(out[0], payload));

    {
        const auto sa = a.serve();
        // A peer set signed by a key the role does not trust is refused by
        // the role, though helm (which verifies nothing) forwarded it.
        BOOST_TEST(a.deliver(peers_record(a, 2, {}, ak::test::rfc_test2_secret)));
        BOOST_TEST((a.sink.forwarded == std::vector<bool>{true, false}));
        BOOST_TEST(a.handler.peers.counters().bad_signature == 1U);
        BOOST_TEST(a.handler.peers.version() == 1U);

        // An older version never leaves helm.
        BOOST_TEST(a.deliver(peers_record(a, 1, {})));
        BOOST_TEST(a.sink.forwarded.size() == 2U);

        // The real version 2 is not shadowed by the forged one: helm
        // forwards it, and the role applies it, withdrawing the peer.
        BOOST_TEST(a.deliver(peers_record(a, 2, {})));
        BOOST_TEST((a.sink.forwarded == std::vector<bool>{true, false, true}));
        // Exactly the same frame again is not forwarded twice.
        BOOST_TEST(a.deliver(peers_record(a, 2, {})));
        BOOST_TEST(a.sink.forwarded.size() == 3U);
    }
    BOOST_TEST(a.handler.peers.version() == 2U);
    BOOST_TEST(a.tunnel->peers().empty());
    BOOST_TEST(!a.tunnel->send_to(b.addr, net::flow_port_base, net::flow_port_base, payload));
}
