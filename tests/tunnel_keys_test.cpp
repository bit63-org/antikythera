// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 5.2 (task 10): helm delivers
// the network role's WireGuard keys over the sideband (OarLink ->
// OarEndpoint), and two roles keyed that way bring a tunnel up.

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

#include "helm/oar_link.hpp"
#include "helm/oar_protocol.hpp"
#include "helm/sideband_binding.hpp"
#include "oar/net/tunnel.hpp"
#include "oar/net/wireguard.hpp"
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
