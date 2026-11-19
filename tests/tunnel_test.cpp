// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 5 (task 10): the WireGuard
// Tunnel between the Vtep and the underlay: handshake, transport, drops
// before Geneve decode, timers and key changes, and the Vtep running over
// it end to end.

#define BOOST_TEST_MODULE tunnel_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_frames.hpp"
#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/tunnel.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/vswitch.hpp"
#include "oar/net/vtep.hpp"
#include "oar/net/wireguard.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;
namespace geneve = ak::oar::net::geneve;
using ak::test::unit_timeout_seconds;
using net::TunnelDrop;
using std::chrono::milliseconds;
using std::chrono::seconds;

namespace {

constexpr std::size_t ipv6_last = 15;
constexpr std::byte ula_prefix{0xfd};
constexpr std::uint16_t flow = 50'000;
constexpr wg::Key no_psk{};

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto bytes(std::string_view s) -> std::vector<std::byte> {
    const auto b = std::as_bytes(std::span{s});
    return {b.begin(), b.end()};
}

auto key_of(std::uint8_t fill) -> wg::Key {
    wg::Key k{};
    k.fill(std::byte{fill});
    return k;
}

struct Datagram {
    net::Ipv6Address from{};
    net::Ipv6Address to{};
    std::uint16_t port{0};
    std::uint16_t flow_port{0};
    std::vector<std::byte> bytes;
};

// A shared clock and an underlay that queues every datagram until delivered.
struct World {
    net::VtepClock::time_point now{seconds{1000}};
    std::chrono::system_clock::time_point wall{seconds{1'700'000'000}};
    std::deque<Datagram> queue;
    bool refuse{false};

    auto advance(milliseconds d) -> void {
        now += d;
        wall += d;
    }

    auto config() -> net::TunnelConfig {
        return {.clock = [this] { return now; }, .wall_clock = [this] { return wall; }};
    }
};

class QueueSender final : public net::DatagramSender {
public:
    QueueSender(World& world, const net::Ipv6Address& self) : _world{&world}, _self{self} {}
    auto send_to(const net::Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                 std::span<const std::byte> payload) -> bool override {
        if (_world->refuse) {
            return false;
        }
        _world->queue.push_back({.from = _self,
                                 .to = dst,
                                 .port = dst_port,
                                 .flow_port = flow_port,
                                 .bytes = {payload.begin(), payload.end()}});
        return true;
    }

private:
    World* _world;
    net::Ipv6Address _self;
};

struct Node {
    Node(World& world, std::uint8_t tail, net::TunnelConfig config)
        : addr{vtep(tail)}, sender{world, addr} {
        auto t = net::Tunnel::create(sender, std::move(config));
        BOOST_REQUIRE(t.has_value());
        tunnel = std::move(*t);
        auto k = wg::generate_private_key();
        BOOST_REQUIRE(k.has_value());
        priv = std::move(*k);
        BOOST_REQUIRE(tunnel->set_private_key(priv.span()).has_value());
        pub = *tunnel->public_key();
    }
    net::Ipv6Address addr;
    QueueSender sender;
    std::unique_ptr<net::Tunnel> tunnel;
    wg::SecretKey priv;
    wg::Key pub{};
};

auto pair(Node& a, Node& b, const wg::Key& psk = {}) -> void {
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, b.pub, psk).has_value());
    BOOST_REQUIRE(b.tunnel->set_peer(a.addr, a.pub, psk).has_value());
}

auto drops(const net::Tunnel& t, TunnelDrop d) -> std::uint64_t {
    return t.counters().rx_drop.at(static_cast<std::size_t>(d));
}

struct Fixture {
    Fixture() : a{world, 1, world.config()}, b{world, 2, world.config()} { pair(a, b); }

    auto node(const net::Ipv6Address& addr) -> Node* {
        for (Node* n : {&a, &b}) {
            if (n->addr == addr) {
                return n;
            }
        }
        return nullptr;
    }

    // Delivers queued datagrams in order; returns the payloads that came out.
    auto deliver(std::size_t max = 100)
        -> std::vector<std::pair<net::Ipv6Address, std::vector<std::byte>>> {
        std::vector<std::pair<net::Ipv6Address, std::vector<std::byte>>> out;
        for (std::size_t i = 0; i < max && !world.queue.empty(); ++i) {
            auto d = std::move(world.queue.front());
            world.queue.pop_front();
            if (Node* n = node(d.to)) {
                if (auto o = n->tunnel->receive(d.bytes, d.from)) {
                    BOOST_TEST((o->peer == d.from));
                    out.emplace_back(o->peer,
                                     std::vector<std::byte>{o->payload.begin(), o->payload.end()});
                }
            }
        }
        return out;
    }

    // Runs the handshake a starts by sending, through to b's confirmation.
    auto establish() -> void {
        BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("first")));
        static_cast<void>(deliver());
        BOOST_REQUIRE(a.tunnel->peers().at(0).session);
        BOOST_REQUIRE(b.tunnel->peers().at(0).session);
    }

    World world;
    Node a;
    Node b;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(configuration)

BOOST_AUTO_TEST_CASE(config_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    World world;
    QueueSender s{world, vtep(1)};
    BOOST_TEST(net::Tunnel::create(s, {}).has_value());
    const auto refused = [&](auto mutate) {
        net::TunnelConfig c;
        mutate(c);
        return net::Tunnel::create(s, c).error();
    };
    BOOST_TEST((refused([](auto& c) { c.peer_port = 0; }) == net::TunnelConfigError::bad_port));
    BOOST_TEST((refused([](auto& c) { c.rekey_timeout = milliseconds{0}; }) ==
                net::TunnelConfigError::bad_timers));
    BOOST_TEST((refused([](auto& c) { c.rekey_after_time = seconds{200}; }) ==
                net::TunnelConfigError::bad_timers));
    BOOST_TEST((refused([](auto& c) { c.rekey_after_messages = ~std::uint64_t{0}; }) ==
                net::TunnelConfigError::bad_limits));
}

BOOST_AUTO_TEST_CASE(key_validation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    World world;
    Node a{world, 1, world.config()};
    Node b{world, 2, world.config()};
    BOOST_TEST((a.tunnel->set_private_key(wg::Key{}).error() == net::TunnelKeyError::bad_key));
    BOOST_TEST(
        (a.tunnel->set_peer(b.addr, wg::Key{}, no_psk).error() == net::TunnelKeyError::bad_key));
    wg::Key low_order{};
    low_order[0] = std::byte{1};
    BOOST_TEST(
        (a.tunnel->set_peer(b.addr, low_order, no_psk).error() == net::TunnelKeyError::bad_key));
    BOOST_TEST((a.tunnel->set_peer(b.addr, a.pub, no_psk).error() == net::TunnelKeyError::own_key));
    BOOST_TEST(a.tunnel->set_peer(b.addr, b.pub, no_psk).has_value());
    BOOST_TEST(
        (a.tunnel->set_peer(vtep(3), b.pub, no_psk).error() == net::TunnelKeyError::duplicate_key));
    // The role's own key may not be a peer's.
    BOOST_TEST((a.tunnel->set_private_key(b.priv.span()).error() == net::TunnelKeyError::own_key));
    BOOST_TEST(a.tunnel->remove_peer(b.addr));
    BOOST_TEST(!a.tunnel->remove_peer(b.addr));
    BOOST_TEST(a.tunnel->peers().empty());
    a.tunnel->clear_private_key();
    BOOST_TEST(!a.tunnel->public_key().has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(handshake)

BOOST_FIXTURE_TEST_CASE(establish_then_carry_both_ways, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // No session yet: the first send starts a handshake and is dropped.
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("first")));
    BOOST_TEST(a.tunnel->counters().tx_no_session == 1U);
    BOOST_TEST(a.tunnel->counters().initiations_tx == 1U);
    BOOST_REQUIRE(world.queue.size() == 1U);
    BOOST_TEST(world.queue.front().bytes.size() == wg::initiation_size);
    BOOST_TEST(world.queue.front().port == geneve::udp_port);

    // initiation -> response -> keepalive.
    BOOST_TEST(deliver().empty());
    BOOST_TEST(b.tunnel->counters().initiations_rx == 1U);
    BOOST_TEST(b.tunnel->counters().responses_tx == 1U);
    BOOST_TEST(a.tunnel->counters().responses_rx == 1U);
    BOOST_TEST(b.tunnel->counters().rx_keepalives == 1U);
    BOOST_TEST(a.tunnel->peers().at(0).session);
    BOOST_TEST(b.tunnel->peers().at(0).session);  // confirmed by the keepalive

    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("hello b")));
    BOOST_REQUIRE(world.queue.size() == 1U);
    BOOST_TEST(world.queue.front().flow_port == flow);  // ECMP entropy survives
    BOOST_TEST(world.queue.front().bytes.size() == wg::transport_overhead + 7);
    auto got = deliver();
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST((got[0].first == a.addr));
    BOOST_TEST((got[0].second == bytes("hello b")));

    BOOST_TEST(b.tunnel->send_to(a.addr, geneve::udp_port, flow, bytes("hello a")));
    got = deliver();
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST((got[0].second == bytes("hello a")));
    BOOST_TEST(a.tunnel->counters().rx_packets == 1U);
    BOOST_TEST(b.tunnel->counters().rx_packets == 1U);
    BOOST_TEST(a.tunnel->counters().tx_bytes == 7U);
}

BOOST_FIXTURE_TEST_CASE(simultaneous_initiations, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Both sides start at once, as two Vteps' first keepalives do.
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    BOOST_TEST(!b.tunnel->send_to(a.addr, geneve::udp_port, flow, bytes("y")));
    static_cast<void>(deliver());
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("ab")));
    BOOST_TEST(b.tunnel->send_to(a.addr, geneve::udp_port, flow, bytes("ba")));
    const auto got = deliver();
    BOOST_REQUIRE(got.size() == 2U);
    BOOST_TEST((got[0].second == bytes("ab")));
    BOOST_TEST((got[1].second == bytes("ba")));
}

BOOST_FIXTURE_TEST_CASE(psk_mismatch_fails, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, b.pub, key_of(1)).has_value());
    BOOST_REQUIRE(b.tunnel->set_peer(a.addr, a.pub, key_of(2)).has_value());
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver());
    // b answers (the psk enters only at the response) but a cannot open it.
    BOOST_TEST(b.tunnel->counters().responses_tx == 1U);
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::decrypt_failed) == 1U);
    BOOST_TEST(!a.tunnel->peers().at(0).session);
}

BOOST_FIXTURE_TEST_CASE(psk_match_works, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    pair(a, b, key_of(7));
    establish();
}

BOOST_FIXTURE_TEST_CASE(unknown_and_misaddressed_initiations, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // c knows b's key, but b does not know c's.
    Node c{world, 3, world.config()};
    BOOST_REQUIRE(c.tunnel->set_peer(b.addr, b.pub, no_psk).has_value());
    BOOST_TEST(!c.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    auto d = std::move(world.queue.front());
    world.queue.clear();
    BOOST_TEST(!b.tunnel->receive(d.bytes, c.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::unknown_peer) == 1U);
    BOOST_TEST(world.queue.empty());  // no response

    // An initiation for someone else's key fails mac1 before any DH.
    BOOST_TEST(!a.tunnel->receive(d.bytes, c.addr).has_value());
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::bad_mac1) == 1U);

    // a's initiation to b, but arriving from another address.
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    d = std::move(world.queue.front());
    world.queue.clear();
    BOOST_TEST(!b.tunnel->receive(d.bytes, c.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::wrong_source) == 1U);

    // A tampered initiation fails mac1 too.
    d.bytes[10] ^= std::byte{1};
    BOOST_TEST(!b.tunnel->receive(d.bytes, a.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::bad_mac1) == 1U);
}

BOOST_FIXTURE_TEST_CASE(replayed_initiation_refused, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    const auto init = world.queue.front();
    static_cast<void>(deliver());
    world.advance(seconds{1});
    BOOST_TEST(!b.tunnel->receive(init.bytes, a.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::stale_timestamp) == 1U);
    BOOST_TEST(world.queue.empty());
}

BOOST_FIXTURE_TEST_CASE(initiation_flood_rate_limited, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver(1));
    world.queue.clear();
    // a retries (new timestamp) within the minimum interval.
    world.wall += seconds{1};
    world.now += milliseconds{5};
    a.tunnel->clear_private_key();
    BOOST_REQUIRE(a.tunnel->set_private_key(a.priv.span()).has_value());
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver(1));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::rate_limited) == 1U);
}

BOOST_FIXTURE_TEST_CASE(stray_responses_and_cookies, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver(1));  // b answers; hold the response
    BOOST_REQUIRE(world.queue.size() == 1U);
    auto resp = world.queue.front();
    world.queue.clear();
    // From the wrong address.
    BOOST_TEST(!a.tunnel->receive(resp.bytes, vtep(9)).has_value());
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::wrong_source) == 1U);
    // Delivered properly, then replayed: its index now names a session.
    BOOST_TEST(!a.tunnel->receive(resp.bytes, b.addr).has_value());
    BOOST_TEST(a.tunnel->peers().at(0).session);
    BOOST_TEST(!a.tunnel->receive(resp.bytes, b.addr).has_value());
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::unknown_index) == 1U);

    std::vector<std::byte> cookie(wg::cookie_reply_size);
    cookie[0] = std::byte{3};
    BOOST_TEST(!a.tunnel->receive(cookie, b.addr).has_value());
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::cookie_reply) == 1U);

    BOOST_TEST(!a.tunnel->receive(bytes("junk"), b.addr).has_value());
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::malformed) == 1U);
    BOOST_TEST(a.tunnel->counters().rx_drop_parse.at(
                   static_cast<std::size_t>(wg::ParseError::unknown_type)) == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(transport)

BOOST_FIXTURE_TEST_CASE(forgeries_dropped_before_decode, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("payload")));
    const auto good = world.queue.front();
    world.queue.clear();

    auto tampered = good.bytes;
    tampered.back() ^= std::byte{1};
    BOOST_TEST(!b.tunnel->receive(tampered, a.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::decrypt_failed) == 1U);

    BOOST_TEST(!b.tunnel->receive(good.bytes, vtep(9)).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::wrong_source) == 1U);

    BOOST_TEST(b.tunnel->receive(good.bytes, a.addr).has_value());
    BOOST_TEST(!b.tunnel->receive(good.bytes, a.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::replay) == 1U);

    auto unknown = good.bytes;
    unknown[4] ^= std::byte{0xff};
    BOOST_TEST(!b.tunnel->receive(unknown, a.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::unknown_index) == 1U);
}

BOOST_FIXTURE_TEST_CASE(reordered_packets_accepted, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    for (const auto* s : {"one", "two", "three"}) {
        BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes(s)));
    }
    std::swap(world.queue[0], world.queue[2]);
    const auto got = deliver();
    BOOST_REQUIRE(got.size() == 3U);
    BOOST_TEST((got[0].second == bytes("three")));
    BOOST_TEST((got[2].second == bytes("one")));
}

BOOST_FIXTURE_TEST_CASE(sends_without_keys_or_peer, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!a.tunnel->send_to(vtep(9), geneve::udp_port, flow, bytes("x")));
    BOOST_TEST(a.tunnel->counters().tx_no_peer == 1U);
    a.tunnel->clear_private_key();
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    BOOST_TEST(a.tunnel->counters().tx_no_key == 1U);
    BOOST_TEST(world.queue.empty());
    BOOST_TEST(!b.tunnel->send_to(a.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver());
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::no_private_key) == 1U);
}

BOOST_FIXTURE_TEST_CASE(underlay_refusal_counted, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    world.refuse = true;
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    BOOST_TEST(a.tunnel->counters().tx_send_failed == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(timers)

BOOST_FIXTURE_TEST_CASE(retransmit_then_give_up, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    world.queue.clear();  // lost
    const auto next = a.tunnel->tick();
    BOOST_TEST((next == world.now + seconds{5}));
    // A send inside rekey_timeout does not start another initiation.
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    BOOST_TEST(world.queue.empty());
    world.advance(seconds{5});
    static_cast<void>(a.tunnel->tick());
    BOOST_TEST(a.tunnel->counters().initiations_tx == 2U);
    world.queue.clear();
    for (int i = 0; i < 20; ++i) {
        world.advance(seconds{5});
        static_cast<void>(a.tunnel->tick());
        world.queue.clear();
    }
    BOOST_TEST(a.tunnel->counters().handshake_timeouts == 1U);
    BOOST_TEST(!a.tunnel->peers().at(0).handshaking);
    BOOST_TEST((a.tunnel->tick() == net::VtepClock::time_point::max()));
}

BOOST_FIXTURE_TEST_CASE(retransmission_completes, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    world.queue.clear();
    world.advance(seconds{5});
    static_cast<void>(a.tunnel->tick());
    static_cast<void>(deliver());
    BOOST_TEST(a.tunnel->peers().at(0).session);
}

BOOST_FIXTURE_TEST_CASE(rekey_keeps_traffic_flowing, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    world.advance(seconds{121});
    // Past rekey_after_time: this send still goes out and starts a rekey.
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("old")));
    BOOST_TEST(a.tunnel->counters().initiations_tx == 2U);
    const auto got = deliver();
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST((got[0].second == bytes("old")));
    BOOST_TEST(a.tunnel->counters().sessions_established == 2U);
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("new")));
    BOOST_TEST(b.tunnel->send_to(a.addr, geneve::udp_port, flow, bytes("back")));
    BOOST_TEST(deliver().size() == 2U);
}

BOOST_FIXTURE_TEST_CASE(expired_sessions_destroyed, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("late")));
    const auto late = world.queue.front();
    world.queue.clear();
    BOOST_TEST((a.tunnel->tick() == world.now + seconds{180}));
    world.advance(seconds{180});
    // Too old to receive on, even before tick() destroys it.
    BOOST_TEST(!b.tunnel->receive(late.bytes, a.addr).has_value());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::expired_session) == 1U);
    static_cast<void>(a.tunnel->tick());
    static_cast<void>(b.tunnel->tick());
    BOOST_TEST(!a.tunnel->peers().at(0).session);
    BOOST_TEST(!b.tunnel->peers().at(0).session);
    // Traffic negotiates a new one.
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver());
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("y")));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(key_changes)

BOOST_FIXTURE_TEST_CASE(same_keys_keep_sessions, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, b.pub, no_psk).has_value());
    BOOST_REQUIRE(a.tunnel->set_private_key(a.priv.span()).has_value());
    BOOST_TEST(a.tunnel->peers().at(0).session);
}

BOOST_FIXTURE_TEST_CASE(new_keys_drop_sessions, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    establish();
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, b.pub, key_of(4)).has_value());
    BOOST_TEST(!a.tunnel->peers().at(0).session);
    BOOST_REQUIRE(b.tunnel->set_peer(a.addr, a.pub, key_of(4)).has_value());
    establish();

    // b rotates its static key; a learns the new public key from helm.
    auto k = wg::generate_private_key();
    BOOST_REQUIRE(k.has_value());
    BOOST_REQUIRE(b.tunnel->set_private_key(k->span()).has_value());
    BOOST_TEST(!b.tunnel->peers().at(0).session);
    // Old sessions are gone on b: a's packets on them are unknown.
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, bytes("x")));
    static_cast<void>(deliver());
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::unknown_index) == 1U);
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, *b.tunnel->public_key(), key_of(4)).has_value());
    world.advance(seconds{1});
    establish();
}

BOOST_AUTO_TEST_SUITE_END()

// ---- With the Vtep --------------------------------------------------------

namespace {

constexpr std::uint32_t vpc = 100;
constexpr geneve::NicId nic_a{11};
constexpr geneve::NicId nic_c{33};
constexpr std::size_t mac_last = 5;

auto mac_of(geneve::NicId id) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = std::byte{0x02};
    m[mac_last] = static_cast<std::byte>(id.value);
    return m;
}

// Each guest is at 10.0.0.<NIC ID>; the VSwitch only forwards IP from the
// sender's own address to the destination NIC's (Requirement 11).
auto ip_of(geneve::NicId id) -> net::neighbor::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{0}, static_cast<std::byte>(id.value)};
}

auto frame(geneve::NicId dst, geneve::NicId src) -> std::vector<std::byte> {
    constexpr std::uint8_t ipproto_udp = 17;
    constexpr std::uint16_t client_port = 40000;
    constexpr std::uint16_t server_port = 80;
    const std::vector<std::byte> payload(32, std::byte{0x5a});
    return ak::test::frames::ipv4(mac_of(dst), mac_of(src), ip_of(src), ip_of(dst), ipproto_udp,
                                  ak::test::frames::udp(client_port, server_port, payload));
}

auto mappings(net::MappingTable& t, const net::Ipv6Address& one, const net::Ipv6Address& two)
    -> void {
    BOOST_REQUIRE(
        t.apply({.vni = vpc,
                 .version = 1,
                 .entries = {{.nic_id = nic_a, .mac = mac_of(nic_a), .owner_vtep = one},
                             {.nic_id = nic_c, .mac = mac_of(nic_c), .owner_vtep = two}}}));
}

struct FakePort final : net::RxPort {
    auto deliver(std::span<const std::byte> f) -> net::RxResult override {
        frames.emplace_back(f.begin(), f.end());
        return net::RxResult::delivered;
    }
    std::vector<std::vector<std::byte>> frames;
};

struct Side {
    Side(World& world, std::uint8_t tail, const net::Ipv6Address& other)
        : node{world, tail, world.config()}, table{node.addr} {
        mappings(table, tail == 1 ? node.addr : other, tail == 1 ? other : node.addr);
        auto v = net::Vtep::create(table, *node.tunnel, nullptr, {});
        BOOST_REQUIRE(v.has_value());
        vtep_ = std::move(*v);
        sw = std::make_unique<net::VSwitch>(table, *vtep_);
        BOOST_REQUIRE(sw->set_neighbors(
            {.vni = vpc,
             .ipv4 = {{.ip = ip_of(nic_a), .nic = nic_a}, {.ip = ip_of(nic_c), .nic = nic_c}},
             .ipv6 = {}}));
    }
    Node node;
    net::MappingTable table;
    std::unique_ptr<net::Vtep> vtep_;
    std::unique_ptr<net::VSwitch> sw;
};

}  // namespace

BOOST_AUTO_TEST_CASE(vteps_over_the_tunnel, *boost::unit_test::timeout(unit_timeout_seconds)) {
    World world;
    Side one{world, 1, vtep(2)};
    Side two{world, 2, vtep(1)};
    pair(one.node, two.node);
    FakePort port_a;
    FakePort port_c;
    BOOST_REQUIRE(one.sw->attach(nic_a, port_a));
    BOOST_REQUIRE(two.sw->attach(nic_c, port_c));

    const auto run = [&] {
        while (!world.queue.empty()) {
            auto d = std::move(world.queue.front());
            world.queue.pop_front();
            Side& to = d.to == one.node.addr ? one : two;
            if (auto o = to.node.tunnel->receive(d.bytes, d.from)) {
                if (auto p = to.vtep_->receive(o->payload, o->peer, world.now)) {
                    static_cast<void>(to.sw->receive(*p, o->peer));
                }
            }
        }
    };

    // The first keepalives start the handshakes; the next ones get through.
    static_cast<void>(one.vtep_->tick(world.now));
    static_cast<void>(two.vtep_->tick(world.now));
    run();
    world.advance(seconds{1});
    static_cast<void>(one.vtep_->tick(world.now));
    static_cast<void>(two.vtep_->tick(world.now));
    run();
    BOOST_TEST((one.vtep_->peers().at(0).state == net::PeerState::up));
    BOOST_TEST((two.vtep_->peers().at(0).state == net::PeerState::up));

    const auto f = frame(nic_c, nic_a);
    one.sw->transmit({.source = nic_a, .frame = f});
    run();
    BOOST_REQUIRE(port_c.frames.size() == 1U);
    BOOST_TEST((port_c.frames[0] == f));

    // A raw Geneve packet (no WireGuard) from the peer's address never
    // reaches the decoder.
    auto forged = geneve::encode({.vni = vpc, .nics = {nic_c, nic_a}}, frame(nic_a, nic_c));
    BOOST_REQUIRE(forged.has_value());
    BOOST_TEST(!one.node.tunnel->receive(*forged, two.node.addr).has_value());
    BOOST_TEST(port_a.frames.empty());
    BOOST_TEST(one.vtep_->counters().rx_datagrams == 1U);  // only two's second keepalive
}

namespace {

auto ipv6_loopback_available() -> bool {
    const int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_loopback;
    const bool ok = ::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) == 0;
    ::close(fd);
    return ok;
}

struct Ipv6Loopback {
    auto operator()(boost::unit_test::test_unit_id /*id*/) const
        -> boost::test_tools::assertion_result {
        boost::test_tools::assertion_result r{ipv6_loopback_available()};
        r.message() << "no IPv6 loopback in this environment";
        return r;
    }
};

}  // namespace

// Two tunnels on one loopback socket each, joined through pump().
BOOST_AUTO_TEST_CASE(pump_authenticates_datagrams,
                     *boost::unit_test::timeout(unit_timeout_seconds) *
                         boost::unit_test::precondition(Ipv6Loopback{})) {
    net::Ipv6Address lo{};
    lo[ipv6_last] = std::byte{1};
    auto ep = net::UdpEndpoint::create({.bind = lo, .port = 0});
    BOOST_REQUIRE(ep.has_value());
    // One endpoint plays both VTEPs: a's tunnel sends to lo, b's receives.
    net::TunnelConfig config;
    config.peer_port = (*ep)->local_port();
    auto a = net::Tunnel::create(**ep, config);
    auto b = net::Tunnel::create(**ep, config);
    BOOST_REQUIRE(a.has_value());
    BOOST_REQUIRE(b.has_value());
    const auto ka = wg::generate_private_key();
    BOOST_REQUIRE(ka.has_value());
    BOOST_REQUIRE((*a)->set_private_key(ka->span()).has_value());
    // b's peer is a at lo, and a's peer is b at lo: both share the address,
    // so each tunnel holds the other's key under lo.
    const auto kb = wg::generate_private_key();
    BOOST_REQUIRE(kb.has_value());
    BOOST_REQUIRE((*b)->set_private_key(kb->span()).has_value());
    BOOST_REQUIRE((*a)->set_peer(lo, *(*b)->public_key(), no_psk).has_value());
    BOOST_REQUIRE((*b)->set_peer(lo, *(*a)->public_key(), no_psk).has_value());

    std::vector<std::byte> buffer(2048);
    const auto step = [&](net::Tunnel& to) -> std::optional<std::vector<std::byte>> {
        pollfd p{.fd = (*ep)->poll_fd(), .events = POLLIN, .revents = 0};
        BOOST_REQUIRE(::poll(&p, 1, 2000) == 1);
        auto d = (*ep)->receive(buffer);
        BOOST_REQUIRE(d.has_value());
        auto o = to.receive(std::span{buffer}.first(d->size), d->source);
        if (!o) {
            return std::nullopt;
        }
        return std::vector<std::byte>{o->payload.begin(), o->payload.end()};
    };
    BOOST_TEST(!(*a)->send_to(lo, config.peer_port, 0, bytes("x")));
    BOOST_TEST(!step(**b).has_value());  // initiation
    BOOST_TEST(!step(**a).has_value());  // response
    BOOST_TEST(!step(**b).has_value());  // keepalive
    BOOST_TEST((*a)->send_to(lo, config.peer_port, 0, bytes("over udp")));
    const auto got = step(**b);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == bytes("over udp")));
}
