// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/fleet-scale-networking/ Requirement 3 (task 3): the certified
// handshake. Two VTEPs in no peer list exchange controller credentials and
// then run WireGuard's handshake; the responder refuses keys it cannot
// certify; verifies are rate limited per source and per role; certified
// peers are dropped on expiry or revocation, kept across a renewal, and
// reclaimed when idle; peer lists win over credentials. A reference model
// test drives random credential events through four VTEPs and checks
// which pairs can talk.

#define BOOST_TEST_MODULE tunnel_credential_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <random>
#include <span>
#include <vector>

#include "oar/net/credentials.hpp"
#include "oar/net/geneve.hpp"
#include "oar/net/tunnel.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/vtep_credential.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;
namespace geneve = ak::oar::net::geneve;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using net::TunnelDrop;
using std::chrono::milliseconds;
using std::chrono::seconds;

namespace {

constexpr std::uint16_t flow = 50'000;
constexpr std::uint16_t good_key = 3;
constexpr std::byte good_mark{0x5A};
constexpr std::int64_t wall_start = 1'800'000'000;
constexpr std::uint64_t day = 86'400;
constexpr std::uint32_t cell = 7;

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xFD};
    a.back() = std::byte{tail};
    return a;
}

struct Datagram {
    net::Ipv6Address from{};
    net::Ipv6Address to{};
    std::vector<std::byte> bytes;
};

struct World {
    net::VtepClock::time_point now{seconds{1000}};
    std::chrono::system_clock::time_point wall{seconds{wall_start}};
    std::deque<Datagram> queue;
    std::uint64_t next_serial{1};

    auto advance(milliseconds d) -> void {
        now += d;
        wall += d;
    }
    [[nodiscard]] auto unix_now() const -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<seconds>(wall.time_since_epoch()).count());
    }
};

class QueueSender final : public net::DatagramSender {
public:
    QueueSender(World& world, const net::Ipv6Address& self) : _world{&world}, _self{self} {}
    auto send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool override {
        _world->queue.push_back(
            {.from = _self, .to = dst, .bytes = {payload.begin(), payload.end()}});
        return true;
    }

private:
    World* _world;
    net::Ipv6Address _self;
};

// Stands in for Ed25519 (credentials_test and the signing vectors cover
// the real formats): a signature verifies when filled with good_mark.
auto fake_verifier() -> net::FrameVerifier {
    return [](std::span<const std::byte> /*signed_bytes*/,
              std::span<const std::byte, net::frame_signature_size> sig, std::uint16_t key_id) {
        return key_id == good_key &&
               std::ranges::all_of(sig, [](std::byte b) { return b == good_mark; });
    };
}

auto credential_frame(World& world, const net::Ipv6Address& addr, const wg::Key& key,
                      std::uint64_t server, std::uint64_t not_before, std::uint64_t not_after,
                      std::uint64_t serial = 0, std::byte mark = good_mark)
    -> std::vector<std::byte> {
    proto::VtepCredential c{.key_id = good_key,
                            .server_id = server,
                            .cell_id = cell,
                            .modes = proto::tunnel_mode_bit(proto::TunnelMode::wireguard),
                            .slot = 0,
                            .key_epoch = 1,
                            .vtep = addr,
                            .public_key = key,
                            .not_before = not_before,
                            .not_after = not_after,
                            .serial = serial == 0 ? world.next_serial++ : serial,
                            .signature = {}};
    c.signature.fill(mark);
    return proto::encode_vtep_credential(c).value();
}

struct Node {
    Node(World& w, std::uint8_t tail, net::TunnelConfig config = {})
        : world{&w},
          addr{vtep(tail)},
          sender{w, addr},
          store{net::CredentialConfig{.server_id = tail,
                                      .vtep = addr,
                                      .skew = seconds{300},
                                      .wall_clock = [&w] { return w.wall; }},
                fake_verifier()} {
        config.clock = [&w] { return w.now; };
        config.wall_clock = [&w] { return w.wall; };
        auto t = net::Tunnel::create(sender, std::move(config));
        BOOST_REQUIRE(t.has_value());
        tunnel = std::move(*t);
        auto k = wg::generate_private_key();
        BOOST_REQUIRE(k.has_value());
        BOOST_REQUIRE(tunnel->set_private_key(k->span()).has_value());
        pub = *tunnel->public_key();
        tunnel->set_credentials(&store);
    }

    // Issues this node a credential valid from now for `life` seconds.
    auto certify(std::uint64_t life = day) -> std::uint64_t {
        const auto serial = world->next_serial++;
        const auto f = credential_frame(*world, addr, pub, server(), world->unix_now() - 60,
                                        world->unix_now() + life, serial);
        BOOST_REQUIRE(net::accepted(store.install_own(f, pub)));
        return serial;
    }
    [[nodiscard]] auto server() const -> std::uint64_t {
        return std::to_integer<std::uint64_t>(addr.back());
    }

    [[nodiscard]] auto peer(const net::Ipv6Address& at) const
        -> std::optional<net::TunnelPeerStatus> {
        for (const auto& p : tunnel->peers()) {
            if (p.vtep == at) {
                return p;
            }
        }
        return std::nullopt;
    }
    [[nodiscard]] auto session_with(const Node& other) const -> bool {
        const auto p = peer(other.addr);
        return p && p->session;
    }

    World* world;
    net::Ipv6Address addr;
    QueueSender sender;
    net::CredentialStore store;
    std::unique_ptr<net::Tunnel> tunnel;
    wg::Key pub{};
};

auto drops(const net::Tunnel& t, TunnelDrop d) -> std::uint64_t {
    return t.counters().rx_drop.at(static_cast<std::size_t>(d));
}

auto credential_message(std::span<const std::byte> frame, std::uint8_t flags = 0)
    -> std::vector<std::byte> {
    std::vector<std::byte> m(wg::credential_message_size);
    m[0] = std::byte{static_cast<std::uint8_t>(wg::MessageType::credential)};
    m[4] = std::byte{flags};
    std::ranges::copy(frame, m.begin() + 8);
    return m;
}

struct Net {
    explicit Net(std::size_t n, net::TunnelConfig config = {}) {
        for (std::size_t i = 0; i < n; ++i) {
            nodes.push_back(
                std::make_unique<Node>(world, static_cast<std::uint8_t>(i + 1), config));
        }
    }
    auto node(const net::Ipv6Address& addr) -> Node* {
        for (auto& n : nodes) {
            if (n->addr == addr) {
                return n.get();
            }
        }
        return nullptr;
    }
    // Delivers everything queued, and whatever that queues, in order.
    auto deliver(std::size_t max = 1000) -> std::size_t {
        std::size_t payloads = 0;
        for (std::size_t i = 0; i < max && !world.queue.empty(); ++i) {
            auto d = std::move(world.queue.front());
            world.queue.pop_front();
            if (Node* n = node(d.to)) {
                if (n->tunnel->receive(d.bytes, d.from)) {
                    ++payloads;
                }
            }
        }
        return payloads;
    }
    auto tick() -> void {
        for (auto& n : nodes) {
            static_cast<void>(n->tunnel->tick());
        }
        static_cast<void>(deliver());
    }
    // Sends from a to b once a second, with the timers running, until a
    // payload arrives or `tries` seconds pass.
    auto connect(Node& a, Node& b, int tries = 30) -> bool {
        for (int i = 0; i < tries; ++i) {
            const bool sent =
                a.tunnel->send_to(b.addr, geneve::udp_port, flow, std::vector<std::byte>(4));
            if (deliver() != 0 && sent) {
                return true;
            }
            world.advance(seconds{1});
            tick();
        }
        return false;
    }
    auto& operator[](std::size_t i) { return *nodes.at(i); }

    World world;
    std::vector<std::unique_ptr<Node>> nodes;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(certified, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(credential_messages_parse_strictly) {
    std::vector<std::byte> body(wg::credential_body_size, std::byte{1});
    auto m = credential_message(body, wg::credential_flag_send_yours);
    auto parsed = wg::parse(m);
    BOOST_REQUIRE(parsed.has_value());
    const auto* c = std::get_if<wg::Credential>(&*parsed);
    BOOST_REQUIRE(c != nullptr);
    BOOST_TEST(c->flags == wg::credential_flag_send_yours);
    BOOST_TEST(c->credential.data() == m.data() + 8);
    for (std::size_t off : {1U, 2U, 3U, 5U, 6U, 7U}) {
        auto bad = m;
        bad[off] = std::byte{1};
        BOOST_TEST((wg::parse(bad).error() == wg::ParseError::reserved_not_zero));
    }
    auto flags = m;
    flags[4] = std::byte{2};
    BOOST_TEST((wg::parse(flags).error() == wg::ParseError::reserved_not_zero));
    m.pop_back();
    BOOST_TEST((wg::parse(m).error() == wg::ParseError::bad_length));
    m.resize(wg::credential_message_size + 1);
    BOOST_TEST((wg::parse(m).error() == wg::ParseError::bad_length));
    BOOST_TEST(wg::credential_body_size == proto::vtep_credential_size);
}

BOOST_AUTO_TEST_CASE(two_certified_vteps_talk_without_peer_lists) {
    Net n{2};
    auto& a = n[0];
    auto& b = n[1];
    a.certify();
    b.certify();
    BOOST_TEST(!a.tunnel->send_to(b.addr, geneve::udp_port, flow, std::vector<std::byte>(4)));
    BOOST_TEST(a.tunnel->counters().credentials_tx == 1U);
    BOOST_TEST(a.tunnel->counters().tx_no_session == 1U);
    static_cast<void>(n.deliver());
    BOOST_TEST(b.tunnel->counters().credentials_verified == 1U);
    BOOST_TEST(b.tunnel->counters().credential_replies_tx == 1U);
    BOOST_TEST(a.tunnel->counters().credentials_verified == 1U);
    BOOST_TEST(a.tunnel->counters().initiations_tx == 1U);
    BOOST_REQUIRE(a.session_with(b));
    BOOST_REQUIRE(b.session_with(a));
    BOOST_TEST(a.peer(b.addr)->certified);
    BOOST_TEST(b.peer(a.addr)->certified);
    BOOST_TEST(a.tunnel->send_to(b.addr, geneve::udp_port, flow, std::vector<std::byte>(4)));
    BOOST_TEST(n.deliver() == 1U);
    // The other way needs no new exchange.
    BOOST_TEST(b.tunnel->send_to(a.addr, geneve::udp_port, flow, std::vector<std::byte>(4)));
    BOOST_TEST(n.deliver() == 1U);
    BOOST_TEST(b.tunnel->counters().credentials_tx == 0U);
}

BOOST_AUTO_TEST_CASE(without_its_own_credential_a_role_reaches_only_list_peers) {
    Net n{2};
    auto& a = n[0];
    n[1].certify();
    BOOST_TEST(!a.tunnel->send_to(n[1].addr, geneve::udp_port, flow, std::vector<std::byte>(4)));
    BOOST_TEST(a.tunnel->counters().tx_no_peer == 1U);
    BOOST_TEST(a.tunnel->counters().credentials_tx == 0U);
    BOOST_TEST(n.world.queue.empty());
}

BOOST_AUTO_TEST_CASE(the_responder_refuses_keys_it_cannot_certify) {
    Net n{2};
    auto& a = n[0];
    auto& b = n[1];
    // a has b in its list, b knows nothing of a: a's initiation is refused.
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, b.pub, wg::Key{}).has_value());
    BOOST_TEST(!n.connect(a, b));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::uncertified) >= 1U);
    BOOST_TEST(b.tunnel->peers().empty());
    // Without a store the same initiation is an unknown peer, as before.
    b.tunnel->set_credentials(nullptr);
    BOOST_TEST(!n.connect(a, b, 6));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::unknown_peer) >= 1U);
}

BOOST_AUTO_TEST_CASE(a_credential_must_name_the_address_it_comes_from) {
    Net n{3};
    auto& a = n[0];
    auto& b = n[1];
    a.certify();
    b.certify();
    const auto f = credential_frame(n.world, a.addr, a.pub, a.server(), n.world.unix_now(),
                                    n.world.unix_now() + day);
    // From c's address: refused, nothing cached, no reply.
    static_cast<void>(b.tunnel->receive(credential_message(f, 1), n[2].addr));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::credential_refused) == 1U);
    BOOST_TEST(b.store.counters().peer_refused.at(
                   static_cast<std::size_t>(net::PeerCredentialError::wrong_source)) == 1U);
    BOOST_TEST(b.tunnel->credential_cache().size() == 0U);
    BOOST_TEST(n.world.queue.empty());
    // A forged signature, and one for b's own key.
    const auto forged = credential_frame(n.world, a.addr, a.pub, a.server(), n.world.unix_now(),
                                         n.world.unix_now() + day, 0, std::byte{1});
    static_cast<void>(b.tunnel->receive(credential_message(forged), a.addr));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::credential_refused) == 2U);
    const auto own = credential_frame(n.world, a.addr, b.pub, a.server(), n.world.unix_now(),
                                      n.world.unix_now() + day);
    static_cast<void>(b.tunnel->receive(credential_message(own), a.addr));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::credential_conflict) == 1U);
}

BOOST_AUTO_TEST_CASE(verifies_are_limited_per_source_and_per_role) {
    net::TunnelConfig c;
    c.source_verify_rate = 4;
    c.role_verify_rate = 5;
    Net n{1, c};
    auto& b = n[0];
    b.certify();
    const auto fresh = [&](std::uint8_t tail) {
        auto k = wg::generate_private_key().value();
        const auto pub = wg::public_key(k.span()).value();
        return credential_frame(n.world, vtep(tail), pub, tail, n.world.unix_now(),
                                n.world.unix_now() + day);
    };
    // One source: four verifies, then refused until the bucket refills.
    for (int i = 0; i < 6; ++i) {
        static_cast<void>(b.tunnel->receive(credential_message(fresh(9)), vtep(9)));
    }
    BOOST_TEST(b.tunnel->counters().credentials_verified == 4U);
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::credential_rate_limited) == 2U);
    // The same cached credential again costs no verify and is not limited.
    const auto again = fresh(10);
    static_cast<void>(b.tunnel->receive(credential_message(again), vtep(10)));
    for (int i = 0; i < 10; ++i) {
        static_cast<void>(b.tunnel->receive(credential_message(again), vtep(10)));
    }
    BOOST_TEST(b.tunnel->counters().credentials_cached == 10U);
    // The role's bucket (5) is now empty: another source is refused.
    static_cast<void>(b.tunnel->receive(credential_message(fresh(11)), vtep(11)));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::credential_rate_limited) == 3U);
    BOOST_TEST(b.tunnel->counters().credentials_verified == 5U);
    // A second later both refill.
    n.world.advance(seconds{1});
    static_cast<void>(b.tunnel->receive(credential_message(fresh(11)), vtep(11)));
    BOOST_TEST(b.tunnel->counters().credentials_verified == 6U);
}

BOOST_AUTO_TEST_CASE(a_peer_with_a_session_is_verified_past_the_role_limit) {
    net::TunnelConfig c;
    c.role_verify_rate = 1;
    Net n{2, c};
    auto& a = n[0];
    auto& b = n[1];
    a.certify();
    b.certify();
    BOOST_REQUIRE(n.connect(a, b));
    // Drain b's role bucket with strangers; a, which has a session, renews
    // anyway.
    for (const std::uint8_t tail : {std::uint8_t{8}, std::uint8_t{9}}) {
        static_cast<void>(b.tunnel->receive(
            credential_message(credential_frame(
                n.world, vtep(tail), wg::public_key(wg::generate_private_key()->span()).value(),
                tail, n.world.unix_now(), n.world.unix_now() + day)),
            vtep(tail)));
    }
    const auto limited = drops(*b.tunnel, TunnelDrop::credential_rate_limited);
    BOOST_TEST(limited >= 1U);
    const auto verified = b.tunnel->counters().credentials_verified;
    const auto renewed = credential_frame(n.world, a.addr, a.pub, a.server(), n.world.unix_now(),
                                          n.world.unix_now() + (2 * day));
    static_cast<void>(b.tunnel->receive(credential_message(renewed), a.addr));
    BOOST_TEST(drops(*b.tunnel, TunnelDrop::credential_rate_limited) == limited);
    BOOST_TEST(b.tunnel->counters().credentials_verified == verified + 1);
    BOOST_TEST(b.session_with(a));
}

BOOST_AUTO_TEST_CASE(expiry_and_revocation_drop_certified_peers) {
    Net n{3};
    auto& a = n[0];
    auto& b = n[1];
    auto& c = n[2];
    a.certify();
    const auto b_serial = b.certify();
    c.certify(3600);
    BOOST_REQUIRE(n.connect(a, b));
    BOOST_REQUIRE(n.connect(a, c));
    // b is revoked: a drops it at the next tick, with its cache entry.
    proto::CredentialRevocations l{
        .key_id = good_key,
        .cell_id = cell,
        .list_version = 1,
        .entries = {{.serial = b_serial, .not_after = n.world.unix_now() + day}},
        .signature = {}};
    l.signature.fill(good_mark);
    BOOST_REQUIRE(net::accepted(
        a.store.install_revocations(proto::encode_credential_revocations(l).value())));
    n.tick();
    BOOST_TEST(a.tunnel->counters().certified_revoked == 1U);
    BOOST_TEST(!a.peer(b.addr).has_value());
    BOOST_TEST(!a.tunnel->credential_cache().contains_vtep(b.addr));
    // b, still holding a session, is heard no more, and re-presenting its
    // credential when it handshakes again is refused.
    BOOST_TEST(!n.connect(b, a));
    BOOST_TEST(a.store.counters().peer_refused.at(
                   static_cast<std::size_t>(net::PeerCredentialError::revoked)) >= 1U);
    // c's credential (an hour) expires, beyond the skew; it is asked for a
    // renewal first, but has none.
    n.world.advance(seconds{3600 + 300});
    n.tick();
    BOOST_TEST(a.tunnel->counters().certified_expired == 1U);
    BOOST_TEST(!a.peer(c.addr).has_value());
}

BOOST_AUTO_TEST_CASE(a_renewal_keeps_the_sessions) {
    Net n{2};
    auto& a = n[0];
    auto& b = n[1];
    a.certify(2 * 3600);
    b.certify(2 * 3600);
    BOOST_REQUIRE(n.connect(a, b));
    const auto established = a.tunnel->counters().sessions_established;
    // Within credential_refresh (1 h) of expiry, a asks b for its current
    // credential; b's helm has renewed it.
    a.certify(day);
    b.certify(day);
    n.world.advance(seconds{3600 + 10});
    BOOST_REQUIRE(n.connect(a, b));  // keep the session fresh
    n.tick();
    BOOST_TEST(a.tunnel->counters().credentials_tx >= 2U);
    // The old window ends; nothing is dropped.
    n.world.advance(seconds{3600});
    for (int i = 0; i < 5; ++i) {
        static_cast<void>(n.connect(a, b));
        n.tick();
    }
    BOOST_TEST(a.tunnel->counters().certified_expired == 0U);
    BOOST_TEST(b.tunnel->counters().certified_expired == 0U);
    BOOST_TEST(a.session_with(b));
    // Only rekeys made new sessions, never a fresh credential exchange.
    BOOST_TEST(a.tunnel->counters().sessions_established >= established);
}

BOOST_AUTO_TEST_CASE(idle_certified_peers_are_reclaimed_and_come_back_from_the_cache) {
    net::TunnelConfig c;
    c.certified_idle = std::chrono::minutes{5};
    Net n{2, c};
    auto& a = n[0];
    auto& b = n[1];
    a.certify();
    b.certify();
    BOOST_REQUIRE(n.connect(a, b));
    // Sessions end after reject_after_time (180 s); the peer goes 5 min later.
    for (int i = 0; i < 12; ++i) {
        n.world.advance(seconds{60});
        n.tick();
    }
    BOOST_TEST(a.tunnel->counters().certified_peers_reclaimed == 1U);
    BOOST_TEST(!a.peer(b.addr).has_value());
    BOOST_TEST(a.tunnel->credential_cache().size() == 1U);
    // Talking again uses the cached credential on both sides.
    const auto asked = a.tunnel->counters().credentials_tx;
    BOOST_REQUIRE(n.connect(a, b));
    BOOST_TEST(a.tunnel->counters().credentials_tx == asked);
}

BOOST_AUTO_TEST_CASE(peer_lists_win_over_credentials) {
    Net n{2};
    auto& a = n[0];
    auto& b = n[1];
    a.certify();
    b.certify();
    BOOST_REQUIRE(n.connect(a, b));
    BOOST_REQUIRE(a.peer(b.addr)->certified);
    // A peer list naming b turns it into a list peer, sessions kept.
    BOOST_REQUIRE(a.tunnel->set_peer(b.addr, b.pub, wg::Key{}).has_value());
    BOOST_TEST(!a.peer(b.addr)->certified);
    BOOST_TEST(a.session_with(b));
    // Its credential expiring no longer matters.
    n.world.advance(seconds{day + 400});
    n.tick();
    BOOST_TEST(a.peer(b.addr).has_value());
    BOOST_TEST(a.tunnel->counters().certified_expired == 0U);
    // A credential for a key a list peer holds at another VTEP is refused.
    const auto clash =
        credential_frame(n.world, vtep(9), b.pub, 9, n.world.unix_now(), n.world.unix_now() + day);
    static_cast<void>(a.tunnel->receive(credential_message(clash), vtep(9)));
    BOOST_TEST(drops(*a.tunnel, TunnelDrop::credential_conflict) == 1U);
}

BOOST_AUTO_TEST_CASE(a_peer_that_rotates_is_followed) {
    Net n{2};
    auto& a = n[0];
    auto& b = n[1];
    a.certify();
    b.certify();
    BOOST_REQUIRE(n.connect(a, b));
    auto k = wg::generate_private_key().value();
    BOOST_REQUIRE(b.tunnel->rotate_private_key(k.span(), seconds{150}).has_value());
    b.pub = *b.tunnel->public_key();
    b.certify();
    // b's next tick presents its new credential; a replaces the key and
    // they handshake again.
    n.tick();
    BOOST_TEST(b.tunnel->counters().credentials_tx >= 1U);
    BOOST_TEST((a.peer(b.addr)->public_key == b.pub));
    BOOST_TEST(a.tunnel->credential_cache().size() == 1U);
    BOOST_REQUIRE(n.connect(a, b));
}

// The reference model: a pair can talk exactly when both hold a credential
// that is current and not revoked. Random events among four VTEPs:
// issue a fresh credential, revoke one, let time pass, or try to talk.
BOOST_AUTO_TEST_CASE(reference_model) {
    constexpr std::size_t count = 4;
    Net n{count};
    std::mt19937 rng{20261128};
    std::vector<std::vector<std::uint64_t>> serials(count);
    std::vector<bool> valid(count, false);
    std::vector<proto::Revocation> revoked;
    std::uint64_t list_version = 0;
    const auto issue = [&](std::size_t i) {
        serials[i].push_back(n[i].certify(day));
        valid[i] = true;
    };
    for (std::size_t i = 0; i < count; ++i) {
        issue(i);
    }
    for (int step = 0; step < 400; ++step) {
        const auto event = rng() % 10;
        const auto i = rng() % count;
        const auto j = (i + 1 + (rng() % (count - 1))) % count;
        if (event == 0) {
            issue(i);
        } else if (event == 1 && valid[i]) {
            // Every credential i was ever issued.
            for (const auto s : serials[i]) {
                if (std::ranges::find(revoked, s, &proto::Revocation::serial) == revoked.end()) {
                    revoked.push_back({.serial = s, .not_after = n.world.unix_now() + day});
                }
            }
            std::ranges::sort(revoked, {}, &proto::Revocation::serial);
            proto::CredentialRevocations l{.key_id = good_key,
                                           .cell_id = cell,
                                           .list_version = ++list_version,
                                           .entries = revoked,
                                           .signature = {}};
            l.signature.fill(good_mark);
            const auto f = proto::encode_credential_revocations(l).value();
            for (auto& node : n.nodes) {
                BOOST_REQUIRE(net::accepted(node->store.install_revocations(f)));
            }
            valid[i] = false;
            n.tick();  // teardown happens on the tick
        } else if (event == 2) {
            n.world.advance(seconds{1 + (rng() % 30)});
            n.tick();
        } else {
            const bool talked = n.connect(n[i], n[j]);
            BOOST_TEST(talked == (valid[i] && valid[j]), "step " << step << ": " << i << "->" << j
                                                                 << " valid " << valid[i]
                                                                 << valid[j]);
        }
        // After a tick no one keeps a session with a revoked VTEP.
        if (event == 1 || event == 2) {
            for (std::size_t x = 0; x < count; ++x) {
                for (std::size_t y = 0; y < count; ++y) {
                    if (x != y && !valid[y]) {
                        BOOST_TEST(!n[x].session_with(n[y]),
                                   "step " << step << " " << x << "~" << y);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
