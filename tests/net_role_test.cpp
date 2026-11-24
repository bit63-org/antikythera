// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 8 (tasks 9 and 11): the
// network role behind helm's sideband. Placeholders between attachments,
// prepare and clean, signed map_updates checked against the controller's
// key, and guest frames crossing the VSwitch locally and two VTEPs over a
// fake underlay, in the clear and inside the WireGuard tunnel (keys from
// helm, peers from the controller's signed TunnelPeers frame). health
// reports a peer that never proves a full-size path (mtu_ok).

#define BOOST_TEST_MODULE net_role_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "ed25519_test_support.hpp"
#include "helm/oar_link.hpp"
#include "helm/sideband_binding.hpp"
#include "hull/signature_verifier.hpp"
#include "net_frames.hpp"
#include "oar/net/net_role.hpp"
#include "proto/map_update.hpp"
#include "proto/tunnel_peers.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

namespace net = ak::oar::net;
namespace oar = ak::helm::oar;
namespace vio = ak::oar::virtio;
namespace proto = ak::proto;
using ak::test::Buffer;
using ak::test::GuestRam;
using ak::test::RecordingInterrupts;
using ak::test::unit_timeout_seconds;
using ak::test::VirtioDriver;
using net::geneve::NicId;
using oar::Status;

namespace {

constexpr std::uint64_t server_one = 7;
constexpr std::uint64_t server_two = 8;
constexpr std::uint16_t key_id = 1;
constexpr std::uint32_t vpc = 0x00AB'CD01;
constexpr std::uint32_t underlay_mtu = 1500;
constexpr std::size_t function_count = 2;
constexpr oar::FunctionNumber fn0 = 0;
constexpr oar::FunctionNumber fn1 = 1;
constexpr std::uint64_t vm_one = 0x101;
constexpr std::uint64_t nic_a = 0x11;
constexpr std::uint64_t nic_b = 0x22;
constexpr std::uint64_t nic_c = 0x33;  // on the second VTEP
constexpr std::uint8_t self_tail = 1;
constexpr std::uint8_t peer_tail = 2;
constexpr std::uint16_t rx = net::virtio_net_rx_queue;
constexpr std::uint16_t tx = net::virtio_net_tx_queue;
constexpr std::size_t hdr = net::virtio_net_hdr_size;
constexpr std::uint8_t ipproto_udp = 17;
constexpr std::size_t ipv4_udp_headers = 20 + 8;
constexpr std::uint16_t udp_port = 4000;
constexpr std::size_t payload_size = 64;
constexpr std::uint8_t payload_fill = 0x5A;
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr auto keepalive = std::chrono::milliseconds{1000};

constexpr std::uint64_t driver_features =
    vio::feature_bit(vio::feature_version_1) | vio::feature_bit(net::virtio_net_f_mac) |
    vio::feature_bit(net::virtio_net_f_mtu) | vio::feature_bit(net::virtio_net_f_status);

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto mac_of(std::uint64_t nic) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = std::byte{0x02};  // locally administered unicast
    m[mac_last - 1] = static_cast<std::byte>(nic >> 8U);
    m[mac_last] = static_cast<std::byte>(nic & 0xFFU);
    return m;
}

auto guest_ip(std::uint64_t nic) -> proto::Ipv4Address;

// An IPv4/UDP frame from one guest to another, between their guest_ip()
// addresses: the VSwitch only forwards IP from the sender's own address to
// the destination NIC's, so both must be in the map. `size` is the IP
// packet's length, so the guest MTU makes a full-size frame.
auto frame(std::uint64_t dst, std::uint64_t src, std::size_t size = payload_size)
    -> std::vector<std::byte> {
    const std::vector<std::byte> payload(size - ipv4_udp_headers, std::byte{payload_fill});
    return ak::test::frames::ipv4(mac_of(dst), mac_of(src), guest_ip(src), guest_ip(dst),
                                  ipproto_udp, ak::test::frames::udp(udp_port, udp_port, payload));
}

auto signer() -> const ak::test::TestSigner& {
    static const ak::test::TestSigner s{ak::test::rfc_test1_secret};
    return s;
}

auto guest_ip(std::uint64_t nic) -> proto::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{0}, static_cast<std::byte>(nic)};
}

// Signs like the controller: encode with a blank signature, sign, set.
// `addressed` NICs also get guest_ip(nic) in the frame (format v2).
auto signed_map(std::uint64_t server, std::uint64_t version,
                const std::vector<std::pair<std::uint64_t, std::uint8_t>>& nics,
                const std::vector<std::uint64_t>& addressed = {}) -> std::vector<std::byte> {
    // Member by member, so the frame format can grow fields (v2's guest
    // addresses) without this needing every one spelled out.
    proto::MapUpdate m{};
    m.server_id = server;
    m.key_id = key_id;
    m.vni = vpc;
    m.map_version = version;
    for (const auto& [nic, tail] : nics) {
        m.entries.push_back({.nic_id = nic, .mac = mac_of(nic), .owner_vtep = vtep(tail)});
    }
    for (const std::uint64_t nic : addressed) {  // ascending NIC IDs give ascending addresses
        m.ipv4.push_back({.nic_id = nic, .address = guest_ip(nic)});
    }
    auto bytes = proto::encode_map_update(m);
    BOOST_REQUIRE(bytes.has_value());
    const auto sig = signer().sign(proto::map_update_signed_bytes(*bytes));
    proto::set_map_update_signature(*bytes, sig);
    return *bytes;
}

// The verifier ak-oar-net builds: hull's Ed25519 verifier over the
// controller key table.
auto verifier() -> net::MapVerifier {
    const std::array keys{ak::test::controller_key(key_id, ak::test::rfc_test1_public)};
    auto v = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(v.has_value());
    auto shared = std::make_shared<ak::hull::SignatureVerifier>(std::move(*v));
    return [shared](std::span<const std::byte> msg, std::span<const std::byte, 64> sig,
                    std::uint16_t id) { return shared->verify(msg, sig, id).has_value(); };
}

class FakeTransport final : public net::NetTransport {
public:
    [[nodiscard]] auto memory() -> const vio::GuestMemory& override { return ram.memory(); }
    [[nodiscard]] auto interrupts() -> vio::InterruptSink& override { return irq; }
    [[nodiscard]] auto bind(vio::PciFunction& function)
        -> std::expected<void, std::string> override {
        if (fail) {
            return std::unexpected("refused");
        }
        served = &function;
        return {};
    }

    GuestRam ram;
    RecordingInterrupts irq;
    vio::PciFunction* served{nullptr};
    bool fail{false};
};

// The underlay between two roles: datagrams queue up until delivered.
// A datagram over `path_limit` bytes is lost, as on a path with a smaller
// MTU than planned (UdpEndpoint never fragments).
class Wire final : public net::DatagramSender {
public:
    struct Datagram {
        net::Ipv6Address dst{};
        std::vector<std::byte> payload;
    };
    auto send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool override {
        if (payload.size() > path_limit) {
            ++lost;
            return true;  // sent, and lost on the way
        }
        sent.push_back({dst, {payload.begin(), payload.end()}});
        return true;
    }
    std::vector<Datagram> sent;
    std::size_t path_limit{SIZE_MAX};
    std::size_t lost{0};
};

enum class Encryption : std::uint8_t {
    none,
    wireguard
};

// One VTEP: a role over `function_count` fake transports, and a guest
// driver per function.
struct Board {
    explicit Board(std::uint64_t server, std::uint8_t tail, Encryption enc = Encryption::none) {
        auto plan = net::plan_mtu(underlay_mtu,
                                  enc == Encryption::wireguard
                                      ? static_cast<std::uint32_t>(net::tunnel_overhead_budget)
                                      : 0);
        BOOST_REQUIRE(plan.has_value());
        std::vector<net::NetTransport*> raw;
        for (auto& t : transports) {
            raw.push_back(&t);
        }
        auto r = net::NetRole::create(
            {.vtep = vtep(tail),
             .server_id = server,
             .mtu = *plan,
             .queue_size = ak::test::test_queue_size,
             .tx_budget = 256,
             .vtep_config = {.keepalive_interval = keepalive},
             .tunnel = enc == Encryption::wireguard
                           ? std::optional<net::TunnelConfig>{net::TunnelConfig{}}
                           : std::nullopt,
             .mtu_grace = {},
             .clock = {}},
            raw, verifier(), wire, nullptr);
        BOOST_REQUIRE_MESSAGE(r.has_value(), r.error());
        role = std::move(*r);
        for (std::size_t i = 0; i < function_count; ++i) {
            const auto fn = static_cast<oar::FunctionNumber>(i);
            BOOST_REQUIRE(transports[i].served == &role->function(fn)->pci());
        }
    }

    auto prepare(oar::FunctionNumber fn, std::uint64_t nic) -> Status {
        return role->prepare_function(
            {.fn = fn,
             .type = ak::helm::FunctionType::nic_vf,
             .vm_id = vm_one,
             .config = oar::NicConfig{.nic_id = nic, .vni = vpc, .mac = mac_of(nic)}});
    }

    // The VMM opens the function after helm prepared it: a fresh driver.
    auto driver(oar::FunctionNumber fn) -> VirtioDriver& {
        drivers[fn] = std::make_unique<VirtioDriver>(transports[fn].ram, role->function(fn)->pci());
        BOOST_REQUIRE(drivers[fn]->bring_up(driver_features, {rx, tx}));
        return *drivers[fn];
    }

    auto send(oar::FunctionNumber fn, const std::vector<std::byte>& f) -> void {
        std::vector<std::byte> bytes(hdr);
        bytes.insert(bytes.end(), f.begin(), f.end());
        std::vector<vio::Gpa> gpas;
        drivers[fn]->post(tx, {{.len = static_cast<std::uint32_t>(bytes.size())}}, &gpas);
        transports[fn].ram.put_bytes(gpas[0], bytes);
        BOOST_REQUIRE(drivers[fn]->notify(tx));
    }

    // Posts one receive buffer; returns its guest address.
    auto post_rx(oar::FunctionNumber fn) -> vio::Gpa {
        std::vector<vio::Gpa> gpas;
        const auto len = static_cast<std::uint32_t>(hdr + role->function(fn)->max_frame());
        drivers[fn]->post(rx, {{.len = len, .writable = true}}, &gpas);
        return gpas[0];
    }

    // The frame in the receive buffer at `gpa`, once it is used.
    auto received(oar::FunctionNumber fn, vio::Gpa gpa) -> std::optional<std::vector<std::byte>> {
        if (drivers[fn]->used_idx(rx) == 0) {
            return std::nullopt;
        }
        const auto len = drivers[fn]->used_len(rx, 0);
        auto bytes = transports[fn].ram.bytes(gpa + hdr, len - hdr);
        return bytes;
    }

    std::array<FakeTransport, function_count> transports;
    Wire wire;
    std::unique_ptr<net::NetRole> role;
    std::array<std::unique_ptr<VirtioDriver>, function_count> drivers;
};

struct One : Board {
    One() : Board(server_one, self_tail) {}
};

// Carries everything `from` sent to `to`'s VTEP into `to` (through its
// tunnel, if it has one). Returns how many data packets reached its VSwitch.
auto deliver(Board& from, Board& to, const net::Ipv6Address& from_addr,
             net::VtepClock::time_point now = net::VtepClock::now()) -> std::size_t {
    std::size_t n = 0;
    auto sent = std::move(from.wire.sent);
    from.wire.sent.clear();
    for (const auto& d : sent) {
        if (to.role->receive(d.payload, from_addr, now)) {
            ++n;
        }
    }
    return n;
}

// Ticks both boards at `now` and carries datagrams both ways until the
// underlay is quiet (handshakes take a round trip or two).
auto exchange(Board& one, Board& two, net::VtepClock::time_point now) -> void {
    static_cast<void>(one.role->tick(now));
    static_cast<void>(two.role->tick(now));
    for (int round = 0; round < 8 && !(one.wire.sent.empty() && two.wire.sent.empty()); ++round) {
        static_cast<void>(deliver(one, two, vtep(self_tail), now));
        static_cast<void>(deliver(two, one, vtep(peer_tail), now));
    }
}

// The controller's TunnelPeers frame for `server`'s VTEP at `tail`, naming
// one WireGuard peer, signed with the key the roles trust.
auto signed_peers(std::uint64_t server, std::uint8_t tail, std::uint64_t version,
                  std::uint8_t peer_tail_addr, const net::wg::Key& peer_key)
    -> std::vector<std::byte> {
    proto::TunnelPeers t{};
    t.server_id = server;
    t.key_id = key_id;
    t.vtep = vtep(tail);
    t.peers_version = version;
    t.peers.push_back({.vtep = vtep(peer_tail_addr),
                       .mode = proto::TunnelMode::wireguard,
                       .spi = 0,
                       .key = peer_key});
    auto bytes = proto::encode_tunnel_peers(t);
    BOOST_REQUIRE(bytes.has_value());
    proto::set_tunnel_peers_signature(*bytes,
                                      signer().sign(proto::tunnel_peers_signed_bytes(*bytes)));
    return *bytes;
}

}  // namespace

BOOST_AUTO_TEST_CASE(create_validates, *boost::unit_test::timeout(unit_timeout_seconds)) {
    FakeTransport t;
    Wire wire;
    auto plan = net::plan_mtu(underlay_mtu);
    BOOST_REQUIRE(plan.has_value());
    net::NetRoleConfig good{};
    good.vtep = vtep(self_tail);
    good.server_id = server_one;
    good.mtu = *plan;
    BOOST_TEST(!net::NetRole::create(good, {}, verifier(), wire, nullptr).has_value());
    BOOST_TEST(!net::NetRole::create(good, {&t}, {}, wire, nullptr).has_value());
    auto bad = good;
    bad.server_id = 0;
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    bad = good;
    bad.vtep = {};
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    bad = good;
    bad.mtu = {};
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    bad = good;
    bad.vtep_config.keepalive_misses = 0;
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    BOOST_TEST(!net::NetRole::create(good, {nullptr}, verifier(), wire, nullptr).has_value());
    t.fail = true;
    BOOST_TEST(!net::NetRole::create(good, {&t}, verifier(), wire, nullptr).has_value());
    t.fail = false;
    BOOST_TEST(net::NetRole::create(good, {&t}, verifier(), wire, nullptr).has_value());
    // A tunnel needs room for WireGuard in the MTU plan.
    bad = good;
    bad.tunnel = net::TunnelConfig{};
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    bad.mtu = *net::plan_mtu(underlay_mtu, net::wireguard_overhead);
    BOOST_TEST(net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    bad.tunnel->rekey_timeout = std::chrono::milliseconds{0};
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
    bad = good;
    bad.mtu_grace = std::chrono::milliseconds{-1};
    BOOST_TEST(!net::NetRole::create(bad, {&t}, verifier(), wire, nullptr).has_value());
}

BOOST_FIXTURE_TEST_CASE(inventory_and_unsupported, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto inv = role->function_inventory();
    BOOST_REQUIRE(inv.has_value());
    BOOST_TEST((inv->role == oar::Role::net));
    BOOST_TEST((inv->vtep == vtep(self_tail)));
    BOOST_REQUIRE(inv->functions.size() == function_count);
    for (std::size_t i = 0; i < function_count; ++i) {
        BOOST_TEST(inv->functions[i].fn == i);
        BOOST_TEST((inv->functions[i].type == ak::helm::FunctionType::nic_vf));
    }
    const std::array<std::byte, ak::helm::volume_key_size> key{};
    BOOST_TEST((role->deliver_key({.fn = fn0, .volume_id = 1, .key = key}) == Status::unsupported));
    BOOST_TEST((role->drop_key({}) == Status::unsupported));
    BOOST_TEST((role->create_volume({}) == Status::unsupported));
    // Without a tunnel, the tunnel requests are not this role's either.
    const net::wg::Key k{};
    BOOST_TEST((role->set_tunnel_key({.private_key = k}) == Status::unsupported));
    BOOST_TEST((role->set_tunnel_peer({.vtep = vtep(peer_tail), .public_key = k, .psk = k}) ==
                Status::unsupported));
    BOOST_TEST((role->remove_tunnel_peer({.vtep = vtep(peer_tail)}) == Status::unsupported));
    BOOST_TEST((role->tunnel_peers(std::array<std::byte, 4>{}) == Status::unsupported));
    BOOST_TEST(role->tunnel() == nullptr);
    auto h = role->health();
    BOOST_REQUIRE(h.has_value());
    BOOST_TEST((h->state == oar::HealthState::ok));
}

BOOST_FIXTURE_TEST_CASE(placeholder_advertises_the_plan_and_reaches_nothing, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Even unattached, a function advertises the planned MTU.
    BOOST_TEST(role->function(fn0)->identity().mtu == 1406U);
    BOOST_TEST(!role->attached(fn0).has_value());
    BOOST_REQUIRE(role->map_update(signed_map(server_one, 1, {{nic_a, self_tail}})) == Status::ok);
    // A stray driver on the placeholder transmits into the dead VPC.
    driver(fn0);
    const auto id = role->function(fn0)->identity();
    const std::vector<std::byte> payload(payload_size, std::byte{payload_fill});
    send(fn0,
         ak::test::frames::ipv4(mac_of(nic_a), id.mac, guest_ip(nic_b), guest_ip(nic_a),
                                ipproto_udp, ak::test::frames::udp(udp_port, udp_port, payload)));
    BOOST_TEST(role->vswitch().counters().tx_drop_dead_vpc == 1U);
    BOOST_TEST(role->vswitch().counters().tx_local == 0U);
}

BOOST_FIXTURE_TEST_CASE(prepare_checks_requests, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((prepare(5, nic_a) == Status::unknown_function));
    BOOST_TEST(
        (role->prepare_function({.fn = fn0,
                                 .type = ak::helm::FunctionType::blk_fn,
                                 .vm_id = vm_one,
                                 .config = oar::BlkConfig{.volume_id = 1}}) == Status::wrong_type));
    BOOST_TEST((role->prepare_function({.fn = fn0,
                                        .type = ak::helm::FunctionType::nic_vf,
                                        .vm_id = vm_one,
                                        .config = std::monostate{}}) == Status::wrong_type));
    BOOST_TEST((role->prepare_function(
                    {.fn = fn0,
                     .type = ak::helm::FunctionType::nic_vf,
                     .vm_id = vm_one,
                     .config = oar::NicConfig{.nic_id = nic_a, .vni = vpc, .mac = {}}}) ==
                Status::bad_request));

    BOOST_TEST((prepare(fn0, nic_a) == Status::ok));
    BOOST_TEST((role->attached(fn0) == NicId{nic_a}));
    const auto& id = role->function(fn0)->identity();
    BOOST_TEST((id.mac == mac_of(nic_a)));
    BOOST_TEST(id.mtu == 1406U);
    BOOST_TEST((prepare(fn0, nic_b) == Status::busy));  // clean first
    BOOST_TEST((prepare(fn1, nic_a) == Status::busy));  // NIC already here
    BOOST_TEST(!role->attached(fn1).has_value());
}

BOOST_FIXTURE_TEST_CASE(map_updates_are_checked, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = signed_map(server_one, 2, {{nic_a, self_tail}, {nic_c, peer_tail}});

    BOOST_TEST((role->map_update(std::span{good}.first(good.size() - 1)) == Status::failed));
    BOOST_TEST(role->counters().map_undecodable == 1U);

    BOOST_TEST(
        (role->map_update(signed_map(server_two, 2, {{nic_a, self_tail}})) == Status::failed));
    BOOST_TEST(role->counters().map_wrong_server == 1U);

    auto tampered = good;
    tampered[proto::map_update_header_size + 8] ^= std::byte{0x04};  // an entry's MAC
    BOOST_TEST((role->map_update(tampered) == Status::failed));
    BOOST_TEST(role->counters().map_bad_signature == 1U);
    BOOST_TEST(role->mappings().snapshot()->nic_count() == 0U);

    BOOST_TEST((role->map_update(good) == Status::ok));
    BOOST_TEST(role->counters().map_applied == 1U);
    BOOST_TEST(role->mappings().snapshot()->version(vpc) == 2U);
    BOOST_TEST(role->mappings().snapshot()->is_local(NicId{nic_a}));
    BOOST_TEST(!role->mappings().snapshot()->is_local(NicId{nic_c}));

    // helm resends after a reconnect: ok, nothing changes.
    BOOST_TEST((role->map_update(good) == Status::ok));
    BOOST_TEST(role->counters().map_redelivered == 1U);
    BOOST_TEST(role->counters().map_applied == 1U);

    // An older version is refused and leaves the table alone.
    BOOST_TEST(
        (role->map_update(signed_map(server_one, 1, {{nic_b, self_tail}})) == Status::failed));
    BOOST_TEST(role->counters().map_rejected == 1U);
    BOOST_TEST(role->mappings().snapshot()->version(vpc) == 2U);

    // An empty list withdraws the VNI.
    BOOST_TEST((role->map_update(signed_map(server_one, 3, {})) == Status::ok));
    BOOST_TEST(role->mappings().snapshot()->nic_count() == 0U);
}

// An ARP request from `nic` for `target`, as a guest sends it.
auto arp_request(std::uint64_t nic, const proto::Ipv4Address& target) -> std::vector<std::byte> {
    constexpr std::uint16_t ethertype_arp = 0x0806;
    constexpr std::uint16_t ethertype_ipv4 = 0x0800;
    std::vector<std::byte> f;
    const auto be16 = [&f](std::uint16_t v) {
        f.push_back(static_cast<std::byte>(v >> 8U));
        f.push_back(static_cast<std::byte>(v & 0xFFU));
    };
    const auto put = [&f](const auto& bytes) { f.insert(f.end(), bytes.begin(), bytes.end()); };
    f.insert(f.end(), 6, std::byte{0xFF});
    put(mac_of(nic));
    be16(ethertype_arp);
    be16(1);  // Ethernet
    be16(ethertype_ipv4);
    f.push_back(std::byte{6});
    f.push_back(std::byte{4});
    be16(1);  // request
    put(mac_of(nic));
    put(guest_ip(nic));
    f.insert(f.end(), 6, std::byte{0});
    put(target);
    return f;
}

BOOST_FIXTURE_TEST_CASE(map_update_feeds_the_proxy, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a, nic_c})) ==
                  Status::ok);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    driver(fn0);
    const auto buf = post_rx(fn0);
    send(fn0, arp_request(nic_a, guest_ip(nic_c)));
    BOOST_TEST(role->vswitch().counters().arp_replies == 1U);
    BOOST_TEST(wire.sent.empty());  // answered on the board, nothing flooded
    const auto got = received(fn0, buf);
    BOOST_REQUIRE(got.has_value());
    // The reply comes from c's MAC.
    BOOST_TEST(std::ranges::equal(std::span{*got}.subspan(6, 6), mac_of(nic_c)));

    // The next version drops c's address: no longer answered.
    BOOST_REQUIRE(role->map_update(signed_map(server_one, 2,
                                              {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a})) ==
                  Status::ok);
    static_cast<void>(post_rx(fn0));
    send(fn0, arp_request(nic_a, guest_ip(nic_c)));
    BOOST_TEST(role->vswitch().counters().arp_replies == 1U);
    BOOST_TEST(role->counters().map_neighbors_rejected == 0U);
}

BOOST_FIXTURE_TEST_CASE(local_guests_talk_through_the_vswitch, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_b, self_tail}}, {nic_a, nic_b})) ==
                  Status::ok);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(prepare(fn1, nic_b) == Status::ok);
    driver(fn0);
    driver(fn1);
    const auto buf = post_rx(fn1);
    const auto f = frame(nic_b, nic_a);
    send(fn0, f);
    BOOST_TEST(role->vswitch().counters().tx_local == 1U);
    auto got = received(fn1, buf);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == f));
    BOOST_TEST(wire.sent.empty());  // nothing left the board
}

BOOST_AUTO_TEST_CASE(guests_on_two_vteps_talk_over_the_underlay,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Board one{server_one, self_tail};
    Board two{server_two, peer_tail};
    // The controller sends each server the same VPC, addressed to it.
    BOOST_REQUIRE(one.role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a, nic_c})) ==
                  Status::ok);
    BOOST_REQUIRE(two.role->map_update(signed_map(
                      server_two, 1, {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a, nic_c})) ==
                  Status::ok);
    BOOST_REQUIRE(one.prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(two.prepare(fn1, nic_c) == Status::ok);
    one.driver(fn0);
    two.driver(fn1);
    const auto buf = two.post_rx(fn1);

    // A full-size frame: the guest MTU plus Ethernet fits the plan exactly.
    const auto mtu = one.role->function(fn0)->identity().mtu;
    const auto f = frame(nic_c, nic_a, mtu);
    one.send(fn0, f);
    BOOST_TEST(one.role->vswitch().counters().tx_remote == 1U);
    BOOST_REQUIRE(one.wire.sent.size() == 1U);
    BOOST_TEST((one.wire.sent[0].dst == vtep(peer_tail)));
    BOOST_TEST(one.wire.sent[0].payload.size() == f.size() + net::geneve_header_size);
    BOOST_TEST(deliver(one, two, vtep(self_tail)) == 1U);
    auto got = two.received(fn1, buf);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == f));

    // Keepalives and probes flow between the two, and the path proves full size.
    const auto t0 = net::VtepClock::now();
    static_cast<void>(one.role->tick(t0));
    static_cast<void>(two.role->tick(t0));
    static_cast<void>(deliver(one, two, vtep(self_tail)));
    static_cast<void>(deliver(two, one, vtep(peer_tail)));
    const auto peers = one.role->vtep().peers();
    BOOST_REQUIRE(peers.size() == 1U);
    BOOST_TEST((peers[0].state == net::PeerState::up));
    BOOST_TEST(peers[0].mtu_ok);
    auto h = one.role->health();
    BOOST_REQUIRE(h.has_value());
    BOOST_TEST((h->state == oar::HealthState::ok));
    BOOST_TEST(h->fault_code == 0U);
}

BOOST_AUTO_TEST_CASE(health_reports_a_path_too_small_for_full_size_frames,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Board one{server_one, self_tail};
    Board two{server_two, peer_tail};
    BOOST_REQUIRE(one.role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}})) == Status::ok);
    BOOST_REQUIRE(two.role->map_update(signed_map(
                      server_two, 1, {{nic_a, self_tail}, {nic_c, peer_tail}})) == Status::ok);
    // Keepalives fit the path; full-size MTU probes do not.
    constexpr std::size_t small_path = 256;
    one.wire.path_limit = small_path;
    two.wire.path_limit = small_path;

    const auto t0 = net::VtepClock::now();
    exchange(one, two, t0);
    const auto peers = one.role->vtep().peers();
    BOOST_REQUIRE(peers.size() == 1U);
    BOOST_TEST((peers[0].state == net::PeerState::up));
    BOOST_TEST(!peers[0].mtu_ok);
    BOOST_TEST(one.wire.lost >= 1U);
    // Up, unproven, but still within the grace (two probe intervals).
    BOOST_TEST((one.role->health()->state == oar::HealthState::ok));

    // tick() first sees the peer up and unproven one keepalive after t0.
    const auto grace = 2 * net::VtepConfig{}.probe_interval;
    for (auto t = t0 + keepalive; t <= t0 + keepalive + grace; t += keepalive) {
        exchange(one, two, t);
    }
    auto h = one.role->health();
    BOOST_REQUIRE(h.has_value());
    BOOST_TEST((h->state == oar::HealthState::degraded));
    BOOST_TEST(h->fault_code == net::net_fault_mtu);  // the peer is up; only the size fails

    // Once the path carries full-size datagrams, the next probe clears it.
    one.wire.path_limit = SIZE_MAX;
    two.wire.path_limit = SIZE_MAX;
    for (auto t = t0 + grace + (2 * keepalive);
         t <= t0 + grace + keepalive + net::VtepConfig{}.probe_interval; t += keepalive) {
        exchange(one, two, t);
    }
    h = one.role->health();
    BOOST_TEST((h->state == oar::HealthState::ok));
    BOOST_TEST(h->fault_code == 0U);
}

BOOST_AUTO_TEST_CASE(guests_talk_through_the_wireguard_tunnel,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Board one{server_one, self_tail, Encryption::wireguard};
    Board two{server_two, peer_tail, Encryption::wireguard};
    BOOST_REQUIRE(one.role->tunnel() != nullptr);
    // Until helm keys it, the role says so.
    auto h = one.role->health();
    BOOST_TEST((h->state == oar::HealthState::degraded));
    BOOST_TEST(h->fault_code == net::net_fault_no_tunnel_key);

    // helm delivers each role its private key (from its TunnelKeyring)...
    const auto k1 = net::wg::generate_private_key();
    const auto k2 = net::wg::generate_private_key();
    BOOST_REQUIRE(k1.has_value());
    BOOST_REQUIRE(k2.has_value());
    const auto p1 = net::wg::public_key(k1->span());
    const auto p2 = net::wg::public_key(k2->span());
    BOOST_REQUIRE(p1.has_value());
    BOOST_REQUIRE(p2.has_value());
    BOOST_TEST((one.role->set_tunnel_key({.private_key = k1->span()}) == Status::ok));
    BOOST_TEST((two.role->set_tunnel_key({.private_key = k2->span()}) == Status::ok));
    const net::wg::Key zero{};
    BOOST_TEST((one.role->set_tunnel_key({.private_key = zero}) == Status::failed));
    BOOST_TEST(one.role->counters().tunnel_keys_refused == 1U);
    BOOST_TEST((one.role->tunnel()->public_key() == *p1));  // the refused key changed nothing

    // ...and forwards the controller's peer sets, which the roles verify.
    auto forged = signed_peers(server_one, self_tail, 1, peer_tail, *p2);
    forged.back() ^= std::byte{1};
    BOOST_TEST((one.role->tunnel_peers(forged) == Status::failed));
    BOOST_TEST((one.role->tunnel_peers(signed_peers(server_two, self_tail, 1, peer_tail, *p2)) ==
                Status::failed));  // for another server
    BOOST_TEST((one.role->tunnel_peers(signed_peers(server_one, self_tail, 1, peer_tail, *p2)) ==
                Status::ok));
    BOOST_TEST((one.role->tunnel_peers(signed_peers(server_one, self_tail, 1, peer_tail, *p2)) ==
                Status::ok));  // re-delivered after a sideband reconnect
    BOOST_TEST((two.role->tunnel_peers(signed_peers(server_two, peer_tail, 1, self_tail, *p1)) ==
                Status::ok));
    BOOST_TEST(one.role->peer_set()->version() == 1U);
    BOOST_TEST(one.role->peer_set()->counters().bad_signature == 1U);
    BOOST_TEST(one.role->peer_set()->counters().wrong_target == 1U);
    BOOST_TEST(
        (one.role->set_tunnel_peer({.vtep = vtep(self_tail), .public_key = *p2, .psk = zero}) ==
         Status::bad_request));  // never its own peer

    BOOST_REQUIRE(one.role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a, nic_c})) ==
                  Status::ok);
    BOOST_REQUIRE(two.role->map_update(signed_map(
                      server_two, 1, {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a, nic_c})) ==
                  Status::ok);
    BOOST_REQUIRE(one.prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(two.prepare(fn1, nic_c) == Status::ok);
    one.driver(fn0);
    two.driver(fn1);

    // The keepalives start the handshake; a second round runs over the session.
    const auto t0 = net::VtepClock::now();
    exchange(one, two, t0);
    exchange(one, two, t0 + keepalive);
    BOOST_TEST(one.role->tunnel()->counters().sessions_established >= 1U);
    const auto peers = one.role->vtep().peers();
    BOOST_REQUIRE(peers.size() == 1U);
    BOOST_TEST((peers[0].state == net::PeerState::up));

    // A full-size guest frame crosses inside one WireGuard transport message.
    const auto buf = two.post_rx(fn1);
    const auto mtu = one.role->function(fn0)->identity().mtu;
    const auto f = frame(nic_c, nic_a, mtu);
    one.send(fn0, f);
    BOOST_REQUIRE(one.wire.sent.size() == 1U);
    BOOST_TEST(one.wire.sent[0].payload.size() ==
               f.size() + net::geneve_header_size + net::wireguard_overhead);
    BOOST_TEST(one.wire.sent[0].payload.size() <=
               underlay_mtu - net::ipv6_header_size - net::udp_header_size);
    // The message is delivered once; a replayed copy is refused by the
    // tunnel before Geneve decode ever sees it.
    auto copy = one.wire.sent[0];
    const auto rx_before = two.role->vtep().counters().rx_datagrams;
    BOOST_TEST(deliver(one, two, vtep(self_tail)) == 1U);
    auto got = two.received(fn1, buf);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == f));
    one.wire.sent.push_back(copy);  // replayed
    BOOST_TEST(deliver(one, two, vtep(self_tail)) == 0U);
    BOOST_TEST(
        two.role->tunnel()->counters().rx_drop[static_cast<std::size_t>(net::TunnelDrop::replay)] ==
        1U);
    BOOST_TEST(two.role->vtep().counters().rx_datagrams == rx_before + 1);

    // With keys, peers up and probes through the tunnel, the role is healthy.
    for (auto t = t0 + (2 * keepalive); t <= t0 + net::VtepConfig{}.probe_interval + keepalive;
         t += keepalive) {
        exchange(one, two, t);
    }
    BOOST_TEST(one.role->vtep().peers()[0].mtu_ok);
    h = one.role->health();
    BOOST_TEST((h->state == oar::HealthState::ok));
    BOOST_TEST(h->fault_code == 0U);
}

BOOST_FIXTURE_TEST_CASE(clean_returns_to_the_dead_vpc, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_b, self_tail}}, {nic_a, nic_b})) ==
                  Status::ok);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(prepare(fn1, nic_b) == Status::ok);
    driver(fn0);
    driver(fn1);

    BOOST_TEST((role->clean_function({.fn = 9}) == Status::unknown_function));
    BOOST_TEST(
        (role->clean_function({.fn = fn0, .action = ak::helm::CleaningAction::drop_volume_key}) ==
         Status::wrong_type));
    BOOST_TEST((role->clean_function({.fn = fn1}) == Status::ok));
    BOOST_TEST(!role->attached(fn1).has_value());
    BOOST_TEST(!role->vswitch().attached(NicId{nic_b}));
    // The function was reset: the old driver's queues are gone.
    auto status = drivers[fn1]->common_read(vio::common_cfg::device_status, ak::test::width8);
    BOOST_REQUIRE(status.has_value());
    BOOST_TEST(*status == 0U);
    BOOST_TEST((role->function(fn1)->identity().mac != mac_of(nic_b)));

    // Frames for the cleaned NIC are no longer delivered.
    send(fn0, frame(nic_b, nic_a));
    BOOST_TEST(role->vswitch().counters().tx_drop_unattached == 1U);

    // Cleaning an unattached function is fine, and it can be prepared again.
    BOOST_TEST((role->clean_function({.fn = fn1}) == Status::ok));
    BOOST_TEST((prepare(fn1, nic_b) == Status::ok));
}

BOOST_FIXTURE_TEST_CASE(health_degrades_when_a_peer_goes_down, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}}, {nic_a, nic_c})) ==
                  Status::ok);
    const auto t0 = net::VtepClock::now();
    static_cast<void>(role->tick(t0));
    BOOST_TEST((role->health()->state == oar::HealthState::ok));  // pending, not down
    static_cast<void>(role->tick(t0 + (keepalive * 3)));
    BOOST_TEST((role->health()->state == oar::HealthState::degraded));
}

BOOST_FIXTURE_TEST_CASE(helm_drives_the_role_over_the_sideband, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A VPC big enough that its frame travels in several sideband chunks.
    constexpr std::uint64_t many = 300;
    std::vector<std::pair<std::uint64_t, std::uint8_t>> nics;
    for (std::uint64_t n = 1; n <= many; ++n) {
        nics.emplace_back(n, n % 2 == 0 ? self_tail : peer_tail);
    }
    const auto frame_bytes = signed_map(server_one, 1, nics);
    BOOST_REQUIRE(frame_bytes.size() > oar::max_map_chunk);

    constexpr ak::helm::LinkAddress helm_side{
        .local_addr = 0x08, .peer_addr = 0x14, .local_eid = 8, .peer_eid = 20};
    auto pair = ak::helm::SocketBinding::make_pair();
    BOOST_REQUIRE(pair);
    ak::helm::OarLink link{*pair->first,
                           {.address = helm_side, .timeout = std::chrono::seconds{5}}};
    ak::helm::OarEndpoint endpoint{*pair->second, {.address = helm_side.reversed()}};
    {
        const std::jthread server{[&](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint.serve_one(*role, std::chrono::milliseconds{5});
                if (!r && r.error() != ak::helm::BindingError::timed_out) {
                    return;
                }
            }
        }};
        auto inv = link.function_inventory();
        BOOST_REQUIRE(inv.has_value());
        BOOST_TEST((inv->role == oar::Role::net));
        BOOST_TEST((inv->vtep == vtep(self_tail)));
        BOOST_TEST(link.map_update(frame_bytes).has_value());
        BOOST_TEST(link.prepare_function(
                           {.fn = fn0,
                            .type = ak::helm::FunctionType::nic_vf,
                            .vm_id = vm_one,
                            .config = oar::NicConfig{.nic_id = 2, .vni = vpc, .mac = mac_of(2)}})
                       .has_value());
        // A frame for another server comes back as a failure.
        BOOST_TEST(!link.map_update(signed_map(server_two, 2, {{2, self_tail}})).has_value());
        BOOST_TEST(link.health().has_value());
    }
    BOOST_TEST(role->mappings().snapshot()->nic_count() == many);
    BOOST_TEST((role->attached(fn0) == NicId{2}));
    BOOST_TEST(role->counters().map_wrong_server == 1U);
}
