// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 8 (tasks 9 and 11): the
// network role behind helm's sideband. Placeholders between attachments,
// prepare and clean, signed map_updates checked against the controller's
// key, and guest frames crossing the VSwitch locally and two VTEPs over a
// fake underlay.

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
#include "oar/net/net_role.hpp"
#include "proto/map_update.hpp"
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
constexpr std::uint16_t ethertype_test = 0x88B5;  // IEEE local experimental
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

auto frame(const net::MacAddress& dst, const net::MacAddress& src,
           std::size_t payload = payload_size) -> std::vector<std::byte> {
    std::vector<std::byte> f;
    f.insert(f.end(), dst.begin(), dst.end());
    f.insert(f.end(), src.begin(), src.end());
    f.push_back(static_cast<std::byte>(ethertype_test >> 8U));
    f.push_back(static_cast<std::byte>(ethertype_test & 0xFFU));
    f.insert(f.end(), payload, std::byte{payload_fill});
    return f;
}

auto signer() -> const ak::test::TestSigner& {
    static const ak::test::TestSigner s{ak::test::rfc_test1_secret};
    return s;
}

// Signs like the controller: encode with a blank signature, sign, set.
auto signed_map(std::uint64_t server, std::uint64_t version,
                const std::vector<std::pair<std::uint64_t, std::uint8_t>>& nics)
    -> std::vector<std::byte> {
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
class Wire final : public net::DatagramSender {
public:
    struct Datagram {
        net::Ipv6Address dst{};
        std::vector<std::byte> payload;
    };
    auto send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool override {
        sent.push_back({dst, {payload.begin(), payload.end()}});
        return true;
    }
    std::vector<Datagram> sent;
};

// One VTEP: a role over `function_count` fake transports, and a guest
// driver per function.
struct Board {
    explicit Board(std::uint64_t server, std::uint8_t tail) {
        auto plan = net::plan_mtu(underlay_mtu);
        BOOST_REQUIRE(plan.has_value());
        std::vector<net::NetTransport*> raw;
        for (auto& t : transports) {
            raw.push_back(&t);
        }
        auto r = net::NetRole::create({.vtep = vtep(tail),
                                       .server_id = server,
                                       .mtu = *plan,
                                       .queue_size = ak::test::test_queue_size,
                                       .tx_budget = 256,
                                       .vtep_config = {.keepalive_interval = keepalive},
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

// Carries everything `from` sent to `to`'s VTEP into `to`.
auto deliver(Board& from, Board& to, const net::Ipv6Address& from_addr) -> std::size_t {
    std::size_t n = 0;
    for (const auto& d : from.wire.sent) {
        if (auto p = to.role->vtep().receive(d.payload, from_addr, net::VtepClock::now())) {
            static_cast<void>(to.role->vswitch().receive(*p, from_addr));
            ++n;
        }
    }
    from.wire.sent.clear();
    return n;
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
    send(fn0, frame(mac_of(nic_a), id.mac));
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

BOOST_FIXTURE_TEST_CASE(local_guests_talk_through_the_vswitch, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_b, self_tail}})) == Status::ok);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(prepare(fn1, nic_b) == Status::ok);
    driver(fn0);
    driver(fn1);
    const auto buf = post_rx(fn1);
    const auto f = frame(mac_of(nic_b), mac_of(nic_a));
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
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}})) == Status::ok);
    BOOST_REQUIRE(two.role->map_update(signed_map(
                      server_two, 1, {{nic_a, self_tail}, {nic_c, peer_tail}})) == Status::ok);
    BOOST_REQUIRE(one.prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(two.prepare(fn1, nic_c) == Status::ok);
    one.driver(fn0);
    two.driver(fn1);
    const auto buf = two.post_rx(fn1);

    // A full-size frame: the guest MTU plus Ethernet fits the plan exactly.
    const auto mtu = one.role->function(fn0)->identity().mtu;
    const auto f = frame(mac_of(nic_c), mac_of(nic_a), mtu);
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
}

BOOST_FIXTURE_TEST_CASE(clean_returns_to_the_dead_vpc, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_b, self_tail}})) == Status::ok);
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
    send(fn0, frame(mac_of(nic_b), mac_of(nic_a)));
    BOOST_TEST(role->vswitch().counters().tx_drop_unattached == 1U);

    // Cleaning an unattached function is fine, and it can be prepared again.
    BOOST_TEST((role->clean_function({.fn = fn1}) == Status::ok));
    BOOST_TEST((prepare(fn1, nic_b) == Status::ok));
}

BOOST_FIXTURE_TEST_CASE(health_degrades_when_a_peer_goes_down, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_c, peer_tail}})) == Status::ok);
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
