// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 8 (tasks 9 and 11): the
// network role behind helm's sideband. Placeholders between attachments,
// prepare and clean, signed map_updates checked against the controller's
// key, and guest frames crossing the VSwitch locally and two VTEPs over a
// fake underlay, in the clear and inside the WireGuard tunnel (keys from
// helm, peers from the controller's signed TunnelPeers frame). health
// reports a peer that never proves a full-size path (mtu_ok). Task 13:
// signed GroupPolicy frames applied to the VSwitch and its group meters
// read back with group_usage. vpc-subnets-routing task 6: three roles
// route between subnets over the WireGuard tunnel, through a middlebox
// appliance and around it, and refuse forged routed and cross-subnet frames.

#define BOOST_TEST_MODULE net_role_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include "ed25519_test_support.hpp"
#include "helm/oar_link.hpp"
#include "helm/sideband_binding.hpp"
#include "hull/signature_verifier.hpp"
#include "metadata_packets.hpp"
#include "net_frames.hpp"
#include "oar/net/net_role.hpp"
#include "proto/group_members.hpp"
#include "proto/group_policy.hpp"
#include "proto/instance_metadata.hpp"
#include "proto/map_update.hpp"
#include "proto/tunnel_peers.hpp"
#include "proto/vpc_config.hpp"
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
constexpr std::uint64_t vpc_subnet = 0x5B01;
constexpr std::uint64_t other_subnet = 0x5B02;
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
// `addressed` NICs also get guest_ip(nic) in the frame (format v2). Every
// NIC is in vpc_subnet unless `subnets` names another (0 for none).
auto signed_map(std::uint64_t server, std::uint64_t version,
                const std::vector<std::pair<std::uint64_t, std::uint8_t>>& nics,
                const std::vector<std::uint64_t>& addressed = {},
                const std::map<std::uint64_t, std::uint64_t>& subnets = {})
    -> std::vector<std::byte> {
    // Member by member, so the frame format can grow fields (v2's guest
    // addresses) without this needing every one spelled out.
    proto::MapUpdate m{};
    m.server_id = server;
    m.key_id = key_id;
    m.vni = vpc;
    m.map_version = version;
    for (const auto& [nic, tail] : nics) {
        const auto subnet = subnets.find(nic);
        m.entries.push_back({.nic_id = nic,
                             .mac = mac_of(nic),
                             .owner_vtep = vtep(tail),
                             .subnet_id = subnet == subnets.end() ? vpc_subnet : subnet->second});
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

// A VpcConfig for `vpc`: block 10.0.0.0/16 and fd10::/56, one subnet
// 10.0.0.0/24 (gateway .1) with fd10::/64, signed like the controller signs
// it. `routes` adds a default route to nic_b to the main table;
// `second_subnet` adds other_subnet, 10.0.1.0/24 without IPv6.
auto signed_vpc(std::uint64_t server, std::uint64_t version, std::uint32_t lease = 3600,
                bool routes = false, bool second_subnet = false) -> std::vector<std::byte> {
    proto::VpcConfigFrame c{};
    c.server_id = server;
    c.key_id = key_id;
    c.vni = vpc;
    c.config_version = version;
    c.gateway_mac = {std::byte{0x02}, std::byte{0}, std::byte{0},
                     std::byte{0},    std::byte{0}, std::byte{0xFE}};
    c.ipv4_blocks = {
        {.prefix = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}}, .length = 16}};
    proto::Ipv6Address ula{};
    ula[0] = std::byte{0xFD};
    ula[1] = std::byte{0x10};
    c.ipv6_block = ula;
    c.subnets = {{.subnet_id = vpc_subnet,
                  .table = 1,
                  .ipv4_prefix = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}},
                  .ipv4_length = 24,
                  .ipv6_prefix = ula}};
    if (second_subnet) {
        c.subnets.push_back(
            {.subnet_id = other_subnet,
             .table = 1,
             .ipv4_prefix = {std::byte{10}, std::byte{0}, std::byte{1}, std::byte{0}},
             .ipv4_length = 24,
             .ipv6_prefix = std::nullopt});
    }
    proto::VpcRouteTable main{.table = 1, .main = true, .routes = {}};
    if (routes) {
        main.routes.push_back({.kind = proto::RouteKind::nic,
                               .family = proto::RouteFamily::ipv4,
                               .length = 0,
                               .prefix = {},
                               .target_nic = nic_b});
    }
    proto::VpcRoute local4{.kind = proto::RouteKind::local,
                           .family = proto::RouteFamily::ipv4,
                           .length = 16,
                           .prefix = {},
                           .target_nic = 0};
    local4.prefix[0] = std::byte{10};
    main.routes.push_back(local4);
    main.routes.push_back({.kind = proto::RouteKind::local,
                           .family = proto::RouteFamily::ipv6,
                           .length = 56,
                           .prefix = ula,
                           .target_nic = 0});
    c.tables = {main};
    c.dns4 = {{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{2}}};
    c.domain = "ec2.internal";
    c.lease_seconds = lease;
    auto bytes = proto::encode_vpc_config(c);
    BOOST_REQUIRE(bytes.has_value());
    const auto sig = signer().sign(proto::vpc_config_signed_bytes(*bytes));
    proto::set_vpc_config_signature(*bytes, sig);
    return *bytes;
}

// A GroupPolicy for `vpc`, signed like the controller signs it. A
// multicast policy gets small limits that fit the oar-net bounds.
auto signed_policy(std::uint64_t server, std::uint64_t version, bool multicast,
                   std::uint16_t max_groups = 0) -> std::vector<std::byte> {
    proto::GroupPolicy p{};
    p.server_id = server;
    p.key_id = key_id;
    p.vni = vpc;
    p.policy_version = version;
    if (multicast) {
        p.mode = proto::GroupMode::multicast;
        p.rate_frames = 100;
        p.burst_frames = 10;
        p.rate_bytes = 1'000'000;
        p.burst_bytes = 100'000;
        p.max_remote_vteps = 4;
        p.max_groups_per_nic = max_groups;
    }
    auto bytes = proto::encode_group_policy(p);
    BOOST_REQUIRE(bytes.has_value());
    const auto sig = signer().sign(proto::group_policy_signed_bytes(*bytes));
    proto::set_group_policy_signature(*bytes, sig);
    return *bytes;
}

// A GroupMembers for `vpc` listing 239.0.0.1 at the peer VTEP, signed
// like the controller signs it.
auto signed_members(std::uint64_t server, std::uint64_t version) -> std::vector<std::byte> {
    proto::GroupMembers m{.server_id = server,
                          .key_id = key_id,
                          .vni = vpc,
                          .members_version = version,
                          .groups = {}};
    proto::MemberGroup& g = m.groups.emplace_back();
    g.family = proto::RouteFamily::ipv4;
    g.group[0] = std::byte{239};
    g.group[3] = std::byte{1};
    g.vteps = {vtep(peer_tail)};
    auto bytes = proto::encode_group_members(m);
    BOOST_REQUIRE(bytes.has_value());
    const auto sig = signer().sign(proto::group_members_signed_bytes(*bytes));
    proto::set_group_members_signature(*bytes, sig);
    return *bytes;
}

// An InstanceMetadata record for `nic`, signed like the controller signs it.
auto signed_metadata(std::uint64_t server, std::uint64_t nic, std::uint64_t version)
    -> std::vector<std::byte> {
    proto::InstanceMetadata m{};
    m.server_id = server;
    m.key_id = key_id;
    m.nic_id = nic;
    m.metadata_version = version;
    m.vni = vpc;
    m.instance_id = "i-0abc";
    m.image_id = "ami-0abc";
    m.instance_type = "m5.large";
    m.account_id = "123456789012";
    m.local_hostname = "ip-10-0-0-17.ec2.internal";
    m.availability_zone = "harbor-1a";
    m.region = "harbor-1";
    m.interface_id = "eni-0abc";
    m.vpc_id = "vpc-0abc";
    auto bytes = proto::encode_instance_metadata(m);
    BOOST_REQUIRE(bytes.has_value());
    const auto sig = signer().sign(proto::instance_metadata_signed_bytes(*bytes));
    proto::set_instance_metadata_signature(*bytes, sig);
    return *bytes;
}

// An IGMPv2 membership report for 239.0.0.1 from a guest.
auto igmp_join(std::uint64_t src) -> std::vector<std::byte> {
    const net::MacAddress group{std::byte{0x01}, std::byte{0x00}, std::byte{0x5e},
                                std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
    const proto::Ipv4Address group_ip{std::byte{239}, std::byte{0}, std::byte{0}, std::byte{1}};
    std::vector<std::byte> m{std::byte{0x16}, std::byte{0}, std::byte{0}, std::byte{0}};
    m.insert(m.end(), group_ip.begin(), group_ip.end());
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < m.size(); i += 2) {
        sum +=
            (std::to_integer<std::uint32_t>(m[i]) << 8U) | std::to_integer<std::uint32_t>(m[i + 1]);
    }
    sum = (sum & 0xFFFFU) + (sum >> 16U);
    const auto c = static_cast<std::uint16_t>(~sum & 0xFFFFU);
    m[2] = static_cast<std::byte>(c >> 8U);
    m[3] = static_cast<std::byte>(c & 0xFFU);
    constexpr std::uint8_t ipproto_igmp = 2;
    return ak::test::frames::ipv4(group, mac_of(src), guest_ip(src), group_ip, ipproto_igmp, m);
}

// An IPv4/UDP multicast frame (239.0.0.1) from a guest.
auto multicast_frame(std::uint64_t src) -> std::vector<std::byte> {
    const net::MacAddress group{std::byte{0x01}, std::byte{0x00}, std::byte{0x5e},
                                std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
    const proto::Ipv4Address group_ip{std::byte{239}, std::byte{0}, std::byte{0}, std::byte{1}};
    const std::vector<std::byte> payload(payload_size, std::byte{payload_fill});
    return ak::test::frames::ipv4(group, mac_of(src), guest_ip(src), group_ip, ipproto_udp,
                                  ak::test::frames::udp(udp_port, udp_port, payload));
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
    explicit Board(std::uint64_t server, std::uint8_t tail, Encryption enc = Encryption::none,
                   bool metadata = false) {
        std::optional<net::NetRoleConfig::Metadata> plumbing;
        if (metadata) {
            // The role's TUN is one end of a datagram pair; the test is the kernel.
            std::array<int, 2> fds{};
            BOOST_REQUIRE(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
            plumbing = net::NetRoleConfig::Metadata{.tun_fd = fds[0], .listen_fd = -1};
            kernel = fds[1];
        }
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
             .clock = {},
             .metadata = plumbing},
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

    Board(const Board&) = delete;
    auto operator=(const Board&) -> Board& = delete;
    Board(Board&&) = delete;
    auto operator=(Board&&) -> Board& = delete;
    ~Board() {
        if (kernel >= 0) {
            ::close(kernel);
        }
    }

    std::array<FakeTransport, function_count> transports;
    int kernel{-1};  // the metadata TUN's other end
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
    BOOST_TEST(
        (role->deliver_key({.fn = fn0, .volume_id = 1, .key = key, .image_key = std::nullopt}) ==
         Status::unsupported));
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

// vpc-subnets-routing Requirement 2.6: a NIC's addresses count only inside
// its subnet, and the mapping and config give the same table in either
// order.
BOOST_FIXTURE_TEST_CASE(guest_addresses_follow_the_nics_subnet, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // nic_b is placed in other_subnet (10.0.1.0/24) but its address is
    // 10.0.0.x; nic_c names no subnet at all.
    const auto map =
        signed_map(server_one, 2, {{nic_a, self_tail}, {nic_b, self_tail}, {nic_c, peer_tail}},
                   {nic_a, nic_b, nic_c}, {{nic_b, other_subnet}, {nic_c, 0}});
    const auto config = signed_vpc(server_one, 2, 3600, false, true);
    const auto count = [](net::NetRole& r, std::uint64_t nic) {
        return r.vswitch().nic_addresses(vpc, net::geneve::NicId{nic}).first.size();
    };

    BOOST_REQUIRE((role->map_update(map) == Status::ok));
    BOOST_TEST(count(*role, nic_b) == 1U);  // no config: one segment, every address counts
    BOOST_REQUIRE((role->vpc_config(config) == Status::ok));
    BOOST_TEST(count(*role, nic_a) == 1U);
    BOOST_TEST(count(*role, nic_b) == 0U);
    BOOST_TEST(count(*role, nic_c) == 0U);
    BOOST_TEST(role->counters().map_addr_outside_subnet == 2U);

    Board other{server_one, self_tail};
    BOOST_REQUIRE((other.role->vpc_config(config) == Status::ok));
    BOOST_REQUIRE((other.role->map_update(map) == Status::ok));
    for (const std::uint64_t nic : {nic_a, nic_b, nic_c}) {
        BOOST_TEST((other.role->vswitch().nic_addresses(vpc, net::geneve::NicId{nic}) ==
                    role->vswitch().nic_addresses(vpc, net::geneve::NicId{nic})));
    }
    BOOST_TEST(other.role->counters().map_addr_outside_subnet == 2U);
}

// An ARP request from `nic` for `target`, as a guest sends it.
BOOST_FIXTURE_TEST_CASE(vpc_configs_are_checked, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = signed_vpc(server_one, 2);

    BOOST_TEST((role->vpc_config(std::span{good}.first(good.size() - 1)) == Status::failed));
    BOOST_TEST(role->counters().vpc_undecodable == 1U);

    BOOST_TEST((role->vpc_config(signed_vpc(server_two, 2)) == Status::failed));
    BOOST_TEST(role->counters().vpc_wrong_server == 1U);

    auto tampered = good;
    tampered[0x28] ^= std::byte{0x01};  // lease_seconds
    BOOST_TEST((role->vpc_config(tampered) == Status::failed));
    BOOST_TEST(role->counters().vpc_bad_signature == 1U);
    BOOST_TEST(role->vswitch().vpc_config(vpc) == nullptr);

    BOOST_TEST((role->vpc_config(good) == Status::ok));
    BOOST_TEST(role->counters().vpc_applied == 1U);
    const auto* applied = role->vswitch().vpc_config(vpc);
    BOOST_REQUIRE(applied != nullptr);
    BOOST_TEST(std::to_integer<int>(applied->gateway_mac[5]) == 0xFE);
    BOOST_REQUIRE(applied->subnets.size() == 1U);
    const auto& subnet = applied->subnets.front();
    BOOST_TEST(subnet.id == vpc_subnet);
    BOOST_TEST(subnet.ipv4.length == 24U);
    BOOST_TEST(std::to_integer<int>(subnet.gateway[3]) == 1);
    BOOST_REQUIRE(subnet.ipv6_prefix.has_value());
    BOOST_TEST(std::to_integer<int>((*subnet.ipv6_prefix)[1]) == 0x10);
    BOOST_REQUIRE(applied->ipv4_blocks.size() == 1U);
    BOOST_TEST(applied->ipv4_blocks.front().length == 16U);
    BOOST_REQUIRE(applied->dns4.size() == 1U);
    BOOST_TEST(applied->domain == "ec2.internal");
    BOOST_TEST(applied->lease_seconds == 3600U);

    // helm resends its kept frames when the sideband reopens: ok, unchanged.
    BOOST_TEST((role->vpc_config(good) == Status::ok));
    BOOST_TEST(role->counters().vpc_redelivered == 1U);
    BOOST_TEST(role->counters().vpc_applied == 1U);

    // An older version is refused, even a validly signed one.
    BOOST_TEST((role->vpc_config(signed_vpc(server_one, 1, 60)) == Status::failed));
    BOOST_TEST(role->counters().vpc_stale == 1U);
    BOOST_TEST(role->vswitch().vpc_config(vpc)->lease_seconds == 3600U);

    // A newer config replaces it.
    BOOST_TEST((role->vpc_config(signed_vpc(server_one, 3, 7200)) == Status::ok));
    BOOST_TEST(role->counters().vpc_applied == 2U);
    BOOST_TEST(role->counters().vpc_rejected == 0U);
    BOOST_TEST(role->vswitch().vpc_config(vpc)->lease_seconds == 7200U);

    // Route tables carry their local and NIC routes into the VSwitch.
    BOOST_TEST((role->vpc_config(signed_vpc(server_one, 4, 600, true)) == Status::ok));
    const auto* routed = role->vswitch().vpc_config(vpc);
    BOOST_REQUIRE(routed->tables.size() == 1U);
    const auto& routes = routed->tables.front().routes;
    BOOST_TEST(routed->tables.front().main);
    BOOST_REQUIRE(routes.size() == 3U);
    BOOST_TEST(std::ranges::count_if(routes, [](const net::VpcRoute& r) { return r.local; }) == 2);
    BOOST_TEST(std::ranges::any_of(
        routes, [](const net::VpcRoute& r) { return !r.local && r.target.value == nic_b; }));
}

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

BOOST_FIXTURE_TEST_CASE(group_policies_are_checked, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = signed_policy(server_one, 2, true);

    BOOST_TEST((role->group_policy(std::span{good}.first(good.size() - 1)) == Status::failed));
    BOOST_TEST(role->counters().group_undecodable == 1U);

    BOOST_TEST((role->group_policy(signed_policy(server_two, 2, true)) == Status::failed));
    BOOST_TEST(role->counters().group_wrong_server == 1U);

    auto tampered = good;
    tampered[0x20] ^= std::byte{0x01};  // rate_frames
    BOOST_TEST((role->group_policy(tampered) == Status::failed));
    BOOST_TEST(role->counters().group_bad_signature == 1U);
    BOOST_TEST((role->vswitch().group_policy(vpc).mode == net::GroupMode::drop));

    BOOST_TEST((role->group_policy(good) == Status::ok));
    BOOST_TEST(role->counters().group_applied == 1U);
    const auto applied = role->vswitch().group_policy(vpc);
    BOOST_TEST((applied.mode == net::GroupMode::multicast));
    BOOST_TEST(applied.rate_frames == 100U);
    BOOST_TEST(applied.burst_frames == 10U);
    BOOST_TEST(applied.rate_bytes == 1'000'000U);
    BOOST_TEST(applied.burst_bytes == 100'000U);
    BOOST_TEST(applied.max_remote_vteps == 4U);

    // helm replays its kept frames when the sideband reopens: ok, unchanged.
    BOOST_TEST((role->group_policy(good) == Status::ok));
    BOOST_TEST(role->counters().group_redelivered == 1U);
    BOOST_TEST(role->counters().group_applied == 1U);

    // An older version is refused, even a validly signed one, and the
    // policy stays.
    BOOST_TEST((role->group_policy(signed_policy(server_one, 1, false)) == Status::failed));
    BOOST_TEST(role->counters().group_stale == 1U);
    BOOST_TEST((role->vswitch().group_policy(vpc).mode == net::GroupMode::multicast));

    // A newer drop policy opts the VNI back out.
    BOOST_TEST((role->group_policy(signed_policy(server_one, 3, false)) == Status::ok));
    BOOST_TEST((role->vswitch().group_policy(vpc).mode == net::GroupMode::drop));
    BOOST_TEST(role->counters().group_applied == 2U);
}

// vpc-subnets-routing task 12: a version 2 policy opts subnets in one by
// one, on the same version sequence as version 1.
BOOST_FIXTURE_TEST_CASE(group_policies_opt_in_per_subnet, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto v2 = [](std::uint64_t version, std::vector<std::uint64_t> subnets) {
        proto::GroupPolicy p{.server_id = server_one,
                             .key_id = key_id,
                             .vni = vpc,
                             .mode = proto::GroupMode::drop,
                             .policy_version = version,
                             .signature = {},
                             .format = proto::group_policy_version_subnets,
                             .subnets = {}};
        for (const std::uint64_t s : subnets) {
            p.subnets.push_back({.subnet_id = s,
                                 .rate_frames = 100,
                                 .burst_frames = 10,
                                 .rate_bytes = 1'000'000,
                                 .burst_bytes = 100'000,
                                 .max_remote_vteps = 4,
                                 .max_groups_per_nic = 3});
        }
        auto bytes = proto::encode_group_policy(p);
        BOOST_REQUIRE(bytes.has_value());
        proto::set_group_policy_signature(*bytes,
                                          signer().sign(proto::group_policy_signed_bytes(*bytes)));
        return *bytes;
    };
    BOOST_REQUIRE(role->group_policy(signed_policy(server_one, 1, true)) == Status::ok);
    const auto only_other = v2(2, {other_subnet});
    auto tampered = only_other;
    tampered[0x20 + 0x08] ^= std::byte{0x01};  // the entry's rate_frames
    BOOST_TEST((role->group_policy(tampered) == Status::failed));
    BOOST_TEST(role->counters().group_bad_signature == 1U);

    BOOST_TEST((role->group_policy(only_other) == Status::ok));
    auto& sw = role->vswitch();
    BOOST_TEST((sw.group_policy(vpc).mode == net::GroupMode::drop));
    BOOST_TEST((sw.group_policy(vpc, vpc_subnet).mode == net::GroupMode::drop));
    const auto other = sw.group_policy(vpc, other_subnet);
    BOOST_TEST((other.mode == net::GroupMode::multicast));
    BOOST_TEST(other.max_groups_per_nic == 3U);
    BOOST_TEST(other.rate_bytes == 1'000'000U);

    // Versions run across both formats: an older version 1 is stale, a
    // newer one takes the whole VNI back.
    BOOST_TEST((role->group_policy(signed_policy(server_one, 1, true)) == Status::failed));
    BOOST_TEST(role->counters().group_stale == 1U);
    BOOST_TEST((role->group_policy(v2(3, {})) == Status::ok));
    BOOST_TEST((sw.group_policy(vpc, other_subnet).mode == net::GroupMode::drop));
    BOOST_TEST((role->group_policy(signed_policy(server_one, 4, true)) == Status::ok));
    BOOST_TEST((sw.group_policy(vpc, vpc_subnet).mode == net::GroupMode::multicast));
    BOOST_TEST(role->counters().group_applied == 4U);
}

BOOST_FIXTURE_TEST_CASE(group_usage_reads_every_attachment, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(
                      server_one, 1, {{nic_a, self_tail}, {nic_b, self_tail}}, {nic_a, nic_b})) ==
                  Status::ok);
    BOOST_REQUIRE(role->group_policy(signed_policy(server_one, 1, true)) == Status::ok);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(prepare(fn1, nic_b) == Status::ok);
    static_cast<void>(driver(fn0));
    send(fn0, multicast_frame(nic_a));
    static_cast<void>(role->poll());
    BOOST_REQUIRE(role->vswitch().group_meter(NicId{nic_a})->frames == 1U);

    // No read open yet: only cursor 0 starts one.
    BOOST_TEST((role->group_usage(1).error() == Status::bad_request));

    auto page = role->group_usage(0);
    BOOST_REQUIRE(page.has_value());
    BOOST_REQUIRE(page->total == 2U);
    BOOST_REQUIRE(page->entries.size() == 2U);
    const auto& a = page->entries[0];
    BOOST_TEST(a.nic_id == nic_a);
    BOOST_TEST(a.vni == vpc);
    BOOST_TEST(!a.detached);
    BOOST_TEST(a.attachment != 0U);
    BOOST_TEST(a.frames == 1U);
    BOOST_TEST(a.replicas_local == role->vswitch().group_meter(NicId{nic_a})->replicas_local);
    const auto first = a.attachment;  // `a` dangles once `page` is reassigned below
    BOOST_TEST(page->entries[1].nic_id == nic_b);
    BOOST_TEST(page->entries[1].frames == 0U);

    // Detach: the final reading comes once, then the NIC is gone.
    BOOST_REQUIRE(role->clean_function(
                      {.fn = fn0, .action = ak::helm::CleaningAction::reset_nic_vf}) == Status::ok);
    page = role->group_usage(0);
    BOOST_REQUIRE(page.has_value());
    BOOST_REQUIRE(page->entries.size() == 2U);
    BOOST_TEST(page->entries[0].nic_id == nic_a);
    BOOST_TEST(page->entries[0].detached);
    BOOST_TEST(page->entries[0].vni == vpc);
    BOOST_TEST(page->entries[0].frames == 1U);
    page = role->group_usage(0);
    BOOST_REQUIRE(page.has_value());
    BOOST_REQUIRE(page->entries.size() == 1U);
    BOOST_TEST(page->entries[0].nic_id == nic_b);

    // A re-attach starts a new series from zero.
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    page = role->group_usage(0);
    BOOST_REQUIRE(page.has_value());
    BOOST_REQUIRE(page->entries.size() == 2U);
    BOOST_TEST(page->entries[0].nic_id == nic_a);
    BOOST_TEST(page->entries[0].attachment > first);
    BOOST_TEST(page->entries[0].frames == 0U);
    BOOST_TEST(role->counters().usage_unknown_vni == 0U);
}

BOOST_FIXTURE_TEST_CASE(group_members_are_checked, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = signed_members(server_one, 2);

    BOOST_TEST((role->group_members(std::span{good}.first(good.size() - 1)) == Status::failed));
    BOOST_TEST(role->counters().members_undecodable == 1U);
    BOOST_TEST((role->group_members(signed_members(server_two, 2)) == Status::failed));
    BOOST_TEST(role->counters().members_wrong_server == 1U);
    auto tampered = good;
    tampered[0x18] ^= std::byte{0x01};  // members_version
    BOOST_TEST((role->group_members(tampered) == Status::failed));
    BOOST_TEST(role->counters().members_bad_signature == 1U);
    BOOST_TEST(role->vswitch().group_members(vpc) == nullptr);

    BOOST_TEST((role->group_members(good) == Status::ok));
    BOOST_TEST(role->counters().members_applied == 1U);
    const auto* lists = role->vswitch().group_members(vpc);
    BOOST_REQUIRE(lists != nullptr);
    BOOST_REQUIRE(lists->size() == 1U);
    BOOST_TEST(!lists->begin()->first.ipv6);
    BOOST_TEST((lists->begin()->first.address[0] == std::byte{239}));
    BOOST_TEST((lists->begin()->second == std::vector{vtep(peer_tail)}));

    // Redelivery answers ok untouched; an older version is refused.
    BOOST_TEST((role->group_members(good) == Status::ok));
    BOOST_TEST(role->counters().members_redelivered == 1U);
    BOOST_TEST((role->group_members(signed_members(server_one, 1)) == Status::failed));
    BOOST_TEST(role->counters().members_stale == 1U);
    BOOST_TEST((role->group_members(signed_members(server_one, 3)) == Status::ok));
    BOOST_TEST(role->counters().members_applied == 2U);
}

// The policy's group cap reaches the VSwitch, and helm reads the joins
// it allows once per change.
BOOST_FIXTURE_TEST_CASE(group_membership_lists_snooped_joins, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(role->map_update(signed_map(server_one, 1, {{nic_a, self_tail}}, {nic_a})) ==
                  Status::ok);
    BOOST_REQUIRE(role->group_policy(signed_policy(server_one, 1, true, 4)) == Status::ok);
    BOOST_TEST(role->vswitch().group_policy(vpc).max_groups_per_nic == 4U);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    static_cast<void>(driver(fn0));

    auto page = role->group_membership({.cursor = 0, .since = std::nullopt});
    BOOST_REQUIRE(page.has_value());
    BOOST_TEST(!page->unchanged);
    BOOST_TEST(page->total == 0U);
    const auto empty = page->generation;

    send(fn0, igmp_join(nic_a));
    static_cast<void>(role->poll());
    BOOST_REQUIRE(role->vswitch().memberships().size() == 1U);

    page = role->group_membership({.cursor = 0, .since = empty});
    BOOST_REQUIRE(page.has_value());
    BOOST_TEST(!page->unchanged);
    BOOST_TEST(page->generation != empty);
    BOOST_REQUIRE(page->entries.size() == 1U);
    BOOST_TEST(page->entries[0].nic_id == nic_a);
    BOOST_TEST(page->entries[0].vni == vpc);
    BOOST_TEST(!page->entries[0].ipv6);
    BOOST_TEST((page->entries[0].group[0] == std::byte{239}));
    BOOST_TEST((page->entries[0].group[3] == std::byte{1}));

    const auto now = page->generation;
    page = role->group_membership({.cursor = 0, .since = now});
    BOOST_REQUIRE(page.has_value());
    BOOST_TEST(page->unchanged);
    BOOST_TEST(
        (role->group_membership({.cursor = 1, .since = now}).error() == Status::bad_request));
}

// Requirement 13.4: a verified record is kept for its NIC from before the
// attach until the NIC is cleaned.
BOOST_FIXTURE_TEST_CASE(instance_metadata_lives_until_the_nic_is_cleaned, One,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((role->instance_metadata(signed_metadata(server_two, nic_a, 1)) == Status::failed));
    auto tampered = signed_metadata(server_one, nic_a, 1);
    tampered[0x24] = std::byte{0};  // http_endpoint disabled after signing
    BOOST_TEST((role->instance_metadata(tampered) == Status::failed));
    BOOST_TEST(role->metadata().find(nic_a) == nullptr);

    BOOST_TEST((role->instance_metadata(signed_metadata(server_one, nic_a, 2)) == Status::ok));
    BOOST_TEST((role->instance_metadata(signed_metadata(server_one, nic_a, 2)) == Status::ok));
    BOOST_TEST((role->instance_metadata(signed_metadata(server_one, nic_a, 1)) == Status::failed));
    BOOST_REQUIRE(role->metadata().find(nic_a) != nullptr);
    BOOST_TEST(role->metadata().find(nic_a)->metadata_version == 2U);
    BOOST_TEST(role->metadata().capacity() == role->function_count());

    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    BOOST_TEST(role->metadata().find(nic_a) != nullptr);  // the attach keeps it
    BOOST_REQUIRE(role->clean_function(
                      {.fn = fn0, .action = ak::helm::CleaningAction::reset_nic_vf}) == Status::ok);
    BOOST_TEST(role->metadata().find(nic_a) == nullptr);
    BOOST_TEST(role->metadata().counters().dropped == 1U);
}

struct WithMetadata : Board {
    WithMetadata() : Board(server_one, self_tail, Encryption::none, true) {}
};

// A guest's metadata request reaches the board's kernel from an alias, and
// the kernel's reply reaches the guest (Requirements 13.1, 13.3, 13.4).
BOOST_FIXTURE_TEST_CASE(metadata_requests_go_through_the_tun_and_back, WithMetadata,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    namespace pk = ak::test::metadata;
    BOOST_REQUIRE(role->map_update(signed_map(server_one, 1, {{nic_a, self_tail}}, {nic_a})) ==
                  Status::ok);
    BOOST_REQUIRE(role->vpc_config(signed_vpc(server_one, 1)) == Status::ok);
    BOOST_REQUIRE(prepare(fn0, nic_a) == Status::ok);
    driver(fn0);
    const net::MacAddress gateway{std::byte{0x02}, std::byte{0}, std::byte{0},
                                  std::byte{0},    std::byte{0}, std::byte{0xFE}};
    const auto syn = pk::tcp4(guest_ip(nic_a), net::metadata_ipv4, 40000, 80);
    const auto frame = net::packet::build_ethernet(gateway, mac_of(nic_a), syn);

    // No record yet: no answer at all.
    send(fn0, frame);
    BOOST_REQUIRE(role->metadata_tap() != nullptr);
    BOOST_TEST(role->metadata_tap()->counters().no_record == 1U);

    BOOST_REQUIRE(role->instance_metadata(signed_metadata(server_one, nic_a, 1)) == Status::ok);
    send(fn0, frame);
    BOOST_TEST(role->metadata_tap()->counters().to_kernel == 1U);
    std::array<std::byte, 2048> buf{};
    const auto n = ::recv(kernel, buf.data(), buf.size(), MSG_DONTWAIT);
    BOOST_REQUIRE(n == static_cast<ssize_t>(syn.size()));
    BOOST_TEST(pk::checksums_ok(std::span{buf}.first(syn.size())));
    pk::Ipv4 alias{};
    std::copy_n(buf.begin() + 12, 4, alias.begin());
    BOOST_TEST(std::to_integer<unsigned>(alias[0]) == 100U);
    BOOST_TEST(role->metadata_aliases()->lookup(net::IpAddress::from(alias))->first.value == nic_a);

    // The kernel answers the alias; the guest sees it from 169.254.169.254.
    const auto rx_buffer = post_rx(fn0);
    const auto reply = pk::tcp4(net::metadata_ipv4, alias, 80, 40000, pk::tcp_syn | pk::tcp_ack);
    BOOST_REQUIRE(::send(kernel, reply.data(), reply.size(), 0) ==
                  static_cast<ssize_t>(reply.size()));
    static_cast<void>(role->poll());
    const auto got = received(fn0, rx_buffer);
    BOOST_REQUIRE(got.has_value());
    const auto ip = std::span{*got}.subspan(14);
    BOOST_TEST(std::ranges::equal(std::span{*got}.first(6), mac_of(nic_a)));
    BOOST_TEST(std::ranges::equal(ip.subspan(12, 4), net::metadata_ipv4));
    BOOST_TEST(std::ranges::equal(ip.subspan(16, 4), guest_ip(nic_a)));
    BOOST_TEST(pk::checksums_ok(ip.first(reply.size())));
    BOOST_TEST(role->metadata_tap()->counters().to_guest == 1U);

    // What the HTTP layer answers from.
    const auto view = role->metadata_view(nic_a);
    BOOST_REQUIRE(view.record != nullptr);
    BOOST_TEST(view.record->instance_id == "i-0abc");
    BOOST_TEST((view.network.mac == mac_of(nic_a)));
    BOOST_REQUIRE(view.network.ipv4.size() == 1U);
    BOOST_TEST((view.network.ipv4[0] == guest_ip(nic_a)));
    BOOST_TEST(view.network.subnet4_length == 24U);
    BOOST_TEST(view.network.subnet_id.value_or(0) == vpc_subnet);
    BOOST_TEST(view.network.subnet6.has_value());
    BOOST_REQUIRE(view.network.vpc4.size() == 1U);
    BOOST_TEST(view.network.vpc4[0].length == 16U);
    BOOST_TEST(view.network.vpc6.has_value());
    BOOST_TEST(role->metadata_view(nic_b).record == nullptr);

    // Cleaning the NIC releases its aliases.
    BOOST_REQUIRE(role->clean_function(
                      {.fn = fn0, .action = ak::helm::CleaningAction::reset_nic_vf}) == Status::ok);
    BOOST_TEST(role->metadata_aliases()->size() == 0U);
    std::vector<pollfd> fds;
    role->metadata_poll_fds(fds);
    BOOST_TEST(fds.size() == 1U);  // the TUN; no listener in this rig
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
        // Group policy and meters (task 13).
        BOOST_TEST(link.group_policy(signed_policy(server_one, 1, true)).has_value());
        BOOST_TEST(!link.group_policy(signed_policy(server_two, 2, true)).has_value());
        auto usage = link.group_usage();
        BOOST_REQUIRE(usage.has_value());
        BOOST_REQUIRE(usage->size() == 1U);
        BOOST_TEST((*usage)[0].nic_id == 2U);
        BOOST_TEST((*usage)[0].vni == vpc);
    }
    BOOST_TEST(role->mappings().snapshot()->nic_count() == many);
    BOOST_TEST((role->attached(fn0) == NicId{2}));
    BOOST_TEST(role->counters().map_wrong_server == 1U);
    BOOST_TEST((role->vswitch().group_policy(vpc).mode == net::GroupMode::multicast));
}

// vpc-subnets-routing task 6: routing between subnets with three roles
// over the WireGuard tunnel. Subnets A (10.0.0.0/27, fd10:0:0:0::/64),
// B (10.0.0.32/27, fd10:0:0:1::/64) and M (10.0.0.64/27, fd10:0:0:2::/64);
// a and b on role one, c on role two, the appliance m (its
// source/destination check off) on role three. guest_ip(nic) lands each
// NIC in its subnet: a .17, b .34, c .51, m .68.
namespace {

constexpr std::uint64_t server_three = 9;
constexpr std::uint8_t third_tail = 3;
constexpr std::uint64_t nic_m = 0x44;
constexpr std::uint64_t subnet_a = 0x5A01;
constexpr std::uint16_t main_table = 1;
constexpr std::uint16_t middlebox_table = 2;
constexpr std::uint8_t subnet_length = 27;
constexpr std::size_t eth_size = 14;
constexpr std::size_t ttl_at = eth_size + 8;
constexpr std::size_t hop_limit_at = eth_size + 7;
constexpr std::size_t subnet_byte = 7;  // of an IPv6 address in fd10::/56

auto gateway_mac() -> net::MacAddress {
    return {std::byte{0x02}, std::byte{0}, std::byte{0},
            std::byte{0},    std::byte{0}, std::byte{0xFE}};
}

// 0 for A, 1 for B, 2 for M.
auto subnet_index(std::uint64_t nic) -> std::uint8_t {
    return static_cast<std::uint8_t>(guest_ip(nic)[3] >> 5U);
}

auto subnet_of(std::uint64_t nic) -> std::uint64_t {
    return subnet_a + subnet_index(nic);
}

auto ula(std::uint8_t subnet) -> proto::Ipv6Address {
    proto::Ipv6Address a{};
    a[0] = std::byte{0xFD};
    a[1] = std::byte{0x10};
    a[subnet_byte] = std::byte{subnet};
    return a;
}

auto guest_ip6(std::uint64_t nic) -> net::Ipv6Address {
    auto a = ula(subnet_index(nic));
    a[ipv6_last] = static_cast<std::byte>(nic);
    return a;
}

struct Member {
    std::uint64_t nic{0};
    std::uint8_t tail{0};
};

// Every NIC of the VPC, both families addressed, m with its check off.
auto subnet_map(std::uint64_t server, std::uint64_t version, const std::vector<Member>& members)
    -> std::vector<std::byte> {
    proto::MapUpdate m{};
    m.server_id = server;
    m.key_id = key_id;
    m.vni = vpc;
    m.map_version = version;
    for (const auto& [nic, tail] : members) {  // ascending NIC IDs, so ascending addresses
        m.entries.push_back({.nic_id = nic,
                             .mac = mac_of(nic),
                             .owner_vtep = vtep(tail),
                             .source_dest_check = nic != nic_m,
                             .subnet_id = subnet_of(nic)});
        m.ipv4.push_back({.nic_id = nic, .address = guest_ip(nic)});
        m.ipv6.push_back({.nic_id = nic, .address = guest_ip6(nic)});
    }
    auto bytes = proto::encode_map_update(m);
    BOOST_REQUIRE(bytes.has_value());
    proto::set_map_update_signature(*bytes, signer().sign(proto::map_update_signed_bytes(*bytes)));
    return *bytes;
}

auto all_members() -> std::vector<Member> {
    return {{nic_a, self_tail}, {nic_b, self_tail}, {nic_c, peer_tail}, {nic_m, third_tail}};
}

// The VPC's subnets and tables. Table 1 (main) holds the local routes;
// table 2 adds subnet B's prefixes in both families to m. With
// `middlebox` A and B use table 2, so A's traffic to B goes through m.
auto subnet_vpc(std::uint64_t server, std::uint64_t version, bool middlebox)
    -> std::vector<std::byte> {
    proto::VpcConfigFrame c{};
    c.server_id = server;
    c.key_id = key_id;
    c.vni = vpc;
    c.config_version = version;
    c.gateway_mac = gateway_mac();
    c.ipv4_blocks = {
        {.prefix = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}}, .length = 16}};
    c.ipv6_block = ula(0);
    const std::uint16_t ab = middlebox ? middlebox_table : main_table;
    for (const std::uint64_t nic : {nic_a, nic_b, nic_m}) {
        auto prefix = guest_ip(nic);
        prefix[3] = static_cast<std::byte>(subnet_index(nic) << 5U);
        c.subnets.push_back({.subnet_id = subnet_of(nic),
                             .table = nic == nic_m ? main_table : ab,
                             .ipv4_prefix = prefix,
                             .ipv4_length = subnet_length,
                             .ipv6_prefix = ula(subnet_index(nic))});
    }
    proto::VpcRoute local4{.kind = proto::RouteKind::local,
                           .family = proto::RouteFamily::ipv4,
                           .length = 16,
                           .prefix = {},
                           .target_nic = 0};
    local4.prefix[0] = std::byte{10};
    const proto::VpcRoute local6{.kind = proto::RouteKind::local,
                                 .family = proto::RouteFamily::ipv6,
                                 .length = 56,
                                 .prefix = ula(0),
                                 .target_nic = 0};
    proto::VpcRouteTable main{.table = main_table, .main = true, .routes = {local4, local6}};
    proto::VpcRouteTable steer{.table = middlebox_table, .main = false, .routes = {local4, local6}};
    proto::VpcRoute to_m4{.kind = proto::RouteKind::nic,
                          .family = proto::RouteFamily::ipv4,
                          .length = subnet_length,
                          .prefix = {},
                          .target_nic = nic_m};
    to_m4.prefix[0] = std::byte{10};
    to_m4.prefix[3] = std::byte{0x20};
    steer.routes.push_back(to_m4);
    steer.routes.push_back({.kind = proto::RouteKind::nic,
                            .family = proto::RouteFamily::ipv6,
                            .length = 64,
                            .prefix = ula(1),
                            .target_nic = nic_m});
    std::ranges::sort(steer.routes, proto::detail::vpc_route_key_less);
    std::ranges::sort(main.routes, proto::detail::vpc_route_key_less);
    c.tables = {main, steer};
    c.lease_seconds = 3600;
    auto bytes = proto::encode_vpc_config(c);
    BOOST_REQUIRE(bytes.has_value());
    proto::set_vpc_config_signature(*bytes, signer().sign(proto::vpc_config_signed_bytes(*bytes)));
    return *bytes;
}

// The controller's TunnelPeers frame naming every other VTEP.
auto signed_peer_set(std::uint64_t server, std::uint8_t tail,
                     const std::vector<std::pair<std::uint8_t, net::wg::Key>>& peers)
    -> std::vector<std::byte> {
    proto::TunnelPeers t{};
    t.server_id = server;
    t.key_id = key_id;
    t.vtep = vtep(tail);
    t.peers_version = 1;
    for (const auto& [peer, key] : peers) {  // ascending tails
        if (peer != tail) {
            t.peers.push_back(
                {.vtep = vtep(peer), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = key});
        }
    }
    auto bytes = proto::encode_tunnel_peers(t);
    BOOST_REQUIRE(bytes.has_value());
    proto::set_tunnel_peers_signature(*bytes,
                                      signer().sign(proto::tunnel_peers_signed_bytes(*bytes)));
    return *bytes;
}

// UDP between two guests' addresses, sent to `dst_mac` from `src_mac`.
auto udp4(const net::MacAddress& dst_mac, const net::MacAddress& src_mac, std::uint64_t from,
          std::uint64_t to) -> std::vector<std::byte> {
    const std::vector<std::byte> payload(payload_size, std::byte{payload_fill});
    return ak::test::frames::ipv4(dst_mac, src_mac, guest_ip(from), guest_ip(to), ipproto_udp,
                                  ak::test::frames::udp(udp_port, udp_port, payload));
}

auto udp6(const net::MacAddress& dst_mac, const net::MacAddress& src_mac, std::uint64_t from,
          std::uint64_t to) -> std::vector<std::byte> {
    const std::vector<std::byte> payload(payload_size, std::byte{payload_fill});
    return ak::test::frames::ipv6(dst_mac, src_mac, guest_ip6(from), guest_ip6(to), ipproto_udp,
                                  ak::test::frames::udp(udp_port, udp_port, payload));
}

// `got` is `sent` after `hops` routers: the target's MAC from the
// gateway's, the TTL or hop limit `hops` lower, the IPv4 header checksum
// still valid, and every other byte unchanged.
auto routed_copy(const std::vector<std::byte>& got, const std::vector<std::byte>& sent,
                 std::uint64_t dst, int hops, bool v6) -> bool {
    if (got.size() != sent.size()) {
        return false;
    }
    const net::MacAddress gw = gateway_mac();
    const net::MacAddress to = mac_of(dst);
    bool ok = std::equal(to.begin(), to.end(), got.begin()) &&
              std::equal(gw.begin(), gw.end(), got.begin() + mac_last + 1);
    const std::size_t hop_at = v6 ? hop_limit_at : ttl_at;
    ok = ok && std::to_integer<int>(got[hop_at]) == ak::test::frames::default_ttl - hops;
    for (std::size_t i = 2 * (mac_last + 1); i < got.size(); ++i) {
        const bool rewritten = i == hop_at || (!v6 && (i == eth_size + 10 || i == eth_size + 11));
        ok = ok && (rewritten || got[i] == sent[i]);
    }
    if (!v6) {
        std::uint32_t sum = 0;
        for (std::size_t i = eth_size; i < eth_size + 20; i += 2) {
            sum += (std::to_integer<std::uint32_t>(got[i]) << 8U) |
                   std::to_integer<std::uint32_t>(got[i + 1]);
        }
        sum = (sum & 0xFFFFU) + (sum >> 16U);
        sum = (sum & 0xFFFFU) + (sum >> 16U);
        ok = ok && sum == 0xFFFFU;
    }
    return ok;
}

// Three WireGuard-keyed roles and the underlay between them.
struct Fabric {
    Fabric() {
        boards[0] = std::make_unique<Board>(server_one, self_tail, Encryption::wireguard);
        boards[1] = std::make_unique<Board>(server_two, peer_tail, Encryption::wireguard);
        boards[2] = std::make_unique<Board>(server_three, third_tail, Encryption::wireguard);
        std::vector<std::pair<std::uint8_t, net::wg::Key>> publics;
        for (std::size_t i = 0; i < boards.size(); ++i) {
            const auto k = net::wg::generate_private_key();
            BOOST_REQUIRE(k.has_value());
            const auto p = net::wg::public_key(k->span());
            BOOST_REQUIRE(p.has_value());
            BOOST_REQUIRE(boards[i]->role->set_tunnel_key({.private_key = k->span()}) ==
                          Status::ok);
            publics.emplace_back(tails[i], *p);
        }
        for (std::size_t i = 0; i < boards.size(); ++i) {
            BOOST_REQUIRE(boards[i]->role->tunnel_peers(
                              signed_peer_set(servers[i], tails[i], publics)) == Status::ok);
        }
    }

    // Ticks every role at `now` and carries datagrams to the VTEP they
    // name until the underlay is quiet.
    auto pump(net::VtepClock::time_point now) -> void {
        for (auto& b : boards) {
            static_cast<void>(b->role->tick(now));
        }
        for (int round = 0; round < 8; ++round) {
            bool quiet = true;
            for (std::size_t i = 0; i < boards.size(); ++i) {
                auto sent = std::move(boards[i]->wire.sent);
                boards[i]->wire.sent.clear();
                for (const auto& d : sent) {
                    quiet = false;
                    for (std::size_t j = 0; j < boards.size(); ++j) {
                        if (d.dst == vtep(tails[j])) {
                            static_cast<void>(
                                boards[j]->role->receive(d.payload, vtep(tails[i]), now));
                        }
                    }
                }
            }
            if (quiet) {
                return;
            }
        }
    }

    auto pump() -> void { pump(clock); }

    // Brings the tunnels up: keepalives start the handshakes.
    auto connect() -> void {
        pump(clock);
        clock += keepalive;
        pump(clock);
    }

    // Posts a receive buffer on `fn` of board `b`.
    auto post(std::size_t b, oar::FunctionNumber fn) -> void {
        gpas[b][fn].push_back(boards[b]->post_rx(fn));
    }

    // The next frame `fn` of board `b` received, if any.
    auto take(std::size_t b, oar::FunctionNumber fn) -> std::optional<std::vector<std::byte>> {
        auto& driver = *boards[b]->drivers[fn];
        auto& seen = taken[b][fn];
        if (driver.used_idx(rx) == seen) {
            return std::nullopt;
        }
        const auto slot = static_cast<std::uint16_t>(seen % ak::test::test_queue_size);
        const auto len = driver.used_len(rx, slot);
        const vio::Gpa gpa = gpas[b][fn].at(seen);
        ++seen;
        return boards[b]->transports[fn].ram.bytes(gpa + hdr, len - hdr);
    }

    auto board(std::size_t b) -> Board& { return *boards[b]; }
    auto vswitch(std::size_t b) -> const net::SwitchCounters& {
        return boards[b]->role->vswitch().counters();
    }

    static constexpr std::array<std::uint64_t, 3> servers{server_one, server_two, server_three};
    static constexpr std::array<std::uint8_t, 3> tails{self_tail, peer_tail, third_tail};
    std::array<std::unique_ptr<Board>, 3> boards;
    std::array<std::array<std::vector<vio::Gpa>, function_count>, 3> gpas;
    std::array<std::array<std::uint16_t, function_count>, 3> taken{};
    net::VtepClock::time_point clock{net::VtepClock::now()};
};

constexpr std::size_t one = 0;
constexpr std::size_t two = 1;
constexpr std::size_t three = 2;

}  // namespace

BOOST_AUTO_TEST_CASE(roles_route_between_subnets_through_a_middlebox,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fabric f;
    // Mapping before config on roles one and two, config before mapping
    // on role three: either order ends in the same state.
    for (const std::size_t b : {one, two}) {
        BOOST_REQUIRE(f.board(b).role->map_update(
                          subnet_map(Fabric::servers[b], 1, all_members())) == Status::ok);
        BOOST_REQUIRE(f.board(b).role->vpc_config(subnet_vpc(Fabric::servers[b], 1, false)) ==
                      Status::ok);
    }
    BOOST_REQUIRE(f.board(three).role->vpc_config(subnet_vpc(server_three, 1, false)) ==
                  Status::ok);
    BOOST_REQUIRE(f.board(three).role->map_update(subnet_map(server_three, 1, all_members())) ==
                  Status::ok);
    BOOST_REQUIRE(f.board(one).prepare(fn0, nic_a) == Status::ok);
    BOOST_REQUIRE(f.board(one).prepare(fn1, nic_b) == Status::ok);
    BOOST_REQUIRE(f.board(two).prepare(fn1, nic_c) == Status::ok);
    BOOST_REQUIRE(f.board(three).prepare(fn0, nic_m) == Status::ok);
    f.board(one).driver(fn0);
    f.board(one).driver(fn1);
    f.board(two).driver(fn1);
    f.board(three).driver(fn0);
    f.connect();
    BOOST_TEST(f.board(one).role->vtep().peers().size() == 2U);
    BOOST_TEST(f.board(three).role->tunnel()->counters().sessions_established >= 1U);

    const auto gw = gateway_mac();
    // a to b on one role, and a to c across roles, in both families: one
    // hop, the gateway's MAC as the source.
    for (const bool v6 : {false, true}) {
        const auto make = v6 ? udp6 : udp4;
        f.post(one, fn1);
        const auto to_b = make(gw, mac_of(nic_a), nic_a, nic_b);
        f.board(one).send(fn0, to_b);
        auto got = f.take(one, fn1);
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(routed_copy(*got, to_b, nic_b, 1, v6));

        f.post(two, fn1);
        const auto to_c = make(gw, mac_of(nic_a), nic_a, nic_c);
        f.board(one).send(fn0, to_c);
        f.pump();
        got = f.take(two, fn1);
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(routed_copy(*got, to_c, nic_c, 1, v6));
    }
    BOOST_TEST(f.vswitch(one).tx_routed == 4U);

    // The middlebox config: A's traffic to B now goes to m on role three,
    // which forwards it back through the gateway to b.
    for (const std::size_t b : {one, two, three}) {
        BOOST_REQUIRE(f.board(b).role->vpc_config(subnet_vpc(Fabric::servers[b], 2, true)) ==
                      Status::ok);
    }
    for (const bool v6 : {false, true}) {
        const auto make = v6 ? udp6 : udp4;
        f.post(three, fn0);
        f.post(one, fn1);
        const auto to_b = make(gw, mac_of(nic_a), nic_a, nic_b);
        f.board(one).send(fn0, to_b);
        BOOST_TEST(!f.take(one, fn1).has_value());  // not switched straight to b
        f.pump();
        const auto at_m = f.take(three, fn0);
        BOOST_REQUIRE(at_m.has_value());
        BOOST_TEST(routed_copy(*at_m, to_b, nic_m, 1, v6));
        // The appliance sends it on unchanged but for its own MAC, as a
        // router would; its check is off, so a's address is allowed.
        const auto forwarded = make(gw, mac_of(nic_m), nic_a, nic_b);
        f.board(three).send(fn0, forwarded);
        f.pump();
        const auto at_b = f.take(one, fn1);
        BOOST_REQUIRE(at_b.has_value());
        BOOST_TEST(routed_copy(*at_b, forwarded, nic_b, 1, v6));
    }

    // Same-subnet traffic is switched, never routed: b to c bypasses m.
    const auto routed_before = f.vswitch(one).tx_routed;
    f.post(two, fn1);
    const auto b_to_c = udp4(mac_of(nic_c), mac_of(nic_b), nic_b, nic_c);
    f.board(one).send(fn1, b_to_c);
    f.pump();
    auto got = f.take(two, fn1);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == b_to_c));
    BOOST_TEST(f.vswitch(one).tx_routed == routed_before);
    BOOST_TEST(!f.take(three, fn0).has_value());

    // The appliance's NIC leaves role one's mapping: its route is a
    // blackhole, and comes back with the NIC.
    BOOST_REQUIRE(f.board(one).role->map_update(subnet_map(
                      server_one, 2,
                      {{nic_a, self_tail}, {nic_b, self_tail}, {nic_c, peer_tail}})) == Status::ok);
    f.board(one).send(fn0, udp4(gw, mac_of(nic_a), nic_a, nic_b));
    f.pump();
    BOOST_TEST(f.vswitch(one).tx_drop_route_target == 1U);
    BOOST_TEST(!f.take(three, fn0).has_value());
    BOOST_REQUIRE(f.board(one).role->map_update(subnet_map(server_one, 3, all_members())) ==
                  Status::ok);
    f.post(three, fn0);
    const auto again = udp4(gw, mac_of(nic_a), nic_a, nic_b);
    f.board(one).send(fn0, again);
    f.pump();
    got = f.take(three, fn0);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(routed_copy(*got, again, nic_m, 1, false));

    // A hostile role two forges frames to a. A "routed" frame from c whose
    // destination address B's table leads to m, not a, and a switched
    // frame from c, in subnet B, with c's own MAC.
    f.post(one, fn0);
    const auto forged_route = udp4(mac_of(nic_a), gw, nic_c, nic_b);
    f.board(two).role->vtep().send({.vtep = vtep(self_tail),
                                    .vni = vpc,
                                    .nics = {.src = NicId{nic_c}, .dst = NicId{nic_a}},
                                    .frame = forged_route});
    const auto cross = udp4(mac_of(nic_a), mac_of(nic_c), nic_c, nic_a);
    f.board(two).role->vtep().send({.vtep = vtep(self_tail),
                                    .vni = vpc,
                                    .nics = {.src = NicId{nic_c}, .dst = NicId{nic_a}},
                                    .frame = cross});
    f.pump();
    BOOST_TEST(!f.take(one, fn0).has_value());
    BOOST_TEST(f.vswitch(one).rx_drop_route_mismatch == 1U);
    BOOST_TEST(f.vswitch(one).rx_drop_cross_subnet == 1U);
}
