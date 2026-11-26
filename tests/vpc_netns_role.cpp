// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// One network role for the network-namespace VPC test (tests/vpc_netns.sh,
// vpc-subnets-routing task 7). A NetRole on a real UdpEndpoint with the
// WireGuard tunnel, whose ports are TAP devices instead of virtio
// functions: the script moves each TAP into a guest namespace, where a
// real Linux stack (dhclient, ping, TCP, traceroute) is the guest.
//
// The process plays helm and the controller for itself. It keys its
// tunnel, then applies the controller's signed TunnelPeers, MapUpdate v4
// and VpcConfig v2 frames for the fixed VPC below (signed with the RFC 8032
// test key, which the role trusts), so every frame still crosses the
// role's verification.
//
//   vpc_netns_role --role N --vtep1 ADDR --vtep2 ADDR [--tap NAME=NIC_ID,MAC ...]
//
// --role (1 or 2) picks this role's VTEP and server ID; the other is the
// WireGuard peer. Each --tap opens an existing TAP device NAME in this
// network namespace, gives it MAC and the planned guest MTU, and attaches
// it as NIC_ID, which must be one of this role's NICs below with that MAC.
// Once everything is applied it prints "ready MTU" (the guest MTU) on
// stdout, then runs until SIGTERM or SIGINT and prints the VSwitch's
// non-zero counters on stderr as it exits.
//
// The VPC (tests/vpc_netns.sh uses the same values):
//
//   VNI 0xAB0001, gateway MAC 02:00:00:00:00:fe, blocks 10.0.0.0/16 and
//   fd10::/56, one main table with the two local routes.
//   subnet A 0x5A01  10.0.1.0/24  fd10:0:0:1::/64
//   subnet B 0x5A02  10.0.2.0/24  fd10:0:0:2::/64
//   NIC 0x11  02:00:00:00:00:11  role 1  A  10.0.1.17  fd10:0:0:1::11
//   NIC 0x22  02:00:00:00:00:22  role 2  B  10.0.2.34  fd10:0:0:2::22
//   NIC 0x33  02:00:00:00:00:33  role 1  B  10.0.2.51  fd10:0:0:2::33

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ed25519_test_support.hpp"
#include "hull/signature_verifier.hpp"
#include "oar/net/mtu.hpp"
#include "oar/net/net_role.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/map_update.hpp"
#include "proto/tunnel_peers.hpp"
#include "proto/vpc_config.hpp"

namespace {

namespace net = ak::oar::net;
namespace proto = ak::proto;
namespace vio = ak::oar::virtio;
using ak::helm::oar::Status;

constexpr std::string_view log_name = "vpc_netns_role";
constexpr int exit_usage = 2;
constexpr std::uint16_t key_id = 1;
constexpr std::uint32_t vni = 0x00AB'0001;
constexpr std::uint64_t server_base = 100;  // role N is server 100 + N
constexpr std::uint32_t underlay_mtu = 1500;
constexpr std::uint16_t geneve_port = 6081;
constexpr std::uint64_t subnet_a = 0x5A01;
constexpr std::uint64_t subnet_b = 0x5A02;
constexpr std::uint8_t subnet_length = 24;
constexpr std::uint8_t block_length = 16;
constexpr std::uint8_t ula_length = 56;
constexpr std::uint32_t lease_seconds = 3600;
constexpr std::size_t udp_buffer_size = 65536;
constexpr std::size_t udp_budget = 64;
constexpr std::size_t tap_budget = 64;
constexpr std::size_t subnet_byte = 7;  // of an address in fd10::/56
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::size_t mac_text_size = 17;
constexpr std::size_t mac_stride = 3;
constexpr int base_hex = 16;
constexpr vio::Gpa ram_base = 0x1000'0000;
constexpr std::size_t ram_size = 0x10000;

struct Nic {
    std::uint64_t id;
    int role;
    std::uint8_t subnet;  // 1 for A, 2 for B: the third octet and the /64
};
constexpr std::array<Nic, 3> nics{{{0x11, 1, 1}, {0x22, 2, 2}, {0x33, 1, 2}}};

auto mac_of(std::uint64_t nic) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = std::byte{0x02};
    m[mac_last] = static_cast<std::byte>(nic);
    return m;
}

auto ipv4_of(const Nic& n) -> proto::Ipv4Address {
    return {std::byte{10}, std::byte{0}, std::byte{n.subnet}, static_cast<std::byte>(n.id)};
}

auto ula(std::uint8_t subnet) -> proto::Ipv6Address {
    proto::Ipv6Address a{};
    a[0] = std::byte{0xFD};
    a[1] = std::byte{0x10};
    a[subnet_byte] = std::byte{subnet};
    return a;
}

auto ipv6_of(const Nic& n) -> proto::Ipv6Address {
    auto a = ula(n.subnet);
    a[ipv6_last] = static_cast<std::byte>(n.id);
    return a;
}

auto signer() -> const ak::test::TestSigner& {
    static const ak::test::TestSigner s{ak::test::rfc_test1_secret};
    return s;
}

// A deterministic WireGuard private key per role, so each role knows its
// peer's public key without an exchange.
auto private_key(int role) -> net::wg::Key {
    net::wg::Key k{};
    k.fill(static_cast<std::byte>(0x40 + role));
    return k;
}

auto map_frame(std::uint64_t server, const net::Ipv6Address& vtep1, const net::Ipv6Address& vtep2)
    -> std::optional<std::vector<std::byte>> {
    proto::MapUpdate m{};
    m.server_id = server;
    m.key_id = key_id;
    m.vni = vni;
    m.map_version = 1;
    for (const Nic& n : nics) {  // ascending IDs and, with them, addresses
        m.entries.push_back({.nic_id = n.id,
                             .mac = mac_of(n.id),
                             .owner_vtep = n.role == 1 ? vtep1 : vtep2,
                             .subnet_id = n.subnet == 1 ? subnet_a : subnet_b});
        m.ipv4.push_back({.nic_id = n.id, .address = ipv4_of(n)});
        m.ipv6.push_back({.nic_id = n.id, .address = ipv6_of(n)});
    }
    auto bytes = proto::encode_map_update(m);
    if (!bytes) {
        return std::nullopt;
    }
    proto::set_map_update_signature(*bytes, signer().sign(proto::map_update_signed_bytes(*bytes)));
    return *bytes;
}

auto vpc_frame(std::uint64_t server) -> std::optional<std::vector<std::byte>> {
    proto::VpcConfigFrame c{};
    c.server_id = server;
    c.key_id = key_id;
    c.vni = vni;
    c.config_version = 1;
    c.gateway_mac = mac_of(0xFE);
    c.ipv4_blocks = {{.prefix = {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}},
                      .length = block_length}};
    c.ipv6_block = ula(0);
    for (const std::uint8_t s : {std::uint8_t{1}, std::uint8_t{2}}) {
        c.subnets.push_back(
            {.subnet_id = s == 1 ? subnet_a : subnet_b,
             .table = 1,
             .ipv4_prefix = {std::byte{10}, std::byte{0}, std::byte{s}, std::byte{0}},
             .ipv4_length = subnet_length,
             .ipv6_prefix = ula(s)});
    }
    proto::VpcRoute local4{.kind = proto::RouteKind::local,
                           .family = proto::RouteFamily::ipv4,
                           .length = block_length,
                           .prefix = {},
                           .target_nic = 0};
    local4.prefix[0] = std::byte{10};
    const proto::VpcRoute local6{.kind = proto::RouteKind::local,
                                 .family = proto::RouteFamily::ipv6,
                                 .length = ula_length,
                                 .prefix = ula(0),
                                 .target_nic = 0};
    c.tables = {{.table = 1, .main = true, .routes = {local4, local6}}};
    c.dns4 = {{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{2}}};
    c.domain = "ec2.internal";
    c.lease_seconds = lease_seconds;
    auto bytes = proto::encode_vpc_config(c);
    if (!bytes) {
        return std::nullopt;
    }
    proto::set_vpc_config_signature(*bytes, signer().sign(proto::vpc_config_signed_bytes(*bytes)));
    return *bytes;
}

auto peers_frame(std::uint64_t server, const net::Ipv6Address& self, const net::Ipv6Address& peer,
                 const net::wg::Key& peer_key) -> std::optional<std::vector<std::byte>> {
    proto::TunnelPeers t{};
    t.server_id = server;
    t.key_id = key_id;
    t.vtep = self;
    t.peers_version = 1;
    t.peers.push_back(
        {.vtep = peer, .mode = proto::TunnelMode::wireguard, .spi = 0, .key = peer_key});
    auto bytes = proto::encode_tunnel_peers(t);
    if (!bytes) {
        return std::nullopt;
    }
    proto::set_tunnel_peers_signature(*bytes,
                                      signer().sign(proto::tunnel_peers_signed_bytes(*bytes)));
    return *bytes;
}

// The role wants at least one virtio function; this one is never driven.
class IdleTransport final : public net::NetTransport {
public:
    IdleTransport() : _ram(ram_size) { static_cast<void>(_memory.add_region(ram_base, _ram)); }
    [[nodiscard]] auto memory() -> const vio::GuestMemory& override { return _memory; }
    [[nodiscard]] auto interrupts() -> vio::InterruptSink& override { return _irq; }
    [[nodiscard]] auto bind(vio::PciFunction& /*function*/)
        -> std::expected<void, std::string> override {
        return {};
    }

private:
    class NoInterrupts final : public vio::InterruptSink {
    public:
        auto raise(std::uint16_t /*vector*/) -> void override {}
    };
    std::vector<std::byte> _ram;
    vio::GuestMemory _memory;
    NoInterrupts _irq;
};

// A TAP device as a VSwitch port: frames for the NIC are written to it,
// and frames the guest's stack sends are read from it.
class TapPort final : public net::RxPort {
public:
    TapPort(std::uint64_t id, int tap) : nic{id}, fd{tap} {}
    auto deliver(std::span<const std::byte> frame) -> net::RxResult override {
        if (::write(fd, frame.data(), frame.size()) < 0) {
            return net::RxResult::no_buffer;  // a full TAP queue, as a congested link
        }
        return net::RxResult::delivered;
    }
    std::uint64_t nic;
    int fd;
};

auto parse_mac(std::string_view s) -> std::optional<net::MacAddress> {
    if (s.size() != mac_text_size) {
        return std::nullopt;
    }
    net::MacAddress mac{};
    for (std::size_t i = 0; i < mac.size(); ++i) {
        std::uint8_t b = 0;
        const char* first = s.data() + (i * mac_stride);
        const auto [p, ec] = std::from_chars(first, first + 2, b, base_hex);
        if (ec != std::errc{} || p != first + 2 ||
            (i + 1 < mac.size() && s[(i * mac_stride) + 2] != ':')) {
            return std::nullopt;
        }
        mac[i] = std::byte{b};
    }
    return mac;
}

auto parse_ipv6(const std::string& s) -> std::optional<net::Ipv6Address> {
    net::Ipv6Address a{};
    if (::inet_pton(AF_INET6, s.c_str(), a.data()) != 1) {
        return std::nullopt;
    }
    return a;
}

// Opens the TAP device `name`, then sets its MAC and MTU.
auto open_tap(const std::string& name, const net::MacAddress& mac, std::uint32_t mtu)
    -> std::optional<int> {
    const int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return std::nullopt;
    }
    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    name.copy(ifr.ifr_name, IFNAMSIZ - 1);
    const int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    bool ok = sock >= 0 && ::ioctl(fd, TUNSETIFF, &ifr) == 0;
    if (ok) {
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        std::memcpy(ifr.ifr_hwaddr.sa_data, mac.data(), mac.size());
        ok = ::ioctl(sock, SIOCSIFHWADDR, &ifr) == 0;
    }
    if (ok) {
        ifr.ifr_mtu = static_cast<int>(mtu);
        ok = ::ioctl(sock, SIOCSIFMTU, &ifr) == 0;
    }
    const int saved = errno;
    if (sock >= 0) {
        ::close(sock);
    }
    if (!ok) {
        ::close(fd);
        errno = saved;
        return std::nullopt;
    }
    return fd;
}

volatile std::sig_atomic_t stop = 0;

auto on_signal(int /*sig*/) -> void {
    stop = 1;
}

auto usage() -> int {
    std::println(stderr, "usage: {} --role N --vtep1 ADDR --vtep2 ADDR [--tap NAME=NIC_ID,MAC ...]",
                 log_name);
    return exit_usage;
}

auto print_counters(const net::SwitchCounters& c) -> void {
    // Enough to tell a routing failure from a delivery one.
    const std::array<std::pair<std::string_view, std::uint64_t>, 19> named{{
        {"tx_frames", c.tx_frames},
        {"tx_local", c.tx_local},
        {"tx_remote", c.tx_remote},
        {"tx_routed", c.tx_routed},
        {"tx_drop_no_route", c.tx_drop_no_route},
        {"tx_drop_no_neighbor", c.tx_drop_no_neighbor},
        {"tx_drop_ttl", c.tx_drop_ttl},
        {"tx_drop_cross_subnet", c.tx_drop_cross_subnet},
        {"tx_drop_arp_other_subnet", c.tx_drop_arp_other_subnet},
        {"tx_drop_ip_spoofed", c.tx_drop_ip_spoofed},
        {"tx_drop_ip_dst", c.tx_drop_ip_dst},
        {"dhcp4_replies", c.dhcp4_replies},
        {"dhcp6_replies", c.dhcp6_replies},
        {"rx_frames", c.rx_frames},
        {"rx_drop_route_mismatch", c.rx_drop_route_mismatch},
        {"rx_drop_cross_subnet", c.rx_drop_cross_subnet},
        {"rx_drop_ip_dst", c.rx_drop_ip_dst},
        {"rx_delivered", c.rx_delivered},
        {"deliver_failed", c.deliver_failed},
    }};
    for (const auto& [name, value] : named) {
        if (value != 0) {
            std::println(stderr, "{}: {} {}", log_name, name, value);
        }
    }
}

struct Options {
    int role{0};
    std::optional<net::Ipv6Address> vtep1;
    std::optional<net::Ipv6Address> vtep2;
    struct Tap {
        std::string name;
        std::uint64_t nic{0};
        net::MacAddress mac{};
    };
    std::vector<Tap> taps;
};

auto parse(int argc, char** argv) -> std::optional<Options> {
    Options o;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::string_view arg{argv[i]};
        const std::string value{argv[i + 1]};
        if (arg == "--role") {
            o.role = value == "1" ? 1 : value == "2" ? 2 : 0;
        } else if (arg == "--vtep1") {
            o.vtep1 = parse_ipv6(value);
        } else if (arg == "--vtep2") {
            o.vtep2 = parse_ipv6(value);
        } else if (arg == "--tap") {
            const auto eq = value.find('=');
            const auto comma = value.find(',');
            if (eq == std::string::npos || comma == std::string::npos || comma < eq) {
                return std::nullopt;
            }
            Options::Tap t{.name = value.substr(0, eq), .nic = 0, .mac = {}};
            const std::string id = value.substr(eq + 1, comma - eq - 1);
            char* end = nullptr;
            t.nic = std::strtoull(id.c_str(), &end, 0);
            const auto mac = parse_mac(std::string_view{value}.substr(comma + 1));
            if (end == id.c_str() || *end != '\0' || !mac) {
                return std::nullopt;
            }
            t.mac = *mac;
            o.taps.push_back(t);
        } else {
            return std::nullopt;
        }
    }
    if (argc % 2 == 0 || o.role == 0 || !o.vtep1 || !o.vtep2) {
        return std::nullopt;
    }
    return o;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opts = parse(argc, argv);
    if (!opts) {
        return usage();
    }
    const std::uint64_t server = server_base + static_cast<std::uint64_t>(opts->role);
    const net::Ipv6Address self = opts->role == 1 ? *opts->vtep1 : *opts->vtep2;
    const net::Ipv6Address peer = opts->role == 1 ? *opts->vtep2 : *opts->vtep1;
    const int peer_role = 3 - opts->role;

    const auto plan = net::plan_mtu(underlay_mtu, net::tunnel_overhead_budget);
    if (!plan) {
        std::println(stderr, "{}: MTU plan: {}", log_name, net::to_string(plan.error()));
        return EXIT_FAILURE;
    }
    const std::array keys{ak::test::controller_key(key_id, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    if (!verifier) {
        std::println(stderr, "{}: controller key refused", log_name);
        return EXIT_FAILURE;
    }
    auto shared = std::make_shared<ak::hull::SignatureVerifier>(std::move(*verifier));

    auto udp = net::UdpEndpoint::create({.bind = self,
                                         .port = geneve_port,
                                         .scope_id = 0,
                                         .source_port_base = net::flow_port_base,
                                         .source_ports = 0});
    if (!udp) {
        std::println(stderr, "{}: underlay: {}", log_name, udp.error());
        return EXIT_FAILURE;
    }
    IdleTransport idle;
    std::vector<net::NetTransport*> transports{&idle};
    auto role = net::NetRole::create(
        {.vtep = self,
         .server_id = server,
         .mtu = *plan,
         .queue_size = net::NetParams{}.queue_size,
         .tx_budget = net::NetParams{}.tx_budget,
         .vtep_config = {},
         .tunnel = net::TunnelConfig{},
         .mtu_grace = {},
         .clock = {},
         .metadata = std::nullopt},
        transports,
        [shared](std::span<const std::byte> msg, std::span<const std::byte, 64> sig,
                 std::uint16_t id) { return shared->verify(msg, sig, id).has_value(); },
        **udp, nullptr);
    if (!role) {
        std::println(stderr, "{}: {}", log_name, role.error());
        return EXIT_FAILURE;
    }

    // helm's part: this VTEP's key, then the controller's frames.
    const auto own_key = private_key(opts->role);
    const auto peer_public = net::wg::public_key(private_key(peer_role));
    const auto peers = peer_public ? peers_frame(server, self, peer, *peer_public) : std::nullopt;
    const auto map = map_frame(server, *opts->vtep1, *opts->vtep2);
    const auto vpc = vpc_frame(server);
    if (!peers || !map || !vpc) {
        std::println(stderr, "{}: building the controller's frames failed", log_name);
        return EXIT_FAILURE;
    }
    if ((*role)->set_tunnel_key({.private_key = own_key}) != Status::ok ||
        (*role)->tunnel_peers(*peers) != Status::ok || (*role)->map_update(*map) != Status::ok ||
        (*role)->vpc_config(*vpc) != Status::ok) {
        std::println(stderr, "{}: the role refused a frame", log_name);
        return EXIT_FAILURE;
    }

    std::vector<std::unique_ptr<TapPort>> taps;
    for (const auto& t : opts->taps) {
        const auto* n = std::ranges::find(nics, t.nic, &Nic::id);
        if (n == nics.end() || n->role != opts->role || t.mac != mac_of(t.nic)) {
            std::println(stderr, "{}: {} is not one of role {}'s NICs with that MAC", log_name,
                         t.name, opts->role);
            return exit_usage;
        }
        const auto fd = open_tap(t.name, t.mac, plan->guest_mtu);
        if (!fd) {
            std::println(stderr, "{}: TAP {}: {}", log_name, t.name, std::strerror(errno));
            return EXIT_FAILURE;
        }
        taps.push_back(std::make_unique<TapPort>(t.nic, *fd));
        auto a = (*role)->vswitch().attach(net::geneve::NicId{t.nic}, *taps.back(),
                                           static_cast<std::uint16_t>(plan->guest_mtu));
        if (!a) {
            std::println(stderr, "{}: attach {} failed", log_name, t.name);
            return EXIT_FAILURE;
        }
    }

    (void)std::signal(SIGTERM, on_signal);
    (void)std::signal(SIGINT, on_signal);
    std::println("ready {}", plan->guest_mtu);
    (void)std::fflush(stdout);

    std::vector<std::byte> datagram(udp_buffer_size);
    std::vector<std::byte> frame(udp_buffer_size);
    auto next_tick = net::VtepClock::now();
    bool more = false;
    while (stop == 0) {
        std::vector<pollfd> fds;
        fds.push_back({.fd = (*udp)->poll_fd(), .events = POLLIN, .revents = 0});
        for (const auto& t : taps) {
            fds.push_back({.fd = t->fd, .events = POLLIN, .revents = 0});
        }
        const auto wait =
            std::chrono::ceil<std::chrono::milliseconds>(next_tick - net::VtepClock::now());
        const int timeout = more ? 0 : static_cast<int>(std::max<std::int64_t>(0, wait.count()));
        if (::poll(fds.data(), fds.size(), timeout) < 0 && errno != EINTR) {
            std::println(stderr, "{}: poll: {}", log_name, std::strerror(errno));
            return EXIT_FAILURE;
        }
        const auto now = net::VtepClock::now();
        bool busy = false;
        if ((fds[0].revents & POLLIN) != 0) {
            busy = (*role)->pump(**udp, datagram, udp_budget, now) == udp_budget;
        }
        for (std::size_t i = 0; i < taps.size(); ++i) {
            if ((fds[i + 1].revents & POLLIN) == 0) {
                continue;
            }
            for (std::size_t n = 0; n < tap_budget; ++n) {
                const auto got = ::read(taps[i]->fd, frame.data(), frame.size());
                if (got <= 0) {
                    break;
                }
                (*role)->vswitch().transmit(
                    {.source = net::geneve::NicId{taps[i]->nic},
                     .frame = std::span{frame}.first(static_cast<std::size_t>(got))});
            }
        }
        if (now >= next_tick) {
            next_tick = (*role)->tick(now);
        }
        more = (*role)->poll() || busy;
    }
    print_counters((*role)->vswitch().counters());
    for (const auto& t : taps) {
        ::close(t->fd);
    }
    return EXIT_SUCCESS;
}
