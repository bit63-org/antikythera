// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-oar-net: the network role for harbor (.kiro/specs/oar-net-data-plane/
// tasks 6, 9 and 11). virtio-net functions served over vfio-user, switched
// by the VSwitch and carried between servers by the Vtep over IPv6/UDP,
// driven by helm over its sideband socket.
//
//   ak-oar-net --vtep ADDR --server-id N --underlay-mtu N [--tunnel-overhead N]
//              --controller-key ID:HEX [--controller-key ID:HEX ...]
//              --sideband PATH --addr A --helm-addr A --eid E --helm-eid E
//              --function SOCKET [--function SOCKET ...]
//              [--port P] [--source-ports N] [--scope IFINDEX] [--metadata TUN]
//
// --metadata serves the instance metadata service (oar-net Requirement 13,
// metadata_tap.hpp): it makes the TUN device of that name (usually akmd0)
// holding 169.254.169.254 and fd00:ec2::254, and listens on port 80 in this
// process's network namespace, which needs CAP_NET_ADMIN there. Without it
// guests' metadata requests are dropped.
//
// --vtep is this board's underlay IPv6 address; the Vtep listens on it at
// --port (6081) and sends from --source-ports sockets (0: the listening one)
// so ECMP sees flows apart (udp_endpoint.hpp). --scope is the interface
// index for a link-local --vtep. --server-id is the server the controller's
// map_updates must name. Each --controller-key is a controller key ID and
// its Ed25519 public key in 64 hex digits; a map_update must verify under
// one of them, and so must the controller's tunnel_peers frames.
// --underlay-mtu and --tunnel-overhead (default 48, the larger of WireGuard
// and PSP, so a pair's tunnel can change without changing a guest MTU) give
// the MTU plan (mtu.hpp): every function advertises the guest MTU, and the
// Vtep neither sends more than the plan allows nor stops probing that size.
//
// The underlay runs WireGuard (tunnel.hpp, oar-net Requirement 5): helm
// delivers this VTEP's private key over the sideband from its
// TunnelKeyring, the controller's signed peer set follows, and nothing
// crosses the underlay until both have arrived. --tunnel-overhead 0 runs
// without the tunnel (Geneve in the clear), for rigs that test the Vtep on
// its own; any other value must leave room for WireGuard's 32 bytes.
//
// Function i is the i-th --function: L0 QEMU attaches to its socket with
// vfio-user-pci when the L1 host boots, the L1 host binds it to vfio-pci
// and Cloud Hypervisor hands it to an L2 guest. Until helm prepares it the
// function carries a placeholder identity in the dead VPC (net_role.hpp).
//
// The sideband is helm's, exactly as for ak-oar-blk: this process listens
// on PATH (SOCK_SEQPACKET; a stale socket there is removed) and serves one
// helm connection at a time. --addr/--eid are this board's bus address and
// EID, --helm-addr/--helm-eid helm's.
//
// Standalone mode, for a single NIC without helm (harbor/oar_net_smoke.py):
//
//   ak-oar-net --socket PATH --nic-id ID --mac MAC
//              (--mtu N | --underlay-mtu N [--tunnel-overhead N]) [--tap IFNAME]
//
// --mtu sets the guest MTU directly; --underlay-mtu derives it as above and
// prints the plan. Frames go to an optional TAP device in this process's
// network namespace: the guest's transmitted frames are written to it and
// frames read from it are delivered to the guest. Without --tap,
// transmitted frames are counted and dropped.

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <format>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "helm/oar_link.hpp"
#include "helm/sideband_binding.hpp"
#include "hull/signature_verifier.hpp"
#include "oar/net/mtu.hpp"
#include "oar/net/net_role.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/virtio_net.hpp"
#include "oar/vfu/virtio_binding.hpp"

namespace {

namespace net = ak::oar::net;

constexpr std::string_view arg_socket = "--socket";
constexpr std::string_view arg_nic_id = "--nic-id";
constexpr std::string_view arg_mac = "--mac";
constexpr std::string_view arg_mtu = "--mtu";
constexpr std::string_view arg_underlay_mtu = "--underlay-mtu";
constexpr std::string_view arg_tunnel_overhead = "--tunnel-overhead";
constexpr std::string_view arg_tap = "--tap";
constexpr std::string_view tun_device = "/dev/net/tun";
constexpr int base_auto = 0;
constexpr int base_hex = 16;
constexpr std::size_t mac_text_size = 17;  // xx:xx:xx:xx:xx:xx
constexpr std::size_t mac_stride = 3;
constexpr int poll_forever = -1;
constexpr int poll_now = 0;
constexpr std::size_t poll_vfu = 0;
constexpr std::size_t poll_tap = 1;
constexpr int exit_usage = 2;

auto usage() -> int {
    std::println(stderr, "usage: ak-oar-net {} PATH {} ID {} MAC ({} N | {} N [{} N]) [{} IFNAME]",
                 arg_socket, arg_nic_id, arg_mac, arg_mtu, arg_underlay_mtu, arg_tunnel_overhead,
                 arg_tap);
    return exit_usage;
}

auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    const std::string text{s};
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(text.c_str(), &end, base_auto);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return std::nullopt;
    }
    return v;
}

auto parse_mac(std::string_view s) -> std::optional<net::MacAddress> {
    if (s.size() != mac_text_size) {
        return std::nullopt;
    }
    net::MacAddress mac{};
    for (std::size_t i = 0; i < mac.size(); ++i) {
        const std::string_view part = s.substr(i * mac_stride, 2);
        if (i + 1 < mac.size() && s[(i * mac_stride) + 2] != ':') {
            return std::nullopt;
        }
        std::uint8_t b = 0;
        const auto [p, ec] = std::from_chars(part.data(), part.data() + part.size(), b, base_hex);
        if (ec != std::errc{} || p != part.data() + part.size()) {
            return std::nullopt;
        }
        mac[i] = std::byte{b};
    }
    return mac;
}

// Opens (or creates) a TAP interface; -1 on failure with errno set.
auto open_tap(const std::string& name) -> int {
    const int fd = ::open(std::string{tun_device}.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    name.copy(ifr.ifr_name, IFNAMSIZ - 1);
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

class TapSink final : public net::FrameSink {
public:
    explicit TapSink(int fd) : _fd{fd} {}
    auto transmit(const net::TxFrame& f) -> void override {
        if (_fd < 0) {
            return;  // no backend: counted by the function, dropped here
        }
        // A full TAP queue drops the frame, as a congested link would.
        static_cast<void>(::write(_fd, f.frame.data(), f.frame.size()));
    }

private:
    int _fd;
};

auto run_standalone(int argc, char** argv) -> int {
    std::string socket_path;
    std::string tap_name;
    std::optional<std::uint64_t> nic_id;
    std::optional<net::MacAddress> mac;
    std::optional<std::uint64_t> mtu;
    std::optional<std::uint64_t> underlay_mtu;
    std::optional<std::uint64_t> tunnel_overhead = net::tunnel_overhead_budget;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (i + 1 >= argc) {
            return usage();
        }
        const std::string_view value{argv[++i]};
        if (arg == arg_socket) {
            socket_path = value;
        } else if (arg == arg_nic_id) {
            nic_id = parse_u64(value);
        } else if (arg == arg_mac) {
            mac = parse_mac(value);
        } else if (arg == arg_mtu) {
            mtu = parse_u64(value);
        } else if (arg == arg_underlay_mtu) {
            underlay_mtu = parse_u64(value);
        } else if (arg == arg_tunnel_overhead) {
            tunnel_overhead = parse_u64(value);
        } else if (arg == arg_tap) {
            tap_name = value;
        } else {
            return usage();
        }
    }
    if (underlay_mtu) {
        if (mtu || !tunnel_overhead || *underlay_mtu > UINT32_MAX ||
            *tunnel_overhead > UINT32_MAX) {
            return usage();
        }
        auto plan = net::plan_mtu(static_cast<std::uint32_t>(*underlay_mtu),
                                  static_cast<std::uint32_t>(*tunnel_overhead));
        if (!plan) {
            std::println(stderr, "ak-oar-net: underlay MTU {} with tunnel overhead {}: {}",
                         *underlay_mtu, *tunnel_overhead, net::to_string(plan.error()));
            return exit_usage;
        }
        std::println(stderr, "ak-oar-net: underlay MTU {}, tunnel {}: guest MTU {}",
                     plan->underlay_mtu, plan->tunnel_overhead, plan->guest_mtu);
        mtu = plan->guest_mtu;
    }
    if (socket_path.empty() || !nic_id || !mac || !mtu || *mtu > UINT16_MAX) {
        return usage();
    }
    const net::NicIdentity identity{.nic_id = net::geneve::NicId{*nic_id},
                                    .mac = *mac,
                                    .mtu = static_cast<std::uint16_t>(*mtu)};
    if (auto ok = net::validate(identity); !ok) {
        std::println(stderr, "ak-oar-net: bad identity: {}", net::to_string(ok.error()));
        return exit_usage;
    }

    const int tap_fd = tap_name.empty() ? -1 : open_tap(tap_name);
    if (!tap_name.empty() && tap_fd < 0) {
        std::println(stderr, "ak-oar-net: open TAP {}: {}", tap_name, std::strerror(errno));
        return EXIT_FAILURE;
    }
    const std::string log_name = "ak-oar-net[" + std::to_string(*nic_id) + "]";
    auto binding = ak::oar::vfu::VirtioBinding::create(socket_path, log_name);
    if (!binding) {
        std::println(stderr, "ak-oar-net: {}", binding.error());
        return EXIT_FAILURE;
    }
    TapSink sink{tap_fd};
    auto function = net::VirtioNetFunction::create({.identity = identity}, (*binding)->memory(),
                                                   **binding, sink);
    if (!function) {
        std::println(stderr, "ak-oar-net: {}", net::to_string(function.error()));
        return EXIT_FAILURE;
    }
    if (auto ok = (*binding)->bind((*function)->pci()); !ok) {
        std::println(stderr, "ak-oar-net: {}", ok.error());
        return EXIT_FAILURE;
    }

    std::println(stderr, "{}: waiting for client on {}", log_name, socket_path);
    // One byte spare, so an oversized TAP frame is refused rather than cut.
    std::vector<std::byte> rx((*function)->max_frame() + 1);
    bool attached = false;
    bool tx_pending = false;
    for (;;) {
        std::array<pollfd, 2> fds{};
        fds[poll_vfu] = {.fd = (*binding)->poll_fd(), .events = POLLIN, .revents = 0};
        fds[poll_tap] = {.fd = attached ? tap_fd : -1, .events = POLLIN, .revents = 0};
        if (::poll(fds.data(), fds.size(), tx_pending ? poll_now : poll_forever) < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::println(stderr, "{}: poll: {}", log_name, std::strerror(errno));
            return EXIT_FAILURE;
        }
        if (!attached) {
            auto a = (*binding)->attach();
            if (!a) {
                std::println(stderr, "{}: {}", log_name, a.error());
                return EXIT_FAILURE;
            }
            attached = *a;
            if (attached) {
                std::println(stderr, "{}: client attached", log_name);
            }
            continue;
        }
        if ((fds[poll_vfu].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            auto r = (*binding)->run();
            if (!r) {
                std::println(stderr, "{}: {}", log_name, r.error());
                return EXIT_FAILURE;
            }
            if (!*r) {
                std::println(stderr, "{}: client disconnected", log_name);
                attached = false;
                tx_pending = false;
                continue;
            }
        }
        if ((fds[poll_tap].revents & POLLIN) != 0) {
            // Drain what the TAP has; the guest takes what it has room for.
            for (;;) {
                const ssize_t n = ::read(tap_fd, rx.data(), rx.size());
                if (n <= 0) {
                    break;
                }
                static_cast<void>((*function)->deliver(
                    std::span<const std::byte>{rx}.first(static_cast<std::size_t>(n))));
            }
        }
        tx_pending = (*function)->pci().poll();
    }
}

// ---- Role mode ------------------------------------------------------------

namespace helm = ak::helm;

constexpr std::string_view arg_vtep = "--vtep";
constexpr std::string_view arg_server_id = "--server-id";
constexpr std::string_view arg_controller_key = "--controller-key";
constexpr std::string_view arg_sideband = "--sideband";
constexpr std::string_view arg_addr = "--addr";
constexpr std::string_view arg_helm_addr = "--helm-addr";
constexpr std::string_view arg_eid = "--eid";
constexpr std::string_view arg_helm_eid = "--helm-eid";
constexpr std::string_view arg_function = "--function";
constexpr std::string_view arg_port = "--port";
constexpr std::string_view arg_source_ports = "--source-ports";
constexpr std::string_view arg_scope = "--scope";
constexpr std::string_view arg_metadata = "--metadata";
constexpr std::string_view role_log = "ak-oar-net";
constexpr std::uint64_t max_bus_addr = 0x7F;
constexpr std::uint64_t max_eid = 0xFE;
constexpr std::size_t key_hex_digits = 2 * ak::hull::ed25519_public_key_size;
constexpr std::size_t udp_budget = 64;
constexpr std::size_t udp_buffer_size = 65536;  // any UDP payload, so none is cut
constexpr auto no_wait = std::chrono::milliseconds{0};

auto role_usage() -> int {
    std::println(stderr,
                 "usage: {} {} ADDR {} N {} N [{} N] {} ID:HEX [...] {} PATH {} A {} A {} E {} E "
                 "{} SOCKET [...] [{} P] [{} N] [{} IFINDEX] [{} TUN]\n"
                 "   or: {} {} PATH {} ID {} MAC ({} N | {} N [{} N]) [{} IFNAME]",
                 role_log, arg_vtep, arg_server_id, arg_underlay_mtu, arg_tunnel_overhead,
                 arg_controller_key, arg_sideband, arg_addr, arg_helm_addr, arg_eid, arg_helm_eid,
                 arg_function, arg_port, arg_source_ports, arg_scope, arg_metadata, role_log,
                 arg_socket, arg_nic_id, arg_mac, arg_mtu, arg_underlay_mtu, arg_tunnel_overhead,
                 arg_tap);
    return exit_usage;
}

auto parse_bounded(std::string_view s, std::uint64_t max) -> std::optional<std::uint64_t> {
    auto v = parse_u64(s);
    return v && *v <= max ? v : std::nullopt;
}

auto parse_ipv6(std::string_view s) -> std::optional<net::Ipv6Address> {
    const std::string text{s};
    in6_addr a{};
    if (::inet_pton(AF_INET6, text.c_str(), &a) != 1) {
        return std::nullopt;
    }
    net::Ipv6Address out{};
    std::memcpy(out.data(), &a, out.size());
    return out;
}

// ID:HEX, the key in 64 hex digits.
auto parse_controller_key(std::string_view s) -> std::optional<ak::hull::ControllerKey> {
    const auto colon = s.find(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    auto id = parse_bounded(s.substr(0, colon), UINT16_MAX);
    const std::string_view hex = s.substr(colon + 1);
    if (!id || hex.size() != key_hex_digits) {
        return std::nullopt;
    }
    ak::hull::ControllerKey key{.id = static_cast<ak::hull::KeyId>(*id), .key = {}};
    for (std::size_t i = 0; i < key.key.size(); ++i) {
        const std::string_view pair = hex.substr(2 * i, 2);
        std::uint8_t b = 0;
        const auto [p, ec] = std::from_chars(pair.data(), pair.data() + pair.size(), b, base_hex);
        if (ec != std::errc{} || p != pair.data() + pair.size()) {
            return std::nullopt;
        }
        key.key[i] = std::byte{b};
    }
    return key;
}

// Parses `s` into `out` if it is a number no larger than `max`.
auto assign(std::uint64_t& out, std::string_view s, std::uint64_t max) -> bool {
    auto v = parse_bounded(s, max);
    if (v) {
        out = *v;
    }
    return v.has_value();
}

struct RoleOptions {
    std::optional<net::Ipv6Address> vtep;
    std::optional<std::uint64_t> server_id;
    std::optional<std::uint64_t> underlay_mtu;
    std::uint64_t tunnel_overhead{net::tunnel_overhead_budget};
    std::vector<ak::hull::ControllerKey> keys;
    std::string sideband;
    std::optional<std::uint64_t> addr;
    std::optional<std::uint64_t> helm_addr;
    std::optional<std::uint64_t> eid;
    std::optional<std::uint64_t> helm_eid;
    std::vector<std::string> functions;
    std::uint64_t port{net::geneve::udp_port};
    std::uint64_t source_ports{0};
    std::uint64_t scope{0};
    std::optional<std::string> metadata;  // the TUN's name
};

auto parse_role(int argc, char** argv) -> std::optional<RoleOptions> {
    RoleOptions o;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (i + 1 >= argc) {
            return std::nullopt;
        }
        const std::string_view value{argv[++i]};
        if (arg == arg_vtep) {
            o.vtep = parse_ipv6(value);
        } else if (arg == arg_server_id) {
            o.server_id = parse_u64(value);
        } else if (arg == arg_underlay_mtu) {
            o.underlay_mtu = parse_bounded(value, UINT32_MAX);
        } else if (arg == arg_tunnel_overhead) {
            if (!assign(o.tunnel_overhead, value, UINT32_MAX)) {
                return std::nullopt;
            }
        } else if (arg == arg_controller_key) {
            auto key = parse_controller_key(value);
            if (!key) {
                return std::nullopt;
            }
            o.keys.push_back(*key);
        } else if (arg == arg_sideband) {
            o.sideband = value;
        } else if (arg == arg_addr) {
            o.addr = parse_bounded(value, max_bus_addr);
        } else if (arg == arg_helm_addr) {
            o.helm_addr = parse_bounded(value, max_bus_addr);
        } else if (arg == arg_eid) {
            o.eid = parse_bounded(value, max_eid);
        } else if (arg == arg_helm_eid) {
            o.helm_eid = parse_bounded(value, max_eid);
        } else if (arg == arg_function) {
            o.functions.emplace_back(value);
        } else if (arg == arg_port) {
            if (!assign(o.port, value, UINT16_MAX)) {
                return std::nullopt;
            }
        } else if (arg == arg_source_ports) {
            if (!assign(o.source_ports, value, UINT16_MAX)) {
                return std::nullopt;
            }
        } else if (arg == arg_scope) {
            if (!assign(o.scope, value, UINT32_MAX)) {
                return std::nullopt;
            }
        } else if (arg == arg_metadata) {
            if (value.empty() || value.size() >= IFNAMSIZ) {
                return std::nullopt;
            }
            o.metadata = value;
        } else {
            return std::nullopt;
        }
    }
    if (!o.vtep || !o.server_id || *o.server_id == 0 || !o.underlay_mtu || o.keys.empty() ||
        o.sideband.empty() || !o.addr || !o.helm_addr || !o.eid || !o.helm_eid ||
        o.functions.empty()) {
        return std::nullopt;
    }
    return o;
}

// One function's vfio-user context, bound once for the life of the role.
class VfuTransport final : public net::NetTransport {
public:
    explicit VfuTransport(std::unique_ptr<ak::oar::vfu::VirtioBinding> binding)
        : _binding{std::move(binding)} {}

    [[nodiscard]] auto memory() -> const ak::oar::virtio::GuestMemory& override {
        return _binding->memory();
    }
    [[nodiscard]] auto interrupts() -> ak::oar::virtio::InterruptSink& override {
        return *_binding;
    }
    [[nodiscard]] auto bind(ak::oar::virtio::PciFunction& function)
        -> std::expected<void, std::string> override {
        return _binding->bind(function);
    }

    [[nodiscard]] auto binding() -> ak::oar::vfu::VirtioBinding& { return *_binding; }
    bool attached{false};

private:
    std::unique_ptr<ak::oar::vfu::VirtioBinding> _binding;
};

class PeerLog final : public net::PeerObserver {
public:
    auto peer_changed(const net::Ipv6Address& vtep, net::PeerState state) -> void override {
        std::array<char, INET6_ADDRSTRLEN> text{};
        ::inet_ntop(AF_INET6, vtep.data(), text.data(), text.size());
        std::println(stderr, "{}: peer {} {}", role_log, text.data(), net::to_string(state));
    }
};

auto remove_stale_socket(const std::string& path) -> void {
    struct stat st{};
    if (::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        std::filesystem::remove(path);
    }
}

auto run_role(const RoleOptions& opts) -> int {
    auto plan = net::plan_mtu(static_cast<std::uint32_t>(*opts.underlay_mtu),
                              static_cast<std::uint32_t>(opts.tunnel_overhead));
    if (!plan) {
        std::println(stderr, "{}: underlay MTU {} with tunnel overhead {}: {}", role_log,
                     *opts.underlay_mtu, opts.tunnel_overhead, net::to_string(plan.error()));
        return exit_usage;
    }
    auto keys = ak::hull::SignatureVerifier::create(opts.keys);
    if (!keys) {
        std::println(stderr, "{}: controller keys: {}", role_log,
                     ak::hull::to_string(keys.error()));
        return exit_usage;
    }
    auto verifier = std::make_shared<ak::hull::SignatureVerifier>(std::move(*keys));

    auto udp =
        net::UdpEndpoint::create({.bind = *opts.vtep,
                                  .port = static_cast<std::uint16_t>(opts.port),
                                  .scope_id = static_cast<std::uint32_t>(opts.scope),
                                  .source_port_base = net::flow_port_base,
                                  .source_ports = static_cast<std::uint16_t>(opts.source_ports)});
    if (!udp) {
        std::println(stderr, "{}: underlay: {}", role_log, udp.error());
        return EXIT_FAILURE;
    }

    std::vector<std::unique_ptr<VfuTransport>> transports;
    std::vector<net::NetTransport*> raw;
    for (std::size_t i = 0; i < opts.functions.size(); ++i) {
        auto b = ak::oar::vfu::VirtioBinding::create(opts.functions[i],
                                                     std::format("{}[fn {}]", role_log, i));
        if (!b) {
            std::println(stderr, "{}: function {}: {}", role_log, i, b.error());
            return EXIT_FAILURE;
        }
        transports.push_back(std::make_unique<VfuTransport>(std::move(*b)));
        raw.push_back(transports.back().get());
    }
    PeerLog peer_log;
    const bool tunnel = opts.tunnel_overhead != 0;
    std::optional<net::NetRoleConfig::Metadata> metadata;
    if (opts.metadata) {
        auto tun = net::open_metadata_tun(*opts.metadata);
        if (!tun) {
            std::println(stderr, "{}: metadata TUN {}: {}", role_log, *opts.metadata, tun.error());
            return EXIT_FAILURE;
        }
        auto listener = net::open_metadata_listener();
        if (!listener) {
            ::close(tun->fd);
            std::println(stderr, "{}: metadata listener: {}", role_log, listener.error());
            return EXIT_FAILURE;
        }
        metadata = net::NetRoleConfig::Metadata{.tun_fd = tun->fd, .listen_fd = *listener};
        std::println(stderr, "{}: metadata service on {}{}", role_log, *opts.metadata,
                     tun->ipv6 ? "" : " (IPv4 only)");
    }
    auto role = net::NetRole::create(
        {.vtep = *opts.vtep,
         .server_id = *opts.server_id,
         .mtu = *plan,
         .queue_size = net::NetParams{}.queue_size,
         .tx_budget = net::NetParams{}.tx_budget,
         .vtep_config = {},
         .tunnel = tunnel ? std::optional<net::TunnelConfig>{net::TunnelConfig{}} : std::nullopt,
         .mtu_grace = {},
         .clock = {},
         .metadata = metadata},
        raw,
        [verifier](std::span<const std::byte> msg, std::span<const std::byte, 64> sig,
                   std::uint16_t key_id) { return verifier->verify(msg, sig, key_id).has_value(); },
        **udp, &peer_log);
    if (!role) {
        std::println(stderr, "{}: {}", role_log, role.error());
        return EXIT_FAILURE;
    }

    remove_stale_socket(opts.sideband);
    auto listener = helm::SocketListener::bind(opts.sideband);
    if (!listener) {
        std::println(stderr, "{}: listen on {}: {}", role_log, opts.sideband,
                     helm::to_string(listener.error()));
        return EXIT_FAILURE;
    }
    const helm::LinkConfig link{.address = {.local_addr = static_cast<std::uint8_t>(*opts.addr),
                                            .peer_addr = static_cast<std::uint8_t>(*opts.helm_addr),
                                            .local_eid = static_cast<std::uint8_t>(*opts.eid),
                                            .peer_eid = static_cast<std::uint8_t>(*opts.helm_eid)},
                                .mtu = helm::mctp::baseline_mtu,
                                .timeout = {}};
    std::unique_ptr<helm::SocketBinding> sideband;
    std::unique_ptr<helm::OarEndpoint> endpoint;
    std::println(
        stderr, "{}: {} function(s), guest MTU {} (underlay {}, tunnel {}), {}, sideband {}",
        role_log, transports.size(), plan->guest_mtu, plan->underlay_mtu, plan->tunnel_overhead,
        tunnel ? "WireGuard, waiting for keys from helm" : "no tunnel", opts.sideband);

    std::vector<std::byte> datagram(udp_buffer_size);
    auto next_tick = net::VtepClock::now();
    bool more = false;
    for (;;) {
        // [0] the sideband (or its listener), [1] the underlay, then one
        // entry per function.
        constexpr std::size_t fixed = 2;
        std::vector<pollfd> fds(fixed + transports.size());
        fds[0] = {
            .fd = sideband ? sideband->fd() : (*listener)->fd(), .events = POLLIN, .revents = 0};
        fds[1] = {.fd = (*udp)->poll_fd(), .events = POLLIN, .revents = 0};
        for (std::size_t i = 0; i < transports.size(); ++i) {
            fds[i + fixed] = {
                .fd = transports[i]->binding().poll_fd(), .events = POLLIN, .revents = 0};
        }
        (*role)->metadata_poll_fds(fds);  // after the rest: served by poll() below
        const auto wait =
            std::chrono::ceil<std::chrono::milliseconds>(next_tick - net::VtepClock::now());
        const int timeout =
            more ? poll_now : static_cast<int>(std::max<std::int64_t>(0, wait.count()));
        if (::poll(fds.data(), fds.size(), timeout) < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::println(stderr, "{}: poll: {}", role_log, std::strerror(errno));
            return EXIT_FAILURE;
        }
        const auto now = net::VtepClock::now();

        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            if (!sideband) {
                auto accepted = (*listener)->accept(no_wait);
                if (accepted) {
                    sideband = std::move(*accepted);
                    endpoint = std::make_unique<helm::OarEndpoint>(*sideband, link);
                    std::println(stderr, "{}: helm connected", role_log);
                }
            } else {
                for (;;) {
                    auto r = endpoint->serve_one(**role, no_wait);
                    if (r) {
                        continue;
                    }
                    if (r.error() != helm::BindingError::timed_out) {
                        std::println(stderr, "{}: helm sideband: {}", role_log,
                                     helm::to_string(r.error()));
                        endpoint.reset();
                        sideband.reset();
                    }
                    break;
                }
            }
        }

        bool underlay_more = false;
        if ((fds[1].revents & POLLIN) != 0) {
            underlay_more = (*role)->pump(**udp, datagram, udp_budget, now) == udp_budget;
        }

        for (std::size_t i = 0; i < transports.size(); ++i) {
            VfuTransport& t = *transports[i];
            if (!t.attached) {
                auto a = t.binding().attach();
                if (!a) {
                    std::println(stderr, "{}: function {}: {}", role_log, i, a.error());
                    return EXIT_FAILURE;
                }
                t.attached = *a;
                continue;
            }
            if ((fds[i + fixed].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                auto r = t.binding().run();
                if (!r) {
                    std::println(stderr, "{}: function {}: {}", role_log, i, r.error());
                    return EXIT_FAILURE;
                }
                t.attached = *r;
            }
        }
        if (now >= next_tick) {
            next_tick = (*role)->tick(now);
        }
        more = (*role)->poll() || underlay_more;
    }
}

}  // namespace

auto main(int argc, char** argv) -> int {
    // --socket selects the standalone single-NIC mode; anything else is the role.
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} == arg_socket) {
            return run_standalone(argc, argv);
        }
    }
    const auto opts = parse_role(argc, argv);
    if (!opts) {
        return role_usage();
    }
    return run_role(*opts);
}
