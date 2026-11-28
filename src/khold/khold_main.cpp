// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-khold: the khold storage role (kythira .kiro/specs/khold-block-service/
// task 17).
//
//   ak-khold --server-id N --address IP --run-dir DIR
//            --ca FILE --cert FILE --key FILE
//            --sideband PATH --addr A --helm-addr A --eid E --helm-eid E
//            --controller-key ID:HEX [--controller-key ID:HEX ...]
//            --drive N:DIR [--drive N:DIR ...]
//            [--link-if IF | --link-mbps M]
//            -- NODE [NODE-ARGS ...]
//
// Launches the khold node (NODE and its arguments, after --) and keeps it
// running, feeding it layouts and taking its reports through files under
// --run-dir (DIR/layouts, DIR/reports; node_process.hpp has the contract),
// and serves helm's sideband for it with KholdRole (khold_role.hpp).
//
// helm's sideband: the process listens on PATH (SOCK_SEQPACKET; a stale
// socket there is removed) and serves one helm connection at a time,
// listening again if helm goes away. --addr/--eid are this board's bus
// address and EID, --helm-addr/--helm-eid helm's, as in helm's `slot`
// directive. Layouts must verify under one of the --controller-key keys
// (a key ID and its Ed25519 public key in 64 hex digits).
//
// Enrollment: --key is the role's own key, created (0600) if the file does
// not exist, and --cert is where it keeps the certificate the controller's
// storage CA issues for it, asked for through helm with role khold and
// checked against --ca, this server, the key and --address (the storage
// endpoint the certificate names). The node reads both files; after a new
// certificate is installed the node gets SIGHUP.
//
// Inventory: --drive names each drive the node keeps replicas on (its
// number and a directory on its file system), measured by the storage
// self-test (self_test.hpp) at start, after each new certificate and on
// the controller's request. --link-if names the storage interface, whose
// speed is read from /sys/class/net; --link-mbps states it instead.
//
// SIGINT or SIGTERM stops the node and the role.

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include <sys/stat.h>

#include "helm/oar_link.hpp"
#include "helm/role_enrollment.hpp"
#include "helm/sideband_binding.hpp"
#include "hull/signature_verifier.hpp"
#include "khold/khold_role.hpp"
#include "khold/node_process.hpp"
#include "khold/self_test.hpp"
#include "tls/role_identity.hpp"

namespace {

std::atomic<bool> g_stop{false};

auto on_signal(int /*sig*/) -> void {
    g_stop.store(true);
}

struct Options {
    std::uint64_t server_id{0};
    std::string address;
    std::filesystem::path run_dir;
    std::filesystem::path ca;
    std::filesystem::path cert;
    std::filesystem::path key;
    std::string sideband;
    std::optional<std::uint64_t> addr;
    std::optional<std::uint64_t> helm_addr;
    std::optional<std::uint64_t> eid;
    std::optional<std::uint64_t> helm_eid;
    std::vector<ak::hull::ControllerKey> keys;
    std::vector<ak::khold::DriveSpec> drives;
    std::string link_if;
    std::uint32_t link_mbps{0};
    std::vector<std::string> node;
    ak::helm::oar::RoleIdentity identity;  // --serial, --firmware, --drive-serial
    bool has_identity{false};
    std::vector<ak::helm::SanitizeTarget> devices;  // --drive-device
};

constexpr std::uint64_t max_bus_addr = 0x7F;
constexpr std::uint64_t max_eid = 0xFE;
constexpr std::size_t key_hex_digits = 2 * ak::hull::ed25519_public_key_size;
constexpr int base_hex = 16;

auto usage() -> int {
    std::println(
        stderr,
        "usage: ak-khold --server-id N --address IP --run-dir DIR\n"
        "                --ca FILE --cert FILE --key FILE\n"
        "                --sideband PATH --addr A --helm-addr A --eid E --helm-eid E\n"
        "                --controller-key ID:HEX [--controller-key ID:HEX ...]\n"
        "                --drive N:DIR [--drive N:DIR ...]\n"
        "                [--link-if IF | --link-mbps M]\n"
        "                [--serial TEXT [--firmware TEXT] [--drive-serial SERIAL:BYTES ...]]\n"
        "                [--drive-device SERIAL:PATH ...]\n"
        "                -- NODE [NODE-ARGS ...]");
    return 2;
}

auto read_file(const std::filesystem::path& p) -> std::optional<std::string> {
    std::ifstream in{p, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    std::uint64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (s.empty() || ec != std::errc{} || p != s.data() + s.size()) {
        return std::nullopt;
    }
    return v;
}

auto parse_bounded(std::string_view s, std::uint64_t max) -> std::optional<std::uint64_t> {
    const auto v = parse_u64(s);
    if (!v || *v > max) {
        return std::nullopt;
    }
    return v;
}

// ID:HEX, the key in 64 hex digits.
auto parse_controller_key(std::string_view s) -> std::optional<ak::hull::ControllerKey> {
    const auto colon = s.find(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    const auto id = parse_bounded(s.substr(0, colon), UINT16_MAX);
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

// N:DIR, drive numbers strictly increasing across the flags.
auto parse_drive(std::string_view s, std::vector<ak::khold::DriveSpec>& drives) -> bool {
    const auto colon = s.find(':');
    if (colon == std::string_view::npos || colon + 1 == s.size()) {
        return false;
    }
    const auto n = parse_bounded(s.substr(0, colon), UINT8_MAX);
    if (!n || (!drives.empty() && *n <= drives.back().drive) ||
        drives.size() >= ak::proto::max_capacity_drives) {
        return false;
    }
    drives.push_back({.drive = static_cast<std::uint8_t>(*n), .dir = s.substr(colon + 1)});
    return true;
}

// True for an IPv4 or IPv6 literal that names one interface.
auto specific_address(const std::string& host) -> bool {
    std::array<unsigned char, sizeof(in6_addr)> buf{};
    if (::inet_pton(AF_INET, host.c_str(), buf.data()) == 1) {
        return host != "0.0.0.0";
    }
    if (::inet_pton(AF_INET6, host.c_str(), buf.data()) == 1) {
        return std::ranges::any_of(buf, [](unsigned char b) { return b != 0; });
    }
    return false;
}

auto parse(int argc, char** argv) -> std::optional<Options> {
    Options o;
    const std::vector<std::string_view> args(argv + 1, argv + argc);
    std::size_t i = 0;
    for (; i < args.size(); ++i) {
        const auto flag = args[i];
        if (flag == "--") {
            ++i;
            break;
        }
        if (i + 1 >= args.size()) {
            return std::nullopt;
        }
        const auto value = args[++i];
        if (flag == "--server-id") {
            const auto id = parse_u64(value);
            if (!id || *id == 0) {
                return std::nullopt;
            }
            o.server_id = *id;
        } else if (flag == "--address") {
            o.address = value;
        } else if (flag == "--run-dir") {
            o.run_dir = value;
        } else if (flag == "--ca") {
            o.ca = value;
        } else if (flag == "--cert") {
            o.cert = value;
        } else if (flag == "--key") {
            o.key = value;
        } else if (flag == "--sideband") {
            o.sideband = value;
        } else if (flag == "--addr") {
            o.addr = parse_bounded(value, max_bus_addr);
        } else if (flag == "--helm-addr") {
            o.helm_addr = parse_bounded(value, max_bus_addr);
        } else if (flag == "--eid") {
            o.eid = parse_bounded(value, max_eid);
        } else if (flag == "--helm-eid") {
            o.helm_eid = parse_bounded(value, max_eid);
        } else if (flag == "--controller-key") {
            auto key = parse_controller_key(value);
            if (!key) {
                return std::nullopt;
            }
            o.keys.push_back(*key);
        } else if (flag == "--drive") {
            if (!parse_drive(value, o.drives)) {
                return std::nullopt;
            }
        } else if (flag == "--link-if") {
            o.link_if = value;
        } else if (flag == "--link-mbps") {
            const auto m = parse_bounded(value, UINT32_MAX);
            if (!m || *m == 0) {
                return std::nullopt;
            }
            o.link_mbps = static_cast<std::uint32_t>(*m);
        } else if (const auto taken =
                       ak::helm::oar::parse_identity_option(flag, value, o.identity)) {
            if (!*taken) {
                return std::nullopt;
            }
            o.has_identity = true;
        } else if (const auto device = ak::helm::parse_sanitize_option(flag, value, o.devices)) {
            if (!*device) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
    // An identity needs at least --serial.
    if (o.has_identity && !ak::helm::oar::valid_role_identity(o.identity)) {
        return std::nullopt;
    }
    for (; i < args.size(); ++i) {
        o.node.emplace_back(args[i]);
    }
    if (o.server_id == 0 || !specific_address(o.address) || o.run_dir.empty() || o.ca.empty() ||
        o.cert.empty() || o.key.empty() || o.sideband.empty() || !o.addr || !o.helm_addr ||
        !o.eid || !o.helm_eid || o.keys.empty() || o.drives.empty() || o.node.empty() ||
        (!o.link_if.empty() && o.link_mbps != 0)) {
        return std::nullopt;
    }
    return o;
}

// A stale socket from an earlier run may be removed; anything else at the
// path is left alone and refused by SocketListener::bind.
auto remove_stale_socket(const std::string& path) -> void {
    struct stat st{};
    if (::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        std::filesystem::remove(path);
    }
}

auto random_seq() -> std::uint64_t {
    std::array<unsigned char, sizeof(std::uint64_t)> b{};
    std::uint64_t v = 0;
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) == 1) {
        for (const auto x : b) {
            v = (v << 8U) | x;
        }
    }
    return v == 0 ? 1 : v;
}

// helm's sideband: one helm connection at a time, served with KholdRole.
class Sideband {
public:
    Sideband(std::unique_ptr<ak::helm::SocketListener> listener, ak::helm::LinkConfig link,
             ak::khold::KholdRole& role)
        : _listener{std::move(listener)}, _link{link}, _role{role} {}

    [[nodiscard]] auto fd() const -> int { return _socket ? _socket->fd() : _listener->fd(); }

    // fd() is readable (or hung up).
    auto serve() -> void {
        constexpr auto no_wait = std::chrono::milliseconds{0};
        if (!_socket) {
            auto accepted = _listener->accept(no_wait);
            if (accepted) {
                _socket = std::move(*accepted);
                _endpoint = std::make_unique<ak::helm::OarEndpoint>(*_socket, _link);
                std::println(stderr, "ak-khold: helm connected");
            }
            return;
        }
        for (;;) {  // each call takes one packet
            auto r = _endpoint->serve_one(_role, no_wait);
            if (r) {
                continue;
            }
            if (r.error() != ak::helm::BindingError::timed_out) {
                std::println(stderr, "ak-khold: helm sideband: {}", ak::helm::to_string(r.error()));
                _endpoint.reset();
                _socket.reset();
            }
            return;
        }
    }

private:
    std::unique_ptr<ak::helm::SocketListener> _listener;
    ak::helm::LinkConfig _link;
    ak::khold::KholdRole& _role;
    std::unique_ptr<ak::helm::SocketBinding> _socket;
    std::unique_ptr<ak::helm::OarEndpoint> _endpoint;
};

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opts = parse(argc, argv);
    if (!opts) {
        return usage();
    }
    const auto ca = read_file(opts->ca);
    if (!ca) {
        std::println(stderr, "ak-khold: cannot read the CA");
        return 1;
    }
    auto opened = ak::tls::RoleIdentity::open({.key_path = opts->key,
                                               .cert_path = opts->cert,
                                               .ca_pem = *ca,
                                               .server_id = opts->server_id,
                                               .common_name = "khold",
                                               .addresses = {opts->address}});
    if (!opened) {
        std::println(stderr, "ak-khold: storage identity: {}", ak::tls::to_string(opened.error()));
        return 1;
    }
    auto identity = std::move(*opened);
    if (!identity.config(ak::tls::Role::server)) {
        std::println(stderr, "ak-khold: no certificate yet: waiting for enrollment");
    }
    auto keys = ak::hull::SignatureVerifier::create(opts->keys);
    if (!keys) {
        std::println(stderr, "ak-khold: controller keys: {}", ak::hull::to_string(keys.error()));
        return 2;
    }
    auto verifier = std::make_shared<ak::hull::SignatureVerifier>(std::move(*keys));

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    ak::khold::NodeProcess node{{.argv = opts->node,
                                 .layout_dir = opts->run_dir / "layouts",
                                 .report_dir = opts->run_dir / "reports"}};
    const ak::khold::SelfTestConfig test{
        .drives = opts->drives, .link_interface = opts->link_if, .link_mbps = opts->link_mbps};
    ak::khold::KholdRole role{
        node, opts->server_id,
        [verifier](std::span<const std::byte> msg, std::span<const std::byte, 64> sig,
                   std::uint16_t key_id) { return verifier->verify(msg, sig, key_id).has_value(); },
        random_seq(), [test] { return ak::khold::run_self_test(test); }};
    if (opts->has_identity) {
        role.set_identity(opts->identity);
    }
    // Media sanitize at decommission: every drive given a device, and
    // every drive named without one (reported failed).
    if (auto targets = ak::helm::sanitize_targets(opts->identity, opts->devices);
        !targets.empty()) {
        role.set_sanitizer(std::make_shared<ak::helm::MediaSanitizer>(std::move(targets)));
    }
    ak::helm::RoleEnrollment enrollment{identity, ak::helm::oar::Role::khold, ak::tls::Role::server,
                                        [&node](const ak::tls::Config& /*cfg*/) {
                                            node.reload();  // the node reads the new files
                                            std::println(stderr,
                                                         "ak-khold: storage certificate installed");
                                            return true;
                                        }};
    role.set_enrollment(enrollment);

    remove_stale_socket(opts->sideband);
    auto listener = ak::helm::SocketListener::bind(opts->sideband);
    if (!listener) {
        std::println(stderr, "ak-khold: listen on {}: {}", opts->sideband,
                     ak::helm::to_string(listener.error()));
        return 1;
    }
    Sideband sideband{std::move(*listener),
                      {.address = {.local_addr = static_cast<std::uint8_t>(*opts->addr),
                                   .peer_addr = static_cast<std::uint8_t>(*opts->helm_addr),
                                   .local_eid = static_cast<std::uint8_t>(*opts->eid),
                                   .peer_eid = static_cast<std::uint8_t>(*opts->helm_eid)},
                       .mtu = ak::helm::mctp::baseline_mtu,
                       .timeout = {}},
                      role};
    std::println("ak-khold: server {} sideband {}", opts->server_id, opts->sideband);
    constexpr int poll_ms = 100;
    while (!g_stop.load()) {
        node.poll(ak::khold::Clock::now());
        pollfd pfd{.fd = sideband.fd(), .events = POLLIN, .revents = 0};
        // Short waits so reports reach helm promptly between sideband polls.
        if (::poll(&pfd, 1, poll_ms) > 0) {
            sideband.serve();
        }
        role.pump();
    }
    node.stop();
    return 0;
}
