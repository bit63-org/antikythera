// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-hold: the storage role (.kiro/specs/block-volume-service/ task 6).
//
//   ak-hold --server-id N --listen HOST:PORT --data-dir DIR
//           --ca FILE --cert FILE --key FILE
//           ( --sideband PATH --addr A --helm-addr A --eid E --helm-eid E
//             --controller-key ID:HEX [--controller-key ID:HEX ...]
//           | --configs DIR )
//
// Listens for TLS sessions from initiators and peers on HOST:PORT (an
// address on the storage segment; IPv6 literals in brackets), keeps its
// replicas under --data-dir, and presents --cert (from the controller's
// CA, carrying urn:antikythera:server:N) with --key, trusting --ca.
//
// helm's sideband (task 12): the process listens on PATH (SOCK_SEQPACKET;
// a stale socket there is removed) and serves one helm connection at a
// time with HoldRole (hold_role.hpp), listening again if helm goes away.
// --addr/--eid are this board's bus address and EID, --helm-addr/--helm-eid
// helm's, as in helm's `slot` directive. Configs and ops must verify under
// one of the --controller-key keys (a key ID and its Ed25519 public key in
// 64 hex digits). The controller grants leases, so a primary serves reads
// only while it holds one.
//
// With the sideband the role enrolls (block-volume-service task 12): --key
// is its own key, created (0600) if the file does not exist, and --cert
// is where it keeps the certificate the controller's CA issues for it,
// asked for through helm and checked against --ca, this server, the key
// and the --listen address (which must then be an IP address, the one the
// certificate names). A --cert that already passes is used at once; until
// one does, the node listens but answers no one.
//
// --configs DIR instead stands in for helm when there is no controller: a
// directory of encoded ReplicaConfig frames (*.rcfg), trusted as they are
// (no signature check) and without leases. It is read at start and
// rescanned every second; a frame is applied when its epoch is new.
// SIGINT or SIGTERM stops the role.

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
#include <map>
#include <memory>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#include "helm/oar_link.hpp"
#include "helm/sideband_binding.hpp"
#include "hold/server/hold_role.hpp"
#include "hold/server/node.hpp"
#include "hold/store/file_layer.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/replica_config.hpp"
#include "tls/role_identity.hpp"

namespace {

std::atomic<bool> g_stop{false};

auto on_signal(int /*sig*/) -> void {
    g_stop.store(true);
}

struct Options {
    std::uint64_t server_id{0};
    std::string host;
    std::uint16_t port{0};
    std::filesystem::path data_dir;
    std::filesystem::path ca;
    std::filesystem::path cert;
    std::filesystem::path key;
    std::filesystem::path configs;
    std::string sideband;
    std::optional<std::uint64_t> addr;
    std::optional<std::uint64_t> helm_addr;
    std::optional<std::uint64_t> eid;
    std::optional<std::uint64_t> helm_eid;
    std::vector<ak::hull::ControllerKey> keys;
};

constexpr std::uint64_t max_bus_addr = 0x7F;
constexpr std::uint64_t max_eid = 0xFE;
constexpr std::size_t key_hex_digits = 2 * ak::hull::ed25519_public_key_size;
constexpr int base_hex = 16;

auto usage() -> int {
    std::println(stderr,
                 "usage: ak-hold --server-id N --listen HOST:PORT --data-dir DIR\n"
                 "               --ca FILE --cert FILE --key FILE\n"
                 "               ( --sideband PATH --addr A --helm-addr A --eid E --helm-eid E\n"
                 "                 --controller-key ID:HEX [--controller-key ID:HEX ...]\n"
                 "               | --configs DIR )");
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
    if (s.empty()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char ch : s) {
        if (ch < '0' || ch > '9' || v > (UINT64_MAX - 9) / 10) {
            return std::nullopt;
        }
        v = (v * 10) + static_cast<std::uint64_t>(ch - '0');
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

// HOST:PORT, [V6]:PORT.
auto parse_listen(std::string_view s, Options& o) -> bool {
    const auto colon = s.rfind(':');
    if (colon == std::string_view::npos) {
        return false;
    }
    auto host = s.substr(0, colon);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    const auto port = parse_u64(s.substr(colon + 1));
    if (host.empty() || !port || *port > UINT16_MAX) {
        return false;
    }
    o.host = std::string{host};
    o.port = static_cast<std::uint16_t>(*port);
    return true;
}

auto parse(int argc, char** argv) -> std::optional<Options> {
    Options o;
    const std::vector<std::string_view> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i + 1 >= args.size()) {
            return std::nullopt;
        }
        const auto flag = args[i];
        const auto value = args[++i];
        if (flag == "--server-id") {
            const auto id = parse_u64(value);
            if (!id || *id == 0) {
                return std::nullopt;
            }
            o.server_id = *id;
        } else if (flag == "--listen") {
            if (!parse_listen(value, o)) {
                return std::nullopt;
            }
        } else if (flag == "--data-dir") {
            o.data_dir = value;
        } else if (flag == "--ca") {
            o.ca = value;
        } else if (flag == "--cert") {
            o.cert = value;
        } else if (flag == "--key") {
            o.key = value;
        } else if (flag == "--configs") {
            o.configs = value;
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
        } else {
            return std::nullopt;
        }
    }
    if (o.server_id == 0 || o.host.empty() || o.data_dir.empty() || o.ca.empty() ||
        o.cert.empty() || o.key.empty()) {
        return std::nullopt;
    }
    // Exactly one source of configs: helm's sideband or the directory.
    const bool sideband =
        !o.sideband.empty() || o.addr || o.helm_addr || o.eid || o.helm_eid || !o.keys.empty();
    if (sideband == !o.configs.empty()) {
        return std::nullopt;
    }
    if (sideband && (o.sideband.empty() || !o.addr || !o.helm_addr || !o.eid || !o.helm_eid ||
                     o.keys.empty())) {
        return std::nullopt;
    }
    return o;
}

// The helm sideband stub: applies each config file whose epoch is new.
class ConfigDir {
public:
    explicit ConfigDir(std::filesystem::path dir) : _dir{std::move(dir)} {}

    auto scan(ak::hold::HoldServer& server) -> void {
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator{_dir, ec}) {
            if (!entry.is_regular_file(ec) || entry.path().extension() != ".rcfg") {
                continue;
            }
            const auto bytes = read_file(entry.path());
            if (!bytes) {
                continue;
            }
            const auto frame = std::as_bytes(std::span{*bytes});
            const auto c = ak::proto::decode_replica_config(frame);
            if (!c) {
                if (_bad.insert(entry.path()).second) {
                    std::println(stderr, "ak-hold: {}: does not decode", entry.path().string());
                }
                continue;
            }
            _bad.erase(entry.path());
            auto& seen = _seen[entry.path()];
            if (seen == c->epoch) {
                continue;
            }
            seen = c->epoch;
            if (auto r = server.apply_config(*c, ak::hold::Clock::now()); !r) {
                std::println(stderr, "ak-hold: {}: epoch {}: {}", entry.path().string(), c->epoch,
                             ak::hold::to_string(r.error()));
            } else {
                std::println("ak-hold: volume {} at epoch {}", c->volume_id, c->epoch);
            }
        }
    }

private:
    std::filesystem::path _dir;
    std::map<std::filesystem::path, std::uint64_t> _seen;
    std::set<std::filesystem::path> _bad;
};

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

// helm's sideband: one helm connection at a time, served with HoldRole.
class Sideband {
public:
    Sideband(std::unique_ptr<ak::helm::SocketListener> listener, ak::helm::LinkConfig link,
             ak::hold::HoldRole& role)
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
                std::println(stderr, "ak-hold: helm connected");
            }
            return;
        }
        for (;;) {  // each call takes one packet
            auto r = _endpoint->serve_one(_role, no_wait);
            if (r) {
                continue;
            }
            if (r.error() != ak::helm::BindingError::timed_out) {
                std::println(stderr, "ak-hold: helm sideband: {}", ak::helm::to_string(r.error()));
                _endpoint.reset();
                _socket.reset();
            }
            return;
        }
    }

private:
    std::unique_ptr<ak::helm::SocketListener> _listener;
    ak::helm::LinkConfig _link;
    ak::hold::HoldRole& _role;
    std::unique_ptr<ak::helm::SocketBinding> _socket;
    std::unique_ptr<ak::helm::OarEndpoint> _endpoint;
};

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

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opts = parse(argc, argv);
    if (!opts) {
        return usage();
    }
    const bool enroll = !opts->sideband.empty();
    const auto ca = read_file(opts->ca);
    if (!ca) {
        std::println(stderr, "ak-hold: cannot read the CA");
        return 1;
    }
    std::optional<ak::tls::RoleIdentity> identity;
    std::string cert_pem;
    std::string key_pem;
    if (enroll) {
        if (!specific_address(opts->host)) {
            std::println(stderr,
                         "ak-hold: with --sideband, --listen must be the IP address the "
                         "certificate names");
            return usage();
        }
        auto opened = ak::tls::RoleIdentity::open({.key_path = opts->key,
                                                   .cert_path = opts->cert,
                                                   .ca_pem = *ca,
                                                   .server_id = opts->server_id,
                                                   .common_name = "hold",
                                                   .addresses = {opts->host}});
        if (!opened) {
            std::println(stderr, "ak-hold: storage identity: {}",
                         ak::tls::to_string(opened.error()));
            return 1;
        }
        identity = std::move(*opened);
        if (const auto cfg = identity->config(ak::tls::Role::server)) {
            cert_pem = cfg->cert_pem;
            key_pem = cfg->key_pem;
        } else {
            std::println(stderr, "ak-hold: no certificate yet: waiting for enrollment");
        }
    } else {
        const auto cert = read_file(opts->cert);
        const auto key = read_file(opts->key);
        if (!cert || !key) {
            std::println(stderr, "ak-hold: cannot read the certificate or key");
            return 1;
        }
        cert_pem = *cert;
        key_pem = *key;
    }
    std::error_code ec;
    std::filesystem::create_directories(opts->data_dir, ec);
    ak::hold::store::PosixFiles files;
    ak::hold::NodeConfig config{
        .host = opts->host,
        .port = opts->port,
        .tls = {.role = ak::tls::Role::server,
                .ca_pem = *ca,
                .cert_pem = std::move(cert_pem),
                .key_pem = std::move(key_pem),
                .peer_name = {}},
        // With --configs there is no controller to grant leases: the
        // primary serves reads without one.
        .server = {.server_id = opts->server_id,
                   .data_dir = opts->data_dir,
                   .leases = opts->configs.empty()},
    };
    auto node = ak::hold::Node::create(files, std::move(config));
    if (!node) {
        std::println(stderr, "ak-hold: cannot listen on {}:{}: {}", opts->host, opts->port,
                     ak::tls::to_string(node.error()));
        return 1;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
    std::println("ak-hold: server {} listening on port {}", opts->server_id, (*node)->port());
    if (!opts->configs.empty()) {
        ConfigDir configs{opts->configs};
        auto next_scan = ak::hold::Clock::now();
        while (!g_stop.load()) {
            if (ak::hold::Clock::now() >= next_scan) {
                configs.scan((*node)->server());
                next_scan = ak::hold::Clock::now() + std::chrono::seconds{1};
            }
            (*node)->run_once(std::chrono::milliseconds{200});
        }
        return 0;
    }

    auto keys = ak::hull::SignatureVerifier::create(opts->keys);
    if (!keys) {
        std::println(stderr, "ak-hold: controller keys: {}", ak::hull::to_string(keys.error()));
        return 2;
    }
    auto verifier = std::make_shared<ak::hull::SignatureVerifier>(std::move(*keys));
    ak::hold::HoldRole role{
        (*node)->server(), opts->server_id,
        [verifier](std::span<const std::byte> msg, std::span<const std::byte, 64> sig,
                   std::uint16_t key_id) { return verifier->verify(msg, sig, key_id).has_value(); },
        random_seq()};
    ak::helm::RoleEnrollment enrollment{*identity, ak::helm::oar::Role::hold, ak::tls::Role::server,
                                        [&node](const ak::tls::Config& cfg) {
                                            if (!(*node)->set_tls(cfg)) {
                                                return false;
                                            }
                                            std::println(stderr,
                                                         "ak-hold: storage certificate installed");
                                            return true;
                                        }};
    role.set_enrollment(enrollment);
    remove_stale_socket(opts->sideband);
    auto listener = ak::helm::SocketListener::bind(opts->sideband);
    if (!listener) {
        std::println(stderr, "ak-hold: listen on {}: {}", opts->sideband,
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
    std::println("ak-hold: sideband {}", opts->sideband);
    while (!g_stop.load()) {
        // Short waits so reports reach helm promptly between sideband polls.
        if ((*node)->run_once(std::chrono::milliseconds{100}, sideband.fd())) {
            sideband.serve();
        }
        role.pump(ak::hold::Clock::now());
    }
    return 0;
}
