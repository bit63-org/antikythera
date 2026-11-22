// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-hold: the storage role (.kiro/specs/block-volume-service/ task 6).
//
//   ak-hold --server-id N --listen HOST:PORT --data-dir DIR
//           --ca FILE --cert FILE --key FILE --configs DIR
//
// Listens for TLS sessions from initiators and peers on HOST:PORT (an
// address on the storage segment; IPv6 literals in brackets), keeps its
// replicas under --data-dir, and presents --cert (from the controller's
// CA, carrying urn:antikythera:server:N) with --key, trusting --ca.
//
// helm sideband stub: until helm relays ReplicaConfigs over this role's
// sideband (task 12), they come from --configs, a directory of encoded
// ReplicaConfig frames (*.rcfg) that helm has already verified. It is read
// at start and rescanned every second; a frame is applied when its epoch
// is new. SIGINT or SIGTERM stops the role.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "hold/server/node.hpp"
#include "hold/store/file_layer.hpp"
#include "proto/replica_config.hpp"

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
};

auto usage() -> int {
    std::println(stderr,
                 "usage: ak-hold --server-id N --listen HOST:PORT --data-dir DIR\n"
                 "               --ca FILE --cert FILE --key FILE --configs DIR");
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
        } else {
            return std::nullopt;
        }
    }
    if (o.server_id == 0 || o.host.empty() || o.data_dir.empty() || o.ca.empty() ||
        o.cert.empty() || o.key.empty() || o.configs.empty()) {
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

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opts = parse(argc, argv);
    if (!opts) {
        return usage();
    }
    const auto ca = read_file(opts->ca);
    const auto cert = read_file(opts->cert);
    const auto key = read_file(opts->key);
    if (!ca || !cert || !key) {
        std::println(stderr, "ak-hold: cannot read the CA, certificate or key");
        return 1;
    }
    std::error_code ec;
    std::filesystem::create_directories(opts->data_dir, ec);
    ak::hold::store::PosixFiles files;
    ak::hold::NodeConfig config{
        .host = opts->host,
        .port = opts->port,
        .tls = {.role = ak::tls::Role::server,
                .ca_pem = *ca,
                .cert_pem = *cert,
                .key_pem = *key,
                .peer_name = {}},
        // No helm sideband yet (configs come from --configs), so no
        // controller grants leases: the primary serves reads without one.
        .server = {.server_id = opts->server_id, .data_dir = opts->data_dir, .leases = false},
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
