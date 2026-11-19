// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-test-controller: harbor's stand-in for kythira's EC2 module
// (.kiro/specs/controller-interface/ task 5). Listens for one server's
// helm over mTLS, waits for it to register, then runs a script of signed
// commands, mapping updates and expectations (see harbor/test_controller.hpp
// for the language). Every report helm sends is printed to stdout.
//
//   ak-test-controller --listen 0.0.0.0:7443
//       --ca server-ca.pem --cert controller.pem --key controller-key.pem
//       --signing-key controller-ed25519.pem --key-id 1 --server-id 7
//       --script phase3.txt
//
// Exit status: 0 when every action succeeded, 1 when one failed (the
// message names the script line), 2 for a usage or setup error.

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "harbor/test_controller.hpp"

namespace {

constexpr int exit_failed = 1;
constexpr int exit_usage = 2;

constexpr std::string_view usage =
    "usage: ak-test-controller --listen HOST:PORT --ca PEM --cert PEM --key PEM\n"
    "                          --signing-key PEM --key-id N --server-id N\n"
    "                          [--client-name NAME] [--timeout SECONDS] [--script FILE|-]\n";

auto read_file(const std::string& path) -> std::optional<std::string> {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

auto parse_u64(const std::string& s) -> std::optional<std::uint64_t> {
    try {
        std::size_t used = 0;
        const auto v = std::stoull(s, &used, 0);
        if (used != s.size()) {
            return std::nullopt;
        }
        return v;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace

auto main(int argc, char** argv) -> int {
    (void)std::signal(SIGPIPE, SIG_IGN);

    std::string listen;
    std::string ca;
    std::string cert;
    std::string key;
    std::string signing_key;
    std::string client_name;
    std::string script = "-";
    std::optional<std::uint64_t> key_id;
    std::optional<std::uint64_t> server_id;
    std::uint64_t timeout_s = 30;

    const std::vector<std::string> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& flag = args[i];
        if (flag == "--help" || flag == "-h") {
            std::cout << usage;
            return 0;
        }
        if (i + 1 >= args.size()) {
            std::cerr << "missing value for " << flag << "\n" << usage;
            return exit_usage;
        }
        const auto& value = args[++i];
        if (flag == "--listen") {
            listen = value;
        } else if (flag == "--ca") {
            ca = value;
        } else if (flag == "--cert") {
            cert = value;
        } else if (flag == "--key") {
            key = value;
        } else if (flag == "--signing-key") {
            signing_key = value;
        } else if (flag == "--client-name") {
            client_name = value;
        } else if (flag == "--script") {
            script = value;
        } else if (flag == "--key-id") {
            key_id = parse_u64(value);
        } else if (flag == "--server-id") {
            server_id = parse_u64(value);
        } else if (flag == "--timeout") {
            timeout_s = parse_u64(value).value_or(0);
        } else {
            std::cerr << "unknown option " << flag << "\n" << usage;
            return exit_usage;
        }
    }
    const auto colon = listen.rfind(':');
    const auto port =
        colon == std::string::npos ? std::nullopt : parse_u64(listen.substr(colon + 1));
    if (listen.empty() || ca.empty() || cert.empty() || key.empty() || signing_key.empty() ||
        !key_id || *key_id == 0 || *key_id > UINT16_MAX || !server_id || *server_id == 0 || !port ||
        *port > UINT16_MAX || timeout_s == 0) {
        std::cerr << usage;
        return exit_usage;
    }
    auto host = listen.substr(0, colon);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }

    const auto ca_pem = read_file(ca);
    const auto cert_pem = read_file(cert);
    const auto key_pem = read_file(key);
    const auto signing_pem = read_file(signing_key);
    if (!ca_pem || !cert_pem || !key_pem || !signing_pem) {
        std::cerr << "cannot read a PEM file\n";
        return exit_usage;
    }
    auto signer = ak::harbor::Signer::from_pem(*signing_pem);
    if (!signer) {
        std::cerr << signing_key << ": not an Ed25519 private key\n";
        return exit_usage;
    }

    std::vector<std::string> lines;
    {
        std::string text;
        if (script == "-") {
            text.assign(std::istreambuf_iterator<char>{std::cin}, std::istreambuf_iterator<char>{});
        } else if (auto t = read_file(script)) {
            text = std::move(*t);
        } else {
            std::cerr << "cannot read " << script << "\n";
            return exit_usage;
        }
        std::istringstream in{text};
        for (std::string line; std::getline(in, line);) {
            lines.push_back(line);
        }
    }
    // Parse the whole script before connecting, so a typo costs nothing.
    std::vector<std::pair<std::size_t, ak::harbor::Action>> actions;
    for (std::size_t n = 0; n < lines.size(); ++n) {
        auto a = ak::harbor::parse_line(lines[n]);
        if (!a) {
            std::cerr << script << ":" << n + 1 << ": " << a.error() << "\n";
            return exit_usage;
        }
        if (a->has_value()) {
            actions.emplace_back(n + 1, std::move(**a));
        }
    }

    ak::harbor::ControllerOptions opts{.tls = {.role = ak::tls::Role::server,
                                               .ca_pem = *ca_pem,
                                               .cert_pem = *cert_pem,
                                               .key_pem = *key_pem,
                                               .peer_name = client_name},
                                       .server_id = *server_id,
                                       .key_id = static_cast<ak::proto::KeyId>(*key_id),
                                       .timeout = std::chrono::seconds{timeout_s},
                                       .on_report = [](const ak::proto::Report& r) {
                                           std::cout << ak::harbor::to_string(r) << std::endl;
                                       }};
    auto controller = ak::harbor::TestController::create(std::move(opts), std::move(*signer));
    if (!controller) {
        std::cerr << controller.error() << "\n";
        return exit_usage;
    }
    auto listener = ak::tls::Listener::bind(host, static_cast<std::uint16_t>(*port));
    if (!listener) {
        std::cerr << "cannot listen on " << listen << ": " << ak::tls::to_string(listener.error())
                  << "\n";
        return exit_usage;
    }
    std::cerr << "listening on " << listen << "\n";
    if (auto ok = controller->accept(*listener); !ok) {
        std::cerr << ok.error() << "\n";
        return exit_failed;
    }
    std::cerr << "server " << *server_id << " registered; next command seq "
              << controller->next_seq() << "\n";
    for (const auto& [line, action] : actions) {
        if (auto ok = controller->run(action); !ok) {
            std::cerr << script << ":" << line << ": " << ok.error() << "\n";
            return exit_failed;
        }
    }
    return 0;
}
