// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-helm: the helm daemon (.kiro/specs/helm-control-plane/), as harbor runs
// it: board processes on a ProcessBackplane, one SOCK_SEQPACKET sideband per
// slot, the ControllerLink over mTLS, the software secure element and the
// audit log, all driven by HelmDaemon's event loop.
//
//   ak-helm --config FILE      run (configuration: src/helm/helm_config.hpp)
//   ak-helm --check FILE       parse the configuration and exit
//
// Order: the slots boot and attach first (the host is released once they
// are up), then the ControllerLink starts, so the controller's first
// inventory already lists every function. SIGTERM or SIGINT stops the loop,
// then holds the host and powers the slots off.
//
// The mailbox to hull (MailboxDevice, helm task 8) is not built yet: until
// it is, every command the router relays fails to post and is answered
// internal_error. Everything else (registration, inventory, slot power,
// cleaning, mapping updates to net roles, status reports) runs.
//
// Exit status: 0 after a clean stop, 1 for a runtime failure, 2 for a usage
// or configuration error.

#include <sys/random.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <pthread.h>
#include <print>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "helm/audit_log.hpp"
#include "helm/controller_link.hpp"
#include "helm/helm_config.hpp"
#include "helm/helm_daemon.hpp"
#include "helm/key_store.hpp"
#include "helm/power_sequencer.hpp"
#include "helm/secure_element.hpp"
#include "helm/sideband_binding.hpp"

namespace {

namespace helm = ak::helm;

constexpr int exit_failed = 1;
constexpr int exit_usage = 2;
constexpr std::string_view log_name = "ak-helm";

constexpr std::string_view usage = "usage: ak-helm --config FILE | --check FILE\n";

auto read_file(const std::filesystem::path& path) -> std::optional<std::string> {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

// A fresh, non-zero boot ID: the controller drops duplicate reports by
// (boot ID, sequence), so a restarted helm must not reuse one.
auto fresh_boot_id() -> std::optional<std::uint64_t> {
    std::uint64_t id = 0;
    while (id == 0) {
        if (::getrandom(&id, sizeof id, 0) != static_cast<ssize_t>(sizeof id)) {
            return std::nullopt;
        }
    }
    return id;
}

// Stands in for the MailboxDevice (helm task 8) until it exists.
class DetachedHostPort final : public helm::HostPort {
public:
    auto post_command(const helm::mailbox::Slot& /*slot*/) -> bool override { return false; }
};

auto make_daemon_config(const helm::HelmConfig& cfg) -> helm::DaemonConfig {
    helm::DaemonConfig dc;
    for (const auto& [slot, entry] : cfg.slots) {
        helm::LinkConfig link{.address = entry.address};
        if (cfg.sideband_timeout) {
            link.timeout = *cfg.sideband_timeout;
        }
        dc.slots.push_back({.slot = slot, .link = link});
    }
    dc.router.server_id = cfg.server_id;
    if (cfg.command_timeout) {
        dc.router.command_timeout = *cfg.command_timeout;
    }
    if (cfg.release_timeout) {
        dc.router.release_timeout = *cfg.release_timeout;
    }
    if (cfg.clean_timeout) {
        dc.router.clean_timeout = *cfg.clean_timeout;
    }
    if (cfg.link_timeout) {
        dc.sequencer.link_timeout = *cfg.link_timeout;
    }
    if (cfg.check_interval) {
        dc.check_interval = *cfg.check_interval;
    }
    return dc;
}

auto run(const helm::HelmConfig& cfg) -> int {
    const auto ca = read_file(cfg.ca);
    const auto cert = read_file(cfg.cert);
    const auto key = read_file(cfg.key);
    if (!ca || !cert || !key) {
        std::println(stderr, "{}: cannot read {}", log_name,
                     (!ca     ? cfg.ca
                      : !cert ? cfg.cert
                              : cfg.key)
                         .string());
        return exit_usage;
    }

    auto se = cfg.master_key ? helm::SoftwareSecureElement::open(*cfg.master_key)
                             : helm::SoftwareSecureElement::ephemeral();
    if (!se) {
        std::println(stderr, "{}: secure element: {}", log_name, helm::to_string(se.error()));
        return exit_failed;
    }
    if (!cfg.master_key) {
        std::println(stderr, "{}: ephemeral master key: wrapped keys die with this process",
                     log_name);
    }
    helm::KeyStore keys{*se};

    auto audit = helm::AuditLog::open(cfg.audit_log.string(), {});
    if (!audit) {
        std::println(stderr, "{}: audit log {}: {} (line {})", log_name, cfg.audit_log.string(),
                     helm::to_string(audit.error().code), audit.error().line);
        return exit_failed;
    }

    const auto boot_id = fresh_boot_id();
    if (!boot_id) {
        std::println(stderr, "{}: getrandom failed", log_name);
        return exit_failed;
    }

    std::map<helm::SlotNumber, helm::ProcessSpec> boards;
    for (const auto& [slot, entry] : cfg.slots) {
        boards.emplace(slot, entry.process);
    }
    helm::ProcessBackplane backplane{std::move(boards),
                                     helm::ProcessSpec{.argv = cfg.host_argv, .ready_path = {}}};
    if (cfg.host_argv.empty()) {
        std::println(stderr, "{}: no host process configured; the host stays in reset", log_name);
    }

    DetachedHostPort host;
    std::println(stderr, "{}: no mailbox device yet (helm task 8): commands are refused", log_name);

    std::unique_ptr<helm::ControllerLink> link;
    helm::HelmDaemon daemon{
        make_daemon_config(cfg),
        keys,
        *audit,
        host,
        backplane,
        [&cfg](helm::SlotNumber slot)
            -> std::expected<std::unique_ptr<helm::Binding>, helm::BindingError> {
            auto b = helm::SocketBinding::connect(cfg.slots.at(slot).process.ready_path);
            if (!b) {
                return std::unexpected(b.error());
            }
            return std::unique_ptr<helm::Binding>{std::move(*b)};
        },
        [&link](ak::proto::ReportBody body) {
            if (link) {
                (void)link->report(std::move(body));
            }
        }};

    helm::ControllerSession session{cfg.server_id, *boot_id,
                                    [&daemon] { return daemon.inventory(); }, daemon};
    auto created = helm::ControllerLink::create({.host = cfg.controller_host,
                                                 .port = cfg.controller_port,
                                                 .tls = {.role = ak::tls::Role::client,
                                                         .ca_pem = *ca,
                                                         .cert_pem = *cert,
                                                         .key_pem = *key,
                                                         .peer_name = cfg.controller_name}},
                                                session);
    if (!created) {
        std::println(stderr, "{}: TLS configuration: {}", log_name,
                     ak::tls::to_string(created.error()));
        return exit_usage;
    }
    link = std::move(*created);

    // Signals go to one thread, which asks the loop to stop.
    sigset_t stop_signals;
    sigemptyset(&stop_signals);
    sigaddset(&stop_signals, SIGTERM);
    sigaddset(&stop_signals, SIGINT);
    std::stop_source stop;
    std::jthread signal_waiter{[&stop, stop_signals](const std::stop_token& st) {
        while (!st.stop_requested()) {
            const timespec poll_interval{.tv_sec = 0, .tv_nsec = 200'000'000};
            if (::sigtimedwait(&stop_signals, nullptr, &poll_interval) > 0) {
                (void)stop.request_stop();
                return;
            }
        }
    }};

    const auto booted = daemon.boot();
    std::println(stderr, "{}: boot {:#x}: {} slot(s) ready, {} faulted, host {}", log_name,
                 *boot_id, booted.ready.size(), booted.faulted.size(),
                 booted.host_released ? "released" : "held");

    std::jthread link_runner{[&link](const std::stop_token& st) { link->run(st); }};
    daemon.run(stop.get_token());

    std::println(stderr, "{}: stopping", log_name);
    link_runner.request_stop();
    link_runner.join();
    daemon.shutdown();
    return 0;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    (void)std::signal(SIGPIPE, SIG_IGN);
    // Block the stop signals in every thread; the signal thread waits for them.
    sigset_t stop_signals;
    sigemptyset(&stop_signals);
    sigaddset(&stop_signals, SIGTERM);
    sigaddset(&stop_signals, SIGINT);
    (void)::pthread_sigmask(SIG_BLOCK, &stop_signals, nullptr);

    const std::vector<std::string_view> args(argv + 1, argv + argc);
    if (args.size() != 2 || (args[0] != "--config" && args[0] != "--check")) {
        std::print(stderr, "{}", usage);
        return exit_usage;
    }
    const auto text = read_file(std::filesystem::path{args[1]});
    if (!text) {
        std::println(stderr, "{}: cannot read {}", log_name, args[1]);
        return exit_usage;
    }
    auto cfg = helm::parse_helm_config(*text);
    if (!cfg) {
        std::println(stderr, "{}: {}: {}", log_name, args[1], cfg.error());
        return exit_usage;
    }
    if (args[0] == "--check") {
        std::println("{}: ok: server {}, {} slot(s)", args[1], cfg->server_id, cfg->slots.size());
        return 0;
    }
    return run(*cfg);
}
