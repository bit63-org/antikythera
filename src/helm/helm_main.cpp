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
#include "helm/boot_state.hpp"
#include "helm/cold_start_reports.hpp"
#include "helm/controller_link.hpp"
#include "helm/flash.hpp"
#include "helm/helm_config.hpp"
#include "helm/helm_daemon.hpp"
#include "helm/image_cache.hpp"
#include "helm/image_keys.hpp"
#include "helm/key_store.hpp"
#include "helm/power_on.hpp"
#include "helm/standing_frames.hpp"
#include "helm/standing_set_keeper.hpp"
#include "helm/power_sequencer.hpp"
#include "helm/sealed_store.hpp"
#include "helm/secure_element.hpp"
#include "helm/sideband_binding.hpp"
#include "helm/store_anchor.hpp"
#include "helm/time_floor.hpp"
#include "hull/host_setup.hpp"
#include "hull/signature_verifier.hpp"

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

// helm's RecordVerifier over hull's Ed25519 verifier and the configured
// controller keys.
class ControllerRecordVerifier final : public helm::RecordVerifier {
public:
    explicit ControllerRecordVerifier(ak::hull::SignatureVerifier verifier) noexcept
        : _verifier{std::move(verifier)} {}
    [[nodiscard]] auto verify(std::span<const std::byte> message,
                              std::span<const std::byte, ak::proto::ed25519_signature_size> sig,
                              std::uint16_t key_id) const -> bool override {
        return _verifier.verify(message, sig, key_id).has_value();
    }

private:
    ak::hull::SignatureVerifier _verifier;
};

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

    // The sealed store, if configured (.kiro/specs/cold-start/
    // Requirements 1 and 6.3): the router records every relayed sequence
    // number there and starts from the recorded one.
    std::unique_ptr<helm::StoreAnchor> anchor;
    std::unique_ptr<helm::FileFlash> flash;
    std::optional<helm::SealedStore> store;
    std::optional<helm::StoreSequenceRecorder> recorder;
    auto daemon_config = make_daemon_config(cfg);
    if (cfg.store) {
        auto a = cfg.store_anchor ? helm::SoftwareStoreAnchor::open(*cfg.store_anchor)
                                  : helm::SoftwareStoreAnchor::ephemeral();
        if (!a) {
            std::println(stderr, "{}: store anchor: {}", log_name, helm::to_string(a.error()));
            return exit_failed;
        }
        anchor = std::move(*a);
        auto f = helm::FileFlash::open(*cfg.store, cfg.store_size);
        if (!f) {
            std::println(stderr, "{}: store {}: {}", log_name, cfg.store->string(),
                         helm::to_string(f.error()));
            return exit_failed;
        }
        flash = std::move(*f);
        auto st = helm::SealedStore::open(*flash, *anchor);
        if (!st) {
            std::println(stderr, "{}: sealed store: {}", log_name, helm::to_string(st.error()));
            return exit_failed;
        }
        store.emplace(std::move(*st));
        if (store->rolled_back() || store->degraded()) {
            std::println(stderr, "{}: sealed store {} ({} fault(s))", log_name,
                         store->rolled_back() ? "rolled back" : "degraded", store->faults());
        }
        const auto floor = helm::load_sequence_floor(*store);
        if (!floor) {
            std::println(stderr, "{}: sequence floor: {}", log_name,
                         helm::to_string(floor.error().error));
            return exit_failed;
        }
        recorder.emplace(*store, *floor);
        daemon_config.router.last_seq = *floor;
        daemon_config.router.sequence_recorder = &*recorder;
    }

    // The power-on policy (cold-start Requirement 3): the newest verified
    // record, or the defaults.
    std::unique_ptr<ControllerRecordVerifier> verifier;
    if (!cfg.controller_keys.empty()) {
        const auto controller_keys = ak::hull::parse_controller_keys(cfg.controller_keys);
        if (!controller_keys) {
            std::println(stderr, "{}: controller-keys: {}", log_name,
                         controller_keys.error().reason);
            return exit_usage;
        }
        auto v = ak::hull::SignatureVerifier::create(*controller_keys);
        if (!v) {
            std::println(stderr, "{}: controller-keys: {}", log_name,
                         ak::hull::to_string(v.error()));
            return exit_usage;
        }
        verifier = std::make_unique<ControllerRecordVerifier>(std::move(*v));
    } else {
        std::println(stderr, "{}: no controller-keys: power policies are refused", log_name);
    }
    // The hull images in the sealed store (cold-start Requirement 2):
    // verified under the image signing keys, compiled in or configured.
    std::unique_ptr<ControllerRecordVerifier> image_verifier;
    std::string_view image_keys = ak::helm::compiled_image_keys();
    if (!image_keys.empty() && !cfg.image_keys.empty()) {
        std::println(stderr, "{}: image-keys: this build has its image keys compiled in", log_name);
        return exit_usage;
    }
    if (image_keys.empty()) {
        image_keys = cfg.image_keys;
    }
    if (!image_keys.empty()) {
        const auto parsed = ak::hull::parse_controller_keys(image_keys);
        if (!parsed) {
            std::println(stderr, "{}: image-keys: {}", log_name, parsed.error().reason);
            return exit_usage;
        }
        auto v = ak::hull::SignatureVerifier::create(*parsed);
        if (!v) {
            std::println(stderr, "{}: image-keys: {}", log_name, ak::hull::to_string(v.error()));
            return exit_usage;
        }
        image_verifier = std::make_unique<ControllerRecordVerifier>(std::move(*v));
    }
    std::optional<helm::ImageCache> images;
    if (store) {
        images.emplace(*store, image_verifier.get());
        if (auto ok = images->load(); !ok) {
            std::println(stderr, "{}: image cache: {}", log_name, helm::to_string(ok.error()));
            images.reset();
        } else if (images->faults() != 0) {
            std::println(stderr, "{}: image cache: {} slot(s) discarded", log_name,
                         images->faults());
        }
    }
    daemon_config.images = images ? &*images : nullptr;
    helm::PowerPolicyKeeper power_policy{cfg.server_id, store ? &*store : nullptr, verifier.get()};
    const auto loaded = power_policy.load();
    if (loaded != helm::PolicyVerdict::kept && loaded != helm::PolicyVerdict::none) {
        std::println(stderr, "{}: stored power policy: {}", log_name, helm::to_string(loaded));
    }
    daemon_config.power_policy = &power_policy;
    // The standing set (cold-start Requirement 4): the pinned instances
    // helm starts after its power returns, with no controller.
    helm::StandingSetKeeper standing_set{cfg.server_id, store ? &*store : nullptr, anchor.get(),
                                         verifier.get()};
    if (const auto v = standing_set.load();
        v != helm::StandingVerdict::kept && v != helm::StandingVerdict::none) {
        std::println(stderr, "{}: stored standing set: {}", log_name, helm::to_string(v));
    }
    daemon_config.standing_set = &standing_set;
    // The network frames of its NICs (Requirement 5.2), replayed to the
    // network roles before the standing starts.
    helm::StandingFrames standing_frames{cfg.server_id, store ? &*store : nullptr, verifier.get()};
    const auto frames_kept =
        standing_frames.load(standing_set.current() ? &*standing_set.current() : nullptr);
    if (frames_kept > 0) {
        std::println(stderr, "{}: {} stored frame(s) for standing NICs", log_name, frames_kept);
    }
    daemon_config.standing_frames = &standing_frames;
    // The time floor (cold-start Requirement 7): the newest stored, raised
    // by the stored policy's; certificates are checked against
    // max(RTC, floor).
    helm::TimeFloor time_floor{store ? &*store : nullptr};
    if (auto ok = time_floor.load(); !ok) {
        std::println(stderr, "{}: time floor: {}", log_name, helm::to_string(ok.error()));
    }
    if (power_policy.from_record()) {
        (void)time_floor.observe(power_policy.current().time_floor);
    }
    if (standing_set.current()) {
        (void)time_floor.observe(standing_set.current()->time_floor);
    }
    const auto started_at = helm::TimeFloor::rtc_now();
    const bool rtc_below_floor = !time_floor.rtc_trusted(started_at);
    if (rtc_below_floor) {
        std::println(stderr, "{}: RTC reads {} s, below the time floor {} s: not trusted", log_name,
                     helm::TimeFloor::rtc_now(), time_floor.floor());
    }
    daemon_config.time_floor = &time_floor;
    auto returned = helm::helm_power_returned(cfg.power_marker);
    if (!returned) {
        // Waiting when helm only restarted is the safe mistake.
        std::println(stderr, "{}: power marker {}: errno {}; assuming power returned", log_name,
                     cfg.power_marker.string(), returned.error());
    }
    const auto& policy = power_policy.current();
    const auto plan =
        // `power-on-policy skip` counts as a restart: no wait.
        helm::plan_power_on(policy, cfg.apply_power_policy && returned.value_or(true),
                            helm::HostPowerOverride::none, helm::draw_jitter(policy.max_jitter_ms));

    // The boot cache's state behind every inventory (cold-start Requirement
    // 8.2).
    daemon_config.boot_cache = [&power_policy, &standing_set, &store, &images] {
        helm::BootImages held;
        if (images) {
            held.lkg = images->digest(helm::ImageSlot::lkg);
            held.previous = images->digest(helm::ImageSlot::previous);
        }
        return helm::make_boot_cache(held, standing_set.generation(), power_policy,
                                     store ? &*store : nullptr);
    };
    // After the power-on wait: one cold_start report per power return
    // (Requirement 8.1), queued so it goes out on the first connection.
    std::unique_ptr<helm::ControllerLink> link;
    helm::HelmDaemon* daemon_ptr = nullptr;  // set once the daemon exists
    const bool power_returned = returned.value_or(true);
    daemon_config.on_boot = [&link, &daemon_ptr, &time_floor, &store, power_returned, started_at,
                             rtc_below_floor, waited = plan.wait](const helm::BootResult& booted) {
        std::println(stderr, "{}: boot: {} slot(s) ready, {} faulted, host {}", log_name,
                     booted.ready.size(), booted.faulted.size(),
                     booted.host_released ? "released" : "held");
        if (!power_returned || !link) {
            return;
        }
        // hull comes from the boot layer until the boot cache exists (task 4).
        auto send = [&link, &time_floor, &store, started_at, rtc_below_floor,
                     waited](std::vector<ak::proto::StandingStartResult> standing) {
            (void)link->report(helm::make_cold_start({.power_return_time = started_at,
                                                      .time_floor = time_floor.floor(),
                                                      .waited = waited,
                                                      .boot_source = ak::proto::BootSource::netboot,
                                                      .rtc_below_floor = rtc_below_floor,
                                                      .standing = std::move(standing)},
                                                     store ? &*store : nullptr));
        };
        // Standing starts go before any envelope (Requirement 4.4); the
        // report waits for their first round, so it lists every one.
        const bool standing =
            daemon_ptr != nullptr &&
            daemon_ptr->expect_standing([send](const std::vector<helm::StandingAttempt>& round) {
                std::println(stderr, "{}: standing starts: {} instance(s) tried", log_name,
                             round.size());
                send(helm::standing_results(round));
            });
        if (!standing) {
            send({});
        }
    };

    DetachedHostPort host;
    std::println(stderr, "{}: no mailbox device yet (helm task 8): commands are refused", log_name);

    helm::HelmDaemon daemon{
        std::move(daemon_config),
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

    daemon_ptr = &daemon;

    helm::ControllerSession session{cfg.server_id, *boot_id,
                                    [&daemon] { return daemon.inventory(); }, daemon};
    session.set_boot_cache_source([&daemon] { return daemon.boot_cache(); });
    // Enrollment: the controller seals volume keys to this key.
    if (auto pk = se->transport_public_key(); pk) {
        ak::proto::Enrollment enrollment;
        std::ranges::copy(*pk, enrollment.transport_key.begin());
        session.set_enrollment(enrollment);
    } else {
        std::println(stderr, "{}: secure element transport key: {}", log_name,
                     helm::to_string(pk.error()));
        return exit_failed;
    }
    auto created = helm::ControllerLink::create(
        {.host = cfg.controller_host,
         .port = cfg.controller_port,
         .tls = {.role = ak::tls::Role::client,
                 .ca_pem = *ca,
                 .cert_pem = *cert,
                 .key_pem = *key,
                 .peer_name = cfg.controller_name,
                 .verification_time =
                     [&time_floor] { return std::optional{time_floor.verification_time_now()}; }}},
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

    // The host stays in reset for the policy's wait; the loop keeps the
    // controller link served meanwhile and boots when it has passed.
    std::println(stderr, "{}: boot {:#x}: tier {} slot {}{}, host released in {} ms", log_name,
                 *boot_id, policy.tier, policy.slot,
                 power_policy.from_record() ? "" : " (default policy)", plan.wait.count());
    daemon.schedule_boot(std::chrono::steady_clock::now() + plan.wait);

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
