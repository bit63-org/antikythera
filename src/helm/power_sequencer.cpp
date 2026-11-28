// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/power_sequencer.hpp"

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <system_error>
#include <thread>
#include <utility>

extern char** environ;  // NOLINT(readability-redundant-declaration): POSIX, for posix_spawn

namespace ak::helm {

namespace {

constexpr auto reap_poll = std::chrono::milliseconds{10};

}  // namespace

auto to_string(SlotHealth h) noexcept -> const char* {
    switch (h) {
        case SlotHealth::off:
            return "off";
        case SlotHealth::starting:
            return "starting";
        case SlotHealth::ready:
            return "ready";
        case SlotHealth::faulted:
            return "faulted";
    }
    return "unknown";
}

// ---- PowerSequencer --------------------------------------------------------

PowerSequencer::PowerSequencer(SequencerConfig config, Backplane& backplane,
                               SequencerObserver& observer)
    : _config{std::move(config)}, _backplane{&backplane}, _observer{&observer} {
    if (!_config.clock) {
        _config.clock = [] { return Clock::now(); };
    }
    if (!_config.sleep) {
        _config.sleep = [](std::chrono::milliseconds d) { std::this_thread::sleep_for(d); };
    }
    for (const auto slot : _config.slots) {
        _health[slot] = SlotHealth::off;
    }
}

auto PowerSequencer::health(SlotNumber slot) const -> std::optional<SlotHealth> {
    const auto it = _health.find(slot);
    if (it == _health.end()) {
        return std::nullopt;
    }
    return it->second;
}

// Polls `slots` (all powered) until each is link-ready or the timeout
// passes; returns those still not ready.
auto PowerSequencer::wait_ready(const std::vector<SlotNumber>& slots) -> std::vector<SlotNumber> {
    std::vector<SlotNumber> waiting = slots;
    const auto deadline = _config.clock() + _config.link_timeout;
    for (;;) {
        std::erase_if(waiting, [this](SlotNumber s) { return _backplane->link_ready(s); });
        if (waiting.empty() || _config.clock() >= deadline) {
            return waiting;
        }
        _config.sleep(_config.poll_interval);
    }
}

auto PowerSequencer::boot() -> BootResult {
    BootResult result;
    // The host must not see a half-built device tree.
    (void)_backplane->set_host_power(false);
    _host_released = false;

    std::vector<SlotNumber> powered;
    bool first = true;
    for (const auto slot : _config.slots) {
        if (!first && _config.slot_stagger.count() > 0) {
            _config.sleep(_config.slot_stagger);
        }
        first = false;
        if (_backplane->set_slot_power(slot, true)) {
            _health[slot] = SlotHealth::starting;
            powered.push_back(slot);
        } else {
            _health[slot] = SlotHealth::faulted;
        }
    }
    const auto late = wait_ready(powered);
    for (const auto slot : _config.slots) {
        if (_health[slot] == SlotHealth::starting && !std::ranges::contains(late, slot)) {
            _health[slot] = SlotHealth::ready;
            result.ready.push_back(slot);
            _observer->on_slot_ready(slot);
            continue;
        }
        // No link in time (or no power at all): off and faulted, so a
        // half-trained link is not left on the host's bus.
        (void)_backplane->set_slot_power(slot, false);
        _health[slot] = SlotHealth::faulted;
        result.faulted.push_back(slot);
        _observer->on_slot_faulted(slot);
    }
    _host_released = _backplane->set_host_power(true);
    result.host_released = _host_released;
    return result;
}

auto PowerSequencer::cycle(SlotNumber slot) -> bool {
    (void)_backplane->set_slot_power(slot, false);
    _health[slot] = SlotHealth::off;
    _config.sleep(_config.off_time);
    if (!_backplane->set_slot_power(slot, true)) {
        _health[slot] = SlotHealth::faulted;
        return false;
    }
    _health[slot] = SlotHealth::starting;
    if (!wait_ready({slot}).empty()) {
        (void)_backplane->set_slot_power(slot, false);
        _health[slot] = SlotHealth::faulted;
        return false;
    }
    _health[slot] = SlotHealth::ready;
    return true;
}

auto PowerSequencer::power_cycle(SlotNumber slot) -> bool {
    if (!_health.contains(slot)) {
        return false;
    }
    if (cycle(slot)) {
        _observer->on_slot_recovered(slot);
        return true;
    }
    _observer->on_slot_faulted(slot);
    return false;
}

auto PowerSequencer::check() -> void {
    for (const auto slot : _config.slots) {
        if (_health[slot] != SlotHealth::ready || _backplane->link_ready(slot)) {
            continue;
        }
        _health[slot] = SlotHealth::faulted;
        bool recovered = false;
        for (unsigned attempt = 0; attempt < _config.max_recoveries && !recovered; ++attempt) {
            recovered = cycle(slot);
        }
        if (recovered) {
            _observer->on_slot_recovered(slot);
        } else {
            _observer->on_slot_faulted(slot);
        }
    }
}

auto PowerSequencer::shutdown() -> void {
    (void)_backplane->set_host_power(false);
    _host_released = false;
    for (const auto slot : _config.slots) {
        (void)_backplane->set_slot_power(slot, false);
        _health[slot] = SlotHealth::off;
    }
}

// ---- ProcessBackplane ------------------------------------------------------

ProcessBackplane::ProcessBackplane(std::map<SlotNumber, ProcessSpec> slots, ProcessSpec host,
                                   std::chrono::milliseconds grace)
    : _host{.spec = std::move(host), .pid = -1}, _grace{grace} {
    for (auto& [slot, spec] : slots) {
        _slots.emplace(slot, Running{.spec = std::move(spec), .pid = -1});
    }
}

ProcessBackplane::~ProcessBackplane() {
    stop(_host);
    for (auto& [slot, r] : _slots) {
        stop(r);
    }
}

auto ProcessBackplane::start(Running& r) -> bool {
    if (alive(r)) {
        return true;
    }
    if (r.spec.argv.empty()) {
        return false;
    }
    if (!r.spec.ready_path.empty()) {
        std::error_code ec;
        std::filesystem::remove(r.spec.ready_path, ec);
    }
    std::vector<char*> argv;
    argv.reserve(r.spec.argv.size() + 1);
    for (auto& a : r.spec.argv) {
        argv.push_back(a.data());
    }
    argv.push_back(nullptr);
    pid_t pid = -1;
    if (::posix_spawn(&pid, argv.front(), nullptr, nullptr, argv.data(), environ) != 0) {
        return false;
    }
    r.pid = pid;
    return true;
}

auto ProcessBackplane::alive(Running& r) -> bool {
    if (r.pid <= 0) {
        return false;
    }
    int status = 0;
    const auto w = ::waitpid(r.pid, &status, WNOHANG);
    if (w == 0) {
        return true;
    }
    // Exited (reaped now) or not our child any more.
    r.pid = -1;
    return false;
}

auto ProcessBackplane::stop(Running& r) -> void {
    if (!alive(r)) {
        return;
    }
    (void)::kill(r.pid, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + _grace;
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const auto w = ::waitpid(r.pid, &status, WNOHANG);
        if (w == r.pid || (w < 0 && errno != EINTR)) {
            r.pid = -1;
            return;
        }
        std::this_thread::sleep_for(reap_poll);
    }
    (void)::kill(r.pid, SIGKILL);
    int status = 0;
    while (::waitpid(r.pid, &status, 0) < 0 && errno == EINTR) {
    }
    r.pid = -1;
}

auto ProcessBackplane::set_slot_power(SlotNumber slot, bool on) -> bool {
    const auto it = _slots.find(slot);
    if (it == _slots.end()) {
        return false;
    }
    if (on) {
        return start(it->second);
    }
    stop(it->second);
    return true;
}

auto ProcessBackplane::link_ready(SlotNumber slot) -> bool {
    const auto it = _slots.find(slot);
    if (it == _slots.end() || !alive(it->second)) {
        return false;
    }
    std::error_code ec;
    return it->second.spec.ready_path.empty() ||
           std::filesystem::exists(it->second.spec.ready_path, ec);
}

auto ProcessBackplane::set_host_power(bool on) -> bool {
    if (on) {
        return start(_host);
    }
    stop(_host);
    return true;
}

auto ProcessBackplane::slot_pid(SlotNumber slot) -> std::optional<pid_t> {
    const auto it = _slots.find(slot);
    if (it == _slots.end() || !alive(it->second)) {
        return std::nullopt;
    }
    return it->second.pid;
}

auto ProcessBackplane::host_pid() -> std::optional<pid_t> {
    if (!alive(_host)) {
        return std::nullopt;
    }
    return _host.pid;
}

}  // namespace ak::helm
