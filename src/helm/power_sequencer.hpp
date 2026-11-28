// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// PowerSequencer: backplane power for the data-plane slots and the host
// (.kiro/specs/helm-control-plane/ Requirement 6, design "PowerSequencer").
//
//   boot()          host held in reset; every slot powered, slot_stagger
//                   apart (cold-start Requirement 3.3); wait until each
//                   is link-ready or its link_timeout passes (that slot is
//                   powered off again and faulted); only then release the
//                   host, so it enumerates a fixed, fully ready device tree
//                   and needs no hot-plug (6.1).
//   power_cycle(s)  one slot off, settle, on, wait for link-ready, without
//                   touching the host or any other slot (6.2).
//   check()         after boot: a ready slot whose link dropped is faulted
//                   and recovered with up to max_recoveries power cycles
//                   (6.3). Its functions return to the pool only after the
//                   CommandRouter cleans them (slot_power_cycled), which the
//                   observer arranges.
//
// The sequencer drives a Backplane: per-slot power enable and PERST#, the
// slot's link-ready input, and host power/PERST#. On hardware that is GPIO;
// in harbor it is ProcessBackplane, which launches and kills board processes
// and then launches the L1 QEMU (design: "In harbor it launches/kills
// board processes and then launches the L1 QEMU").
//
// Time is injected (clock and sleep), so tests run the whole sequence
// without waiting. Not thread-safe.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

namespace ak::helm {

using SlotNumber = std::uint8_t;

class Backplane {
public:
    Backplane() = default;
    Backplane(const Backplane&) = delete;
    auto operator=(const Backplane&) -> Backplane& = delete;
    Backplane(Backplane&&) = delete;
    auto operator=(Backplane&&) -> Backplane& = delete;
    virtual ~Backplane() = default;

    // Power on (and release PERST#) or hold in reset and power off. False
    // if the backplane could not do it.
    virtual auto set_slot_power(SlotNumber slot, bool on) -> bool = 0;
    // The slot's link-ready input.
    virtual auto link_ready(SlotNumber slot) -> bool = 0;
    // Releases the host from reset (true) or holds it (false).
    virtual auto set_host_power(bool on) -> bool = 0;
};

enum class SlotHealth : std::uint8_t {
    off,
    starting,  // powered, waiting for link-ready
    ready,
    faulted,  // never came up, or dropped and could not be recovered
};

[[nodiscard]] auto to_string(SlotHealth h) noexcept -> const char*;

// What the rest of helm hears from the sequencer. All calls run on the
// sequencer's thread, inside boot(), power_cycle() or check().
class SequencerObserver {
public:
    SequencerObserver() = default;
    SequencerObserver(const SequencerObserver&) = default;
    auto operator=(const SequencerObserver&) -> SequencerObserver& = default;
    SequencerObserver(SequencerObserver&&) = default;
    auto operator=(SequencerObserver&&) -> SequencerObserver& = default;
    virtual ~SequencerObserver() = default;

    // First link-ready since boot: read the role's inventory, add_slot().
    virtual auto on_slot_ready(SlotNumber /*slot*/) -> void {}
    // The slot was power-cycled and is link-ready again: slot_power_cycled().
    virtual auto on_slot_recovered(SlotNumber /*slot*/) -> void {}
    // The slot is faulted (no link at boot, or lost and not recovered).
    virtual auto on_slot_faulted(SlotNumber /*slot*/) -> void {}
};

struct SequencerConfig {
    using Clock = std::chrono::steady_clock;

    std::vector<SlotNumber> slots;
    std::chrono::milliseconds link_timeout{std::chrono::seconds{30}};
    std::chrono::milliseconds poll_interval{std::chrono::milliseconds{50}};
    // How long a slot stays off in a power cycle.
    std::chrono::milliseconds off_time{std::chrono::milliseconds{500}};
    unsigned max_recoveries{3};
    // Time between powering one slot and the next at boot, so their inrush
    // does not add up (.kiro/specs/cold-start/ Requirement 3.3: at most one
    // slot per 500 ms).
    std::chrono::milliseconds slot_stagger{std::chrono::milliseconds{500}};
    // Empty: steady_clock and std::this_thread::sleep_for.
    std::function<Clock::time_point()> clock;
    std::function<void(std::chrono::milliseconds)> sleep;
};

struct BootResult {
    std::vector<SlotNumber> ready;
    std::vector<SlotNumber> faulted;
    bool host_released{false};
};

class PowerSequencer {
public:
    // `backplane` and `observer` must outlive the sequencer.
    PowerSequencer(SequencerConfig config, Backplane& backplane, SequencerObserver& observer);

    auto boot() -> BootResult;
    // True if the slot came back link-ready.
    auto power_cycle(SlotNumber slot) -> bool;
    // Looks for ready slots that lost their link and recovers them.
    auto check() -> void;
    // Holds the host, then powers every slot off.
    auto shutdown() -> void;

    [[nodiscard]] auto health(SlotNumber slot) const -> std::optional<SlotHealth>;
    [[nodiscard]] auto host_released() const noexcept -> bool { return _host_released; }

private:
    using Clock = SequencerConfig::Clock;

    auto wait_ready(const std::vector<SlotNumber>& slots) -> std::vector<SlotNumber>;
    auto cycle(SlotNumber slot) -> bool;

    SequencerConfig _config;
    Backplane* _backplane;
    SequencerObserver* _observer;
    std::map<SlotNumber, SlotHealth> _health;
    bool _host_released{false};
};

// ---- harbor ---------------------------------------------------------------

// A process standing in for a board or for the host.
struct ProcessSpec {
    std::vector<std::string> argv;  // argv[0] is the executable path
    // The board process creates this (its sideband socket, say) once it is
    // ready; its existence, with the process alive, is link-ready. Removed
    // before each launch so a stale one does not count.
    std::filesystem::path ready_path;
};

// harbor's Backplane: slot power is a board process, link-ready is that
// process alive with its ready_path present, and releasing the host
// launches the L1 QEMU. Power-off sends SIGTERM, waits up to `grace`, then
// SIGKILLs, and always reaps the process.
class ProcessBackplane final : public Backplane {
public:
    ProcessBackplane(std::map<SlotNumber, ProcessSpec> slots, ProcessSpec host,
                     std::chrono::milliseconds grace = std::chrono::seconds{5});
    ProcessBackplane(const ProcessBackplane&) = delete;
    auto operator=(const ProcessBackplane&) -> ProcessBackplane& = delete;
    ProcessBackplane(ProcessBackplane&&) = delete;
    auto operator=(ProcessBackplane&&) -> ProcessBackplane& = delete;
    ~ProcessBackplane() override;  // stops everything still running

    auto set_slot_power(SlotNumber slot, bool on) -> bool override;
    auto link_ready(SlotNumber slot) -> bool override;
    auto set_host_power(bool on) -> bool override;

    // The pid running for a slot, or nullopt (off, or exited and reaped).
    [[nodiscard]] auto slot_pid(SlotNumber slot) -> std::optional<pid_t>;
    [[nodiscard]] auto host_pid() -> std::optional<pid_t>;

private:
    struct Running {
        ProcessSpec spec;
        pid_t pid{-1};
    };

    auto start(Running& r) -> bool;
    auto stop(Running& r) -> void;
    static auto alive(Running& r) -> bool;

    std::map<SlotNumber, Running> _slots;
    Running _host;
    std::chrono::milliseconds _grace;
};

}  // namespace ak::helm
