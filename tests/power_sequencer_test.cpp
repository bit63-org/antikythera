// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirement 6: boot order, single-slot
// power cycles, recovery after boot, and harbor's process backplane.

#define BOOST_TEST_MODULE power_sequencer_test
#include <boost/test/unit_test.hpp>

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "helm/power_sequencer.hpp"
#include "test_support.hpp"

using ak::helm::Backplane;
using ak::helm::PowerSequencer;
using ak::helm::ProcessBackplane;
using ak::helm::ProcessSpec;
using ak::helm::SequencerConfig;
using ak::helm::SequencerObserver;
using ak::helm::SlotHealth;
using ak::helm::SlotNumber;
using ak::test::unit_timeout_seconds;

namespace {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

constexpr SlotNumber slot_a = 1;
constexpr SlotNumber slot_b = 2;
constexpr SlotNumber slot_c = 3;
constexpr milliseconds link_timeout{1000};
constexpr milliseconds poll{50};
constexpr milliseconds off_time{200};
constexpr milliseconds come_up{300};  // fake slots go link-ready this long after power-on
constexpr milliseconds real_timeout{3000};
constexpr milliseconds real_poll{10};
constexpr milliseconds grace{500};
constexpr milliseconds wait_step{10};
constexpr unsigned recoveries = 2;

// Records every backplane operation, in order, with simulated time.
struct FakeBackplane final : Backplane {
    Clock::time_point* now;
    std::map<SlotNumber, Clock::time_point> powered_at;
    std::set<SlotNumber> never_ready;  // power on, never link-ready
    std::set<SlotNumber> dead;         // refuses power
    std::set<SlotNumber> link_lost;    // link drops (until power-cycled)
    unsigned cycles_until_fixed{0};    // power-ons of a lost slot that still fail
    bool host_on{false};
    std::vector<std::string> log;

    explicit FakeBackplane(Clock::time_point& t) : now{&t} {}

    auto set_slot_power(SlotNumber slot, bool on) -> bool override {
        log.push_back((on ? "on " : "off ") + std::to_string(slot));
        if (dead.contains(slot) && on) {
            return false;
        }
        if (on) {
            powered_at[slot] = *now;
            if (link_lost.contains(slot)) {
                if (cycles_until_fixed == 0) {
                    link_lost.erase(slot);
                } else {
                    --cycles_until_fixed;
                }
            }
        } else {
            powered_at.erase(slot);
        }
        return true;
    }
    auto link_ready(SlotNumber slot) -> bool override {
        const auto it = powered_at.find(slot);
        return it != powered_at.end() && !never_ready.contains(slot) && !link_lost.contains(slot) &&
               *now - it->second >= come_up;
    }
    auto set_host_power(bool on) -> bool override {
        log.push_back(on ? "host on" : "host off");
        // The host must never come up beside a slot still training.
        if (on) {
            for (const auto& [slot, t] : powered_at) {
                if (!link_ready(slot)) {
                    log.push_back("host released early");
                }
            }
        }
        host_on = on;
        return true;
    }
};

struct Recorder final : SequencerObserver {
    std::vector<std::string> events;
    auto on_slot_ready(SlotNumber s) -> void override {
        events.push_back("ready " + std::to_string(s));
    }
    auto on_slot_recovered(SlotNumber s) -> void override {
        events.push_back("recovered " + std::to_string(s));
    }
    auto on_slot_faulted(SlotNumber s) -> void override {
        events.push_back("faulted " + std::to_string(s));
    }
};

struct Rig {
    Clock::time_point t{};
    FakeBackplane backplane{t};
    Recorder observer;
    PowerSequencer seq{SequencerConfig{.slots = {slot_a, slot_b, slot_c},
                                       .link_timeout = link_timeout,
                                       .poll_interval = poll,
                                       .off_time = off_time,
                                       .max_recoveries = recoveries,
                                       .clock = [this] { return t; },
                                       .sleep = [this](milliseconds d) { t += d; }},
                       backplane, observer};
};

auto contains(const std::vector<std::string>& v, const std::string& s) -> bool {
    return std::ranges::find(v, s) != v.end();
}

auto index_of(const std::vector<std::string>& v, const std::string& s) -> std::ptrdiff_t {
    return std::ranges::find(v, s) - v.begin();
}

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-power-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

// A board process: becomes ready by creating `ready`, then runs until killed.
auto board(const std::filesystem::path& ready) -> ProcessSpec {
    return {.argv = {"/bin/sh", "-c", "touch \"$0\" && exec sleep 30", ready.string()},
            .ready_path = ready};
}

}  // namespace

BOOST_AUTO_TEST_CASE(boot_releases_the_host_only_after_every_slot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig r;
    const auto result = r.seq.boot();
    BOOST_TEST(result.host_released);
    BOOST_TEST((result.ready == std::vector<SlotNumber>{slot_a, slot_b, slot_c}));
    BOOST_TEST(result.faulted.empty());
    const auto& log = r.backplane.log;
    BOOST_TEST(log.front() == "host off");
    BOOST_TEST(log.back() == "host on");
    BOOST_TEST(!contains(log, "host released early"));
    for (const auto s : {slot_a, slot_b, slot_c}) {
        BOOST_TEST((r.seq.health(s) == SlotHealth::ready));
        BOOST_TEST(contains(r.observer.events, "ready " + std::to_string(s)));
    }
    BOOST_TEST(!r.seq.health(9).has_value());
}

// cold-start Requirement 3.3: at most one slot per slot_stagger.
BOOST_AUTO_TEST_CASE(boot_staggers_slot_power, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig r;
    const auto start = r.t;
    const auto result = r.seq.boot();
    BOOST_TEST(result.ready.size() == 3U);
    const auto a = r.backplane.powered_at.at(slot_a);
    const auto b = r.backplane.powered_at.at(slot_b);
    const auto c = r.backplane.powered_at.at(slot_c);
    BOOST_TEST((a == start));
    BOOST_TEST((b - a == SequencerConfig{}.slot_stagger));
    BOOST_TEST((c - b == SequencerConfig{}.slot_stagger));
    BOOST_TEST(SequencerConfig{}.slot_stagger == milliseconds{500});
}

BOOST_AUTO_TEST_CASE(a_slot_without_link_faults_and_the_host_still_boots,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig r;
    r.backplane.never_ready.insert(slot_b);
    r.backplane.dead.insert(slot_c);
    const auto result = r.seq.boot();
    BOOST_TEST((result.ready == std::vector<SlotNumber>{slot_a}));
    BOOST_TEST((result.faulted == std::vector<SlotNumber>{slot_b, slot_c}));
    BOOST_TEST(result.host_released);
    BOOST_TEST((r.seq.health(slot_b) == SlotHealth::faulted));
    // It waited the full link timeout, and powered the faulted slot off
    // before releasing the host.
    BOOST_TEST((r.t - Clock::time_point{} >= link_timeout));
    BOOST_TEST(index_of(r.backplane.log, "off 2") < index_of(r.backplane.log, "host on"));
    BOOST_TEST(!r.backplane.powered_at.contains(slot_b));
    BOOST_TEST(!contains(r.backplane.log, "host released early"));
    BOOST_TEST(contains(r.observer.events, "faulted 2"));
}

BOOST_AUTO_TEST_CASE(power_cycling_one_slot_leaves_the_rest_alone,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig r;
    r.seq.boot();
    r.backplane.log.clear();
    BOOST_TEST(r.seq.power_cycle(slot_b));
    BOOST_TEST((r.backplane.log == std::vector<std::string>{"off 2", "on 2"}));
    BOOST_TEST(r.backplane.host_on);
    BOOST_TEST((r.seq.health(slot_b) == SlotHealth::ready));
    BOOST_TEST(r.observer.events.back() == "recovered 2");

    r.backplane.never_ready.insert(slot_b);
    BOOST_TEST(!r.seq.power_cycle(slot_b));
    BOOST_TEST((r.seq.health(slot_b) == SlotHealth::faulted));
    BOOST_TEST(r.observer.events.back() == "faulted 2");
    BOOST_TEST(!r.seq.power_cycle(9));
}

BOOST_AUTO_TEST_CASE(check_recovers_a_slot_that_dropped,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig r;
    r.seq.boot();
    r.observer.events.clear();
    r.seq.check();
    BOOST_TEST(r.observer.events.empty());

    // Drops; the first power cycle does not fix it, the second does.
    r.backplane.link_lost.insert(slot_a);
    r.backplane.cycles_until_fixed = 1;
    r.seq.check();
    BOOST_TEST((r.observer.events == std::vector<std::string>{"recovered 1"}));
    BOOST_TEST((r.seq.health(slot_a) == SlotHealth::ready));

    // Never fixed within max_recoveries: faulted, and checks leave it alone.
    r.backplane.link_lost.insert(slot_c);
    r.backplane.cycles_until_fixed = recoveries;
    r.seq.check();
    BOOST_TEST(r.observer.events.back() == "faulted 3");
    BOOST_TEST((r.seq.health(slot_c) == SlotHealth::faulted));
    r.observer.events.clear();
    r.seq.check();
    BOOST_TEST(r.observer.events.empty());
}

BOOST_AUTO_TEST_CASE(shutdown_holds_the_host_first,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Rig r;
    r.seq.boot();
    r.backplane.log.clear();
    r.seq.shutdown();
    BOOST_TEST(r.backplane.log.front() == "host off");
    BOOST_TEST(r.backplane.powered_at.empty());
    BOOST_TEST(!r.seq.host_released());
}

BOOST_AUTO_TEST_CASE(harbor_boots_board_processes_then_the_host,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto host_ready = dir.path / "host";
    std::map<SlotNumber, ProcessSpec> slots;
    slots.emplace(slot_a, board(dir.path / "a.sock"));
    // A board that dies before it is ready.
    slots.emplace(slot_b, ProcessSpec{.argv = {"/bin/sh", "-c", "exit 1"},
                                      .ready_path = dir.path / "b.sock"});
    ProcessBackplane backplane{std::move(slots), board(host_ready), grace};
    Recorder observer;
    PowerSequencer seq{SequencerConfig{.slots = {slot_a, slot_b},
                                       .link_timeout = real_timeout,
                                       .poll_interval = real_poll,
                                       .off_time = real_poll,
                                       .max_recoveries = recoveries,
                                       .clock = {},
                                       .sleep = {}},
                       backplane, observer};

    const auto result = seq.boot();
    BOOST_TEST((result.ready == std::vector<SlotNumber>{slot_a}));
    BOOST_TEST((result.faulted == std::vector<SlotNumber>{slot_b}));
    BOOST_TEST(result.host_released);
    BOOST_TEST(backplane.slot_pid(slot_a).has_value());
    BOOST_TEST(!backplane.slot_pid(slot_b).has_value());
    BOOST_TEST(backplane.host_pid().has_value());

    // Killing a board drops its link; check() restarts it.
    const auto old_pid = *backplane.slot_pid(slot_a);
    BOOST_REQUIRE(::kill(old_pid, SIGKILL) == 0);
    const auto until = Clock::now() + real_timeout;
    while (backplane.link_ready(slot_a) && Clock::now() < until) {
        std::this_thread::sleep_for(wait_step);
    }
    seq.check();
    BOOST_TEST(observer.events.back() == "recovered 1");
    BOOST_REQUIRE(backplane.slot_pid(slot_a).has_value());
    BOOST_TEST(*backplane.slot_pid(slot_a) != old_pid);

    seq.shutdown();
    BOOST_TEST(!backplane.host_pid().has_value());
    BOOST_TEST(!backplane.slot_pid(slot_a).has_value());
}

BOOST_AUTO_TEST_CASE(a_stale_ready_file_does_not_count,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto ready = dir.path / "a.sock";
    {
        std::ofstream{ready};
    }  // left over from a previous run
    std::map<SlotNumber, ProcessSpec> slots;
    slots.emplace(slot_a,
                  ProcessSpec{.argv = {"/bin/sh", "-c", "exec sleep 30"}, .ready_path = ready});
    ProcessBackplane backplane{std::move(slots), ProcessSpec{}, grace};
    BOOST_REQUIRE(backplane.set_slot_power(slot_a, true));
    BOOST_TEST(!backplane.link_ready(slot_a));
    BOOST_TEST(!std::filesystem::exists(ready));
    // An unknown slot, and a host with no command, cannot be powered.
    BOOST_TEST(!backplane.set_slot_power(slot_b, true));
    BOOST_TEST(!backplane.set_host_power(true));
}
