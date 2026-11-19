// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// GroupUsageReporter: helm's half of opt-in multicast and its billing
// (.kiro/specs/helm-control-plane/ Requirement 11, controller-interface
// Requirement 7, oar-net Requirement 10).
//
// Policy fan-out. The controller's signed GroupPolicy frames reach helm
// through the ControllerLink (ControllerSink::on_group_policy). helm keeps
// the newest frame per VNI and forwards it, unmodified, to every network
// role; a role registered later gets every kept frame before it is used
// (add_slot), so a NIC never sends under a missing policy. helm does not
// verify the signature: the role does, as for MapUpdate. Forwarding every
// VNI to every network role is simpler than tracking which VNIs a role
// hosts, and costs one small message per role per change.
//
// Usage. Every `interval`, and on the next poll() after nic_detached(),
// helm reads each network role's meters (OarLink group_usage, paged) and
// reports what changed since the last report as `group_usage` reports:
// every entry whose counters moved, and every detached NIC's final
// reading. Counters are cumulative per attachment, so the controller bills
// the difference between successive readings and a report lost before its
// ack is replayed by the ControllerSession, not re-read (Requirement
// 11.3). A role whose read fails keeps its final readings for the next
// read (oar::UsagePager), so nothing billable is dropped.
//
// Not thread-safe: one thread, like the router.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <tuple>
#include <vector>

#include "helm/command_router.hpp"
#include "proto/group_policy.hpp"
#include "proto/report.hpp"

namespace ak::helm {

struct GroupUsageConfig {
    using Clock = std::chrono::steady_clock;

    // Requirement 11.2 and controller-interface 7.5: at least every minute.
    std::chrono::milliseconds interval{std::chrono::minutes{1}};
    // Empty: steady_clock::now.
    std::function<Clock::time_point()> clock;
};

struct GroupUsageStats {
    std::uint64_t policies_kept{0};       // newer frames accepted
    std::uint64_t policies_stale{0};      // not newer than the kept frame: ignored
    std::uint64_t policies_forwarded{0};  // frame x role deliveries that succeeded
    std::uint64_t policy_forward_failures{0};
    std::uint64_t reads{0};  // role meter reads that succeeded
    std::uint64_t read_failures{0};
    std::uint64_t reports{0};  // group_usage reports sent
    std::uint64_t entries_reported{0};
};

class GroupUsageReporter {
public:
    using Clock = GroupUsageConfig::Clock;

    // `reports` must outlive the reporter.
    GroupUsageReporter(GroupUsageConfig config, ReportSink& reports);

    // A network role on `slot` is link-ready: it gets every kept policy now
    // and is read from the next poll on. `port` must outlive its slot.
    auto add_slot(std::uint8_t slot, OarPort& port) -> void;
    // The slot went away (power cycle): forgotten until added again.
    auto remove_slot(std::uint8_t slot) -> void;

    // A controller GroupPolicy (shape and server checked by the
    // ControllerSession) and its exact frame.
    auto on_group_policy(const proto::GroupPolicy& policy, std::span<const std::byte> frame)
        -> void;

    // A NIC was detached: read its final meter on the next poll rather than
    // waiting out the interval (Requirement 11.2).
    auto nic_detached() -> void { _read_now = true; }

    // Reads and reports when due. Call it at least as often as the interval.
    auto poll() -> void;

    [[nodiscard]] auto stats() const noexcept -> const GroupUsageStats& { return _stats; }

private:
    using Key = std::tuple<std::uint8_t, std::uint64_t, std::uint64_t>;  // slot, nic, attachment

    struct KeptPolicy {
        std::uint64_t version{0};
        std::vector<std::byte> frame;
    };

    [[nodiscard]] auto now() const -> Clock::time_point;
    auto forward(OarPort& port, std::span<const std::byte> frame) -> void;
    auto read_and_report() -> void;

    GroupUsageConfig _config;
    ReportSink* _reports;
    std::map<std::uint8_t, OarPort*> _slots;
    std::map<std::uint32_t, KeptPolicy> _policies;  // by VNI
    // The counters last reported for each live attachment.
    std::map<Key, proto::GroupUsageEntry> _reported;
    Clock::time_point _next_read{};
    bool _read_now{false};
    GroupUsageStats _stats;
};

}  // namespace ak::helm
