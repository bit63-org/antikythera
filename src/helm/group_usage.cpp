// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/group_usage.hpp"

#include <algorithm>
#include <utility>

namespace ak::helm {

namespace {

auto to_report_entry(std::uint8_t slot, const oar::UsageEntry& e) -> proto::GroupUsageEntry {
    return {.slot = slot,
            .nic_id = e.nic_id,
            .vni = e.vni,
            .detached = e.detached,
            .attachment = e.attachment,
            .frames = e.frames,
            .bytes = e.bytes,
            .replicas_remote = e.replicas_remote,
            .replica_bytes_remote = e.replica_bytes_remote,
            .replicas_local = e.replicas_local,
            .replica_bytes_local = e.replica_bytes_local,
            .drop_policy = e.drop_policy,
            .drop_rate = e.drop_rate,
            .drop_fanout = e.drop_fanout};
}

// Equal counters: nothing new to bill or show.
auto same_counters(const proto::GroupUsageEntry& a, const proto::GroupUsageEntry& b) -> bool {
    auto x = a;
    x.detached = b.detached;
    return x == b;
}

}  // namespace

GroupUsageReporter::GroupUsageReporter(GroupUsageConfig config, ReportSink& reports)
    : _config{std::move(config)}, _reports{&reports} {}

auto GroupUsageReporter::now() const -> Clock::time_point {
    return _config.clock ? _config.clock() : Clock::now();
}

auto GroupUsageReporter::add_slot(std::uint8_t slot, OarPort& port) -> void {
    _slots.insert_or_assign(slot, &port);
    for (const auto& [vni, kept] : _policies) {
        forward(port, kept.frame);
    }
}

auto GroupUsageReporter::remove_slot(std::uint8_t slot) -> void {
    _slots.erase(slot);
    // Its attachments are gone with the role's state; a re-added role
    // starts new series.
    std::erase_if(_reported, [slot](const auto& kv) { return std::get<0>(kv.first) == slot; });
}

auto GroupUsageReporter::forward(OarPort& port, std::span<const std::byte> frame) -> void {
    if (port.group_policy(frame)) {
        ++_stats.policies_forwarded;
    } else {
        ++_stats.policy_forward_failures;
    }
}

auto GroupUsageReporter::on_group_policy(const proto::GroupPolicy& policy,
                                         std::span<const std::byte> frame) -> void {
    auto& kept = _policies[policy.vni];
    if (policy.policy_version <= kept.version) {
        ++_stats.policies_stale;
        return;
    }
    kept.version = policy.policy_version;
    kept.frame.assign(frame.begin(), frame.end());
    ++_stats.policies_kept;
    for (const auto& [slot, port] : _slots) {
        forward(*port, kept.frame);
    }
}

auto GroupUsageReporter::poll() -> void {
    const auto t = now();
    if (!_read_now && t < _next_read) {
        return;
    }
    _read_now = false;
    _next_read = t + _config.interval;
    read_and_report();
}

auto GroupUsageReporter::read_and_report() -> void {
    std::vector<proto::GroupUsageEntry> changed;
    for (const auto& [slot, port] : _slots) {
        auto usage = port->group_usage();
        if (!usage) {
            ++_stats.read_failures;
            continue;
        }
        ++_stats.reads;
        for (const auto& u : *usage) {
            auto entry = to_report_entry(slot, u);
            const Key key{slot, entry.nic_id, entry.attachment};
            const auto it = _reported.find(key);
            const bool moved = it == _reported.end() || !same_counters(it->second, entry);
            if (entry.detached) {
                // The series ends: always reported, then forgotten.
                if (it != _reported.end()) {
                    _reported.erase(it);
                }
                changed.push_back(entry);
            } else if (moved) {
                _reported.insert_or_assign(key, entry);
                changed.push_back(entry);
            }
        }
    }
    // (slot, nic_id, attachment) order, as the report requires; one role's
    // read is already in (nic_id, attachment) order and slots ascend.
    std::ranges::sort(changed, {}, [](const proto::GroupUsageEntry& e) {
        return std::tuple{e.slot, e.nic_id, e.attachment};
    });
    for (std::size_t at = 0; at < changed.size(); at += proto::max_group_usage_entries) {
        const auto end = std::min(changed.size(), at + proto::max_group_usage_entries);
        proto::GroupUsage body;
        body.entries.assign(changed.begin() + static_cast<std::ptrdiff_t>(at),
                            changed.begin() + static_cast<std::ptrdiff_t>(end));
        _stats.entries_reported += body.entries.size();
        ++_stats.reports;
        _reports->report(std::move(body));
    }
}

}  // namespace ak::helm
