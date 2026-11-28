// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/cold_start_reports.hpp"

#include <algorithm>
#include <limits>

#include "proto/standing_set.hpp"

namespace ak::helm {

auto make_cold_start(const ColdStartFacts& facts, const SealedStore* store) -> proto::ColdStart {
    proto::ColdStart c{};
    c.power_return_time =
        facts.power_return_time > 0 ? static_cast<std::uint64_t>(facts.power_return_time) : 0;
    c.time_floor = facts.time_floor;
    constexpr auto max_wait = std::numeric_limits<std::uint32_t>::max();
    const auto waited = std::max<std::chrono::milliseconds::rep>(facts.waited.count(), 0);
    c.waited_ms = waited > max_wait ? max_wait : static_cast<std::uint32_t>(waited);
    c.boot_source = facts.boot_source;
    if (facts.rtc_below_floor) {
        c.flags |= proto::cold_start_rtc_below_floor;
    }
    if (store != nullptr) {
        c.store_faults = store->faults();
        if (store->rolled_back()) {
            c.flags |= proto::cold_start_rollback;
        }
    }
    // One entry per VM, in VM order: a later result for the same VM is a
    // retry and replaces the earlier one.
    for (const auto& e : facts.standing) {
        if (e.vm_id == 0) {
            continue;
        }
        const auto at = std::ranges::find(c.standing, e.vm_id, &proto::StandingStartResult::vm_id);
        if (at != c.standing.end()) {
            *at = e;
        } else {
            c.standing.push_back(e);
        }
    }
    std::ranges::sort(c.standing, {}, &proto::StandingStartResult::vm_id);
    if (c.standing.size() > proto::max_standing_instances) {
        c.standing.resize(proto::max_standing_instances);
    }
    return c;
}

auto make_boot_cache(const BootImages& images, std::uint64_t standing_generation,
                     const PowerPolicyKeeper& policy, const SealedStore* store)
    -> proto::BootCache {
    proto::BootCache b{};
    b.lkg_image = images.lkg;
    // A previous image without an LKG cannot happen in a sound cache; the
    // report refuses it, so it is left out rather than dropping the report.
    if (std::ranges::any_of(images.lkg, [](std::byte x) { return x != std::byte{0}; })) {
        b.previous_image = images.previous;
    }
    b.standing_generation = standing_generation;
    b.policy_version = policy.from_record() ? policy.current().policy_version : 0;
    if (store != nullptr) {
        b.store_total_bytes = store->half_size();
        b.store_free_bytes = std::min(store->free_bytes(), b.store_total_bytes);
    }
    return b;
}

}  // namespace ak::helm
