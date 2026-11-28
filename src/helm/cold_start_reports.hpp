// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The cold-start reports helm sends the controller (.kiro/specs/cold-start/
// Requirement 8, task 9):
//
//   cold_start (kind 27) -- once per power return, from ak-helm's on_boot
//     after the power-on wait: when power came back by helm's RTC, the
//     time floor, how long helm held the host, where hull came from, the
//     store faults and rollback it found, and each standing start. It is
//     queued like any report, so it goes out on the first connection and
//     is resent until acknowledged.
//   boot_cache (kind 28) -- behind every inventory (ControllerSession's
//     BootCacheSource): the LKG and previous hull images, the standing
//     set's generation, the power-on policy version and the store's free
//     space, so the controller knows what this server can restart from on
//     its own.
//
// Until the boot cache (task 4) and standing set (task 6) exist, hull
// always comes from the boot layer (netboot), the image digests are zero
// and no standing starts are reported; the builders take those values as
// arguments so the later tasks only change what ak-helm passes in.

#include <chrono>
#include <cstdint>
#include <vector>

#include "helm/command_router.hpp"
#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "proto/report.hpp"

namespace ak::helm {

struct ColdStartFacts {
    std::int64_t power_return_time{0};  // helm's RTC when it started (Unix seconds)
    std::uint64_t time_floor{0};
    std::chrono::milliseconds waited{0};  // the power-on hold applied
    proto::BootSource boot_source{proto::BootSource::netboot};
    bool rtc_below_floor{false};  // the RTC read below the floor at start
    std::vector<proto::StandingStartResult> standing{};
};

// `store` may be null (no sealed store configured: no faults, no
// rollback). A negative RTC reads as 0, a wait beyond u32 milliseconds
// saturates, and standing starts are sorted by VM and cut to
// max_standing_instances, so the report always passes check_body.
[[nodiscard]] auto make_cold_start(const ColdStartFacts& facts, const SealedStore* store)
    -> proto::ColdStart;

// What hull's (or helm's own) answer to a standing start says about it:
// ok is started; a function the pool or hull does not have is a device
// missing; a volume helm or a storage role would not attach is a volume
// refused; a start hull would not take (signature, server, generation, a
// signed command already accepted) is refused; anything else failed.
[[nodiscard]] auto to_standing_result(mailbox::Status status) noexcept -> proto::StandingResult;
// The router's standing round results, as the cold_start report lists them.
[[nodiscard]] auto standing_results(const std::vector<StandingAttempt>& attempts)
    -> std::vector<proto::StandingStartResult>;

struct BootImages {
    proto::ImageDigest lkg{};       // all zero: none
    proto::ImageDigest previous{};  // all zero: none; never without an LKG
};

// `store` may be null (free and total space 0). The policy version is the
// kept record's, or 0 when helm runs on the defaults.
[[nodiscard]] auto make_boot_cache(const BootImages& images, std::uint64_t standing_generation,
                                   const PowerPolicyKeeper& policy, const SealedStore* store)
    -> proto::BootCache;

}  // namespace ak::helm
