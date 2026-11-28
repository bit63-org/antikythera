// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The standing set helm keeps (.kiro/specs/cold-start/ Requirements
// 4.1-4.3, 1.5; task 6). It is the controller's signed list of the pinned
// instances helm starts after power returns, with no controller.
//
// StandingSetKeeper verifies each standing_set record (link type 23) and
// keeps the newest in the sealed store. The generation it accepted is
// committed to the secure element's standing_generation counter
// (Requirement 4.2), so an older set is refused even when the store
// itself is restored from an older copy:
//
//   offer()  decodes strictly, needs this server, a generation above both
//            the counter and the set held, and a signature that verifies.
//            It then stores the frame and advances the counter, in that
//            order. If the counter cannot advance, the set is still kept
//            (it is verified and newer) and load() advances the counter
//            later.
//   load()   reads the stored set at start and verifies it again. A set
//            below the counter is a rolled-back copy and is discarded. So
//            is everything in a store that opened rolled back or degraded
//            (Requirement 1.5): helm then starts nothing on its own and
//            waits for the controller.
//
// An empty set (no instances) is kept like any other. It unpins every
// instance on the server (Requirement 4.3): there is nothing to start.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/standing_set.hpp"

namespace ak::helm {

inline constexpr std::string_view standing_set_object = "helm.standing-set";

enum class StandingVerdict : std::uint8_t {
    kept,               // verified, newer, stored, anchored
    none,               // load(): nothing stored, or the stored set was discarded
    stale,              // generation not above the anchored or held one
    wrong_server,       // names another server
    bad_signature,      // does not verify, or no verifier to check it
    corrupt,            // does not decode (load(): the stored frame)
    rolled_back,        // load(): stored below the anchored generation; discarded
    store_failed,       // could not be written (or read); the set held is unchanged
    anchor_failed,      // kept, but the counter did not advance (load() retries)
    anchor_unreadable,  // the counter cannot be read, so nothing can be checked
};

[[nodiscard]] auto to_string(StandingVerdict v) noexcept -> const char*;

class StandingSetKeeper {
public:
    // `store`, `anchor` and `verifier` may each be null: the set then lives
    // in memory only, its generation is checked against the set held only,
    // or every set is refused. None is owned.
    StandingSetKeeper(std::uint64_t server_id, SealedStore* store, StoreAnchor* anchor,
                      const RecordVerifier* verifier) noexcept;

    // Loads the stored set, if any. Call once at start.
    auto load() -> StandingVerdict;
    // A standing_set record's exact encoding, from the controller.
    auto offer(std::span<const std::byte> frame) -> StandingVerdict;

    // The set held, and its exact signed bytes (what hull verifies).
    [[nodiscard]] auto current() const noexcept -> const std::optional<proto::StandingSet>& {
        return _current;
    }
    [[nodiscard]] auto frame() const noexcept -> std::span<const std::byte> { return _frame; }
    // The newest generation accepted: the counter, or the set held if the
    // counter lags it (0 when there is neither).
    [[nodiscard]] auto generation() const noexcept -> std::uint64_t;
    // Instances to start after power returns: none without a set, and none
    // for an empty set.
    [[nodiscard]] auto pinned() const noexcept -> std::size_t {
        return _current ? _current->instances.size() : 0;
    }

private:
    [[nodiscard]] auto verified(const proto::StandingSet& s, std::span<const std::byte> frame) const
        -> bool;
    [[nodiscard]] auto anchored() -> std::optional<std::uint64_t>;
    auto anchor(std::uint64_t generation) -> bool;

    std::uint64_t _server_id;
    SealedStore* _store;
    StoreAnchor* _anchor;
    const RecordVerifier* _verifier;
    std::optional<proto::StandingSet> _current;
    std::vector<std::byte> _frame;
    std::uint64_t _anchored{0};  // the counter, as last read or advanced
};

}  // namespace ak::helm
