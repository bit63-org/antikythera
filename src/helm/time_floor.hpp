// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The time floor in helm (.kiro/specs/cold-start/ Requirement 7, task 8;
// kythira az-cold-start Requirement 10): the newest time, in Unix
// seconds, that the controller's clock is known to have passed.
//
// A server whose RTC battery died comes back in 1970; one with a bad RTC
// can come back anywhere. Certificates care: checked against a clock in
// 1970, an expired certificate looks valid until its notBefore. The
// bootstrap tier commits a time floor every ten minutes and the
// controller puts it in every power_policy and standing set; helm keeps
// the newest it has verified in its sealed store, so it survives power
// loss, and:
//
//   - does not treat its RTC as correct while it reads below the floor
//     (rtc_trusted(); Requirement 7.1); the cold-start report carries the
//     flag (task 9);
//   - checks certificates' notBefore and notAfter against
//     max(RTC, floor) (verification_time(); Requirement 7.2). helm has no
//     time source of its own, so this always applies; the floor only ever
//     moves a wrong clock forward, never a right one back.
//
// The floor only rises. Raising it in memory is always safe, so a floor
// that cannot be stored still applies until power is lost. A store that
// opened rolled back may hold an older floor; an older floor is still a
// true lower bound, so it is kept.
//
// floor() and verification_time() may be called from any thread (the
// controller link's TLS handshakes); observe() and load() from one.

#include <atomic>
#include <cstdint>
#include <expected>
#include <string_view>

#include "helm/sealed_store.hpp"

namespace ak::helm {

inline constexpr std::string_view time_floor_object = "helm.time-floor";

class TimeFloor {
public:
    // `store` may be null (the floor then lives in memory only); not owned.
    explicit TimeFloor(SealedStore* store) noexcept : _store{store} {}

    // Loads the stored floor. A stored value that is not 8 bytes is
    // ignored (counted as corrupt).
    auto load() -> std::expected<void, StoreError>;
    // A floor from a verified record. True if it raised the floor. If it
    // could not be stored, the raised floor still applies in memory and
    // store_failures() counts it.
    auto observe(std::uint64_t floor) -> bool;

    [[nodiscard]] auto floor() const noexcept -> std::uint64_t {
        return _floor.load(std::memory_order_acquire);
    }
    [[nodiscard]] auto rtc_trusted(std::int64_t rtc) const noexcept -> bool;
    [[nodiscard]] auto verification_time(std::int64_t rtc) const noexcept -> std::int64_t;
    // verification_time() of the system clock now.
    [[nodiscard]] auto verification_time_now() const noexcept -> std::int64_t;
    [[nodiscard]] static auto rtc_now() noexcept -> std::int64_t;

    [[nodiscard]] auto store_failures() const noexcept -> std::uint64_t { return _store_failures; }
    [[nodiscard]] auto corrupt() const noexcept -> bool { return _corrupt; }

private:
    SealedStore* _store;
    std::atomic<std::uint64_t> _floor{0};
    std::uint64_t _store_failures{0};
    bool _corrupt{false};
};

}  // namespace ak::helm
