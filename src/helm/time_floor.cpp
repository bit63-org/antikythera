// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/time_floor.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <vector>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

// Floors beyond this are clamped when compared with a signed clock.
constexpr auto max_seconds = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

auto as_seconds(std::uint64_t floor) noexcept -> std::int64_t {
    return static_cast<std::int64_t>(std::min(floor, max_seconds));
}

}  // namespace

auto TimeFloor::load() -> std::expected<void, StoreError> {
    if (_store == nullptr) {
        return {};
    }
    const auto data = _store->get(time_floor_object);
    if (!data) {
        return std::unexpected(data.error());
    }
    if (!*data) {
        return {};
    }
    if ((*data)->size() != sizeof(std::uint64_t)) {
        _corrupt = true;
        return {};
    }
    wire::Reader r{**data};
    const auto stored = r.le64().value_or(0);
    if (stored > floor()) {
        _floor.store(stored, std::memory_order_release);
    }
    return {};
}

auto TimeFloor::observe(std::uint64_t floor_s) -> bool {
    if (floor_s <= floor()) {
        return false;
    }
    _floor.store(floor_s, std::memory_order_release);
    if (_store != nullptr) {
        std::vector<std::byte> bytes;
        wire::Writer w{bytes};
        w.le64(floor_s);
        if (!_store->put(time_floor_object, bytes)) {
            ++_store_failures;
        }
    }
    return true;
}

auto TimeFloor::rtc_trusted(std::int64_t rtc) const noexcept -> bool {
    return rtc >= as_seconds(floor());
}

auto TimeFloor::verification_time(std::int64_t rtc) const noexcept -> std::int64_t {
    return std::max(rtc, as_seconds(floor()));
}

auto TimeFloor::rtc_now() noexcept -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

auto TimeFloor::verification_time_now() const noexcept -> std::int64_t {
    return verification_time(rtc_now());
}

}  // namespace ak::helm
