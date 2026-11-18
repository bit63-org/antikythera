// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/virtio/guest_memory.hpp"

#include <algorithm>
#include <limits>

namespace ak::oar::virtio {

auto to_string(MemoryError e) noexcept -> const char* {
    switch (e) {
        case MemoryError::unmapped:
            return "unmapped";
        case MemoryError::overlap:
            return "overlap";
        case MemoryError::empty:
            return "empty";
        case MemoryError::not_found:
            return "not_found";
    }
    return "unknown";
}

auto GuestMemory::add_region(Gpa gpa, std::span<std::byte> bytes)
    -> std::expected<void, MemoryError> {
    if (bytes.empty()) {
        return std::unexpected(MemoryError::empty);
    }
    // Last byte, not one past it, so a region ending at the top of the
    // address space is representable.
    if (bytes.size() - 1 > std::numeric_limits<Gpa>::max() - gpa) {
        return std::unexpected(MemoryError::unmapped);
    }
    const Gpa last = gpa + (bytes.size() - 1);
    auto pos = std::ranges::lower_bound(_regions, gpa, {}, &Region::gpa);
    if (pos != _regions.end() && pos->gpa <= last) {
        return std::unexpected(MemoryError::overlap);
    }
    if (pos != _regions.begin()) {
        const auto& prev = *std::prev(pos);
        if (prev.gpa + (prev.bytes.size() - 1) >= gpa) {
            return std::unexpected(MemoryError::overlap);
        }
    }
    _regions.insert(pos, Region{gpa, bytes});
    return {};
}

auto GuestMemory::remove_region(Gpa gpa) -> std::expected<void, MemoryError> {
    auto pos = std::ranges::lower_bound(_regions, gpa, {}, &Region::gpa);
    if (pos == _regions.end() || pos->gpa != gpa) {
        return std::unexpected(MemoryError::not_found);
    }
    _regions.erase(pos);
    return {};
}

auto GuestMemory::writable(Gpa gpa, std::size_t len) const noexcept
    -> std::expected<std::span<std::byte>, MemoryError> {
    // The region containing gpa is the last one starting at or below it.
    auto pos = std::ranges::upper_bound(_regions, gpa, {}, &Region::gpa);
    if (pos == _regions.begin()) {
        return std::unexpected(MemoryError::unmapped);
    }
    const auto& region = *std::prev(pos);
    const Gpa offset = gpa - region.gpa;
    if (offset > region.bytes.size() || len > region.bytes.size() - offset) {
        return std::unexpected(MemoryError::unmapped);
    }
    return region.bytes.subspan(offset, len);
}

auto GuestMemory::readable(Gpa gpa, std::size_t len) const noexcept
    -> std::expected<std::span<const std::byte>, MemoryError> {
    return writable(gpa, len).transform(
        [](std::span<std::byte> s) { return std::span<const std::byte>{s}; });
}

}  // namespace ak::oar::virtio
