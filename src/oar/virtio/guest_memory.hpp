// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Guest-physical memory as a virtio device sees it: the DMA regions its
// transport registered (vfio-user DMA map messages in harbor, the pci-epf
// window on hardware). Every guest address a virtqueue hands us is
// translated here and must lie entirely inside one region; anything else
// is the guest pointing us at memory it does not own
// (.kiro/specs/oar-net-data-plane/ Requirement 1.4,
// .kiro/specs/oar-blk-data-plane/ Requirement 6.1).
//
// A buffer that straddles two adjacent regions is refused rather than
// stitched together: guests allocate virtqueue buffers inside one RAM slot,
// and refusing keeps every translated buffer one contiguous span.
//
// Lifetime: translated spans alias the region memory. Removing a region
// invalidates them, so a transport must reset every queue that could hold
// such spans before it calls remove_region().

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace ak::oar::virtio {

using Gpa = std::uint64_t;  // guest-physical (or IOVA) address

enum class MemoryError : std::uint8_t {
    unmapped,   // some byte of [gpa, gpa + len) is in no region, or the range wraps
    overlap,    // add_region: the new region overlaps an existing one
    empty,      // add_region: zero-length region
    not_found,  // remove_region: no region starts at that address
};

[[nodiscard]] auto to_string(MemoryError e) noexcept -> const char*;

class GuestMemory {
public:
    // Registers [gpa, gpa + bytes.size()) backed by `bytes`.
    auto add_region(Gpa gpa, std::span<std::byte> bytes) -> std::expected<void, MemoryError>;
    auto remove_region(Gpa gpa) -> std::expected<void, MemoryError>;

    // Translates a guest range the device will only read.
    [[nodiscard]] auto readable(Gpa gpa, std::size_t len) const noexcept
        -> std::expected<std::span<const std::byte>, MemoryError>;
    // Translates a guest range the device will write.
    [[nodiscard]] auto writable(Gpa gpa, std::size_t len) const noexcept
        -> std::expected<std::span<std::byte>, MemoryError>;

    [[nodiscard]] auto region_count() const noexcept -> std::size_t { return _regions.size(); }

private:
    struct Region {
        Gpa gpa;
        std::span<std::byte> bytes;
    };
    std::vector<Region> _regions;  // sorted by gpa, non-overlapping
};

}  // namespace ak::oar::virtio
