// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A volume backend that also takes hydrate writes
// (.kiro/specs/block-volume-service/ task 23): NetworkVolumeBackend, whose
// hold stores such a write only where blocks still await hydration.
// HydratingBackend (hydrating_backend.hpp) fills a foreign-key restore
// through it.

#include <cstddef>
#include <cstdint>
#include <span>

#include "oar/blk/virtio_blk_function.hpp"

namespace ak::oar::blk {

class HydrationTarget : public BlockBackend {
public:
    // Writes `in` at `offset` with the hold's hydrate flag: only blocks
    // still unhydrated are stored, so a block the guest wrote keeps its
    // data. Completes like submit_write.
    virtual auto submit_hydrate(std::uint64_t offset, std::span<const std::byte> in,
                                BackendCompletion done) -> void = 0;
};

}  // namespace ak::oar::blk
