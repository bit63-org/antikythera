// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/sequence_tracker.hpp"

namespace ak::hull {

auto to_string(SequenceError e) noexcept -> const char* {
    switch (e) {
        case SequenceError::replayed:
            return "replayed";
    }
    return "unknown";
}

auto SequenceTracker::accept(std::uint64_t seq) noexcept -> std::expected<void, SequenceError> {
    if (seq <= _last_accepted) {
        return std::unexpected(SequenceError::replayed);
    }
    _last_accepted = seq;
    return {};
}

}  // namespace ak::hull
