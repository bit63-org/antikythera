// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Replay protection for mailbox commands
// (.kiro/specs/hull-host-agent/ Requirement 4.3): every accepted command's
// sequence number must be strictly greater than the last accepted one. Gaps
// are allowed, because the controller numbers commands per server and some
// may never reach the mailbox (a dropped controller link, a helm restart).
//
// Only call accept() for a command whose signature has verified; otherwise
// a forged command could burn sequence numbers and lock out the controller.

#include <cstdint>
#include <expected>

namespace ak::hull {

enum class SequenceError : std::uint8_t {
    replayed,  // seq <= the last accepted sequence number
};

[[nodiscard]] auto to_string(SequenceError e) noexcept -> const char*;

class SequenceTracker {
public:
    // `last_accepted` is the floor: only sequence numbers above it are
    // accepted. 0 (the default) accepts any first command, since valid
    // sequence numbers start at 1.
    explicit SequenceTracker(std::uint64_t last_accepted = 0) noexcept
        : _last_accepted{last_accepted} {}

    // Accepts `seq` and raises the floor to it, or rejects it unchanged.
    [[nodiscard]] auto accept(std::uint64_t seq) noexcept -> std::expected<void, SequenceError>;

    [[nodiscard]] auto last_accepted() const noexcept -> std::uint64_t { return _last_accepted; }

private:
    std::uint64_t _last_accepted;
};

}  // namespace ak::hull
