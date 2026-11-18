// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Shared test constants (.kiro/steering/test-execution-standards.md).

#include <cstddef>
#include <vector>

namespace ak::test {

// Per-test-case timeout for pure unit tests, in seconds. The steering
// standard gives 10-30 s for unit tests; these run in milliseconds.
inline constexpr unsigned unit_timeout_seconds = 30;

// Builds a byte vector from integer literals, for hand-written wire images.
template<typename... B> auto bytes_of(B... b) -> std::vector<std::byte> {
    return {static_cast<std::byte>(b)...};
}

}  // namespace ak::test
