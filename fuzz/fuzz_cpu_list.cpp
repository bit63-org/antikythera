// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes parse_cpu_list(): it must never crash, and every list it accepts
// must be strictly ascending, within max_cpu_id, and survive a round trip
// through format_cpu_list().

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "hull/cpu_topology.hpp"

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    const auto cpus = ak::hull::parse_cpu_list(text);
    if (!cpus) {
        return 0;
    }
    for (std::size_t i = 0; i < cpus->size(); ++i) {
        if ((*cpus)[i] > ak::hull::max_cpu_id || (i > 0 && (*cpus)[i] <= (*cpus)[i - 1])) {
            std::abort();
        }
    }
    const auto text_out = ak::hull::format_cpu_list(*cpus);
    if (!text_out || ak::hull::parse_cpu_list(*text_out) != cpus) {
        std::abort();
    }
    return 0;
}
