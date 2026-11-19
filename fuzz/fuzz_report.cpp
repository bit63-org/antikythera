// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the report decoder: an accepted report must re-encode to
// identical bytes (the encoding is canonical).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/report.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto r = ak::proto::decode_report(bytes);
    if (!r) {
        return 0;
    }
    auto again = ak::proto::encode_report(*r);
    if (!again || !std::ranges::equal(*again, bytes)) {
        std::abort();
    }
    return 0;
}
