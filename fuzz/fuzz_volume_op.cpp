// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VolumeOp decoder: an accepted frame must re-encode to
// identical bytes, which also proves every args byte its kind does not use
// was zero.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/volume_op.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto op = ak::proto::decode_volume_op(bytes);
    if (!op) {
        return 0;
    }
    auto again = ak::proto::encode_volume_op(*op);
    if (!again || !std::ranges::equal(*again, bytes)) {
        std::abort();
    }
    return 0;
}
