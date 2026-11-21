// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VolumeKey decoder: an accepted frame must re-encode to
// identical bytes, and its AAD must be the frame's header.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/volume_key.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto k = ak::proto::decode_volume_key(bytes);
    if (!k) {
        return 0;
    }
    auto again = ak::proto::encode_volume_key(*k);
    if (!again || !std::ranges::equal(*again, bytes) ||
        !std::ranges::equal(ak::proto::volume_key_aad(*again),
                            bytes.first(ak::proto::volume_key_aad_size))) {
        std::abort();
    }
    return 0;
}
