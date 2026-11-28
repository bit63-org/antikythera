// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the standing set decoder (.kiro/specs/cold-start/ Requirement 8.3):
// an accepted frame must re-encode to identical bytes, and its signed
// bytes must be the frame less its trailing signature.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/standing_set.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto f = ak::proto::decode_standing_set(bytes);
    if (!f) {
        return 0;
    }
    auto again = ak::proto::encode_standing_set(*f);
    if (!again || !std::ranges::equal(*again, bytes) ||
        ak::proto::standing_set_signed_bytes(*again).size() !=
            bytes.size() - ak::proto::ed25519_signature_size) {
        std::abort();
    }
    return 0;
}
