// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the boot_image assignment decoder (.kiro/specs/cold-start/
// Requirement 2.1): an accepted frame must re-encode to identical bytes,
// its signed bytes must be the frame less its trailing signature, and its
// embedded descriptor must decode on its own.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/boot_image.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto f = ak::proto::decode_boot_image(bytes);
    if (!f) {
        return 0;
    }
    auto again = ak::proto::encode_boot_image(*f);
    if (!again || !std::ranges::equal(*again, bytes) ||
        ak::proto::boot_image_signed_bytes(*again).size() !=
            bytes.size() - ak::proto::ed25519_signature_size ||
        !ak::proto::decode_host_image(ak::proto::boot_image_descriptor(bytes)).has_value()) {
        std::abort();
    }
    return 0;
}
