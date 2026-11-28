// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the host image descriptor decoder
// (.kiro/specs/server-provisioning/ Requirement 4.1): an accepted frame
// must re-encode to identical bytes, and its signed bytes must be the
// frame less its trailing signature.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/host_image.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto f = ak::proto::decode_host_image(bytes);
    if (!f) {
        return 0;
    }
    auto again = ak::proto::encode_host_image(*f);
    if (!again || !std::ranges::equal(*again, bytes) ||
        ak::proto::host_image_signed_bytes(*again).size() !=
            bytes.size() - ak::proto::ed25519_signature_size) {
        std::abort();
    }
    return 0;
}
