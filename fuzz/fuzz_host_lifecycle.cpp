// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the host_power and decommission decoders
// (.kiro/specs/server-provisioning/ Requirement 7.1): an accepted frame
// must re-encode to identical bytes, its signed bytes must be the frame
// less its trailing signature, and no frame may decode as both.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/host_lifecycle.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace proto = ak::proto;
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto power = proto::decode_host_power(bytes);
    auto order = proto::decode_decommission(bytes);
    if (power && order) {
        std::abort();
    }
    if (power) {
        auto again = proto::encode_host_power(*power);
        if (!again || !std::ranges::equal(*again, bytes)) {
            std::abort();
        }
    }
    if (order) {
        auto again = proto::encode_decommission(*order);
        if (!again || !std::ranges::equal(*again, bytes)) {
            std::abort();
        }
    }
    if ((power || order) && proto::host_lifecycle_signed_bytes(bytes).size() !=
                                bytes.size() - proto::ed25519_signature_size) {
        std::abort();
    }
    return 0;
}
