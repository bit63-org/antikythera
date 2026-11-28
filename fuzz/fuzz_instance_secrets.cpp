// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the instance_secrets frame decoder (.kiro/specs/cold-start/
// Requirement 5.4), which the network role runs on what arrives over the
// sideband: an accepted frame must re-encode to identical bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "helm/oar_protocol.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto s = ak::helm::oar::decode_instance_secrets(bytes);
    if (!s) {
        return 0;
    }
    auto again = ak::helm::oar::encode_instance_secrets(*s);
    if (!again || !std::ranges::equal(*again, bytes)) {
        std::abort();
    }
    ak::helm::oar::wipe(*s);
    return 0;
}
