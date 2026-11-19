// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the controller envelope decoder and checks that an accepted
// envelope re-encodes to identical bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/envelope.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto env = ak::proto::decode_envelope(bytes);
    if (!env) {
        return 0;
    }
    auto again = ak::proto::encode_envelope(*env);
    if (!again || !std::ranges::equal(*again, bytes) ||
        ak::proto::slot_key_id(env->slot) != env->key_id ||
        ak::proto::slot_server_id(env->slot) != env->server_id) {
        std::abort();
    }
    return 0;
}
