// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the mailbox slot decoder and every command-body decoder, and checks
// that an accepted slot re-encodes to identical bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "helm/mailbox.hpp"

namespace mb = ak::helm::mailbox;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    mb::Slot slot{};
    std::copy_n(reinterpret_cast<const std::byte*>(data), std::min(size, slot.size()), slot.begin());
    auto msg = mb::decode(slot);
    if (!msg) {
        return 0;
    }
    (void)mb::decode_create_vm(*msg);
    (void)mb::decode_destroy_vm(*msg);

    auto again = mb::encode(msg->header, msg->body_bytes(), msg->signature);
    if (!again || *again != slot) {
        std::abort();
    }
    return 0;
}
