// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the mailbox slot decoder and every body decoder, and checks that an
// accepted slot, and an accepted body, re-encode to identical bytes. The
// same input also feeds the LIST_VMS and VM_STATUS payload decoders, which
// must round-trip too.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "helm/mailbox.hpp"

namespace mb = ak::helm::mailbox;

namespace {

auto fuzz_payloads(std::span<const std::byte> in) -> void {
    const auto payload = in.first(std::min(in.size(), mb::max_response_payload));
    if (auto st = mb::decode_vm_status_payload(payload)) {
        if (!std::ranges::equal(mb::encode_vm_status_payload(*st), payload)) {
            std::abort();
        }
    }
    if (auto list = mb::decode_vm_list_payload(payload)) {
        // The encoder writes total = the IDs it is given, so only a list
        // that was not cut re-encodes to the same bytes.
        if (list->vm_ids.size() == list->total &&
            !std::ranges::equal(mb::encode_vm_list_payload(list->vm_ids), payload)) {
            std::abort();
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    fuzz_payloads({reinterpret_cast<const std::byte*>(data), size});
    mb::Slot slot{};
    std::copy_n(reinterpret_cast<const std::byte*>(data), std::min(size, slot.size()),
                slot.begin());
    auto msg = mb::decode(slot);
    if (!msg) {
        return 0;
    }
    (void)mb::decode_create_vm(*msg);
    (void)mb::decode_destroy_vm(*msg);

    if (auto body = mb::decode_body(*msg)) {
        const auto bytes = mb::encode_body(*body);
        if (mb::type_of(*body) != msg->header.type ||
            !std::ranges::equal(bytes, msg->body_bytes())) {
            std::abort();
        }
    }

    auto again = mb::encode(msg->header, msg->body_bytes(), msg->signature);
    if (!again || *again != slot) {
        std::abort();
    }
    return 0;
}
