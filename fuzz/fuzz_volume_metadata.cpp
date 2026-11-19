// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the volume metadata header decoder (harbor's file backend reads
// it back from disk, so it is untrusted input). Every header it accepts
// must satisfy the field rules and re-encode to exactly the same 4 KiB.
//
// Input: the header block. Short inputs are padded with zeros and long ones
// cut to 4 KiB, so the fuzzer can also reach the "valid header" region by
// starting from a seed made with encode_metadata.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/blk/file_backend.hpp"

namespace blk = ak::oar::blk;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // The exact size, as the backend reads it, and one other size.
    const auto raw = std::as_bytes(std::span{data, size});
    static_cast<void>(blk::decode_metadata(raw));

    std::array<std::byte, blk::metadata_block_size> block{};
    std::copy_n(raw.begin(), std::min(raw.size(), block.size()), block.begin());
    const auto m = blk::decode_metadata(block);
    if (!m) {
        return 0;
    }
    if (m->volume_id == 0 || m->owner_vm == 0 || m->capacity_sectors == 0 ||
        (m->logical_block_size != 512 && m->logical_block_size != 4096) ||
        m->capacity_sectors % (m->logical_block_size / blk::sector_size) != 0 ||
        m->wrapped_key.empty() || m->wrapped_key.size() > blk::max_wrapped_key_size) {
        std::abort();
    }
    const auto again = blk::encode_metadata(*m);
    if (!again || *again != block) {
        std::abort();
    }
    return 0;
}
