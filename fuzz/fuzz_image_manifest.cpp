// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the image manifest decoder (.kiro/specs/oar-blk-data-plane/
// Requirement 8.11): manifests come from the object store, so they are
// untrusted input. Every manifest it accepts must satisfy the field rules
// and re-encode to exactly the input bytes.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "objstore/image_manifest.hpp"

namespace objstore = ak::objstore;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto raw = std::as_bytes(std::span{data, size});
    const auto m = objstore::decode_manifest(raw);
    if (!m) {
        return 0;
    }
    if ((m->logical_block_size != 512 && m->logical_block_size != 4096) ||
        m->chunk_shift < objstore::min_chunk_shift || m->chunk_shift > objstore::max_chunk_shift ||
        m->image_bytes == 0 || m->image_bytes % m->logical_block_size != 0 || m->chunks.empty() ||
        m->chunks.size() > objstore::max_image_chunks ||
        m->chunk_offset(m->chunk_count() - 1) >= m->image_bytes ||
        m->chunk_offset(m->chunk_count() - 1) + m->chunk_size() < m->image_bytes) {
        std::abort();
    }
    const auto again = objstore::encode_manifest(*m);
    if (!again || again->size() != raw.size() ||
        !std::equal(again->begin(), again->end(), raw.begin())) {
        std::abort();
    }
    return 0;
}
