// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the HTTP response head parser (.kiro/specs/oar-blk-data-plane/
// Requirement 8.11): object store responses are untrusted. An accepted
// head must lie inside the input and the first 16 KiB, and any range it
// reports must be well-ordered.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

#include "objstore/http_response.hpp"

namespace objstore = ak::objstore;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto raw = std::as_bytes(std::span{data, size});
    const auto head = objstore::parse_response_head(raw);
    if (head) {
        if (head->head_bytes > size || head->head_bytes > objstore::max_response_head ||
            head->status < 100 || head->status > 999) {
            std::abort();
        }
        if (head->content_range && (head->content_range->last < head->content_range->first ||
                                    (head->content_range->total &&
                                     *head->content_range->total <= head->content_range->last))) {
            std::abort();
        }
    }
    static_cast<void>(objstore::parse_content_range({reinterpret_cast<const char*>(data), size}));
    return 0;
}
