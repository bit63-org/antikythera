// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes harbor's frame store request parser (.kiro/specs/
// fleet-scale-networking/ task 12): any client that holds a role
// certificate can send it bytes. An accepted request names exactly 64
// lowercase hex digits that appear in the input after "GET /v1/frames/".

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

#include "harbor/frame_store.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto raw = std::as_bytes(std::span{data, size});
    const auto digest = ak::harbor::parse_frame_request(raw);
    if (digest) {
        const std::string_view text{reinterpret_cast<const char*>(data), size};
        if (digest->size() != ak::harbor::frame_digest_hex_size ||
            !text.starts_with("GET /v1/frames/" + *digest + " HTTP/1.1\r\n")) {
            std::abort();
        }
        for (const char c : *digest) {
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                std::abort();
            }
        }
    }
    return 0;
}
