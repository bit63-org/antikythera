// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "objstore/object_store.hpp"

#include <format>

namespace ak::objstore {

auto to_string(FetchError e) noexcept -> const char* {
    switch (e) {
        case FetchError::not_found:
            return "not_found";
        case FetchError::denied:
            return "denied";
        case FetchError::timed_out:
            return "timed_out";
        case FetchError::bad_response:
            return "bad_response";
        case FetchError::too_large:
            return "too_large";
        case FetchError::io:
            return "io";
        case FetchError::corrupt:
            return "corrupt";
        case FetchError::shut_down:
            return "shut_down";
    }
    return "unknown";
}

namespace {
auto image_key(std::string_view prefix, std::string_view name_hex, std::string_view leaf)
    -> std::string {
    std::string key;
    key.reserve(prefix.size() + name_hex.size() + leaf.size() + 2);
    if (!prefix.empty()) {
        key.append(prefix);
        if (prefix.back() != '/') {
            key.push_back('/');
        }
    }
    key.append(name_hex);
    key.push_back('/');
    key.append(leaf);
    return key;
}
}  // namespace

auto image_manifest_key(std::string_view prefix, std::string_view name_hex) -> std::string {
    return image_key(prefix, name_hex, "manifest");
}

auto image_data_key(std::string_view prefix, std::string_view name_hex) -> std::string {
    return image_key(prefix, name_hex, "data");
}

auto lineage_chunks_prefix(std::string_view prefix, std::uint64_t lineage) -> std::string {
    return image_key(prefix, std::format("lineage-{:016x}", lineage), "chunks");
}

auto chunk_key(std::string_view chunks_prefix, std::string_view digest_hex) -> std::string {
    std::string key{chunks_prefix};
    key.push_back('/');
    key.append(digest_hex);
    return key;
}

auto snapshot_manifest_key(std::string_view prefix, std::uint64_t lineage,
                           std::string_view name_hex) -> std::string {
    const auto snap = std::format("lineage-{:016x}/snap-{}", lineage, name_hex);
    return image_key(prefix, snap, "manifest");
}

}  // namespace ak::objstore
