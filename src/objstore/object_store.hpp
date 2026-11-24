// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The object store seam for image volumes (.kiro/specs/oar-blk-data-plane/
// Requirement 8.2, design "Components"): where images live. S3ObjectStore
// speaks S3 over HTTP (oar-blk task 11); tests use an in-memory store.
//
// Everything a store returns is untrusted: the caller checks manifests
// against the image name and chunks against the manifest. A store only has
// to return exactly the bytes asked for, or fail.
//
// Implementations must be safe to call from several threads at once: the
// fetcher's workers share one store.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ak::objstore {

enum class FetchError : std::uint8_t {
    not_found,     // no such object, or the range starts past its end
    denied,        // the store refused our credentials
    timed_out,     // the deadline passed
    bad_response,  // malformed, the wrong range, or the wrong length
    too_large,     // get(): the object is bigger than max_bytes
    io,            // connection or server failure
    corrupt,       // the bytes did not match their digest (fetcher)
    shut_down,     // the fetcher is stopping
};

[[nodiscard]] auto to_string(FetchError e) noexcept -> const char*;

// Whether retrying the same request could succeed.
[[nodiscard]] constexpr auto retryable(FetchError e) noexcept -> bool {
    return e == FetchError::io || e == FetchError::bad_response || e == FetchError::corrupt;
}

class ObjectStore {
public:
    using Clock = std::chrono::steady_clock;

    ObjectStore() = default;
    ObjectStore(const ObjectStore&) = delete;
    auto operator=(const ObjectStore&) -> ObjectStore& = delete;
    ObjectStore(ObjectStore&&) = delete;
    auto operator=(ObjectStore&&) -> ObjectStore& = delete;
    virtual ~ObjectStore() = default;

    // Fills `out` with object bytes [offset, offset + out.size()).
    [[nodiscard]] virtual auto get_range(std::string_view key, std::uint64_t offset,
                                         std::span<std::byte> out, Clock::time_point deadline)
        -> std::expected<void, FetchError> = 0;
    // The whole object, refusing one longer than max_bytes (manifests).
    [[nodiscard]] virtual auto get(std::string_view key, std::size_t max_bytes,
                                   Clock::time_point deadline)
        -> std::expected<std::vector<std::byte>, FetchError> = 0;
};

// Object keys of an image: <prefix>/<name>/manifest and <prefix>/<name>/data,
// the name in lowercase hex. An empty prefix leaves no leading slash.
[[nodiscard]] auto image_manifest_key(std::string_view prefix, std::string_view name_hex)
    -> std::string;
[[nodiscard]] auto image_data_key(std::string_view prefix, std::string_view name_hex)
    -> std::string;

// Object keys of a lineage's snapshots (manifest version 2,
// block-volume-service design "Format: image manifest version 2"):
//
//   <prefix>/lineage-<id>/chunks/<chunk digest>
//   <prefix>/lineage-<id>/snap-<manifest name>/manifest
//
// with the lineage ID as 16 lowercase hex digits and digests and names as
// 64. A chunked image's data key (CachedImage::data_key) is its lineage's
// chunks prefix, and each chunk is the whole object chunk_key names.
[[nodiscard]] auto lineage_chunks_prefix(std::string_view prefix, std::uint64_t lineage)
    -> std::string;
[[nodiscard]] auto chunk_key(std::string_view chunks_prefix, std::string_view digest_hex)
    -> std::string;
[[nodiscard]] auto snapshot_manifest_key(std::string_view prefix, std::uint64_t lineage,
                                         std::string_view name_hex) -> std::string;

}  // namespace ak::objstore
