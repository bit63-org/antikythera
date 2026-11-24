// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The local cache of image chunks (.kiro/specs/oar-blk-data-plane/
// Requirement 8.4, design "ChunkCache"): one sparse file per image, shared
// by every volume of that image in the role, under one byte budget for all
// images.
//
// Only chunks whose digest matched enter the cache (the fetcher checks
// before it inserts), and they hold exactly what the object store holds:
// a public image's plaintext or an encrypted image's ciphertext. Once in,
// a chunk is read back from local media without hashing it again: local
// media is trusted for integrity exactly as volume files are.
//
// Each image's file is an O_TMPFILE in the cache directory, never linked,
// so the cache vanishes with the role (it is not persisted across
// restarts). Eviction is least recently used at chunk granularity across
// all images and punches the chunk's hole in its file; a chunk being read
// is pinned and never evicted under the reader.
//
// Thread-safe: the fetcher's workers insert while the role thread reads.
// The ChunkCache must outlive every CachedImage it opened.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <list>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "objstore/image_manifest.hpp"

namespace ak::objstore {

class ChunkCache;

struct CacheCounters {
    std::uint64_t hits{0};
    std::uint64_t misses{0};
    std::uint64_t inserted{0};
    std::uint64_t evicted{0};
    std::uint64_t refused{0};  // inserts that did not fit next to pinned chunks
};

// One image as the role knows it: its name, manifest, data object key (for
// a chunked, version-2 image: its lineage's chunks prefix) and the chunks
// of it held locally.
class CachedImage {
public:
    CachedImage(const CachedImage&) = delete;
    auto operator=(const CachedImage&) -> CachedImage& = delete;
    CachedImage(CachedImage&&) = delete;
    auto operator=(CachedImage&&) -> CachedImage& = delete;
    ~CachedImage();

    [[nodiscard]] auto name() const noexcept -> const ImageDigest& { return _name; }
    [[nodiscard]] auto manifest() const noexcept -> const ImageManifest& { return _manifest; }
    [[nodiscard]] auto data_key() const noexcept -> const std::string& { return _data_key; }

    // Copies chunk bytes [offset, offset + out.size()) into `out` if the
    // chunk is resident; false on a miss (or if the local read failed,
    // which drops the chunk).
    [[nodiscard]] auto read(std::uint32_t chunk, std::uint64_t offset, std::span<std::byte> out)
        -> bool;
    // Stores a verified chunk (exactly chunk_length bytes). False if it
    // could not be stored: no room beside pinned chunks, or a write error.
    auto insert(std::uint32_t chunk, std::span<const std::byte> data) -> bool;
    [[nodiscard]] auto resident(std::uint32_t chunk) const -> bool;

private:
    friend class ChunkCache;

    enum class State : std::uint8_t {
        absent,
        filling,
        resident,
    };
    struct Chunk {
        State state{State::absent};
        std::uint32_t pins{0};
        std::list<std::pair<CachedImage*, std::uint32_t>>::iterator lru;
    };

    CachedImage(ChunkCache& cache, int fd, ImageDigest name, ImageManifest manifest,
                std::string data_key);

    ChunkCache* _cache;
    int _fd;
    ImageDigest _name;
    ImageManifest _manifest;
    std::string _data_key;
    std::vector<Chunk> _chunks;  // guarded by _cache->_mutex
};

class ChunkCache {
public:
    // `dir` must allow O_TMPFILE (ext4, xfs, btrfs, tmpfs). `budget_bytes`
    // bounds the chunks held for all images together.
    [[nodiscard]] static auto create(std::filesystem::path dir, std::uint64_t budget_bytes)
        -> std::expected<std::unique_ptr<ChunkCache>, int>;

    ChunkCache(const ChunkCache&) = delete;
    auto operator=(const ChunkCache&) -> ChunkCache& = delete;
    ChunkCache(ChunkCache&&) = delete;
    auto operator=(ChunkCache&&) -> ChunkCache& = delete;
    ~ChunkCache() = default;

    // The image with this name, opened once and shared while anyone holds
    // it. A second open of a live image returns the same object; the
    // manifest is the same since the name is its digest.
    [[nodiscard]] auto open_image(const ImageDigest& name, const ImageManifest& manifest,
                                  std::string data_key)
        -> std::expected<std::shared_ptr<CachedImage>, int>;

    [[nodiscard]] auto budget_bytes() const noexcept -> std::uint64_t { return _budget; }
    [[nodiscard]] auto used_bytes() const -> std::uint64_t;
    [[nodiscard]] auto counters() const -> CacheCounters;

private:
    friend class CachedImage;
    using Lru = std::list<std::pair<CachedImage*, std::uint32_t>>;

    ChunkCache(std::filesystem::path dir, std::uint64_t budget) noexcept
        : _dir{std::move(dir)}, _budget{budget} {}

    // Evicts unpinned resident chunks, oldest first, until `need` more
    // bytes fit. Caller holds _mutex.
    [[nodiscard]] auto make_room(std::uint64_t need) -> bool;
    auto drop(CachedImage& image, std::uint32_t chunk) -> void;  // caller holds _mutex
    auto forget(CachedImage& image) -> void;

    std::filesystem::path _dir;
    std::uint64_t _budget;
    mutable std::mutex _mutex;
    std::uint64_t _used{0};
    Lru _lru;  // front = most recently used
    CacheCounters _counters;
    std::unordered_map<std::string, std::weak_ptr<CachedImage>> _images;  // by hex name
};

}  // namespace ak::objstore
