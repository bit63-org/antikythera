// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/chunk_cache.hpp"

#include <cerrno>

#include <fcntl.h>
#include <unistd.h>

#include "oar/blk/file_io.hpp"

namespace ak::oar::blk {

CachedImage::CachedImage(ChunkCache& cache, int fd, ImageDigest name, ImageManifest manifest,
                         std::string data_key)
    : _cache{&cache},
      _fd{fd},
      _name{name},
      _manifest{std::move(manifest)},
      _data_key{std::move(data_key)},
      _chunks(_manifest.chunk_count()) {}

CachedImage::~CachedImage() {
    _cache->forget(*this);
    ::close(_fd);
}

auto CachedImage::read(std::uint32_t chunk, std::uint64_t offset, std::span<std::byte> out)
    -> bool {
    if (chunk >= _chunks.size() || offset > _manifest.chunk_length(chunk) ||
        out.size() > _manifest.chunk_length(chunk) - offset) {
        return false;
    }
    {
        const std::scoped_lock lock{_cache->_mutex};
        Chunk& c = _chunks[chunk];
        if (c.state != State::resident) {
            ++_cache->_counters.misses;
            return false;
        }
        ++c.pins;
        _cache->_lru.splice(_cache->_lru.begin(), _cache->_lru, c.lru);
    }
    const auto at = static_cast<off_t>(_manifest.chunk_offset(chunk) + offset);
    const auto got = file_io::pread_all(_fd, out, at);
    const bool ok = got && *got == out.size();
    const std::scoped_lock lock{_cache->_mutex};
    Chunk& c = _chunks[chunk];
    --c.pins;
    if (!ok) {
        ++_cache->_counters.misses;
        if (c.pins == 0 && c.state == State::resident) {
            _cache->drop(*this, chunk);
        }
        return false;
    }
    ++_cache->_counters.hits;
    return true;
}

auto CachedImage::insert(std::uint32_t chunk, std::span<const std::byte> data) -> bool {
    if (chunk >= _chunks.size() || data.size() != _manifest.chunk_length(chunk)) {
        return false;
    }
    {
        const std::scoped_lock lock{_cache->_mutex};
        Chunk& c = _chunks[chunk];
        if (c.state != State::absent) {
            return c.state == State::resident;
        }
        if (!_cache->make_room(data.size())) {
            ++_cache->_counters.refused;
            return false;
        }
        c.state = State::filling;
        _cache->_used += data.size();
    }
    const auto at = static_cast<off_t>(_manifest.chunk_offset(chunk));
    const bool ok = file_io::pwrite_all(_fd, data, at).has_value();
    const std::scoped_lock lock{_cache->_mutex};
    Chunk& c = _chunks[chunk];
    if (!ok) {
        c.state = State::absent;
        _cache->_used -= data.size();
        return false;
    }
    c.state = State::resident;
    _cache->_lru.emplace_front(this, chunk);
    c.lru = _cache->_lru.begin();
    ++_cache->_counters.inserted;
    return true;
}

auto CachedImage::resident(std::uint32_t chunk) const -> bool {
    const std::scoped_lock lock{_cache->_mutex};
    return chunk < _chunks.size() && _chunks[chunk].state == State::resident;
}

auto ChunkCache::create(std::filesystem::path dir, std::uint64_t budget_bytes)
    -> std::expected<std::unique_ptr<ChunkCache>, int> {
    // Fail now, not on the first image, if the directory cannot hold an
    // O_TMPFILE.
    const int fd = ::open(dir.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        return std::unexpected(errno);
    }
    ::close(fd);
    return std::unique_ptr<ChunkCache>(new ChunkCache(std::move(dir), budget_bytes));
}

auto ChunkCache::open_image(const ImageDigest& name, const ImageManifest& manifest,
                            std::string data_key)
    -> std::expected<std::shared_ptr<CachedImage>, int> {
    const std::string hex = image_name_hex(name);
    const std::scoped_lock lock{_mutex};
    if (auto it = _images.find(hex); it != _images.end()) {
        if (auto live = it->second.lock()) {
            return live;
        }
    }
    const int fd = ::open(_dir.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        return std::unexpected(errno);
    }
    if (::ftruncate(fd, static_cast<off_t>(manifest.image_bytes)) != 0) {
        const int err = errno;
        ::close(fd);
        return std::unexpected(err);
    }
    std::shared_ptr<CachedImage> image{
        new CachedImage(*this, fd, name, manifest, std::move(data_key))};
    _images[hex] = image;
    return image;
}

auto ChunkCache::used_bytes() const -> std::uint64_t {
    const std::scoped_lock lock{_mutex};
    return _used;
}

auto ChunkCache::counters() const -> CacheCounters {
    const std::scoped_lock lock{_mutex};
    return _counters;
}

auto ChunkCache::make_room(std::uint64_t need) -> bool {
    if (need > _budget) {
        return false;
    }
    auto it = _lru.end();
    while (_used + need > _budget && it != _lru.begin()) {
        --it;
        auto [image, chunk] = *it;
        if (image->_chunks[chunk].pins != 0) {
            continue;
        }
        it = std::next(it);  // drop() erases the entry it pointed at
        drop(*image, chunk);
        ++_counters.evicted;
    }
    return _used + need <= _budget;
}

auto ChunkCache::drop(CachedImage& image, std::uint32_t chunk) -> void {
    CachedImage::Chunk& c = image._chunks[chunk];
    const std::uint64_t len = image._manifest.chunk_length(chunk);
    _lru.erase(c.lru);
    c.state = CachedImage::State::absent;
    _used -= len;
    // Give the space back; if punching fails the bytes linger in an
    // unlinked file, harmless and freed with it.
    static_cast<void>(::fallocate(image._fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                                  static_cast<off_t>(image._manifest.chunk_offset(chunk)),
                                  static_cast<off_t>(len)));
}

auto ChunkCache::forget(CachedImage& image) -> void {
    const std::scoped_lock lock{_mutex};
    for (std::uint32_t i = 0; i < image._chunks.size(); ++i) {
        if (image._chunks[i].state == CachedImage::State::resident) {
            _lru.erase(image._chunks[i].lru);
            _used -= image._manifest.chunk_length(i);
        }
    }
    // A new open of the same name may already have replaced the entry.
    const std::string hex = image_name_hex(image._name);
    if (auto it = _images.find(hex); it != _images.end() && it->second.expired()) {
        _images.erase(it);
    }
}

}  // namespace ak::oar::blk
