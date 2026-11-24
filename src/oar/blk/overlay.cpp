// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/overlay.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>

#include <fcntl.h>
#include <unistd.h>

#include "objstore/file_io.hpp"

namespace ak::oar::blk {

namespace {
constexpr unsigned word_bits = 64;
constexpr std::uint64_t one = 1;
}  // namespace

auto to_string(OverlayError e) noexcept -> const char* {
    switch (e) {
        case OverlayError::full:
            return "full";
        case OverlayError::out_of_range:
            return "out_of_range";
        case OverlayError::io:
            return "io";
    }
    return "unknown";
}

Overlay::Overlay(int fd, std::uint64_t size, std::uint32_t block, std::uint64_t limit_blocks)
    : _fd{fd},
      _size{size},
      _block{block},
      _limit_blocks{limit_blocks},
      _bits(((size / block) + word_bits - 1) / word_bits) {}

Overlay::~Overlay() {
    ::close(_fd);
}

auto Overlay::create(const std::filesystem::path& dir, std::uint64_t size_bytes,
                     std::uint32_t logical_block_size, std::uint64_t limit_bytes)
    -> std::expected<std::unique_ptr<Overlay>, int> {
    if ((logical_block_size != 512 && logical_block_size != 4096) || size_bytes == 0 ||
        size_bytes % logical_block_size != 0 ||
        size_bytes > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        return std::unexpected(EINVAL);
    }
    const int fd = ::open(dir.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        return std::unexpected(errno);
    }
    if (::ftruncate(fd, static_cast<off_t>(size_bytes)) != 0) {
        const int err = errno;
        ::close(fd);
        return std::unexpected(err);
    }
    const std::uint64_t blocks = size_bytes / logical_block_size;
    const std::uint64_t limit = limit_bytes == 0 ? blocks : limit_bytes / logical_block_size;
    return std::unique_ptr<Overlay>(new Overlay(fd, size_bytes, logical_block_size, limit));
}

auto Overlay::written(std::uint64_t block) const noexcept -> bool {
    const std::uint64_t word = block / word_bits;
    return word < _bits.size() && (_bits[word] & (one << (block % word_bits))) != 0;
}

auto Overlay::check(std::uint64_t offset, std::size_t len) const noexcept -> bool {
    return len != 0 && offset % _block == 0 && len % _block == 0 && offset <= _size &&
           len <= _size - offset;
}

auto Overlay::read(std::uint64_t offset, std::span<std::byte> out) const
    -> std::expected<void, OverlayError> {
    if (!check(offset, out.size())) {
        return std::unexpected(OverlayError::out_of_range);
    }
    const auto got = objstore::file_io::pread_all(_fd, out, static_cast<off_t>(offset));
    if (!got || *got != out.size()) {
        return std::unexpected(OverlayError::io);
    }
    return {};
}

auto Overlay::write(std::uint64_t offset, std::span<const std::byte> in)
    -> std::expected<void, OverlayError> {
    if (!check(offset, in.size())) {
        return std::unexpected(OverlayError::out_of_range);
    }
    const std::uint64_t first = offset / _block;
    const std::uint64_t n = in.size() / _block;
    std::uint64_t fresh = 0;
    for (std::uint64_t b = first; b < first + n; ++b) {
        fresh += written(b) ? 0U : 1U;
    }
    if (_count + fresh > _limit_blocks) {
        return std::unexpected(OverlayError::full);
    }
    if (!objstore::file_io::pwrite_all(_fd, in, static_cast<off_t>(offset))) {
        return std::unexpected(OverlayError::io);
    }
    for (std::uint64_t b = first; b < first + n; ++b) {
        _bits[b / word_bits] |= one << (b % word_bits);
    }
    _count += fresh;
    return {};
}

auto Overlay::discard() -> void {
    std::ranges::fill(_bits, 0);
    _count = 0;
    // The blocks are unreadable without the dropped key either way; this
    // gives the space back.
    static_cast<void>(
        ::fallocate(_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, static_cast<off_t>(_size)));
}

}  // namespace ak::oar::blk
