// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/flash.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>

namespace ak::helm {

namespace {

constexpr mode_t flash_file_mode = 0600;

[[nodiscard]] auto in_range(std::uint64_t offset, std::size_t len, std::uint64_t size) noexcept
    -> bool {
    return offset <= size && len <= size - offset;
}

}  // namespace

auto to_string(FlashError e) noexcept -> const char* {
    switch (e) {
        case FlashError::io:
            return "flash I/O error";
        case FlashError::out_of_range:
            return "flash access out of range";
        case FlashError::power_lost:
            return "power lost";
        case FlashError::wrong_size:
            return "flash file has the wrong size";
    }
    return "unknown";
}

auto MemoryFlash::read(std::uint64_t offset, std::span<std::byte> out)
    -> std::expected<void, FlashError> {
    if (!in_range(offset, out.size(), _bytes.size())) {
        return std::unexpected(FlashError::out_of_range);
    }
    const auto first = _bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    std::copy_n(first, out.size(), out.begin());
    return {};
}

auto MemoryFlash::write(std::uint64_t offset, std::span<const std::byte> data)
    -> std::expected<void, FlashError> {
    if (!in_range(offset, data.size(), _bytes.size())) {
        return std::unexpected(FlashError::out_of_range);
    }
    std::ranges::copy(data, _bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    return {};
}

auto FileFlash::open(const std::filesystem::path& path, std::uint64_t size)
    -> std::expected<std::unique_ptr<FileFlash>, FlashError> {
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, flash_file_mode);
    if (fd < 0) {
        return std::unexpected(FlashError::io);
    }
    auto flash = std::make_unique<FileFlash>(fd, size);
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        return std::unexpected(FlashError::io);
    }
    if (st.st_size == 0) {
        if (::ftruncate(fd, static_cast<off_t>(size)) != 0 || ::fsync(fd) != 0) {
            return std::unexpected(FlashError::io);
        }
    } else if (static_cast<std::uint64_t>(st.st_size) != size) {
        return std::unexpected(FlashError::wrong_size);
    }
    return flash;
}

FileFlash::~FileFlash() {
    if (_fd >= 0) {
        (void)::close(_fd);
    }
}

auto FileFlash::read(std::uint64_t offset, std::span<std::byte> out)
    -> std::expected<void, FlashError> {
    if (!in_range(offset, out.size(), _size)) {
        return std::unexpected(FlashError::out_of_range);
    }
    while (!out.empty()) {
        const auto n = ::pread(_fd, out.data(), out.size(), static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return std::unexpected(FlashError::io);
        }
        out = out.subspan(static_cast<std::size_t>(n));
        offset += static_cast<std::uint64_t>(n);
    }
    return {};
}

auto FileFlash::write(std::uint64_t offset, std::span<const std::byte> data)
    -> std::expected<void, FlashError> {
    if (!in_range(offset, data.size(), _size)) {
        return std::unexpected(FlashError::out_of_range);
    }
    while (!data.empty()) {
        const auto n = ::pwrite(_fd, data.data(), data.size(), static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return std::unexpected(FlashError::io);
        }
        data = data.subspan(static_cast<std::size_t>(n));
        offset += static_cast<std::uint64_t>(n);
    }
    return {};
}

auto FileFlash::sync() -> std::expected<void, FlashError> {
    if (::fdatasync(_fd) != 0) {
        return std::unexpected(FlashError::io);
    }
    return {};
}

auto FaultInjectingFlash::read(std::uint64_t offset, std::span<std::byte> out)
    -> std::expected<void, FlashError> {
    if (_cut) {
        return std::unexpected(FlashError::power_lost);
    }
    return _inner.read(offset, out);
}

auto FaultInjectingFlash::write(std::uint64_t offset, std::span<const std::byte> data)
    -> std::expected<void, FlashError> {
    if (_cut) {
        return std::unexpected(FlashError::power_lost);
    }
    if (_writes++ == _cut_at) {
        _cut = true;
        (void)_inner.write(offset, data.first(data.size() / 2));
        return std::unexpected(FlashError::power_lost);
    }
    return _inner.write(offset, data);
}

auto FaultInjectingFlash::sync() -> std::expected<void, FlashError> {
    if (_cut) {
        return std::unexpected(FlashError::power_lost);
    }
    return _inner.sync();
}

}  // namespace ak::helm
