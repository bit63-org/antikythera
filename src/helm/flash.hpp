// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The flash partition under helm's sealed store (.kiro/specs/cold-start/
// Requirement 1). helm boots from its own flash; the store lives in a
// partition of it. The store needs only byte-addressed reads and writes
// and a barrier that makes earlier writes durable, so that is the whole
// interface: the board's driver (an MTD partition on a BMC-class SoC) does
// wear levelling and erase below it.
//
// FileFlash backs a partition with a regular file (harbor, the QEMU
// cold-start run). MemoryFlash keeps it in memory for tests.
// FaultInjectingFlash cuts power at a chosen write: that write lands only
// partly, and every later call fails, as on a board that lost power with
// a write in flight. Bytes written but not yet synced are not lost by the
// cut (a stricter model would drop them); the store syncs before every
// commit point, so the cut points it is tested at are the ones that
// matter.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace ak::helm {

enum class FlashError : std::uint8_t {
    io,            // the device or file failed
    out_of_range,  // the access runs past the end of the partition
    power_lost,    // FaultInjectingFlash: power was cut
    wrong_size,    // FileFlash: an existing file is not the partition's size
};

[[nodiscard]] auto to_string(FlashError e) noexcept -> const char*;

class Flash {
public:
    Flash() = default;
    Flash(const Flash&) = delete;
    auto operator=(const Flash&) -> Flash& = delete;
    Flash(Flash&&) = delete;
    auto operator=(Flash&&) -> Flash& = delete;
    virtual ~Flash() = default;

    [[nodiscard]] virtual auto size() const noexcept -> std::uint64_t = 0;
    virtual auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, FlashError> = 0;
    virtual auto write(std::uint64_t offset, std::span<const std::byte> data)
        -> std::expected<void, FlashError> = 0;
    // Every earlier write is durable when this returns.
    virtual auto sync() -> std::expected<void, FlashError> = 0;
};

class MemoryFlash final : public Flash {
public:
    explicit MemoryFlash(std::uint64_t size) : _bytes(size) {}

    [[nodiscard]] auto size() const noexcept -> std::uint64_t override { return _bytes.size(); }
    auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, FlashError> override;
    auto write(std::uint64_t offset, std::span<const std::byte> data)
        -> std::expected<void, FlashError> override;
    auto sync() -> std::expected<void, FlashError> override { return {}; }

    // The raw partition, for tests that copy, corrupt or roll it back.
    [[nodiscard]] auto bytes() noexcept -> std::vector<std::byte>& { return _bytes; }

private:
    std::vector<std::byte> _bytes;
};

class FileFlash final : public Flash {
public:
    // Opens `path`, creating it (0600, `size` bytes of zeros, sparse) if it
    // does not exist. An existing file must be exactly `size` bytes.
    [[nodiscard]] static auto open(const std::filesystem::path& path, std::uint64_t size)
        -> std::expected<std::unique_ptr<FileFlash>, FlashError>;

    FileFlash(int fd, std::uint64_t size) noexcept : _fd{fd}, _size{size} {}
    FileFlash(const FileFlash&) = delete;
    auto operator=(const FileFlash&) -> FileFlash& = delete;
    FileFlash(FileFlash&&) = delete;
    auto operator=(FileFlash&&) -> FileFlash& = delete;
    ~FileFlash() override;

    [[nodiscard]] auto size() const noexcept -> std::uint64_t override { return _size; }
    auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, FlashError> override;
    auto write(std::uint64_t offset, std::span<const std::byte> data)
        -> std::expected<void, FlashError> override;
    auto sync() -> std::expected<void, FlashError> override;

private:
    int _fd;
    std::uint64_t _size;
};

// Passes calls to `inner` until the `cut_at`-th write (counting from 0):
// that write stores only its first half, and it and every later call
// return power_lost. cut_at = no_cut never cuts.
class FaultInjectingFlash final : public Flash {
public:
    static constexpr std::uint64_t no_cut = ~std::uint64_t{0};

    FaultInjectingFlash(Flash& inner, std::uint64_t cut_at) noexcept
        : _inner{inner}, _cut_at{cut_at} {}

    [[nodiscard]] auto size() const noexcept -> std::uint64_t override { return _inner.size(); }
    auto read(std::uint64_t offset, std::span<std::byte> out)
        -> std::expected<void, FlashError> override;
    auto write(std::uint64_t offset, std::span<const std::byte> data)
        -> std::expected<void, FlashError> override;
    auto sync() -> std::expected<void, FlashError> override;

    [[nodiscard]] auto writes() const noexcept -> std::uint64_t { return _writes; }
    [[nodiscard]] auto cut() const noexcept -> bool { return _cut; }

private:
    Flash& _inner;
    std::uint64_t _cut_at;
    std::uint64_t _writes{0};
    bool _cut{false};
};

}  // namespace ak::helm
