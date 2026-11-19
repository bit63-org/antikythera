// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An image volume's writes for one attachment (.kiro/specs/oar-blk-data-plane/
// Requirements 8.6 and 8.7, design "Overlay"): a sparse O_TMPFILE the size
// of the volume, never linked into the directory, so closing it or a crash
// frees it, plus a bitmap of the logical blocks written so far.
//
// The overlay stores what VirtioBlkFunction hands the backend, which is
// already ciphertext under the attachment's ephemeral key. A write lands in
// the file before its bits are set, so a failed write never makes a block
// read back as written. discard() forgets every block and punches the file
// empty: the backend calls it when the key is dropped.
//
// Not thread-safe: the role thread owns it.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace ak::oar::blk {

enum class OverlayError : std::uint8_t {
    full,          // the write would pass the overlay's limit
    out_of_range,  // past the volume, or not whole logical blocks
    io,            // a system call failed
};

[[nodiscard]] auto to_string(OverlayError e) noexcept -> const char*;

class Overlay {
public:
    // `size_bytes` whole logical blocks; `limit_bytes` caps the blocks that
    // may be written (0: no cap beyond the volume size).
    [[nodiscard]] static auto create(const std::filesystem::path& dir, std::uint64_t size_bytes,
                                     std::uint32_t logical_block_size, std::uint64_t limit_bytes)
        -> std::expected<std::unique_ptr<Overlay>, int>;

    Overlay(const Overlay&) = delete;
    auto operator=(const Overlay&) -> Overlay& = delete;
    Overlay(Overlay&&) = delete;
    auto operator=(Overlay&&) -> Overlay& = delete;
    ~Overlay();

    [[nodiscard]] auto written(std::uint64_t block) const noexcept -> bool;
    [[nodiscard]] auto written_blocks() const noexcept -> std::uint64_t { return _count; }
    [[nodiscard]] auto block_size() const noexcept -> std::uint32_t { return _block; }

    // Reads bytes the caller knows are written (whole blocks).
    [[nodiscard]] auto read(std::uint64_t offset, std::span<std::byte> out) const
        -> std::expected<void, OverlayError>;
    [[nodiscard]] auto write(std::uint64_t offset, std::span<const std::byte> in)
        -> std::expected<void, OverlayError>;
    // Forgets every written block and frees their space.
    auto discard() -> void;

private:
    Overlay(int fd, std::uint64_t size, std::uint32_t block, std::uint64_t limit_blocks);

    [[nodiscard]] auto check(std::uint64_t offset, std::size_t len) const noexcept -> bool;

    int _fd;
    std::uint64_t _size;
    std::uint32_t _block;
    std::uint64_t _limit_blocks;
    std::uint64_t _count{0};
    std::vector<std::uint64_t> _bits;
};

}  // namespace ak::oar::blk
