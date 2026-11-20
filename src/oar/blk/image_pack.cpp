// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/image_pack.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <sys/types.h>
#include <unistd.h>

#include "oar/blk/file_io.hpp"
#include "oar/blk/image_manifest.hpp"
#include "oar/blk/xts_cipher.hpp"

namespace ak::oar::blk {

auto to_string(PackError e) noexcept -> const char* {
    switch (e) {
        case PackError::bad_options:
            return "bad_options";
        case PackError::bad_image_size:
            return "bad_image_size";
        case PackError::too_many_chunks:
            return "too_many_chunks";
        case PackError::read_failed:
            return "read_failed";
        case PackError::write_failed:
            return "write_failed";
        case PackError::crypto_failure:
            return "crypto_failure";
    }
    return "unknown";
}

namespace {

auto all_zero(std::span<const std::byte> bytes) -> bool {
    return std::ranges::all_of(bytes, [](std::byte b) { return b == std::byte{0}; });
}

auto check_options(std::uint64_t image_bytes, const PackOptions& o)
    -> std::expected<std::uint32_t, PackError> {
    if (o.logical_block_size != data_unit_512 && o.logical_block_size != data_unit_4k) {
        return std::unexpected(PackError::bad_options);
    }
    if (o.chunk_shift < min_chunk_shift || o.chunk_shift > max_chunk_shift) {
        return std::unexpected(PackError::bad_options);
    }
    if (o.image_key.has_value() == all_zero(o.key_id)) {
        return std::unexpected(PackError::bad_options);
    }
    if (image_bytes == 0 || image_bytes % o.logical_block_size != 0) {
        return std::unexpected(PackError::bad_image_size);
    }
    const std::uint64_t chunk = std::uint64_t{1} << o.chunk_shift;
    const std::uint64_t count = (image_bytes + chunk - 1) / chunk;
    if (count > max_image_chunks) {
        return std::unexpected(PackError::too_many_chunks);
    }
    return static_cast<std::uint32_t>(count);
}

}  // namespace

auto pack_image(int image_fd, std::uint64_t image_bytes, int data_fd, const PackOptions& options)
    -> std::expected<PackedImage, PackError> {
    const auto count = check_options(image_bytes, options);
    if (!count) {
        return std::unexpected(count.error());
    }
    std::optional<XtsCipher> cipher;
    if (options.image_key) {
        auto c = XtsCipher::create(*options.image_key, options.logical_block_size);
        if (!c) {
            return std::unexpected(PackError::crypto_failure);
        }
        cipher.emplace(std::move(*c));
    }
    if (::ftruncate(data_fd, static_cast<off_t>(image_bytes)) != 0) {
        return std::unexpected(PackError::write_failed);
    }

    PackedImage out;
    auto& m = out.manifest;
    m.encrypted = cipher.has_value();
    m.logical_block_size = options.logical_block_size;
    m.chunk_shift = options.chunk_shift;
    m.image_bytes = image_bytes;
    m.key_id = options.key_id;
    m.chunks.resize(*count);

    std::vector<std::byte> buf(m.chunk_size());
    for (std::uint32_t c = 0; c < *count; ++c) {
        const auto at = static_cast<off_t>(m.chunk_offset(c));
        const auto piece = std::span{buf}.first(m.chunk_length(c));
        const auto got = file_io::pread_all(image_fd, piece, at);
        if (!got || *got != piece.size()) {
            return std::unexpected(PackError::read_failed);
        }
        if (all_zero(piece)) {
            continue;  // a hole: zero digest, nothing stored
        }
        if (cipher &&
            !cipher->encrypt(static_cast<std::uint64_t>(at) / m.logical_block_size, piece, piece)) {
            return std::unexpected(PackError::crypto_failure);
        }
        auto digest = sha256_digest(piece);
        if (!digest) {
            return std::unexpected(PackError::crypto_failure);
        }
        m.chunks[c] = *digest;
        if (!file_io::pwrite_all(data_fd, piece, at)) {
            return std::unexpected(PackError::write_failed);
        }
        ++out.stored_chunks;
    }

    auto bytes = encode_manifest(m);
    if (!bytes) {
        return std::unexpected(PackError::bad_options);
    }
    auto name = sha256_digest(*bytes);
    if (!name) {
        return std::unexpected(PackError::crypto_failure);
    }
    out.manifest_bytes = std::move(*bytes);
    out.name = *name;
    return out;
}

}  // namespace ak::oar::blk
