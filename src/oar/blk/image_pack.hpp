// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Packing a raw disk image into the two objects of an image volume
// (.kiro/specs/oar-blk-data-plane/ Requirement 8.8, task 12): the data
// object, the image as stored (ciphertext under the image key when
// encrypted), and the manifest that names it.
//
// The image is read one chunk at a time. A chunk of plaintext zeros is a
// hole: its digest is all zero and nothing is written for it, so the data
// object stays sparse (it is still image_bytes long, and a hole reads back
// as zeros). Every other chunk is encrypted with AES-256-XTS when an image
// key is given, data unit = logical block, tweak = block number, exactly as
// LazyImageBackend decrypts it, and its SHA-256 is taken over the bytes as
// stored.
//
// Packing is deterministic: the same image and options always give the
// same manifest, so the same name.

#include <cstdint>
#include <expected>
#include <optional>
#include <vector>

#include "objstore/image_manifest.hpp"
#include "oar/blk/xts_cipher.hpp"

namespace ak::oar::blk {

struct PackOptions {
    std::uint32_t logical_block_size{512};  // 512 or 4096
    std::uint8_t chunk_shift{objstore::default_chunk_shift};
    std::optional<XtsKey> image_key;  // encrypt under this key when set
    objstore::ImageKeyId key_id{};    // non-zero exactly when image_key is set
};

enum class PackError : std::uint8_t {
    bad_options,      // block size, chunk shift, or key and key ID not paired
    bad_image_size,   // zero, or not whole logical blocks
    too_many_chunks,  // more than 2^20 chunks: use a larger chunk shift
    read_failed,      // the image could not be read, or is shorter than its size
    write_failed,     // the data object could not be written
    crypto_failure,   // OpenSSL failed to encrypt or digest
};

[[nodiscard]] auto to_string(PackError e) noexcept -> const char*;

struct PackedImage {
    objstore::ImageManifest manifest;
    std::vector<std::byte> manifest_bytes;  // the manifest object
    objstore::ImageDigest name{};           // SHA-256 of manifest_bytes
    std::uint32_t stored_chunks{0};         // chunks that are not holes
};

// Reads image_bytes bytes of the image from `image_fd` (from offset 0, with
// pread) and writes the data object to `data_fd`, which must be empty: it
// is extended to image_bytes and only non-hole chunks are written.
[[nodiscard]] auto pack_image(int image_fd, std::uint64_t image_bytes, int data_fd,
                              const PackOptions& options) -> std::expected<PackedImage, PackError>;

}  // namespace ak::oar::blk
