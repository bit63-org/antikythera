// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The manifest of an image in object storage (.kiro/specs/oar-blk-data-plane/
// Requirement 8, design "Image format"): what an image volume's base layer
// is made of, and the SHA-256 of every chunk so each fetched chunk can be
// checked before any of it reaches a guest. Version 2 (.kiro/specs/
// block-volume-service/ design "Format: image manifest version 2", task 20)
// is the snapshot format: every chunk is its own object, named by its
// digest, so the snapshots of one lineage share unchanged chunks.
//
// An image is named by the SHA-256 of its manifest bytes. The attach request
// carries that name, so the object store cannot substitute a manifest, and
// the manifest in turn pins every chunk: the whole image is content
// addressed.
//
// Layout (little-endian):
//
//   0   8   magic "AKIMAGE\0"
//   8   2   version (1 or 2)
//   10  2   flags: bit 0 encrypted (AES-256-XTS), bit 1 chunked; others zero
//   12  4   logical block size: 512 or 4096
//   16  1   chunk shift: 16..22 (64 KiB to 4 MiB)
//   17  7   zero
//   24  8   image bytes: non-zero, whole logical blocks
//   32  4   chunk count: ceil(image bytes / chunk size), 1..2^20
//   36  4   zero
//   40  16  image key ID: non-zero exactly when encrypted
//   version 1:
//   56  32 × chunk count: SHA-256 of each chunk as stored; all zero = hole
//   version 2:
//   56  8   lineage ID: non-zero
//   64  32  parent: the parent snapshot's manifest name, all zero for none
//   96  32 × chunk count: as in version 1
//
// Version 1 keeps the image in one `data` object read with ranged GETs.
// Version 2 is chunked: each chunk is the object named by its digest under
// the lineage's chunks prefix (object_store.hpp). The chunked flag is set
// exactly in version 2, and a version-2 manifest is always encrypted:
// snapshot chunks are the volume's ciphertext under the lineage key, with
// the LBA as tweak, so a chunk is valid in place in any volume of the
// lineage and deduplication never crosses a key. The logical block size is
// the volume's.
//
// The last chunk may be short. A hole is a chunk of plaintext zeros that is
// never stored, fetched or cached, in an encrypted image too (which reveals
// which chunks are empty, as a sparse file would); in a snapshot it is a
// chunk the volume never wrote. The manifest is exactly the header (56 or
// 96 bytes) + 32 × count bytes. It comes from the object store, so it is
// untrusted input: decoded with ak::wire, every field checked
// (fuzz/fuzz_image_manifest.cpp).

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ak::objstore {

inline constexpr std::size_t image_digest_size = 32;  // SHA-256
using ImageDigest = std::array<std::byte, image_digest_size>;
using ImageKeyId = std::array<std::byte, 16>;

inline constexpr std::uint16_t manifest_version = 1;
inline constexpr std::uint16_t manifest_version_chunked = 2;
inline constexpr std::size_t manifest_header_size = 56;          // version 1
inline constexpr std::size_t manifest_header_size_chunked = 96;  // version 2
inline constexpr std::uint8_t min_chunk_shift = 16;              // 64 KiB
inline constexpr std::uint8_t max_chunk_shift = 22;              // 4 MiB
inline constexpr std::uint8_t default_chunk_shift = 20;          // 1 MiB
inline constexpr std::uint32_t max_image_chunks = 1U << 20U;
inline constexpr std::uint16_t manifest_flag_encrypted = 1U << 0U;
inline constexpr std::uint16_t manifest_flag_chunked = 1U << 1U;

struct ImageManifest {
    bool encrypted{false};
    std::uint32_t logical_block_size{512};  // 512 or 4096; the XTS data unit when encrypted
    std::uint8_t chunk_shift{default_chunk_shift};
    std::uint64_t image_bytes{0};
    ImageKeyId key_id{};              // which image key, when encrypted
    std::vector<ImageDigest> chunks;  // per chunk; all zero bytes = hole
    // Version 2 (snapshots): one object per chunk, in the lineage's chunk
    // prefix. Both fields below are zero unless chunked.
    bool chunked{false};
    std::uint64_t lineage_id{0};  // non-zero when chunked
    ImageDigest parent{};         // the parent snapshot's name, or zero

    [[nodiscard]] auto version() const noexcept -> std::uint16_t {
        return chunked ? manifest_version_chunked : manifest_version;
    }
    [[nodiscard]] auto header_size() const noexcept -> std::size_t {
        return chunked ? manifest_header_size_chunked : manifest_header_size;
    }
    [[nodiscard]] auto has_parent() const noexcept -> bool;

    [[nodiscard]] auto chunk_size() const noexcept -> std::uint64_t {
        return std::uint64_t{1} << chunk_shift;
    }
    [[nodiscard]] auto chunk_count() const noexcept -> std::uint32_t {
        return static_cast<std::uint32_t>(chunks.size());
    }
    // Byte offset of chunk `index` in the image (and its data object).
    [[nodiscard]] auto chunk_offset(std::uint32_t index) const noexcept -> std::uint64_t {
        return std::uint64_t{index} << chunk_shift;
    }
    // Bytes in chunk `index`: chunk_size(), or less for the last one.
    [[nodiscard]] auto chunk_length(std::uint32_t index) const noexcept -> std::uint64_t;
    [[nodiscard]] auto is_hole(std::uint32_t index) const noexcept -> bool;

    friend auto operator==(const ImageManifest&, const ImageManifest&) -> bool = default;
};

enum class ManifestError : std::uint8_t {
    truncated,   // shorter than its header or its chunk table
    wrong_size,  // longer than 56 + 32 × chunk count
    bad_magic,
    unsupported_version,
    bad_flags,         // an unknown flag bit
    bad_block_size,    // not 512 or 4096
    bad_chunk_shift,   // outside 16..22
    bad_image_size,    // zero, or not whole logical blocks
    bad_chunk_count,   // zero, above 2^20, or not ceil(image bytes / chunk size)
    nonzero_reserved,  // a reserved byte is set
    bad_key_id,        // zero on an encrypted image, or set on a plain one
    bad_lineage,       // chunked without a lineage ID or encryption, or the flag
                       // and version disagree
    name_mismatch,     // the manifest's SHA-256 is not the image name
    crypto_failure,    // OpenSSL could not compute a digest
};

[[nodiscard]] auto to_string(ManifestError e) noexcept -> const char*;

[[nodiscard]] auto encode_manifest(const ImageManifest& m)
    -> std::expected<std::vector<std::byte>, ManifestError>;
[[nodiscard]] auto decode_manifest(std::span<const std::byte> bytes)
    -> std::expected<ImageManifest, ManifestError>;

// SHA-256 of anything: a manifest (its image name) or a chunk.
[[nodiscard]] auto sha256_digest(std::span<const std::byte> bytes)
    -> std::expected<ImageDigest, ManifestError>;
// Checks the manifest against the image name first, then decodes it.
[[nodiscard]] auto decode_named_manifest(std::span<const std::byte> bytes, const ImageDigest& name)
    -> std::expected<ImageManifest, ManifestError>;
// True if `data` is chunk `index` of the image exactly as stored: the right
// length and SHA-256. Holes never match: they are not fetched.
[[nodiscard]] auto chunk_matches(const ImageManifest& m, std::uint32_t index,
                                 std::span<const std::byte> data) -> bool;

// Image names as they appear in object keys: 64 lowercase hex digits.
[[nodiscard]] auto image_name_hex(const ImageDigest& name) -> std::string;
[[nodiscard]] auto parse_image_name(std::string_view hex) -> std::optional<ImageDigest>;

}  // namespace ak::objstore
