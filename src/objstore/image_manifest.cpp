// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "objstore/image_manifest.hpp"

#include <algorithm>

#include <openssl/evp.h>

#include "common/wire.hpp"

namespace ak::objstore {

namespace {

namespace wire = ak::wire;

// "AKIMAGE\0"
constexpr std::array<std::byte, 8> magic{std::byte{'A'}, std::byte{'K'}, std::byte{'I'},
                                         std::byte{'M'}, std::byte{'A'}, std::byte{'G'},
                                         std::byte{'E'}, std::byte{0}};
constexpr std::size_t reserved_after_shift = 7;
constexpr std::uint32_t block_512 = 512;
constexpr std::uint32_t block_4k = 4096;

auto all_zero(std::span<const std::byte> b) -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

// ceil(image_bytes / 2^shift), or 0 when that does not fit the chunk limit.
auto expected_chunks(std::uint64_t image_bytes, std::uint8_t shift) -> std::uint64_t {
    const std::uint64_t size = std::uint64_t{1} << shift;
    return (image_bytes / size) + (image_bytes % size != 0 ? 1 : 0);
}

auto check_fields(const ImageManifest& m) -> std::expected<void, ManifestError> {
    if (m.logical_block_size != block_512 && m.logical_block_size != block_4k) {
        return std::unexpected(ManifestError::bad_block_size);
    }
    if (m.chunk_shift < min_chunk_shift || m.chunk_shift > max_chunk_shift) {
        return std::unexpected(ManifestError::bad_chunk_shift);
    }
    if (m.image_bytes == 0 || m.image_bytes % m.logical_block_size != 0) {
        return std::unexpected(ManifestError::bad_image_size);
    }
    if (m.chunks.empty() || m.chunks.size() > max_image_chunks ||
        m.chunks.size() != expected_chunks(m.image_bytes, m.chunk_shift)) {
        return std::unexpected(ManifestError::bad_chunk_count);
    }
    if (m.encrypted == all_zero(m.key_id)) {
        return std::unexpected(ManifestError::bad_key_id);
    }
    if (m.chunked ? (m.lineage_id == 0 || !m.encrypted)
                  : (m.lineage_id != 0 || !all_zero(m.parent))) {
        return std::unexpected(ManifestError::bad_lineage);
    }
    return {};
}

}  // namespace

auto ImageManifest::chunk_length(std::uint32_t index) const noexcept -> std::uint64_t {
    if (index >= chunks.size()) {
        return 0;
    }
    return std::min(chunk_size(), image_bytes - chunk_offset(index));
}

auto ImageManifest::has_parent() const noexcept -> bool {
    return !all_zero(parent);
}

auto ImageManifest::is_hole(std::uint32_t index) const noexcept -> bool {
    return index < chunks.size() && all_zero(chunks[index]);
}

auto to_string(ManifestError e) noexcept -> const char* {
    switch (e) {
        case ManifestError::truncated:
            return "truncated";
        case ManifestError::wrong_size:
            return "wrong_size";
        case ManifestError::bad_magic:
            return "bad_magic";
        case ManifestError::unsupported_version:
            return "unsupported_version";
        case ManifestError::bad_flags:
            return "bad_flags";
        case ManifestError::bad_block_size:
            return "bad_block_size";
        case ManifestError::bad_chunk_shift:
            return "bad_chunk_shift";
        case ManifestError::bad_image_size:
            return "bad_image_size";
        case ManifestError::bad_chunk_count:
            return "bad_chunk_count";
        case ManifestError::nonzero_reserved:
            return "nonzero_reserved";
        case ManifestError::bad_key_id:
            return "bad_key_id";
        case ManifestError::bad_lineage:
            return "bad_lineage";
        case ManifestError::name_mismatch:
            return "name_mismatch";
        case ManifestError::crypto_failure:
            return "crypto_failure";
    }
    return "unknown";
}

auto encode_manifest(const ImageManifest& m)
    -> std::expected<std::vector<std::byte>, ManifestError> {
    if (auto ok = check_fields(m); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(m.header_size() + (m.chunks.size() * image_digest_size));
    wire::Writer w{out};
    w.bytes(magic);
    w.le16(m.version());
    w.le16(static_cast<std::uint16_t>((m.encrypted ? manifest_flag_encrypted : 0U) |
                                      (m.chunked ? manifest_flag_chunked : 0U)));
    w.le32(m.logical_block_size);
    w.u8(m.chunk_shift);
    const std::array<std::byte, reserved_after_shift> zeros{};
    w.bytes(zeros);
    w.le64(m.image_bytes);
    w.le32(m.chunk_count());
    w.le32(0);
    w.bytes(m.key_id);
    if (m.chunked) {
        w.le64(m.lineage_id);
        w.bytes(m.parent);
    }
    for (const auto& d : m.chunks) {
        w.bytes(d);
    }
    return out;
}

auto decode_manifest(std::span<const std::byte> bytes)
    -> std::expected<ImageManifest, ManifestError> {
    wire::Reader r{bytes};
    const auto mg = r.bytes(magic.size());
    if (!mg) {
        return std::unexpected(ManifestError::truncated);
    }
    if (!std::ranges::equal(*mg, magic)) {
        return std::unexpected(ManifestError::bad_magic);
    }
    const auto version = r.le16();
    const auto flags = r.le16();
    const auto lbs = r.le32();
    const auto shift = r.u8();
    const auto reserved1 = r.bytes(reserved_after_shift);
    const auto image_bytes = r.le64();
    const auto count = r.le32();
    const auto reserved2 = r.le32();
    const auto key_id = r.bytes(ImageKeyId{}.size());
    if (!version || !flags || !lbs || !shift || !reserved1 || !image_bytes || !count ||
        !reserved2 || !key_id) {
        return std::unexpected(ManifestError::truncated);
    }
    if (*version != manifest_version && *version != manifest_version_chunked) {
        return std::unexpected(ManifestError::unsupported_version);
    }
    if ((*flags & ~(manifest_flag_encrypted | manifest_flag_chunked)) != 0) {
        return std::unexpected(ManifestError::bad_flags);
    }
    if (!all_zero(*reserved1) || *reserved2 != 0) {
        return std::unexpected(ManifestError::nonzero_reserved);
    }
    const bool chunked = *version == manifest_version_chunked;
    if (chunked != ((*flags & manifest_flag_chunked) != 0)) {
        return std::unexpected(ManifestError::bad_lineage);
    }
    std::uint64_t lineage = 0;
    ImageDigest parent{};
    if (chunked) {
        const auto l = r.le64();
        const auto p = r.bytes(parent.size());
        if (!l || !p) {
            return std::unexpected(ManifestError::truncated);
        }
        lineage = *l;
        std::ranges::copy(*p, parent.begin());
    }
    // Check the count before trusting it with an allocation.
    if (*count == 0 || *count > max_image_chunks) {
        return std::unexpected(ManifestError::bad_chunk_count);
    }
    const std::size_t table = std::size_t{*count} * image_digest_size;
    if (r.remaining() < table) {
        return std::unexpected(ManifestError::truncated);
    }
    if (r.remaining() > table) {
        return std::unexpected(ManifestError::wrong_size);
    }
    ImageManifest m;
    m.encrypted = (*flags & manifest_flag_encrypted) != 0;
    m.logical_block_size = *lbs;
    m.chunk_shift = *shift;
    m.image_bytes = *image_bytes;
    std::ranges::copy(*key_id, m.key_id.begin());
    m.chunked = chunked;
    m.lineage_id = lineage;
    m.parent = parent;
    m.chunks.resize(*count);
    for (auto& d : m.chunks) {
        const auto raw = r.bytes(image_digest_size);
        if (!raw) {
            return std::unexpected(ManifestError::truncated);
        }
        std::ranges::copy(*raw, d.begin());
    }
    if (auto ok = check_fields(m); !ok) {
        return std::unexpected(ok.error());
    }
    return m;
}

auto sha256_digest(std::span<const std::byte> bytes) -> std::expected<ImageDigest, ManifestError> {
    ImageDigest out{};
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), reinterpret_cast<unsigned char*>(out.data()), &len,
                   EVP_sha256(), nullptr) != 1 ||
        len != out.size()) {
        return std::unexpected(ManifestError::crypto_failure);
    }
    return out;
}

auto decode_named_manifest(std::span<const std::byte> bytes, const ImageDigest& name)
    -> std::expected<ImageManifest, ManifestError> {
    const auto digest = sha256_digest(bytes);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    if (*digest != name) {
        return std::unexpected(ManifestError::name_mismatch);
    }
    return decode_manifest(bytes);
}

auto chunk_matches(const ImageManifest& m, std::uint32_t index, std::span<const std::byte> data)
    -> bool {
    if (index >= m.chunks.size() || m.is_hole(index) || data.size() != m.chunk_length(index)) {
        return false;
    }
    const auto digest = sha256_digest(data);
    return digest && *digest == m.chunks[index];
}

auto image_name_hex(const ImageDigest& name) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    constexpr unsigned nibble_bits = 4;
    constexpr unsigned nibble_mask = 0xF;
    std::string out;
    out.reserve(name.size() * 2);
    for (const std::byte b : name) {
        const auto v = std::to_integer<unsigned>(b);
        out.push_back(digits[v >> nibble_bits]);
        out.push_back(digits[v & nibble_mask]);
    }
    return out;
}

auto parse_image_name(std::string_view hex) -> std::optional<ImageDigest> {
    if (hex.size() != image_digest_size * 2) {
        return std::nullopt;
    }
    constexpr unsigned nibble_bits = 4;
    constexpr unsigned ten = 10;
    auto value = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + static_cast<int>(ten);
        }
        return -1;  // uppercase is refused: names have one spelling
    };
    ImageDigest out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = value(hex[2 * i]);
        const int lo = value(hex[(2 * i) + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out[i] = static_cast<std::byte>((static_cast<unsigned>(hi) << nibble_bits) |
                                        static_cast<unsigned>(lo));
    }
    return out;
}

}  // namespace ak::objstore
