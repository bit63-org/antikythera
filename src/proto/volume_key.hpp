// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VolumeKey: a network volume's data key for one attachment, wrapped by
// kythira KMS to the attaching helm's secure-element X25519 key
// (.kiro/specs/block-volume-service/ Requirement 12.2-12.3, design
// "VolumeKey" and "Keys and crypto-erase"). It travels controller -> helm
// on the controller link only; it never touches the mailbox, the host or a
// hold role. helm opens it inside the secure element and delivers the key
// to oar-blk with the existing deliver_key.
//
// Layout (little-endian, fixed 0x98 bytes):
//   0x00  magic          u32  'AKVK'
//   0x04  version        u16  frame format version (1)
//   0x06  reserved       u16  zero
//   0x08  server_id      u64  recipient server; non-zero
//   0x10  volume_id      u64  non-zero
//   0x18  attachment_id  u64  non-zero
//   0x20  generation     u32  attachment generation; non-zero
//   0x24  reserved       u32  zero
//   0x28  hpke_enc       [32] HPKE encapsulated key (an X25519 public key)
//   0x48  wrapped_key    [80] AES-256-GCM ciphertext of the 64-byte XTS key + 16-byte tag
//
// HPKE is RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
// and AES-256-GCM. The AAD is bytes [0x00, 0x28) (volume_key_aad), so the
// key opens only for the server, volume, attachment and generation it was
// wrapped for. The frame is not signed: the mTLS controller link
// authenticates the controller, and the AEAD makes any change to the
// header or ciphertext fail to open.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint32_t volume_key_magic = 0x4B56'4B41;  // "AKVK" as little-endian bytes
inline constexpr std::uint16_t volume_key_version = 1;
inline constexpr std::size_t volume_key_aad_size = 0x28;
inline constexpr std::size_t hpke_enc_size = 32;
inline constexpr std::size_t volume_data_key_size = 64;  // AES-256-XTS: two 256-bit keys
inline constexpr std::size_t aead_tag_size = 16;
inline constexpr std::size_t wrapped_volume_key_size = volume_data_key_size + aead_tag_size;
inline constexpr std::size_t volume_key_size =
    volume_key_aad_size + hpke_enc_size + wrapped_volume_key_size;

using HpkeEnc = std::array<std::byte, hpke_enc_size>;
using WrappedVolumeKey = std::array<std::byte, wrapped_volume_key_size>;

struct VolumeKey {
    std::uint64_t server_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t attachment_id{0};
    std::uint32_t generation{0};
    HpkeEnc hpke_enc{};
    WrappedVolumeKey wrapped_key{};
    friend auto operator==(const VolumeKey&, const VolumeKey&) -> bool = default;
};

// The HPKE AAD: the header, which binds the wrapped key to its recipient.
[[nodiscard]] inline auto volume_key_aad(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), volume_key_aad_size));
}

namespace detail {

[[nodiscard]] inline auto check_volume_key(const VolumeKey& k) noexcept
    -> std::expected<void, DecodeError> {
    if (k.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    // An all-zero X25519 share is the identity point, which HPKE refuses.
    if (k.volume_id == 0 || k.attachment_id == 0 || k.generation == 0 || all_zero(k.hpke_enc)) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

}  // namespace detail

[[nodiscard]] inline auto decode_volume_key(std::span<const std::byte> bytes)
    -> std::expected<VolumeKey, DecodeError> {
    if (bytes.size() < volume_key_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > volume_key_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    bool zero = r.le16().value_or(1) == 0;
    VolumeKey k;
    k.server_id = r.le64().value_or(0);
    k.volume_id = r.le64().value_or(0);
    k.attachment_id = r.le64().value_or(0);
    k.generation = r.le32().value_or(0);
    zero = r.le32().value_or(1) == 0 && zero;
    std::ranges::copy(r.bytes(hpke_enc_size).value_or(std::span<const std::byte>{}),
                      k.hpke_enc.begin());
    std::ranges::copy(r.bytes(wrapped_volume_key_size).value_or(std::span<const std::byte>{}),
                      k.wrapped_key.begin());
    if (magic != volume_key_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != volume_key_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_volume_key(k); !ok) {
        return std::unexpected(ok.error());
    }
    return k;
}

[[nodiscard]] inline auto encode_volume_key(const VolumeKey& k)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_volume_key(k); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(volume_key_size);
    wire::Writer w{out};
    w.le32(volume_key_magic);
    w.le16(volume_key_version);
    w.le16(0);
    w.le64(k.server_id);
    w.le64(k.volume_id);
    w.le64(k.attachment_id);
    w.le32(k.generation);
    w.le32(0);
    w.bytes(k.hpke_enc);
    w.bytes(k.wrapped_key);
    return out;
}

}  // namespace ak::proto
