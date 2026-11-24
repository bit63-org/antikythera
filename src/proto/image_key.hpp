// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ImageKey: an encrypted image's key K_img, sent by the controller to the
// helm that is about to create an image volume of that image
// (.kiro/specs/oar-blk-data-plane/ Requirement 8.8, task 15; design
// "Image volumes", Keys). It is wrapped to the helm secure element's
// X25519 transport key exactly as a VolumeKey is, and travels controller ->
// helm on the controller link only: never on the mailbox, the host or a
// storage role. helm checks that it opens and keeps the frame until the
// CREATE_VOLUME naming the same volume and owner, which re-wraps K_img
// inside the secure element under the owner's VM key, as that image
// volume's volume key. From then on it is held, delivered, rewrapped and
// crypto-erased like any volume key.
//
// Layout (little-endian, fixed 0x90 bytes):
//   0x00  magic        u32  'AKIK'
//   0x04  version      u16  frame format version (1)
//   0x06  reserved     u16  zero
//   0x08  server_id    u64  recipient server; non-zero
//   0x10  volume_id    u64  the image volume CREATE_VOLUME will create; non-zero
//   0x18  owner_vm     u64  the VM that will own it; non-zero
//   0x20  hpke_enc     [32] HPKE encapsulated key (an X25519 public key)
//   0x40  wrapped_key  [80] AES-256-GCM ciphertext of the 64-byte XTS key + 16-byte tag
//
// HPKE as for VolumeKey (RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256, AES-256-GCM), with its own info, image_key_info, so a
// VolumeKey's wrapped key cannot be passed off as an image key or the
// reverse. The AAD is bytes [0x00, 0x20) (image_key_aad): the key opens
// only for the server, volume and owner it was wrapped for, so the host
// cannot create the volume for another VM and have helm wrap K_img to that
// VM. Unsigned, like VolumeKey: the mTLS link authenticates the
// controller, and the AEAD makes any change fail to open.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/volume_key.hpp"

namespace ak::proto {

inline constexpr std::uint32_t image_key_magic = 0x4B49'4B41;  // "AKIK" as little-endian bytes
inline constexpr std::uint16_t image_key_version = 1;
inline constexpr std::size_t image_key_aad_size = 0x20;
inline constexpr std::size_t image_key_size =
    image_key_aad_size + hpke_enc_size + wrapped_volume_key_size;

inline constexpr std::string_view image_key_info = "antikythera image key v1";

struct ImageKey {
    std::uint64_t server_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t owner_vm{0};
    HpkeEnc hpke_enc{};
    WrappedVolumeKey wrapped_key{};
    friend auto operator==(const ImageKey&, const ImageKey&) -> bool = default;
};

// The HPKE AAD: the header, which binds the key to its server, volume and owner.
[[nodiscard]] inline auto image_key_aad(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), image_key_aad_size));
}

namespace detail {

[[nodiscard]] inline auto check_image_key(const ImageKey& k) noexcept
    -> std::expected<void, DecodeError> {
    if (k.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    // An all-zero X25519 share is the identity point, which HPKE refuses.
    if (k.volume_id == 0 || k.owner_vm == 0 || all_zero(k.hpke_enc)) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

}  // namespace detail

[[nodiscard]] inline auto decode_image_key(std::span<const std::byte> bytes)
    -> std::expected<ImageKey, DecodeError> {
    if (bytes.size() < image_key_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > image_key_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    const bool zero = r.le16().value_or(1) == 0;
    ImageKey k;
    k.server_id = r.le64().value_or(0);
    k.volume_id = r.le64().value_or(0);
    k.owner_vm = r.le64().value_or(0);
    std::ranges::copy(r.bytes(hpke_enc_size).value_or(std::span<const std::byte>{}),
                      k.hpke_enc.begin());
    std::ranges::copy(r.bytes(wrapped_volume_key_size).value_or(std::span<const std::byte>{}),
                      k.wrapped_key.begin());
    if (magic != image_key_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != image_key_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_image_key(k); !ok) {
        return std::unexpected(ok.error());
    }
    return k;
}

[[nodiscard]] inline auto encode_image_key(const ImageKey& k)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_image_key(k); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(image_key_size);
    wire::Writer w{out};
    w.le32(image_key_magic);
    w.le16(image_key_version);
    w.le16(0);
    w.le64(k.server_id);
    w.le64(k.volume_id);
    w.le64(k.owner_vm);
    w.bytes(k.hpke_enc);
    w.bytes(k.wrapped_key);
    return out;
}

}  // namespace ak::proto
