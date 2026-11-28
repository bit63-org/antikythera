// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// BootImage: the controller's assignment of a hull image to a server
// (.kiro/specs/cold-start/ Requirement 2.1; .kiro/specs/server-provisioning/
// Requirement 4, design "Host images"). Link record type 25, controller ->
// helm.
//
// Layout (little-endian, fixed 0xE0 bytes):
//   0x00  magic               u32  'AKBI'
//   0x04  version             u16  frame format version (1)
//   0x06  key_id              u16  controller key that signed it; non-zero
//   0x08  server_id           u64  target server; non-zero
//   0x10  assignment_version  u64  non-zero; helm keeps only a newer one
//   0x18  reserved            [8]  zero
//   0x20  image               [0x80] the image's HostImage descriptor
//                                  (host_image.hpp), kind hull
//   0xA0  signature           [64] Ed25519 over bytes [0x00, 0xA0)
//
// Two signatures guard an assignment. The controller's says this server
// should boot this image; the image key's, inside the descriptor, says the
// release pipeline built it. helm needs both: a compromised controller can
// pick only among signed releases, and a stolen descriptor cannot be
// pushed to a server without the controller. assignment_version only
// grows, so a captured older assignment cannot roll a server back to a
// release the controller has moved off.
//
// helm keeps the newest assignment in its sealed store and, before every
// host boot, boots the assigned image: from its cache if it holds it,
// else fetched from the metal boot layer within 30 seconds, else the LKG
// (cold-start Requirement 2.2). Booting an assigned image does not make
// it the LKG; only a power policy's keep_image does (2.3).
//
// This record is not in either spec's table: cold-start says helm boots
// "an assigned image" without naming the record that assigns it, so it
// is added here, with the next free link type.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/host_image.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint32_t boot_image_magic = 0x4942'4B41;  // "AKBI" as little-endian bytes
inline constexpr std::uint16_t boot_image_version = 1;
inline constexpr std::size_t boot_image_header_size = 0x20;
inline constexpr std::size_t boot_image_signed_size = boot_image_header_size + host_image_size;
inline constexpr std::size_t boot_image_size = boot_image_signed_size + ed25519_signature_size;

struct BootImage {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint64_t assignment_version{0};
    HostImage image;
    Ed25519Signature signature{};
    friend auto operator==(const BootImage&, const BootImage&) -> bool = default;
};

// The bytes the controller signs: the frame less its trailing signature.
[[nodiscard]] inline auto boot_image_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), boot_image_signed_size));
}

// The embedded descriptor frame, exactly as the image key signed it.
[[nodiscard]] inline auto boot_image_descriptor(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    if (frame.size() < boot_image_signed_size) {
        return {};
    }
    return frame.subspan(boot_image_header_size, host_image_size);
}

inline auto set_boot_image_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() == boot_image_size) {
        std::ranges::copy(signature, frame.begin() + boot_image_signed_size);
    }
}

namespace detail {

[[nodiscard]] inline auto check_boot_image(const BootImage& b) noexcept
    -> std::expected<void, DecodeError> {
    if (b.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (b.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (b.assignment_version == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (auto ok = check_host_image(b.image); !ok) {
        return ok;
    }
    if (b.image.kind != HostImageKind::hull) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

}  // namespace detail

// Strict decode, including the embedded descriptor. Verifies neither
// signature: helm checks the controller's over boot_image_signed_bytes()
// and the image key's over the descriptor.
[[nodiscard]] inline auto decode_boot_image(std::span<const std::byte> bytes)
    -> std::expected<BootImage, DecodeError> {
    if (bytes.size() < boot_image_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > boot_image_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    BootImage b;
    b.key_id = r.le16().value_or(0);
    b.server_id = r.le64().value_or(0);
    b.assignment_version = r.le64().value_or(0);
    const bool zero = detail::all_zero(r.bytes(8).value_or(std::span<const std::byte>{}));
    const auto descriptor = r.bytes(host_image_size).value_or(std::span<const std::byte>{});
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      b.signature.begin());
    if (magic != boot_image_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != boot_image_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    auto image = decode_host_image(descriptor);
    if (!image) {
        return std::unexpected(image.error());
    }
    b.image = *image;
    if (auto ok = detail::check_boot_image(b); !ok) {
        return std::unexpected(ok.error());
    }
    return b;
}

// Encodes a BootImage (with whatever is in both signatures), enforcing
// every rule decode_boot_image checks.
[[nodiscard]] inline auto encode_boot_image(const BootImage& b)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_boot_image(b); !ok) {
        return std::unexpected(ok.error());
    }
    auto descriptor = encode_host_image(b.image);
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    std::vector<std::byte> out;
    out.reserve(boot_image_size);
    wire::Writer w{out};
    w.le32(boot_image_magic);
    w.le16(boot_image_version);
    w.le16(b.key_id);
    w.le64(b.server_id);
    w.le64(b.assignment_version);
    w.bytes(std::array<std::byte, 8>{});
    w.bytes(*descriptor);
    w.bytes(b.signature);
    return out;
}

}  // namespace ak::proto
