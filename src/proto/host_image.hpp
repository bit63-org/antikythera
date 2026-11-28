// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// HostImage: the signed descriptor of a host boot image, a hull UKI on an
// antikythera server (.kiro/specs/server-provisioning/ Requirement 4;
// .kiro/specs/cold-start/ Requirement 2.5; kythira
// .kiro/specs/metal-host-lifecycle/ design "Signed images only, data on
// disk only"). The metal boot layer serves it beside the image, and helm
// keeps it with every image in its sealed store.
//
// The descriptor is signed by an image signing key, not the controller
// key: images are built and signed by the release pipeline, and a
// controller that is compromised must still not be able to put an image
// of its own on a server. helm checks it against its image keys before an
// image is stored and again before it is booted, and checks the image
// bytes against `digest` both times.
//
// Layout (little-endian, fixed 0x80 bytes):
//   0x00  magic          u32  'AKHI'
//   0x04  version        u16  frame format version (1)
//   0x06  key_id         u16  image signing key; non-zero
//   0x08  image_version  u64  non-zero; the release's number, for reports
//   0x10  size           u64  image bytes, 1 .. max_host_image_size
//   0x18  kind           u8   HostImageKind
//   0x19  reserved       [7]  zero
//   0x20  digest         [32] SHA-256 of the image bytes; never all zero
//   0x40  signature      [64] Ed25519 over bytes [0x00, 0x40)
//
// The boot layer's object keys for an image are host_image_descriptor_key()
// and host_image_data_key(): the lowercase hex digest names both, so an
// image is fetched by what it is, never by a name the boot layer chose.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"
#include "proto/standing_set.hpp"

namespace ak::proto {

inline constexpr std::uint32_t host_image_magic = 0x4948'4B41;  // "AKHI" as little-endian bytes
inline constexpr std::uint16_t host_image_version = 1;
inline constexpr std::size_t host_image_signed_size = 0x40;
inline constexpr std::size_t host_image_size = host_image_signed_size + ed25519_signature_size;
// A hull UKI is tens of megabytes; this bounds what helm will ever fetch.
inline constexpr std::uint64_t max_host_image_size = std::uint64_t{512} << 20;

// Values are part of the wire protocol: never renumber.
enum class HostImageKind : std::uint8_t {
    hull = 1,          // hull's UKI, for an antikythera server's host
    kythira_host = 2,  // the Kythira host image (khold or S3 storage hosts)
    discovery = 3,     // the discovery image: reports hardware and powers off
    wipe = 4,          // the wipe image
};

struct HostImage {
    KeyId key_id{no_key_id};
    std::uint64_t image_version{0};
    std::uint64_t size{0};
    HostImageKind kind{HostImageKind::hull};
    ImageDigest digest{};
    Ed25519Signature signature{};
    friend auto operator==(const HostImage&, const HostImage&) -> bool = default;
};

[[nodiscard]] inline auto host_image_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(std::min(frame.size(), host_image_signed_size));
}

inline auto set_host_image_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() == host_image_size) {
        std::ranges::copy(signature, frame.begin() + host_image_signed_size);
    }
}

// Lowercase hex of a digest.
[[nodiscard]] inline auto digest_hex(const ImageDigest& d) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    out.reserve(2 * d.size());
    for (const auto b : d) {
        const auto v = std::to_integer<unsigned>(b);
        out.push_back(digits[v >> 4U]);
        out.push_back(digits[v & 0xFU]);
    }
    return out;
}

// The boot layer's object keys: v1/images/<hex digest>/descriptor and
// v1/images/<hex digest>/data.
[[nodiscard]] inline auto host_image_descriptor_key(const ImageDigest& d) -> std::string {
    return "v1/images/" + digest_hex(d) + "/descriptor";
}
[[nodiscard]] inline auto host_image_data_key(const ImageDigest& d) -> std::string {
    return "v1/images/" + digest_hex(d) + "/data";
}

namespace detail {

[[nodiscard]] constexpr auto known(HostImageKind k) noexcept -> bool {
    return k >= HostImageKind::hull && k <= HostImageKind::wipe;
}

[[nodiscard]] inline auto check_host_image(const HostImage& h) noexcept
    -> std::expected<void, DecodeError> {
    if (h.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (h.image_version == 0) {
        return std::unexpected(DecodeError::bad_generation);
    }
    if (h.size == 0 || h.size > max_host_image_size) {
        return std::unexpected(DecodeError::bad_payload_size);
    }
    if (!known(h.kind)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (all_zero(h.digest)) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: helm verifies
// host_image_signed_bytes(frame) against `signature` under `key_id` with
// its image keys.
[[nodiscard]] inline auto decode_host_image(std::span<const std::byte> bytes)
    -> std::expected<HostImage, DecodeError> {
    if (bytes.size() < host_image_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > host_image_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    HostImage h;
    h.key_id = r.le16().value_or(0);
    h.image_version = r.le64().value_or(0);
    h.size = r.le64().value_or(0);
    h.kind = static_cast<HostImageKind>(r.u8().value_or(0));
    const bool zero = detail::all_zero(r.bytes(7).value_or(std::span<const std::byte>{}));
    std::ranges::copy(r.bytes(image_digest_size).value_or(std::span<const std::byte>{}),
                      h.digest.begin());
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      h.signature.begin());
    if (magic != host_image_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != host_image_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_host_image(h); !ok) {
        return std::unexpected(ok.error());
    }
    return h;
}

// Encodes a HostImage (with whatever is in `signature`), enforcing every
// rule decode_host_image checks.
[[nodiscard]] inline auto encode_host_image(const HostImage& h)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_host_image(h); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(host_image_size);
    wire::Writer w{out};
    w.le32(host_image_magic);
    w.le16(host_image_version);
    w.le16(h.key_id);
    w.le64(h.image_version);
    w.le64(h.size);
    w.u8(static_cast<std::uint8_t>(h.kind));
    w.bytes(std::array<std::byte, 7>{});
    w.bytes(h.digest);
    w.bytes(h.signature);
    return out;
}

}  // namespace ak::proto
