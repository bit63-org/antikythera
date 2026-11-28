// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VtepCredential and CredentialRevocations: the controller's certificate
// for one VTEP's static tunnel key, and its list of credentials revoked
// before they expire (.kiro/specs/fleet-scale-networking/ Requirements 2
// and 3, design "VTEP credentials").
//
// A credential binds a VTEP's X25519 public key to its server, slot, key
// epoch, VTEP address and cell for a validity window. Peers exchange
// credentials before a WireGuard handshake (the tunnel's `credential`
// message), so no host needs a list of every other host's key. A
// credential authorizes nothing by itself: what a peer may send is still
// decided by the signed mapping (check_ingress).
//
// VtepCredential layout (little-endian, 160 bytes):
//   0x00  magic       u32  'AKVC'
//   0x04  version     u16  1
//   0x06  key_id      u16  controller key that signed it; non-zero
//   0x08  server_id   u64  non-zero
//   0x10  cell_id     u32  0: no cells (kythira fleet-cells)
//   0x14  modes       u8   TunnelModes bit set (bit 0 WireGuard, bit 1 PSP); non-zero
//   0x15  slot        u8   the network role's slot on that server
//   0x16  key_epoch   u16  the key epoch the key was derived at; non-zero
//   0x18  vtep        [16] the VTEP's underlay address (unicast)
//   0x28  public_key  [32] X25519; never all zero
//   0x48  not_before  u64  Unix seconds
//   0x50  not_after   u64  Unix seconds, after not_before
//   0x58  serial      u64  per cell, increasing, non-zero; revocations name it
//   0x60  signature   [64] Ed25519 over bytes 0x00-0x5F
//
// CredentialRevocations layout (little-endian):
//   0x00  magic         u32  'AKCR'
//   0x04  version       u16  1
//   0x06  key_id        u16  non-zero
//   0x08  cell_id       u32
//   0x0C  reserved      u32  zero
//   0x10  list_version  u64  per cell, starts at 1, increases
//   0x18  count         u32  at most max_revocations
//   0x1C  reserved      u32  zero
//   0x20  entries       count x { serial u64 | not_after u64 }, serials
//                       strictly ascending, serials non-zero
//   then  signature     [64] Ed25519 over every byte before it
//
// The revocation list is a full snapshot for its cell, not a delta: a
// role keeps the highest list_version it has verified. An entry is only
// useful until its not_after (the credential it revokes has expired by
// then), so the controller drops expired entries and the list holds at
// most a day of revocations with 24-hour credentials. max_revocations is
// 16,384, below the design's first estimate of 65,536, so that a full list
// (262 KiB) fits one controller link record (max_record_payload).
//
// Neither decoder verifies the signature: the receiver verifies the
// signed bytes under key_id before trusting anything else.

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
#include "proto/tunnel_peers.hpp"

namespace ak::proto {

inline constexpr std::uint32_t vtep_credential_magic = 0x4356'4B41;  // "AKVC"
inline constexpr std::uint16_t vtep_credential_version = 1;
inline constexpr std::size_t vtep_credential_signed_size = 0x60;
inline constexpr std::size_t vtep_credential_size =
    vtep_credential_signed_size + ed25519_signature_size;  // 160
static_assert(vtep_credential_size == 160);

inline constexpr std::uint32_t credential_revocations_magic = 0x5243'4B41;  // "AKCR"
inline constexpr std::uint16_t credential_revocations_version = 1;
inline constexpr std::size_t credential_revocations_header_size = 0x20;
inline constexpr std::size_t revocation_entry_size = 16;
inline constexpr std::size_t max_revocations = 16384;
inline constexpr std::size_t max_credential_revocations_size =
    credential_revocations_header_size + (max_revocations * revocation_entry_size) +
    ed25519_signature_size;

struct VtepCredential {
    KeyId key_id{no_key_id};
    std::uint64_t server_id{0};
    std::uint32_t cell_id{0};
    TunnelModes modes{tunnel_mode_bit(TunnelMode::wireguard)};
    std::uint8_t slot{0};
    std::uint16_t key_epoch{0};
    VtepAddress vtep{};
    TunnelPublicKey public_key{};
    std::uint64_t not_before{0};
    std::uint64_t not_after{0};
    std::uint64_t serial{0};
    Ed25519Signature signature{};

    friend auto operator==(const VtepCredential&, const VtepCredential&) -> bool = default;
};

struct Revocation {
    std::uint64_t serial{0};
    std::uint64_t not_after{0};
    friend auto operator==(const Revocation&, const Revocation&) -> bool = default;
};

struct CredentialRevocations {
    KeyId key_id{no_key_id};
    std::uint32_t cell_id{0};
    std::uint64_t list_version{0};
    std::vector<Revocation> entries;
    Ed25519Signature signature{};

    friend auto operator==(const CredentialRevocations&, const CredentialRevocations&)
        -> bool = default;
};

[[nodiscard]] inline constexpr auto credential_revocations_size(std::size_t count) noexcept
    -> std::size_t {
    return credential_revocations_header_size + (count * revocation_entry_size) +
           ed25519_signature_size;
}

// The bytes either signature covers: all but the trailing 64.
[[nodiscard]] inline auto credential_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return map_update_signed_bytes(frame);
}

// Writes `signature` over the trailing 64 bytes of an encoded frame.
inline auto set_credential_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    set_map_update_signature(frame, signature);
}

namespace detail {

[[nodiscard]] inline auto check_vtep_credential(const VtepCredential& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (c.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (c.modes == 0 || (c.modes & ~known_tunnel_modes) != 0) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (c.key_epoch == 0 || c.serial == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (!valid_unicast_vtep(c.vtep)) {
        return std::unexpected(DecodeError::bad_vtep);
    }
    if (all_zero(c.public_key)) {
        return std::unexpected(DecodeError::bad_public_key);
    }
    if (c.not_before >= c.not_after) {
        return std::unexpected(DecodeError::bad_validity);
    }
    return {};
}

[[nodiscard]] inline auto check_credential_revocations(const CredentialRevocations& l) noexcept
    -> std::expected<void, DecodeError> {
    if (l.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (l.list_version == 0) {
        return std::unexpected(DecodeError::bad_list_version);
    }
    if (l.entries.size() > max_revocations) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < l.entries.size(); ++i) {
        if (l.entries[i].serial == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (i > 0 && l.entries[i - 1].serial >= l.entries[i].serial) {
            return std::unexpected(DecodeError::not_ascending);
        }
    }
    return {};
}

}  // namespace detail

[[nodiscard]] inline auto decode_vtep_credential(std::span<const std::byte> bytes)
    -> std::expected<VtepCredential, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto cell_id = r.le32();
    auto modes = r.u8();
    auto slot = r.u8();
    auto key_epoch = r.le16();
    auto vtep = r.bytes(vtep_address_size);
    auto public_key = r.bytes(tunnel_key_size);
    auto not_before = r.le64();
    auto not_after = r.le64();
    auto serial = r.le64();
    auto signature = r.bytes(ed25519_signature_size);
    if (!magic || !version || !key_id || !server_id || !cell_id || !modes || !slot || !key_epoch ||
        !vtep || !public_key || !not_before || !not_after || !serial || !signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*magic != vtep_credential_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != vtep_credential_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    VtepCredential out{.key_id = *key_id,
                       .server_id = *server_id,
                       .cell_id = *cell_id,
                       .modes = *modes,
                       .slot = *slot,
                       .key_epoch = *key_epoch,
                       .vtep = {},
                       .public_key = {},
                       .not_before = *not_before,
                       .not_after = *not_after,
                       .serial = *serial,
                       .signature = {}};
    std::ranges::copy(*vtep, out.vtep.begin());
    std::ranges::copy(*public_key, out.public_key.begin());
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = detail::check_vtep_credential(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a credential (with whatever is in `signature`), enforcing every
// rule decode_vtep_credential checks.
[[nodiscard]] inline auto encode_vtep_credential(const VtepCredential& c)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_vtep_credential(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(vtep_credential_size);
    wire::Writer w{out};
    w.le32(vtep_credential_magic);
    w.le16(vtep_credential_version);
    w.le16(c.key_id);
    w.le64(c.server_id);
    w.le32(c.cell_id);
    w.u8(c.modes);
    w.u8(c.slot);
    w.le16(c.key_epoch);
    w.bytes(c.vtep);
    w.bytes(c.public_key);
    w.le64(c.not_before);
    w.le64(c.not_after);
    w.le64(c.serial);
    w.bytes(c.signature);
    return out;
}

[[nodiscard]] inline auto decode_credential_revocations(std::span<const std::byte> bytes)
    -> std::expected<CredentialRevocations, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto cell_id = r.le32();
    auto reserved1 = r.le32();
    auto list_version = r.le64();
    auto count = r.le32();
    auto reserved2 = r.le32();
    if (!magic || !version || !key_id || !cell_id || !reserved1 || !list_version || !count ||
        !reserved2) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != credential_revocations_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != credential_revocations_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved1 != 0 || *reserved2 != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*count > max_revocations) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    // Check the length before allocating, so a hostile count costs nothing.
    const std::size_t want =
        credential_revocations_size(*count) - credential_revocations_header_size;
    if (r.remaining() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    CredentialRevocations out{.key_id = *key_id,
                              .cell_id = *cell_id,
                              .list_version = *list_version,
                              .entries = {},
                              .signature = {}};
    out.entries.resize(*count);
    for (auto& e : out.entries) {
        // Length was checked above; these reads cannot fail.
        e.serial = r.le64().value_or(0);
        e.not_after = r.le64().value_or(0);
    }
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      out.signature.begin());
    if (auto ok = detail::check_credential_revocations(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a revocation list (with whatever is in `signature`), enforcing
// every rule decode_credential_revocations checks.
[[nodiscard]] inline auto encode_credential_revocations(const CredentialRevocations& l)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_credential_revocations(l); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(credential_revocations_size(l.entries.size()));
    wire::Writer w{out};
    w.le32(credential_revocations_magic);
    w.le16(credential_revocations_version);
    w.le16(l.key_id);
    w.le32(l.cell_id);
    w.le32(0);
    w.le64(l.list_version);
    w.le32(static_cast<std::uint32_t>(l.entries.size()));
    w.le32(0);
    for (const auto& e : l.entries) {
        w.le64(e.serial);
        w.le64(e.not_after);
    }
    w.bytes(l.signature);
    return out;
}

}  // namespace ak::proto
