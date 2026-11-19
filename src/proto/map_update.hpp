// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MapUpdate: the controller's versioned NIC-to-VTEP mapping for one VPC,
// sent to every server hosting a NIC in it (.kiro/specs/controller-interface/
// Requirement 5, design "Envelope"). helm checks it and hands it to oar-net,
// whose MappingTable swaps it in whole (oar-net design "MappingTable").
//
// A MapUpdate is a full snapshot of the VPC's mapping at `map_version`, not
// a delta: applying it is idempotent, a receiver that missed versions
// catches up from the newest one alone, and "converged" (Requirement 5.3)
// is just every member reporting the same version.
//
// Layout (little-endian):
//   0x00  magic        u32  'AKMU'
//   0x04  version      u16  frame format version (1)
//   0x06  key_id       u16  controller key that signed it; non-zero
//   0x08  server_id    u64  target server; non-zero
//   0x10  vni          u32  VPC's 24-bit Geneve VNI; non-zero
//   0x14  entry_count  u16  at most max_map_entries
//   0x16  reserved     u16  zero
//   0x18  map_version  u64  per-VPC, starts at 1, increases on every change
//   0x20  entries      entry_count x 32 bytes, NIC IDs strictly ascending:
//           +0x00 nic_id u64 (non-zero) | +0x08 mac [6] | +0x0E reserved [2]
//           +0x10 owner_vtep [16] (IPv6 underlay address, network order)
//   then  signature    64 bytes, Ed25519 over every byte before it
//
// Unlike the envelope, key_id and server_id are inside the signed bytes:
// nothing else carries them, so a mapping cannot be replayed to another
// server or attributed to another key.
//
// Ascending NIC IDs make the encoding canonical (one byte string per
// mapping, so re-signing is reproducible) and rule out duplicate NICs
// without a set. MACs must be locally administered unicast, the range the
// controller allocates from (Requirement 4.2).

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"

namespace ak::proto {

inline constexpr std::uint32_t map_update_magic = 0x554D'4B41;  // "AKMU" as little-endian bytes
inline constexpr std::uint16_t map_update_version = 1;
inline constexpr std::size_t map_update_header_size = 0x20;
inline constexpr std::size_t map_entry_size = 0x20;
inline constexpr std::uint32_t max_vni = 0x00FF'FFFF;
// Bounds one frame to 128 KiB plus header and signature. A VPC with more
// NICs than this needs a new frame version (deltas or paging).
inline constexpr std::size_t max_map_entries = 4096;
inline constexpr std::size_t max_map_update_size =
    map_update_header_size + (max_map_entries * map_entry_size) + ed25519_signature_size;

inline constexpr std::size_t mac_size = 6;
inline constexpr std::size_t vtep_address_size = 16;
inline constexpr std::uint8_t mac_multicast_bit = 0x01;
inline constexpr std::uint8_t mac_local_bit = 0x02;
inline constexpr std::uint8_t ipv6_multicast_prefix = 0xFF;

using Mac = std::array<std::byte, mac_size>;
using VtepAddress = std::array<std::byte, vtep_address_size>;
using Ed25519Signature = std::array<std::byte, ed25519_signature_size>;

struct MapEntry {
    std::uint64_t nic_id{0};
    Mac mac{};
    VtepAddress owner_vtep{};

    friend auto operator==(const MapEntry&, const MapEntry&) -> bool = default;
};

struct MapUpdate {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint32_t vni{0};
    std::uint64_t map_version{0};
    std::vector<MapEntry> entries;
    Ed25519Signature signature{};

    friend auto operator==(const MapUpdate&, const MapUpdate&) -> bool = default;
};

[[nodiscard]] inline constexpr auto map_update_size(std::size_t entry_count) noexcept
    -> std::size_t {
    return map_update_header_size + (entry_count * map_entry_size) + ed25519_signature_size;
}

// The bytes a MapUpdate signature covers: all but the trailing 64. Callers
// pass a frame that decoded (or that encode_map_update produced).
[[nodiscard]] inline auto map_update_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

// Writes `signature` over the trailing 64 bytes of an encoded frame: encode
// with a blank signature, sign map_update_signed_bytes, then set it.
inline auto set_map_update_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= ed25519_signature_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

namespace detail {

[[nodiscard]] inline auto check_map_header(std::uint64_t server_id, KeyId key_id, std::uint32_t vni,
                                           std::uint64_t map_version,
                                           std::size_t entry_count) noexcept
    -> std::expected<void, DecodeError> {
    if (key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (vni == 0 || vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (map_version == 0) {
        return std::unexpected(DecodeError::bad_map_version);
    }
    if (entry_count > max_map_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    return {};
}

[[nodiscard]] inline auto check_map_entry(const MapEntry& e, std::uint64_t prev_nic_id) noexcept
    -> std::expected<void, DecodeError> {
    if (e.nic_id == 0) {
        return std::unexpected(DecodeError::bad_nic_id);
    }
    if (e.nic_id <= prev_nic_id) {
        return std::unexpected(DecodeError::nic_ids_not_ascending);
    }
    const auto mac0 = std::to_integer<std::uint8_t>(e.mac[0]);
    if ((mac0 & mac_multicast_bit) != 0 || (mac0 & mac_local_bit) == 0) {
        return std::unexpected(DecodeError::bad_mac);
    }
    if (std::ranges::all_of(e.owner_vtep, [](std::byte b) { return b == std::byte{0}; }) ||
        std::to_integer<std::uint8_t>(e.owner_vtep[0]) == ipv6_multicast_prefix) {
        return std::unexpected(DecodeError::bad_vtep);
    }
    return {};
}

[[nodiscard]] inline auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// map_update_signed_bytes(frame) against `signature` under `key_id` before
// acting on anything else in the result.
[[nodiscard]] inline auto decode_map_update(std::span<const std::byte> bytes)
    -> std::expected<MapUpdate, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto vni = r.le32();
    auto entry_count = r.le16();
    auto reserved = r.le16();
    auto map_version = r.le64();
    if (!magic || !version || !key_id || !server_id || !vni || !entry_count || !reserved ||
        !map_version) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != map_update_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != map_update_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_map_header(*server_id, *key_id, *vni, *map_version, *entry_count);
        !ok) {
        return std::unexpected(ok.error());
    }
    // Check the length before allocating, so a hostile count costs nothing.
    const std::size_t want = map_update_size(*entry_count) - map_update_header_size;
    if (r.remaining() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }

    MapUpdate out{.server_id = *server_id,
                  .key_id = *key_id,
                  .vni = *vni,
                  .map_version = *map_version,
                  .entries = {},
                  .signature = {}};
    out.entries.reserve(*entry_count);
    std::uint64_t prev = 0;
    for (std::size_t i = 0; i < *entry_count; ++i) {
        // Length was checked above; these reads cannot fail.
        MapEntry e{};
        e.nic_id = r.le64().value_or(0);
        std::ranges::copy(r.bytes(mac_size).value_or(std::span<const std::byte>{}), e.mac.begin());
        const auto pad = r.bytes(2).value_or(std::span<const std::byte>{});
        std::ranges::copy(r.bytes(vtep_address_size).value_or(std::span<const std::byte>{}),
                          e.owner_vtep.begin());
        if (!detail::all_zero(pad)) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        if (auto ok = detail::check_map_entry(e, prev); !ok) {
            return std::unexpected(ok.error());
        }
        prev = e.nic_id;
        out.entries.push_back(e);
    }
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      out.signature.begin());
    return out;
}

// Encodes a MapUpdate (with whatever is in `signature`), enforcing every
// rule decode_map_update checks.
[[nodiscard]] inline auto encode_map_update(const MapUpdate& m)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok =
            detail::check_map_header(m.server_id, m.key_id, m.vni, m.map_version, m.entries.size());
        !ok) {
        return std::unexpected(ok.error());
    }
    std::uint64_t prev = 0;
    for (const auto& e : m.entries) {
        if (auto ok = detail::check_map_entry(e, prev); !ok) {
            return std::unexpected(ok.error());
        }
        prev = e.nic_id;
    }

    std::vector<std::byte> out;
    out.reserve(map_update_size(m.entries.size()));
    wire::Writer w{out};
    w.le32(map_update_magic);
    w.le16(map_update_version);
    w.le16(m.key_id);
    w.le64(m.server_id);
    w.le32(m.vni);
    w.le16(static_cast<std::uint16_t>(m.entries.size()));
    w.le16(0);
    w.le64(m.map_version);
    for (const auto& e : m.entries) {
        constexpr std::array<std::byte, 2> pad{};
        w.le64(e.nic_id);
        w.bytes(e.mac);
        w.bytes(pad);
        w.bytes(e.owner_vtep);
    }
    w.bytes(m.signature);
    return out;
}

}  // namespace ak::proto
