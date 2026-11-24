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
//   0x04  version      u16  frame format version (3)
//   0x06  key_id       u16  controller key that signed it; non-zero
//   0x08  server_id    u64  target server; non-zero
//   0x10  vni          u32  VPC's 24-bit Geneve VNI; non-zero
//   0x14  entry_count  u16  at most max_map_entries
//   0x16  ipv4_count   u16  at most max_guest_addresses
//   0x18  map_version  u64  per-VPC, starts at 1, increases on every change
//   0x20  ipv6_count   u16  at most max_guest_addresses
//   0x22  reserved     6 bytes, zero
//   0x28  entries      entry_count x 32 bytes, NIC IDs strictly ascending:
//           +0x00 nic_id u64 (non-zero) | +0x08 mac [6] | +0x0E flags u8
//           (bit 0: source/destination check off) | +0x0F reserved u8
//           +0x10 owner_vtep [16] (IPv6 underlay address, network order)
//   then  ipv4         ipv4_count x 16 bytes, addresses strictly ascending:
//           +0x00 nic_id u64 | +0x08 address [4] (network order) | +0x0C reserved [4]
//   then  ipv6         ipv6_count x 24 bytes, addresses strictly ascending:
//           +0x00 nic_id u64 | +0x08 address [16] (network order)
//   then  signature    64 bytes, Ed25519 over every byte before it
//
// Version 2 added the guest addresses: the IPv4 and IPv6 addresses each
// NIC owns inside the VPC, which oar-net's ARP/ND proxy answers for with
// that NIC's MAC (oar-net-data-plane design "VSwitch"). Every address names
// a NIC listed in the same frame, so the proxy can never answer for a NIC
// the mapping does not know, and an address appears at most once (sorted,
// so canonical). Addresses must be unicast: IPv4 not 0.0.0.0 and below
// 224.0.0.0, IPv6 neither unspecified nor multicast.
//
// Version 3 added per-NIC flags in what was entry padding. Bit 0 turns the
// NIC's source/destination check off (oar-net Requirement 11.10, like EC2
// `SourceDestCheck=false`): it may send from addresses it does not own and
// receive traffic addressed to others, so it can be a route target
// (proto::VpcConfigFrame routes). The flag is in the signed mapping, not a
// separate frame, so every VTEP judges the NIC's traffic by the same
// record. Nothing spoke versions 1 or 2 outside this repository, so decode
// accepts version 3 only.
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
inline constexpr std::uint16_t map_update_version = 3;
inline constexpr std::uint8_t map_entry_no_source_dest_check = 0x01;
inline constexpr std::size_t map_update_header_size = 0x28;
inline constexpr std::size_t map_update_reserved_offset = 0x22;
inline constexpr std::size_t map_entry_size = 0x20;
inline constexpr std::size_t map_ipv4_size = 0x10;
inline constexpr std::size_t map_ipv6_size = 0x18;
inline constexpr std::uint32_t max_vni = 0x00FF'FFFF;
// Bound one frame to about 450 KiB. A VPC with more NICs or addresses than
// this needs a new frame version (deltas or paging).
inline constexpr std::size_t max_map_entries = 4096;
inline constexpr std::size_t max_guest_addresses = 8192;  // per address family

inline constexpr std::size_t mac_size = 6;
inline constexpr std::size_t vtep_address_size = 16;
inline constexpr std::size_t ipv4_address_size = 4;
inline constexpr std::size_t ipv6_address_size = 16;
inline constexpr std::uint8_t ipv4_multicast_first_octet = 224;  // 224.0.0.0 and up
inline constexpr std::uint8_t mac_multicast_bit = 0x01;
inline constexpr std::uint8_t mac_local_bit = 0x02;
inline constexpr std::uint8_t ipv6_multicast_prefix = 0xFF;

using Mac = std::array<std::byte, mac_size>;
using VtepAddress = std::array<std::byte, vtep_address_size>;
using Ipv4Address = std::array<std::byte, ipv4_address_size>;
using Ipv6Address = std::array<std::byte, ipv6_address_size>;
using Ed25519Signature = std::array<std::byte, ed25519_signature_size>;

struct MapEntry {
    std::uint64_t nic_id{0};
    Mac mac{};
    VtepAddress owner_vtep{};
    bool source_dest_check{true};  // false: the NIC may send and receive for others

    friend auto operator==(const MapEntry&, const MapEntry&) -> bool = default;
};

// A guest address the ARP/ND proxy answers for, and the NIC that owns it.
struct GuestIpv4 {
    std::uint64_t nic_id{0};
    Ipv4Address address{};

    friend auto operator==(const GuestIpv4&, const GuestIpv4&) -> bool = default;
};

struct GuestIpv6 {
    std::uint64_t nic_id{0};
    Ipv6Address address{};

    friend auto operator==(const GuestIpv6&, const GuestIpv6&) -> bool = default;
};

struct MapUpdate {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint32_t vni{0};
    std::uint64_t map_version{0};
    std::vector<MapEntry> entries;
    std::vector<GuestIpv4> ipv4;  // addresses strictly ascending
    std::vector<GuestIpv6> ipv6;  // addresses strictly ascending
    Ed25519Signature signature{};

    friend auto operator==(const MapUpdate&, const MapUpdate&) -> bool = default;
};

[[nodiscard]] inline constexpr auto map_update_size(std::size_t entry_count,
                                                    std::size_t ipv4_count = 0,
                                                    std::size_t ipv6_count = 0) noexcept
    -> std::size_t {
    return map_update_header_size + (entry_count * map_entry_size) + (ipv4_count * map_ipv4_size) +
           (ipv6_count * map_ipv6_size) + ed25519_signature_size;
}

inline constexpr std::size_t max_map_update_size =
    map_update_size(max_map_entries, max_guest_addresses, max_guest_addresses);

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
                                           std::uint64_t map_version, std::size_t entry_count,
                                           std::size_t ipv4_count, std::size_t ipv6_count) noexcept
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
    if (ipv4_count > max_guest_addresses || ipv6_count > max_guest_addresses) {
        return std::unexpected(DecodeError::too_many_addresses);
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

[[nodiscard]] inline auto unicast(const Ipv4Address& a) noexcept -> bool {
    return !all_zero(a) && std::to_integer<std::uint8_t>(a[0]) < ipv4_multicast_first_octet;
}

[[nodiscard]] inline auto unicast(const Ipv6Address& a) noexcept -> bool {
    return !all_zero(a) && std::to_integer<std::uint8_t>(a[0]) != ipv6_multicast_prefix;
}

// Checks one address list: unicast, strictly ascending (so each address
// once), and every owner a NIC in `entries` (which are sorted by NIC ID).
template<typename Guest>
[[nodiscard]] auto check_addresses(std::span<const Guest> guests,
                                   std::span<const MapEntry> entries) noexcept
    -> std::expected<void, DecodeError> {
    const Guest* prev = nullptr;
    for (const auto& g : guests) {
        if (!unicast(g.address)) {
            return std::unexpected(DecodeError::bad_guest_address);
        }
        if (prev != nullptr && !std::ranges::lexicographical_compare(prev->address, g.address)) {
            return std::unexpected(DecodeError::addresses_not_ascending);
        }
        if (!std::ranges::binary_search(entries, g.nic_id, std::ranges::less{},
                                        &MapEntry::nic_id)) {
            return std::unexpected(DecodeError::unknown_address_nic);
        }
        prev = &g;
    }
    return {};
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
    auto ipv4_count = r.le16();
    auto map_version = r.le64();
    auto ipv6_count = r.le16();
    auto reserved = r.bytes(map_update_header_size - map_update_reserved_offset);
    if (!magic || !version || !key_id || !server_id || !vni || !entry_count || !ipv4_count ||
        !map_version || !ipv6_count || !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != map_update_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != map_update_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!detail::all_zero(*reserved)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_map_header(*server_id, *key_id, *vni, *map_version, *entry_count,
                                           *ipv4_count, *ipv6_count);
        !ok) {
        return std::unexpected(ok.error());
    }
    // Check the length before allocating, so a hostile count costs nothing.
    const std::size_t want =
        map_update_size(*entry_count, *ipv4_count, *ipv6_count) - map_update_header_size;
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
                  .ipv4 = {},
                  .ipv6 = {},
                  .signature = {}};
    out.entries.reserve(*entry_count);
    std::uint64_t prev = 0;
    for (std::size_t i = 0; i < *entry_count; ++i) {
        // Length was checked above; these reads cannot fail.
        MapEntry e{};
        e.nic_id = r.le64().value_or(0);
        std::ranges::copy(r.bytes(mac_size).value_or(std::span<const std::byte>{}), e.mac.begin());
        const auto flags = r.u8().value_or(0);
        const auto pad = r.u8().value_or(0);
        std::ranges::copy(r.bytes(vtep_address_size).value_or(std::span<const std::byte>{}),
                          e.owner_vtep.begin());
        if (pad != 0 || (flags & ~map_entry_no_source_dest_check) != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        e.source_dest_check = (flags & map_entry_no_source_dest_check) == 0;
        if (auto ok = detail::check_map_entry(e, prev); !ok) {
            return std::unexpected(ok.error());
        }
        prev = e.nic_id;
        out.entries.push_back(e);
    }
    out.ipv4.reserve(*ipv4_count);
    for (std::size_t i = 0; i < *ipv4_count; ++i) {
        GuestIpv4 g{};
        g.nic_id = r.le64().value_or(0);
        std::ranges::copy(r.bytes(ipv4_address_size).value_or(std::span<const std::byte>{}),
                          g.address.begin());
        if (!detail::all_zero(r.bytes(4).value_or(std::span<const std::byte>{}))) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        out.ipv4.push_back(g);
    }
    out.ipv6.reserve(*ipv6_count);
    for (std::size_t i = 0; i < *ipv6_count; ++i) {
        GuestIpv6 g{};
        g.nic_id = r.le64().value_or(0);
        std::ranges::copy(r.bytes(ipv6_address_size).value_or(std::span<const std::byte>{}),
                          g.address.begin());
        out.ipv6.push_back(g);
    }
    if (auto ok = detail::check_addresses<GuestIpv4>(out.ipv4, out.entries); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = detail::check_addresses<GuestIpv6>(out.ipv6, out.entries); !ok) {
        return std::unexpected(ok.error());
    }
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      out.signature.begin());
    return out;
}

// Encodes a MapUpdate (with whatever is in `signature`), enforcing every
// rule decode_map_update checks.
[[nodiscard]] inline auto encode_map_update(const MapUpdate& m)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_map_header(m.server_id, m.key_id, m.vni, m.map_version,
                                           m.entries.size(), m.ipv4.size(), m.ipv6.size());
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
    if (auto ok = detail::check_addresses<GuestIpv4>(m.ipv4, m.entries); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = detail::check_addresses<GuestIpv6>(m.ipv6, m.entries); !ok) {
        return std::unexpected(ok.error());
    }

    std::vector<std::byte> out;
    out.reserve(map_update_size(m.entries.size(), m.ipv4.size(), m.ipv6.size()));
    wire::Writer w{out};
    w.le32(map_update_magic);
    w.le16(map_update_version);
    w.le16(m.key_id);
    w.le64(m.server_id);
    w.le32(m.vni);
    w.le16(static_cast<std::uint16_t>(m.entries.size()));
    w.le16(static_cast<std::uint16_t>(m.ipv4.size()));
    w.le64(m.map_version);
    w.le16(static_cast<std::uint16_t>(m.ipv6.size()));
    w.bytes(std::array<std::byte, map_update_header_size - map_update_reserved_offset>{});
    for (const auto& e : m.entries) {
        w.le64(e.nic_id);
        w.bytes(e.mac);
        w.u8(e.source_dest_check ? std::uint8_t{0} : map_entry_no_source_dest_check);
        w.u8(0);
        w.bytes(e.owner_vtep);
    }
    for (const auto& g : m.ipv4) {
        w.le64(g.nic_id);
        w.bytes(g.address);
        w.le32(0);
    }
    for (const auto& g : m.ipv6) {
        w.le64(g.nic_id);
        w.bytes(g.address);
    }
    w.bytes(m.signature);
    return out;
}

}  // namespace ak::proto
