// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// TunnelPeers: the controller's signed list of the WireGuard peers of one
// VTEP (.kiro/specs/controller-interface/ Requirement 8, design
// "TunnelPeers"; oar-net Requirement 5.2).
//
// Every VTEP has its own X25519 key pair. helm generates it, hands the
// private key to the VTEP's network role over the sideband, and reports
// the public key in its inventory (report.hpp, Inventory::tunnel_keys).
// The controller collects those public keys and sends each VTEP the keys
// of its peers: the other VTEPs it shares a VNI with. helm forwards the
// frame unmodified, and the network role verifies it and installs the
// peers in its Tunnel, as it does with a MapUpdate.
//
// A TunnelPeers frame is a full snapshot of one VTEP's peers at
// `peers_version`, not a delta: applying it is idempotent, and a role that
// missed versions catches up from the newest one alone. Versions are per
// (server, VTEP) and start at 1; a new helm boot generates new keys, which
// the controller sees in the inventory and answers with a new version.
//
// Layout (little-endian):
//   0x00  magic          u32  'AKTP'
//   0x04  version        u16  frame format version (1)
//   0x06  key_id         u16  controller key that signed it; non-zero
//   0x08  server_id      u64  target server; non-zero
//   0x10  vtep           [16] the target VTEP (IPv6 underlay address)
//   0x20  peers_version  u64  per (server, VTEP), starts at 1, increases
//   0x28  peer_count     u16  at most max_tunnel_peers
//   0x2A  reserved       [6]  zero
//   0x30  peers          peer_count x 48 bytes, VTEPs strictly ascending:
//           +0x00 vtep [16] (IPv6, network order) | +0x10 public_key [32]
//   then  signature      64 bytes, Ed25519 over every byte before it
//
// key_id, server_id and the target VTEP are inside the signed bytes, so a
// peer set cannot be replayed to another server or VTEP. Ascending VTEPs
// make the encoding canonical and rule out duplicate peers; no peer may be
// the target VTEP itself, no public key may be all zero, and no two peers
// may share a public key (WireGuard finds a peer by its key).
//
// The frame carries public keys only. WireGuard's optional pre-shared key
// stays unset (all zero) for peers installed this way.

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

inline constexpr std::uint32_t tunnel_peers_magic = 0x5054'4B41;  // "AKTP" as little-endian bytes
inline constexpr std::uint16_t tunnel_peers_version = 1;
inline constexpr std::size_t tunnel_peers_header_size = 0x30;
inline constexpr std::size_t tunnel_key_size = 32;
inline constexpr std::size_t tunnel_peer_size = vtep_address_size + tunnel_key_size;  // 48
// Bounds one frame to 96 KiB plus header and signature, under the largest
// MapUpdate, so the sideband's chunked transfer carries both.
inline constexpr std::size_t max_tunnel_peers = 2048;
inline constexpr std::size_t max_tunnel_peers_size =
    tunnel_peers_header_size + (max_tunnel_peers * tunnel_peer_size) + ed25519_signature_size;

using TunnelPublicKey = std::array<std::byte, tunnel_key_size>;

struct TunnelPeer {
    VtepAddress vtep{};
    TunnelPublicKey public_key{};

    friend auto operator==(const TunnelPeer&, const TunnelPeer&) -> bool = default;
};

struct TunnelPeers {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    VtepAddress vtep{};
    std::uint64_t peers_version{0};
    std::vector<TunnelPeer> peers;
    Ed25519Signature signature{};

    friend auto operator==(const TunnelPeers&, const TunnelPeers&) -> bool = default;
};

[[nodiscard]] inline constexpr auto tunnel_peers_size(std::size_t peer_count) noexcept
    -> std::size_t {
    return tunnel_peers_header_size + (peer_count * tunnel_peer_size) + ed25519_signature_size;
}

// The bytes a TunnelPeers signature covers: all but the trailing 64.
[[nodiscard]] inline auto tunnel_peers_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return map_update_signed_bytes(frame);
}

// Writes `signature` over the trailing 64 bytes of an encoded frame.
inline auto set_tunnel_peers_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    set_map_update_signature(frame, signature);
}

namespace detail {

[[nodiscard]] inline auto valid_unicast_vtep(const VtepAddress& a) noexcept -> bool {
    return !all_zero(a) && std::to_integer<std::uint8_t>(a[0]) != ipv6_multicast_prefix;
}

[[nodiscard]] inline auto check_tunnel_peers(const TunnelPeers& t)
    -> std::expected<void, DecodeError> {
    if (t.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (t.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (!valid_unicast_vtep(t.vtep)) {
        return std::unexpected(DecodeError::bad_vtep);
    }
    if (t.peers_version == 0) {
        return std::unexpected(DecodeError::bad_peers_version);
    }
    if (t.peers.size() > max_tunnel_peers) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < t.peers.size(); ++i) {
        const TunnelPeer& p = t.peers[i];
        if (!valid_unicast_vtep(p.vtep) || p.vtep == t.vtep) {
            return std::unexpected(DecodeError::bad_vtep);
        }
        if (i > 0 && !(t.peers[i - 1].vtep < p.vtep)) {
            return std::unexpected(DecodeError::not_ascending);
        }
        if (all_zero(p.public_key)) {
            return std::unexpected(DecodeError::bad_public_key);
        }
    }
    std::vector<TunnelPublicKey> keys;
    keys.reserve(t.peers.size());
    for (const auto& p : t.peers) {
        keys.push_back(p.public_key);
    }
    std::ranges::sort(keys);
    if (std::ranges::adjacent_find(keys) != keys.end()) {
        return std::unexpected(DecodeError::duplicate_public_key);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// tunnel_peers_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_tunnel_peers(std::span<const std::byte> bytes)
    -> std::expected<TunnelPeers, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto vtep = r.bytes(vtep_address_size);
    auto peers_version = r.le64();
    auto peer_count = r.le16();
    auto reserved = r.bytes(6);
    if (!magic || !version || !key_id || !server_id || !vtep || !peers_version || !peer_count ||
        !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != tunnel_peers_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != tunnel_peers_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!detail::all_zero(*reserved)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*peer_count > max_tunnel_peers) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    // Check the length before allocating, so a hostile count costs nothing.
    const std::size_t want = tunnel_peers_size(*peer_count) - tunnel_peers_header_size;
    if (r.remaining() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }

    TunnelPeers out{.server_id = *server_id,
                    .key_id = *key_id,
                    .vtep = {},
                    .peers_version = *peers_version,
                    .peers = {},
                    .signature = {}};
    std::ranges::copy(*vtep, out.vtep.begin());
    out.peers.resize(*peer_count);
    for (auto& p : out.peers) {
        // Length was checked above; these reads cannot fail.
        std::ranges::copy(r.bytes(vtep_address_size).value_or(std::span<const std::byte>{}),
                          p.vtep.begin());
        std::ranges::copy(r.bytes(tunnel_key_size).value_or(std::span<const std::byte>{}),
                          p.public_key.begin());
    }
    std::ranges::copy(r.bytes(ed25519_signature_size).value_or(std::span<const std::byte>{}),
                      out.signature.begin());
    if (auto ok = detail::check_tunnel_peers(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a TunnelPeers frame (with whatever is in `signature`), enforcing
// every rule decode_tunnel_peers checks.
[[nodiscard]] inline auto encode_tunnel_peers(const TunnelPeers& t)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_tunnel_peers(t); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(tunnel_peers_size(t.peers.size()));
    wire::Writer w{out};
    constexpr std::array<std::byte, 6> pad{};
    w.le32(tunnel_peers_magic);
    w.le16(tunnel_peers_version);
    w.le16(t.key_id);
    w.le64(t.server_id);
    w.bytes(t.vtep);
    w.le64(t.peers_version);
    w.le16(static_cast<std::uint16_t>(t.peers.size()));
    w.bytes(pad);
    for (const auto& p : t.peers) {
        w.bytes(p.vtep);
        w.bytes(p.public_key);
    }
    w.bytes(t.signature);
    return out;
}

}  // namespace ak::proto
