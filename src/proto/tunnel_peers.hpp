// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// TunnelPeers: the controller's signed list of the tunnel peers of one
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
//   0x30  peers          peer_count x 56 bytes, VTEPs strictly ascending:
//           +0x00 vtep [16] (IPv6, network order) | +0x10 mode u8 (TunnelMode)
//           +0x11 reserved [3] | +0x14 spi u32 | +0x18 key [32]
//   then  signature      64 bytes, Ed25519 over every byte before it
//
// key_id, server_id and the target VTEP are inside the signed bytes, so a
// peer set cannot be replayed to another server or VTEP. Ascending VTEPs
// make the encoding canonical and rule out duplicate peers; no peer may be
// the target VTEP itself and no key may be all zero.
//
// Tunnel modes. The controller picks a mode per pair of VTEPs from the
// modes both advertise in their inventories (report.hpp, VtepTunnel),
// so a fleet can move from WireGuard to PSP pair by pair:
//
//   wireguard  key is the peer's X25519 public key; spi is 0. No two
//              WireGuard peers may share a key (WireGuard finds a peer by
//              its key). The pre-shared key stays unset for peers
//              installed this way.
//   psp        reserved for PSP offload: spi is the peer's receive SPI
//              (non-zero) and key the AES-256-GCM key derived for it.
//              Nothing implements PSP yet, and VTEPs advertise only
//              WireGuard, so a correct controller never sends it; a role
//              refuses a frame that asks for it. PSP keys are secrets, so
//              whoever implements it must wipe the frames that held them.

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
inline constexpr std::size_t tunnel_peer_size = vtep_address_size + 8 + tunnel_key_size;  // 56
// Bounds one frame to 112 KiB plus header and signature, under the largest
// MapUpdate, so the sideband's chunked transfer carries both.
inline constexpr std::size_t max_tunnel_peers = 2048;
inline constexpr std::size_t max_tunnel_peers_size =
    tunnel_peers_header_size + (max_tunnel_peers * tunnel_peer_size) + ed25519_signature_size;

using TunnelPublicKey = std::array<std::byte, tunnel_key_size>;
using TunnelKey = std::array<std::byte, tunnel_key_size>;

// How a pair of VTEPs protects its traffic. Values are part of the wire
// protocol: never renumber.
enum class TunnelMode : std::uint8_t {
    wireguard = 1,
    psp = 2,
};

// A VTEP's supported modes, as a bit set (bit = 1 << (mode - 1)).
using TunnelModes = std::uint8_t;
[[nodiscard]] constexpr auto tunnel_mode_bit(TunnelMode m) noexcept -> TunnelModes {
    return static_cast<TunnelModes>(1U << (static_cast<unsigned>(m) - 1U));
}
inline constexpr TunnelModes known_tunnel_modes =
    tunnel_mode_bit(TunnelMode::wireguard) | tunnel_mode_bit(TunnelMode::psp);

struct TunnelPeer {
    VtepAddress vtep{};
    TunnelMode mode{TunnelMode::wireguard};
    std::uint32_t spi{0};  // psp only
    TunnelKey key{};       // wireguard: X25519 public key; psp: the derived key

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
        if (p.mode != TunnelMode::wireguard && p.mode != TunnelMode::psp) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (all_zero(p.key)) {
            return std::unexpected(DecodeError::bad_public_key);
        }
        if ((p.spi != 0) != (p.mode == TunnelMode::psp)) {
            return std::unexpected(DecodeError::bad_id);
        }
    }
    std::vector<TunnelKey> keys;
    keys.reserve(t.peers.size());
    for (const auto& p : t.peers) {
        if (p.mode == TunnelMode::wireguard) {
            keys.push_back(p.key);
        }
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
    bool zero = true;
    for (auto& p : out.peers) {
        // Length was checked above; these reads cannot fail.
        std::ranges::copy(r.bytes(vtep_address_size).value_or(std::span<const std::byte>{}),
                          p.vtep.begin());
        p.mode = static_cast<TunnelMode>(r.u8().value_or(0));
        zero = detail::all_zero(r.bytes(3).value_or(std::span<const std::byte>{})) && zero;
        p.spi = r.le32().value_or(0);
        std::ranges::copy(r.bytes(tunnel_key_size).value_or(std::span<const std::byte>{}),
                          p.key.begin());
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
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
        constexpr std::array<std::byte, 3> rsvd{};
        w.bytes(p.vtep);
        w.u8(static_cast<std::uint8_t>(p.mode));
        w.bytes(rsvd);
        w.le32(p.spi);
        w.bytes(p.key);
    }
    w.bytes(t.signature);
    return out;
}

}  // namespace ak::proto
