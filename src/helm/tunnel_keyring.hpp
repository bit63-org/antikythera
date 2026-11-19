// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// TunnelKeyring: helm's WireGuard key pairs, one per VTEP on this server,
// and the newest controller peer set for each (oar-net Requirement 5.2;
// controller-interface Requirement 8, design "TunnelPeers"; helm design
// "Tunnel keys").
//
// The flow it serves:
//
//   1. A network role attaches and names its VTEP (function_inventory).
//      ensure() generates the VTEP's X25519 key pair the first time, and
//      fill() puts the public key in the inventory helm reports.
//   2. provision() delivers the private key to the role (set_tunnel_key)
//      and, if the controller has already sent one, the newest peer set
//      (tunnel_peers). helm calls it again whenever the role restarts, so
//      a restarted role gets the same key and peers back.
//   3. The controller sends a TunnelPeers frame for the VTEP. store_peers()
//      keeps it if it is newer than the one held, and helm forwards it
//      unmodified to the VTEP's role, which verifies the signature. helm
//      checks only the frame's shape (ControllerSession does) and version,
//      never its signature, as with a MapUpdate.
//
// Key pairs live as long as this helm process: a new helm boot makes new
// ones, which reach the controller in the registration inventory, and the
// controller sends every peer a new peer set. Nothing secret is persisted.
// Private keys are held in SecretBytes and wiped when forgotten.
//
// Not thread-safe: it belongs to helm's loop thread, like the OarLinks.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "helm/oar_link.hpp"
#include "helm/oar_protocol.hpp"
#include "helm/scoped_key.hpp"
#include "proto/report.hpp"
#include "proto/tunnel_peers.hpp"

namespace ak::helm {

enum class KeyringError : std::uint8_t {
    bad_vtep,   // an all-zero or multicast VTEP address
    no_crypto,  // OpenSSL could not generate an X25519 key pair
};

[[nodiscard]] auto to_string(KeyringError e) noexcept -> const char*;

enum class PeersOutcome : std::uint8_t {
    stored,     // newer than the set held (or the first, or a different frame
                // of the same version): forward it
    duplicate,  // exactly the frame already held: nothing new to forward
    stale,      // older than the set held: drop it
};

[[nodiscard]] auto to_string(PeersOutcome o) noexcept -> const char*;

class TunnelKeyring {
public:
    using PublicKey = proto::TunnelPublicKey;

    // The VTEP's public key, generating its key pair the first time.
    auto ensure(const oar::Vtep& vtep) -> std::expected<PublicKey, KeyringError>;
    [[nodiscard]] auto public_key(const oar::Vtep& vtep) const -> std::optional<PublicKey>;
    // Forgets the VTEP's key pair and peer set, wiping the private key.
    // False if there was neither.
    auto forget(const oar::Vtep& vtep) -> bool;

    // Keeps a decoded frame (exact bytes in `frame`) as its VTEP's newest
    // peer set if its version is higher than the one held, or equal with
    // different bytes. helm cannot tell a forged frame from a real one, so
    // a real frame must never be shadowed by a refused one of the same
    // version; the role, which verifies, decides which one applies.
    auto store_peers(const proto::TunnelPeers& peers, std::span<const std::byte> frame)
        -> PeersOutcome;
    // The newest peer set frame held for the VTEP; empty if none.
    [[nodiscard]] auto peers_frame(const oar::Vtep& vtep) const -> std::span<const std::byte>;
    [[nodiscard]] auto peers_version(const oar::Vtep& vtep) const -> std::uint64_t;

    // Brings the VTEP's role up to date over `link`: the private key, then
    // the newest peer set if there is one. Fails as bad_request without
    // sending anything if the VTEP has no key pair (call ensure() first).
    auto provision(OarLink& link, const oar::Vtep& vtep) -> std::expected<void, LinkError>;

    // Sets inv.tunnel_keys from inv.vteps: each VTEP's public key, zero for
    // a VTEP with no key pair; left empty if none has one.
    auto fill(proto::Inventory& inv) const -> void;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _pairs.size(); }

private:
    struct Pair {
        SecretBytes<oar::tunnel_key_size> private_key;
        PublicKey public_key{};
    };
    struct Peers {
        std::uint64_t version{0};
        std::vector<std::byte> frame;
    };

    std::map<oar::Vtep, Pair> _pairs;
    std::map<oar::Vtep, Peers> _peers;
};

}  // namespace ak::helm
