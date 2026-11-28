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
//      ensure() makes the VTEP's X25519 key pair the first time, and
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
// Stable keys (.kiro/specs/fleet-scale-networking/ Requirement 1, task 1).
// helm's keyring derives each VTEP's key pair from the secure element
// (SecureElement::derive_vtep_key: server ID, the role's slot and the
// slot's key epoch), so a helm or board restart gives every role the key
// it had and the controller has nothing to re-sign. Only the epochs are
// persisted (KeyEpochs, a small state file); nothing secret is. A
// keyring built without a deriver draws random keys instead, as helm did
// before (unit tests that do not care which key a VTEP gets).
//
// Rotation. The controller's rotate_vtep_key record raises a slot's epoch
// (rotate()); the keyring stores the new epoch first, then derives the new
// pair, so a crash between the two can only leave the newer epoch. helm
// delivers the new key with a grace period (deliver_rotation()): the role
// keeps sessions made under the old key, and answers handshakes addressed
// to it, until the grace ends, so peers that have not yet learned the new
// public key are not cut off. A rotation for a slot with no network role
// attached only raises the epoch; the role gets the new key when it
// attaches. An epoch at or below the one held is ignored.
//
// Private keys are held in SecretBytes and wiped when forgotten.
//
// Not thread-safe: it belongs to helm's loop thread, like the OarLinks.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
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
    no_crypto,  // OpenSSL or the secure element could not make a key pair
    state_io,   // the key epoch could not be saved; nothing changed
};

[[nodiscard]] auto to_string(KeyringError e) noexcept -> const char*;

enum class EpochFileError : std::uint8_t {
    io,       // the file could not be read or written
    corrupt,  // a line is not `vtep-key-epoch SLOT EPOCH`, or repeats a slot
};

[[nodiscard]] auto to_string(EpochFileError e) noexcept -> const char*;

// Each slot's VTEP key epoch: 1 until the controller rotates it. With a
// path, every raise is written to the file (a temporary file, fsynced,
// then renamed over it) before it takes effect, and open() reads them
// back; without one they live in memory. The file holds one line per
// rotated slot: `vtep-key-epoch SLOT EPOCH`. A corrupt file is refused
// rather than read as epoch 1, which would bring back a retired key.
class KeyEpochs {
public:
    static constexpr std::uint32_t first = 1;

    KeyEpochs() = default;
    // Reads `path`, which need not exist yet.
    [[nodiscard]] static auto open(std::filesystem::path path)
        -> std::expected<KeyEpochs, EpochFileError>;

    [[nodiscard]] auto epoch(std::uint8_t slot) const -> std::uint32_t;
    // Sets the slot's epoch, saving the file first. `epoch` must be above
    // the current one (the caller checks).
    auto raise(std::uint8_t slot, std::uint32_t epoch) -> std::expected<void, EpochFileError>;

private:
    [[nodiscard]] auto save(const std::map<std::uint8_t, std::uint32_t>& epochs) const
        -> std::expected<void, EpochFileError>;

    std::optional<std::filesystem::path> _path;
    std::map<std::uint8_t, std::uint32_t> _epochs;
};

enum class RotateOutcome : std::uint8_t {
    rotated,  // the slot's VTEP has a new key pair: deliver it
    raised,   // no VTEP key for the slot yet: it gets the new epoch's key
    stale,    // at or below the epoch held: nothing changed
};

[[nodiscard]] auto to_string(RotateOutcome o) noexcept -> const char*;

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
    // Writes the private key of `slot` at `epoch`; false on failure.
    using Deriver = std::function<bool(std::uint8_t slot, std::uint32_t epoch,
                                       std::span<std::byte, oar::tunnel_key_size> out)>;

    // Random keys, epochs in memory.
    TunnelKeyring() = default;
    // Derived keys; `epochs` as opened from helm's state file.
    TunnelKeyring(Deriver derive, KeyEpochs epochs);

    // The public key of the VTEP served from `slot`, making its key pair
    // the first time (or again if the VTEP moved to another slot).
    auto ensure(const oar::Vtep& vtep, std::uint8_t slot) -> std::expected<PublicKey, KeyringError>;
    [[nodiscard]] auto public_key(const oar::Vtep& vtep) const -> std::optional<PublicKey>;
    // Forgets the VTEP's key pair and peer set, wiping the private key.
    // False if there was neither.
    auto forget(const oar::Vtep& vtep) -> bool;

    // Moves `slot` to `epoch` (a controller rotate_vtep_key). On rotated,
    // `rotated_vtep` names the VTEP whose key changed.
    auto rotate(std::uint8_t slot, std::uint32_t epoch, oar::Vtep* rotated_vtep = nullptr)
        -> std::expected<RotateOutcome, KeyringError>;
    [[nodiscard]] auto key_epoch(std::uint8_t slot) const -> std::uint32_t {
        return _epochs.epoch(slot);
    }

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
    // Delivers a rotated key, asking the role to keep the old one for
    // `grace`. A role that refuses the grace form (bad_request: built
    // before rotation) gets the plain key instead, dropping its sessions.
    auto deliver_rotation(OarLink& link, const oar::Vtep& vtep, std::chrono::seconds grace)
        -> std::expected<void, LinkError>;

    // Sets inv.tunnels from inv.vteps: each VTEP supports WireGuard (the
    // only mode oar-net implements) and has its public key, zero for a
    // VTEP with no key pair yet.
    auto fill(proto::Inventory& inv) const -> void;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _pairs.size(); }

private:
    struct Pair {
        SecretBytes<oar::tunnel_key_size> private_key;
        PublicKey public_key{};
        std::uint8_t slot{0};
        std::uint32_t epoch{0};
    };

    // A pair for `slot` at its current epoch.
    [[nodiscard]] auto make_pair(std::uint8_t slot) const -> std::optional<Pair>;

    Deriver _derive;  // empty: random keys
    KeyEpochs _epochs;
    struct Peers {
        std::uint64_t version{0};
        std::vector<std::byte> frame;
    };

    std::map<oar::Vtep, Pair> _pairs;
    std::map<oar::Vtep, Peers> _peers;
};

}  // namespace ak::helm
