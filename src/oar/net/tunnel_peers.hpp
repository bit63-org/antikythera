// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// TunnelPeerSet: applies the controller's TunnelPeers frames
// (src/proto/tunnel_peers.hpp) to a network role's Tunnel
// (.kiro/specs/oar-net-data-plane/ Requirement 5.2, design "Tunnel";
// controller-interface Requirement 8).
//
// helm forwards each frame unmodified over the sideband and verifies
// nothing, so this is where the frame is trusted or not. apply():
//
//   1. decodes it strictly, and checks that it names this server and this
//      VTEP;
//   2. verifies the Ed25519 signature over tunnel_peers_signed_bytes with
//      the controller's key `key_id` (the FrameVerifier the role was built
//      with, the same keys as for MapUpdates);
//   3. compares the version with the last one applied: the same version is
//      a re-delivery (helm resends after a sideband reconnect) and changes
//      nothing; an older one is refused;
//   4. makes the frame's peers the Tunnel's controller-managed peers:
//      peers it installed earlier that are gone, or whose key changed, are
//      removed first (so a key that moved between VTEPs is never held by
//      two peers at once), then every peer in the frame is set. Unchanged
//      peers keep their sessions (Tunnel::set_peer leaves them alone).
//
// Every peer must be in WireGuard mode: the role advertises only WireGuard,
// so a PSP peer is a controller error, and the whole frame is refused
// (unsupported) before anything changes.
//
// Peers added directly with Tunnel::set_peer (helm's set_tunnel_peer, for
// pre-shared keys) are left alone unless the frame names their VTEP, in
// which case the frame's key replaces theirs and the pre-shared key is
// cleared. Any refusal leaves the version unchanged, so the frame can be
// sent again; if the Tunnel refuses a peer part way (a key it cannot use,
// which a correct controller never signs), the peers before it are
// installed and the result says rejected.
//
// Not thread-safe: it belongs to the role's data-plane thread, like the
// Tunnel.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <span>

#include "oar/net/tunnel.hpp"
#include "oar/net/vtep_policy.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/tunnel_peers.hpp"

namespace ak::oar::net {

inline constexpr std::size_t frame_signature_size = 64;

// Checks a controller frame signature: Ed25519 over `signed_bytes` under
// the controller key `key_id`. True only if it verifies.
using FrameVerifier = std::function<bool(std::span<const std::byte> signed_bytes,
                                         std::span<const std::byte, frame_signature_size> signature,
                                         std::uint16_t key_id)>;

enum class PeersResult : std::uint8_t {
    applied,        // the Tunnel now has exactly the frame's peers
    redelivered,    // the version already applied: nothing changed
    undecodable,    // proto::decode_tunnel_peers refused it
    wrong_target,   // for another server or another VTEP
    bad_signature,  // the signature does not verify
    stale,          // older than the version applied
    rejected,       // the Tunnel refused a peer's key
    unsupported,    // a peer in a tunnel mode this role does not run (PSP)
};

[[nodiscard]] auto to_string(PeersResult r) noexcept -> const char*;
// True for the results the role answers ok to.
[[nodiscard]] constexpr auto accepted(PeersResult r) noexcept -> bool {
    return r == PeersResult::applied || r == PeersResult::redelivered;
}

struct PeerSetCounters {
    std::uint64_t applied{0};
    std::uint64_t redelivered{0};
    std::uint64_t undecodable{0};
    std::uint64_t wrong_target{0};
    std::uint64_t bad_signature{0};
    std::uint64_t stale{0};
    std::uint64_t rejected{0};
    std::uint64_t unsupported{0};
    std::uint64_t peers_added{0};    // set_peer for a VTEP not installed before
    std::uint64_t peers_removed{0};  // removed: gone from the set, or re-keyed
};

class TunnelPeerSet {
public:
    // `tunnel` must outlive the set. `server_id` and `vtep` are this role's.
    TunnelPeerSet(Tunnel& tunnel, std::uint64_t server_id, const Ipv6Address& vtep,
                  FrameVerifier verifier);

    auto apply(std::span<const std::byte> frame) -> PeersResult;

    // The version applied last; 0 before the first.
    [[nodiscard]] auto version() const noexcept -> std::uint64_t { return _version; }
    // How many controller-managed peers are installed.
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _installed.size(); }
    [[nodiscard]] auto counters() const noexcept -> const PeerSetCounters& { return _counters; }

private:
    auto count(PeersResult r) -> PeersResult;

    Tunnel* _tunnel;
    std::uint64_t _server_id;
    Ipv6Address _vtep;
    FrameVerifier _verifier;
    std::uint64_t _version{0};
    // The peers the last frames installed, by VTEP.
    std::map<Ipv6Address, wg::Key> _installed;
    PeerSetCounters _counters;
};

}  // namespace ak::oar::net
