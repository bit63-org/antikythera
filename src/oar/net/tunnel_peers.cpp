// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/tunnel_peers.hpp"

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

namespace ak::oar::net {

auto to_string(PeersResult r) noexcept -> const char* {
    switch (r) {
        case PeersResult::applied:
            return "applied";
        case PeersResult::redelivered:
            return "redelivered";
        case PeersResult::undecodable:
            return "undecodable";
        case PeersResult::wrong_target:
            return "wrong_target";
        case PeersResult::bad_signature:
            return "bad_signature";
        case PeersResult::stale:
            return "stale";
        case PeersResult::rejected:
            return "rejected";
        case PeersResult::unsupported:
            return "unsupported";
    }
    return "unknown";
}

TunnelPeerSet::TunnelPeerSet(Tunnel& tunnel, std::uint64_t server_id, const Ipv6Address& vtep,
                             FrameVerifier verifier)
    : _tunnel{&tunnel}, _server_id{server_id}, _vtep{vtep}, _verifier{std::move(verifier)} {}

auto TunnelPeerSet::count(PeersResult r) -> PeersResult {
    switch (r) {
        case PeersResult::applied:
            ++_counters.applied;
            break;
        case PeersResult::redelivered:
            ++_counters.redelivered;
            break;
        case PeersResult::undecodable:
            ++_counters.undecodable;
            break;
        case PeersResult::wrong_target:
            ++_counters.wrong_target;
            break;
        case PeersResult::bad_signature:
            ++_counters.bad_signature;
            break;
        case PeersResult::stale:
            ++_counters.stale;
            break;
        case PeersResult::rejected:
            ++_counters.rejected;
            break;
        case PeersResult::unsupported:
            ++_counters.unsupported;
            break;
    }
    return r;
}

auto TunnelPeerSet::apply(std::span<const std::byte> frame) -> PeersResult {
    auto peers = proto::decode_tunnel_peers(frame);
    if (!peers) {
        return count(PeersResult::undecodable);
    }
    if (peers->server_id != _server_id || peers->vtep != _vtep) {
        return count(PeersResult::wrong_target);
    }
    if (!_verifier || !_verifier(proto::tunnel_peers_signed_bytes(frame),
                                 std::span<const std::byte, frame_signature_size>{peers->signature},
                                 peers->key_id)) {
        return count(PeersResult::bad_signature);
    }
    if (peers->peers_version == _version) {
        return count(PeersResult::redelivered);
    }
    if (peers->peers_version < _version) {
        return count(PeersResult::stale);
    }

    if (std::ranges::any_of(peers->peers, [](const proto::TunnelPeer& p) {
            return p.mode != proto::TunnelMode::wireguard;
        })) {
        return count(PeersResult::unsupported);
    }
    std::map<Ipv6Address, wg::Key> wanted;
    for (const auto& p : peers->peers) {
        wanted.emplace(p.vtep, p.key);
    }
    // Remove first, so a key moving from one VTEP to another is never held
    // by two peers (the Tunnel refuses duplicate keys).
    for (auto it = _installed.begin(); it != _installed.end();) {
        const auto w = wanted.find(it->first);
        if (w == wanted.end() || w->second != it->second) {
            _tunnel->remove_peer(it->first);
            ++_counters.peers_removed;
            it = _installed.erase(it);
        } else {
            ++it;
        }
    }
    constexpr wg::Key no_psk{};
    for (const auto& [vtep, key] : wanted) {
        if (!_tunnel->set_peer(vtep, key, no_psk)) {
            return count(PeersResult::rejected);
        }
        if (_installed.emplace(vtep, key).second) {
            ++_counters.peers_added;
        }
    }
    _version = peers->peers_version;
    return count(PeersResult::applied);
}

}  // namespace ak::oar::net
