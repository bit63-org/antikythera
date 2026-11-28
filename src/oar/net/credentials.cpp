// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/credentials.hpp"

#include <algorithm>
#include <utility>

namespace ak::oar::net {

auto to_string(CredentialResult r) noexcept -> const char* {
    switch (r) {
        case CredentialResult::installed:
            return "installed";
        case CredentialResult::redelivered:
            return "redelivered";
        case CredentialResult::undecodable:
            return "undecodable";
        case CredentialResult::wrong_target:
            return "wrong_target";
        case CredentialResult::wrong_key:
            return "wrong_key";
        case CredentialResult::bad_signature:
            return "bad_signature";
        case CredentialResult::expired:
            return "expired";
        case CredentialResult::stale:
            return "stale";
    }
    return "unknown";
}

auto to_string(PeerCredentialError e) noexcept -> const char* {
    switch (e) {
        case PeerCredentialError::undecodable:
            return "undecodable";
        case PeerCredentialError::bad_signature:
            return "bad_signature";
        case PeerCredentialError::not_yet_valid:
            return "not_yet_valid";
        case PeerCredentialError::expired:
            return "expired";
        case PeerCredentialError::revoked:
            return "revoked";
        case PeerCredentialError::wrong_source:
            return "wrong_source";
        case PeerCredentialError::no_mode:
            return "no_mode";
    }
    return "unknown";
}

CredentialStore::CredentialStore(CredentialConfig config, FrameVerifier verifier)
    : _config{std::move(config)}, _verifier{std::move(verifier)} {}

auto CredentialStore::now_unix() const -> std::uint64_t {
    const auto now = _config.wall_clock ? _config.wall_clock() : std::chrono::system_clock::now();
    const auto secs =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return secs < 0 ? 0 : static_cast<std::uint64_t>(secs);
}

auto CredentialStore::signature_ok(std::span<const std::byte> frame,
                                   const proto::Ed25519Signature& signature,
                                   proto::KeyId key_id) const -> bool {
    return _verifier &&
           _verifier(proto::credential_signed_bytes(frame),
                     std::span<const std::byte, frame_signature_size>{signature}, key_id);
}

auto CredentialStore::install_own(std::span<const std::byte> frame, const wg::Key& current_key)
    -> CredentialResult {
    const auto refuse = [this](CredentialResult r) {
        ++_counters.own_refused;
        return r;
    };
    auto c = proto::decode_vtep_credential(frame);
    if (!c) {
        return refuse(CredentialResult::undecodable);
    }
    if (c->server_id != _config.server_id || c->vtep != _config.vtep) {
        return refuse(CredentialResult::wrong_target);
    }
    if (!std::ranges::equal(c->public_key, current_key)) {
        return refuse(CredentialResult::wrong_key);
    }
    if (!signature_ok(frame, c->signature, c->key_id)) {
        return refuse(CredentialResult::bad_signature);
    }
    const auto skew = static_cast<std::uint64_t>(_config.skew.count());
    if (c->not_after + skew <= now_unix()) {
        return refuse(CredentialResult::expired);
    }
    if (_own && std::ranges::equal(_own_frame, frame)) {
        return CredentialResult::redelivered;
    }
    // The same key: keep the newer credential. A different key (the role
    // was rotated) always takes the new one.
    if (_own && _own->public_key == c->public_key &&
        (c->not_after < _own->not_after ||
         (c->not_after == _own->not_after && c->serial <= _own->serial))) {
        return refuse(CredentialResult::stale);
    }
    _own = *c;
    _own_frame.assign(frame.begin(), frame.end());
    ++_counters.own_installed;
    return CredentialResult::installed;
}

auto CredentialStore::own(const wg::Key& current_key) const
    -> std::optional<std::span<const std::byte>> {
    if (!_own || !std::ranges::equal(_own->public_key, current_key)) {
        return std::nullopt;
    }
    const auto now = now_unix();
    const auto skew = static_cast<std::uint64_t>(_config.skew.count());
    if (now + skew < _own->not_before || _own->not_after + skew <= now) {
        return std::nullopt;
    }
    return std::span<const std::byte>{_own_frame};
}

auto CredentialStore::install_revocations(std::span<const std::byte> frame) -> CredentialResult {
    const auto refuse = [this](CredentialResult r) {
        ++_counters.revocations_refused;
        return r;
    };
    auto l = proto::decode_credential_revocations(frame);
    if (!l) {
        return refuse(CredentialResult::undecodable);
    }
    if (!signature_ok(frame, l->signature, l->key_id)) {
        return refuse(CredentialResult::bad_signature);
    }
    auto& held = _revocations[l->cell_id];
    if (l->list_version < held.version) {
        return refuse(CredentialResult::stale);
    }
    if (l->list_version == held.version) {
        // A different list under the same version is the controller's bug;
        // the first verified one stands.
        return std::ranges::equal(held.frame, frame) ? CredentialResult::redelivered
                                                     : refuse(CredentialResult::stale);
    }
    held.version = l->list_version;
    held.entries = std::move(l->entries);
    held.frame.assign(frame.begin(), frame.end());
    ++_counters.revocations_installed;
    return CredentialResult::installed;
}

auto CredentialStore::revoked(std::uint32_t cell_id, std::uint64_t serial) const -> bool {
    const auto it = _revocations.find(cell_id);
    if (it == _revocations.end()) {
        return false;
    }
    const auto& entries = it->second.entries;
    const auto e = std::ranges::lower_bound(entries, serial, {}, &proto::Revocation::serial);
    // An entry outlives the credential it revokes by the skew allowance, so
    // a peer whose clock lags cannot use it in between.
    return e != entries.end() && e->serial == serial &&
           now_unix() < e->not_after + static_cast<std::uint64_t>(_config.skew.count());
}

auto CredentialStore::revocations_version(std::uint32_t cell_id) const -> std::uint64_t {
    const auto it = _revocations.find(cell_id);
    return it == _revocations.end() ? 0 : it->second.version;
}

auto CredentialStore::verify_peer(std::span<const std::byte> frame, const Ipv6Address& source)
    -> std::expected<proto::VtepCredential, PeerCredentialError> {
    const auto refuse = [this](PeerCredentialError e) {
        ++_counters.peer_refused.at(static_cast<std::size_t>(e));
        return std::unexpected(e);
    };
    auto c = proto::decode_vtep_credential(frame);
    if (!c) {
        return refuse(PeerCredentialError::undecodable);
    }
    if (c->vtep != source) {
        return refuse(PeerCredentialError::wrong_source);
    }
    if ((c->modes & proto::tunnel_mode_bit(proto::TunnelMode::wireguard)) == 0) {
        return refuse(PeerCredentialError::no_mode);
    }
    if (!signature_ok(frame, c->signature, c->key_id)) {
        return refuse(PeerCredentialError::bad_signature);
    }
    const auto now = now_unix();
    const auto skew = static_cast<std::uint64_t>(_config.skew.count());
    if (now + skew < c->not_before) {
        return refuse(PeerCredentialError::not_yet_valid);
    }
    if (c->not_after + skew <= now) {
        return refuse(PeerCredentialError::expired);
    }
    if (revoked(c->cell_id, c->serial)) {
        return refuse(PeerCredentialError::revoked);
    }
    ++_counters.peer_verified;
    return *c;
}

}  // namespace ak::oar::net
