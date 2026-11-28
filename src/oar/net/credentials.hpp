// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// CredentialStore: a network role's own VTEP credential and the cells'
// revocation lists (.kiro/specs/fleet-scale-networking/ Requirements 2.3,
// 2.4 and 3, design "VTEP credentials", task 2).
//
// helm forwards both frames unmodified (vtep_credential and
// credential_revocations over OarLink); this is where they are trusted.
//
// install_own() takes the role's own credential. It is decoded strictly,
// must name this server and this VTEP and carry the role's current
// public key (Requirement 2.4: a credential for an old key, another VTEP
// or another server is refused), and its signature must verify under the
// controller key it names. A credential already past its not_after is
// refused too; one not yet valid is kept (the role's clock may lag the
// controller's) and becomes presentable at not_before less the skew. A
// newer credential (a later not_after, or the same window with a higher
// serial) replaces the one held; the same bytes again are a re-delivery.
// After a key rotation the held credential no longer matches the key and
// own() stops returning it until the controller certifies the new key.
//
// install_revocations() keeps, per cell, the highest list_version whose
// signature verifies. revoked() says whether a credential's serial is on
// its cell's list and the entry has not yet expired.
//
// verify_peer() (used by the tunnel's credential exchange in task 3)
// checks a peer's credential: decoded, signature, the validity window
// against the role's wall clock with the skew allowance, not revoked,
// naming the address it arrived from, and advertising WireGuard.
//
// Not thread-safe: it belongs to the role's data-plane thread.

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "oar/net/tunnel_peers.hpp"
#include "oar/net/vtep.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/vtep_credential.hpp"

namespace ak::oar::net {

enum class CredentialResult : std::uint8_t {
    installed,      // now the role's credential (or the cell's revocation list)
    redelivered,    // exactly what is held: nothing changed
    undecodable,    // the strict decoder refused it
    wrong_target,   // another server or VTEP
    wrong_key,      // not the role's current public key
    bad_signature,  // the signature does not verify
    expired,        // past not_after (with the skew allowance)
    stale,          // older than what is held
};

[[nodiscard]] auto to_string(CredentialResult r) noexcept -> const char*;
[[nodiscard]] constexpr auto accepted(CredentialResult r) noexcept -> bool {
    return r == CredentialResult::installed || r == CredentialResult::redelivered;
}

// Why a peer's credential was refused. Counted per reason.
enum class PeerCredentialError : std::uint8_t {
    undecodable,
    bad_signature,
    not_yet_valid,
    expired,
    revoked,
    wrong_source,  // vtep is not the address the credential arrived from
    no_mode,       // does not advertise WireGuard
};

inline constexpr std::size_t peer_credential_error_count =
    static_cast<std::size_t>(PeerCredentialError::no_mode) + 1;

[[nodiscard]] auto to_string(PeerCredentialError e) noexcept -> const char*;

struct CredentialConfig {
    std::uint64_t server_id{0};
    Ipv6Address vtep{};
    // Allowance for clock differences when checking validity windows
    // (design: 5 minutes).
    std::chrono::seconds skew{std::chrono::minutes{5}};
    // Empty: system_clock::now. Credentials carry Unix seconds.
    std::function<std::chrono::system_clock::time_point()> wall_clock;
};

struct CredentialCounters {
    std::uint64_t own_installed{0};
    std::uint64_t own_refused{0};
    std::uint64_t revocations_installed{0};
    std::uint64_t revocations_refused{0};
    std::array<std::uint64_t, peer_credential_error_count> peer_refused{};
    std::uint64_t peer_verified{0};
};

class CredentialStore {
public:
    CredentialStore(CredentialConfig config, FrameVerifier verifier);

    // The role's own credential, for the role's current public key.
    auto install_own(std::span<const std::byte> frame, const wg::Key& current_key)
        -> CredentialResult;
    // The held credential's exact bytes, if it certifies `current_key` and
    // is inside its validity window (with the skew allowance).
    [[nodiscard]] auto own(const wg::Key& current_key) const
        -> std::optional<std::span<const std::byte>>;
    [[nodiscard]] auto own_credential() const -> const std::optional<proto::VtepCredential>& {
        return _own;
    }

    auto install_revocations(std::span<const std::byte> frame) -> CredentialResult;
    [[nodiscard]] auto revoked(std::uint32_t cell_id, std::uint64_t serial) const -> bool;
    [[nodiscard]] auto revocations_version(std::uint32_t cell_id) const -> std::uint64_t;

    // A peer's credential, received from `source`; the decoded credential
    // if it may be used.
    auto verify_peer(std::span<const std::byte> frame, const Ipv6Address& source)
        -> std::expected<proto::VtepCredential, PeerCredentialError>;

    // Unix seconds now, by the configured clock.
    [[nodiscard]] auto now_unix() const -> std::uint64_t;
    [[nodiscard]] auto counters() const noexcept -> const CredentialCounters& { return _counters; }

private:
    struct Revocations {
        std::uint64_t version{0};
        std::vector<proto::Revocation> entries;
        std::vector<std::byte> frame;
    };

    [[nodiscard]] auto signature_ok(std::span<const std::byte> frame,
                                    const proto::Ed25519Signature& signature,
                                    proto::KeyId key_id) const -> bool;

    CredentialConfig _config;
    FrameVerifier _verifier;
    std::optional<proto::VtepCredential> _own;
    std::vector<std::byte> _own_frame;
    std::map<std::uint32_t, Revocations> _revocations;
    CredentialCounters _counters;
};

}  // namespace ak::oar::net
