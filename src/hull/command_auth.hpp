// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The agent's front door for a command slot copied out of the mailbox, in the
// order .kiro/specs/hull-host-agent/ Requirement 3.4 fixes: strict decode,
// then signature, then sequence number, rejecting at the first failure. Body
// validation (decode_create_vm and friends) comes after, per command type.

#include <cstdint>
#include <expected>

#include "helm/mailbox.hpp"
#include "hull/sequence_tracker.hpp"
#include "hull/signature_verifier.hpp"

namespace ak::hull {

enum class AuthFailure : std::uint8_t {
    malformed,       // mailbox::decode rejected the slot; see AuthError::decode
    not_a_command,   // a well-formed response or event type in the command slot
    unknown_key,     // no compiled-in key has the slot's key ID
    bad_signature,   // the signature does not verify
    crypto_failure,  // OpenSSL failed before it could decide
    replayed,        // sequence number not above the last accepted one
};

struct AuthError {
    AuthFailure failure{AuthFailure::malformed};
    // Meaningful only when failure == malformed.
    helm::mailbox::DecodeError decode{helm::mailbox::DecodeError::bad_magic};

    friend auto operator==(const AuthError&, const AuthError&) -> bool = default;
};

[[nodiscard]] auto to_string(AuthFailure f) noexcept -> const char*;

// Authenticates one command slot. The sequence tracker advances only when
// the slot decodes, is a command and carries a valid signature, so neither
// garbage nor a forgery can consume sequence numbers.
//
// The verification key is the one named by the slot header's key_id
// (mailbox protocol v2), which lies inside the signed bytes: a slot that
// names a different key than the one that signed it fails verification.
[[nodiscard]] auto authenticate(const helm::mailbox::Slot& slot, const SignatureVerifier& verifier,
                                SequenceTracker& sequence)
    -> std::expected<helm::mailbox::Message, AuthError>;

}  // namespace ak::hull
