// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/command_auth.hpp"

#include <utility>

namespace ak::hull {

namespace mb = helm::mailbox;

namespace {

auto to_failure(VerifyError e) noexcept -> AuthFailure {
    switch (e) {
        case VerifyError::unknown_key:
            return AuthFailure::unknown_key;
        case VerifyError::bad_signature:
            return AuthFailure::bad_signature;
        case VerifyError::crypto_failure:
            return AuthFailure::crypto_failure;
    }
    return AuthFailure::crypto_failure;
}

}  // namespace

auto to_string(AuthFailure f) noexcept -> const char* {
    switch (f) {
        case AuthFailure::malformed:
            return "malformed";
        case AuthFailure::not_a_command:
            return "not_a_command";
        case AuthFailure::unknown_key:
            return "unknown_key";
        case AuthFailure::bad_signature:
            return "bad_signature";
        case AuthFailure::crypto_failure:
            return "crypto_failure";
        case AuthFailure::replayed:
            return "replayed";
    }
    return "unknown";
}

auto authenticate(const mb::Slot& slot, KeyId key_id, const SignatureVerifier& verifier,
                  SequenceTracker& sequence) -> std::expected<mb::Message, AuthError> {
    auto msg = mb::decode(slot);
    if (!msg) {
        return std::unexpected(AuthError{.failure = AuthFailure::malformed, .decode = msg.error()});
    }
    if (!mb::is_command(msg->header.type)) {
        return std::unexpected(AuthError{.failure = AuthFailure::not_a_command});
    }
    if (auto ok = verifier.verify_slot(slot, key_id); !ok) {
        return std::unexpected(AuthError{.failure = to_failure(ok.error())});
    }
    if (auto ok = sequence.accept(msg->header.seq); !ok) {
        return std::unexpected(AuthError{.failure = AuthFailure::replayed});
    }
    return std::move(*msg);
}

}  // namespace ak::hull
