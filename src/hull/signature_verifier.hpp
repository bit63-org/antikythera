// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Ed25519 verification of mailbox commands against the controller's public
// keys (.kiro/specs/hull-host-agent/ Requirement 4, design "SignatureVerifier").
//
// The key table is fixed when the verifier is built: in the agent it comes
// from keys compiled into the signed host image, so nothing at runtime can
// add a key. Each key carries the key ID the controller signs under, so keys
// can be rotated by shipping an image with both the old and new key.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include <openssl/types.h>

#include "helm/mailbox.hpp"

namespace ak::hull {

using KeyId = std::uint16_t;

inline constexpr std::size_t ed25519_public_key_size = 32;
inline constexpr std::size_t ed25519_signature_size = 64;
static_assert(ed25519_signature_size == helm::mailbox::signature_size);

// Upper bound on compiled-in keys: enough for an overlapping rotation plus
// spares, small enough that a key-table mistake is obvious.
inline constexpr std::size_t max_controller_keys = 8;

using PublicKey = std::array<std::byte, ed25519_public_key_size>;
using Signature = std::span<const std::byte, ed25519_signature_size>;

struct ControllerKey {
    KeyId id{0};
    PublicKey key{};
};

enum class KeyTableError : std::uint8_t {
    empty,             // no keys: every command would be rejected
    too_many_keys,     // more than max_controller_keys
    duplicate_key_id,  // two keys share an ID, so the choice would be ambiguous
    invalid_key,       // OpenSSL refused the raw public key
};

enum class VerifyError : std::uint8_t {
    unknown_key,     // no compiled-in key has this ID
    bad_signature,   // the signature does not verify under the key
    crypto_failure,  // OpenSSL failed for a reason other than a bad signature
};

[[nodiscard]] auto to_string(KeyTableError e) noexcept -> const char*;
[[nodiscard]] auto to_string(VerifyError e) noexcept -> const char*;

class SignatureVerifier {
public:
    [[nodiscard]] static auto create(std::span<const ControllerKey> keys)
        -> std::expected<SignatureVerifier, KeyTableError>;

    // Verifies a pure Ed25519 (RFC 8032, no context, no prehash) signature
    // over `message` under the key with ID `key_id`.
    [[nodiscard]] auto verify(std::span<const std::byte> message, Signature signature,
                              KeyId key_id) const -> std::expected<void, VerifyError>;

    // Verifies a command slot: the signature at [0xC0, 0x100) over the slot
    // bytes [0x00, 0xC0), taken from the raw slot rather than a re-encoding.
    [[nodiscard]] auto verify_slot(const helm::mailbox::Slot& slot, KeyId key_id) const
        -> std::expected<void, VerifyError>;

    [[nodiscard]] auto key_count() const noexcept -> std::size_t { return _keys.size(); }

private:
    struct PkeyDeleter {
        auto operator()(EVP_PKEY* p) const noexcept -> void;
    };
    struct Entry {
        KeyId id{0};
        std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey;
    };

    explicit SignatureVerifier(std::vector<Entry> keys) noexcept : _keys{std::move(keys)} {}

    std::vector<Entry> _keys;
};

}  // namespace ak::hull
