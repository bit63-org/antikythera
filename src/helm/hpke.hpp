// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// HPKE (RFC 9180) base mode for one suite: DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and AES-256-GCM (kem 0x0020, kdf 0x0001, aead 0x0002), the
// suite kythira KMS wraps network volume keys with
// (.kiro/specs/block-volume-service/ design "VolumeKey"). Single-shot only:
// one message per encapsulation, so the nonce is the base nonce.
//
// Built from OpenSSL 3.0 primitives (X25519, HMAC-SHA256, AES-256-GCM)
// rather than OSSL_HPKE, which needs OpenSSL 3.2; the tests check it
// against the CFRG test vector for this suite.
//
// open() writes the plaintext into a caller buffer so a key can go
// straight into SecretBytes; nothing else here holds plaintext beyond the
// call, and intermediate secrets are wiped.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "helm/scoped_key.hpp"

namespace ak::helm::hpke {

inline constexpr std::size_t public_key_size = 32;
inline constexpr std::size_t private_key_size = 32;
inline constexpr std::size_t enc_size = 32;  // the ephemeral public key
inline constexpr std::size_t tag_size = 16;
inline constexpr std::size_t ikm_size = 32;  // what seal() draws for the ephemeral key

using PublicKey = std::array<std::byte, public_key_size>;
using Enc = std::array<std::byte, enc_size>;

enum class Error : std::uint8_t {
    crypto_failure,  // OpenSSL failed, or the RNG did
    bad_public_key,  // a low-order X25519 point: the shared secret would be zero
    bad_size,        // ciphertext shorter than the tag, or output the wrong size
    open_failed,     // wrong key, wrong info or AAD, or a tampered ciphertext
};

[[nodiscard]] auto to_string(Error e) noexcept -> const char*;

struct KeyPair {
    SecretBytes<private_key_size> private_key;
    PublicKey public_key{};
};

// DeriveKeyPair (RFC 9180 7.1.3): the same ikm always gives the same pair.
[[nodiscard]] auto derive_key_pair(std::span<const std::byte> ikm) -> std::expected<KeyPair, Error>;

struct Sealed {
    Enc enc{};
    std::vector<std::byte> ciphertext;  // plaintext size + tag_size
};

// Encrypts `plaintext` to `recipient`. The ephemeral key comes from
// `ikm_e` through DeriveKeyPair (the test vectors' way); seal() without it
// draws ikm_e at random.
[[nodiscard]] auto seal(const PublicKey& recipient, std::span<const std::byte> info,
                        std::span<const std::byte> aad, std::span<const std::byte> plaintext,
                        std::span<const std::byte, ikm_size> ikm_e) -> std::expected<Sealed, Error>;
[[nodiscard]] auto seal(const PublicKey& recipient, std::span<const std::byte> info,
                        std::span<const std::byte> aad, std::span<const std::byte> plaintext)
    -> std::expected<Sealed, Error>;

// Decrypts into `out`, which must be ciphertext.size() - tag_size bytes.
// On failure `out` is zeroed.
[[nodiscard]] auto open(std::span<const std::byte, private_key_size> recipient_key,
                        std::span<const std::byte, enc_size> enc, std::span<const std::byte> info,
                        std::span<const std::byte> aad, std::span<const std::byte> ciphertext,
                        std::span<std::byte> out) -> std::expected<void, Error>;

}  // namespace ak::helm::hpke
