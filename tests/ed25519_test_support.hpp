// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// RFC 8032 section 7.1 Ed25519 test keys and a signer for tests that need
// to produce signed mailbox slots. Ed25519 is deterministic, so every slot
// these sign is reproducible.

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "helm/mailbox.hpp"
#include "hull/signature_verifier.hpp"

namespace ak::test {

inline constexpr std::size_t ed25519_secret_key_size = 32;
inline constexpr unsigned hex_digit_bits = 4;
inline constexpr int hex_letter_base = 10;

// RFC 8032 7.1 TEST 1 (empty message).
inline constexpr std::string_view rfc_test1_secret =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
inline constexpr std::string_view rfc_test1_public =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
inline constexpr std::string_view rfc_test1_message;
inline constexpr std::string_view rfc_test1_signature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b4"
    "6bd25bf5f0595bbe24655141438e7a100b";

// RFC 8032 7.1 TEST 2 (one byte).
inline constexpr std::string_view rfc_test2_secret =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
inline constexpr std::string_view rfc_test2_public =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
inline constexpr std::string_view rfc_test2_message = "72";
inline constexpr std::string_view rfc_test2_signature =
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d"
    "8c387b2eaeb4302aeeb00d291612bb0c00";

// RFC 8032 7.1 TEST 3 (two bytes).
inline constexpr std::string_view rfc_test3_secret =
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
inline constexpr std::string_view rfc_test3_public =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
inline constexpr std::string_view rfc_test3_message = "af82";
inline constexpr std::string_view rfc_test3_signature =
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6"
    "594a7c15e9716ed28dc027beceea1ec40a";

inline auto hex_nibble(char c) -> unsigned {
    if (c >= '0' && c <= '9') {
        return static_cast<unsigned>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<unsigned>(c - 'a' + hex_letter_base);
    }
    throw std::invalid_argument("bad hex digit");
}

inline auto from_hex(std::string_view hex) -> std::vector<std::byte> {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("odd hex length");
    }
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<std::byte>((hex_nibble(hex[i]) << hex_digit_bits) |
                                             hex_nibble(hex[i + 1])));
    }
    return out;
}

template<std::size_t n> auto fixed_from_hex(std::string_view hex) -> std::array<std::byte, n> {
    const auto v = from_hex(hex);
    if (v.size() != n) {
        throw std::invalid_argument("wrong hex length");
    }
    std::array<std::byte, n> out{};
    std::ranges::copy(v, out.begin());
    return out;
}

inline auto controller_key(hull::KeyId id, std::string_view public_hex) -> hull::ControllerKey {
    return {.id = id, .key = fixed_from_hex<hull::ed25519_public_key_size>(public_hex)};
}

// Signs like the controller does: pure Ed25519 with a raw 32-byte secret.
class TestSigner {
public:
    explicit TestSigner(std::string_view secret_hex) {
        const auto secret = fixed_from_hex<ed25519_secret_key_size>(secret_hex);
        _pkey.reset(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(secret.data()),
            secret.size()));
        if (!_pkey) {
            throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
        }
    }

    [[nodiscard]] auto sign(std::span<const std::byte> message) const
        -> std::array<std::byte, hull::ed25519_signature_size> {
        std::array<std::byte, hull::ed25519_signature_size> sig{};
        const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(),
                                                                          &EVP_MD_CTX_free};
        std::size_t len = sig.size();
        if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, _pkey.get()) != 1 ||
            EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(sig.data()), &len,
                           reinterpret_cast<const unsigned char*>(message.data()),
                           message.size()) != 1 ||
            len != sig.size()) {
            throw std::runtime_error("EVP_DigestSign failed");
        }
        return sig;
    }

    // Encodes a command slot and signs its bytes [0x00, 0xC0).
    [[nodiscard]] auto signed_slot(const helm::mailbox::Header& header,
                                   std::span<const std::byte> body) const -> helm::mailbox::Slot {
        const std::array<std::byte, helm::mailbox::signature_size> blank{};
        auto slot = helm::mailbox::encode(header, body, blank);
        if (!slot) {
            throw std::runtime_error("mailbox::encode failed");
        }
        const auto sig =
            sign(std::span<const std::byte>{*slot}.first<helm::mailbox::signature_offset>());
        std::ranges::copy(sig, slot->begin() + helm::mailbox::signature_offset);
        return *slot;
    }

private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _pkey{nullptr, &EVP_PKEY_free};
};

}  // namespace ak::test
