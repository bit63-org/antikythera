// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/signature_verifier.hpp"

#include <algorithm>
#include <utility>

#include <openssl/err.h>
#include <openssl/evp.h>

namespace ak::hull {

namespace {

struct MdCtxDeleter {
    auto operator()(EVP_MD_CTX* c) const noexcept -> void { EVP_MD_CTX_free(c); }
};

auto as_uchar(std::span<const std::byte> b) noexcept -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(b.data());
}

}  // namespace

auto to_string(KeyTableError e) noexcept -> const char* {
    switch (e) {
        case KeyTableError::empty:
            return "empty";
        case KeyTableError::too_many_keys:
            return "too_many_keys";
        case KeyTableError::duplicate_key_id:
            return "duplicate_key_id";
        case KeyTableError::invalid_key:
            return "invalid_key";
    }
    return "unknown";
}

auto to_string(VerifyError e) noexcept -> const char* {
    switch (e) {
        case VerifyError::unknown_key:
            return "unknown_key";
        case VerifyError::bad_signature:
            return "bad_signature";
        case VerifyError::crypto_failure:
            return "crypto_failure";
    }
    return "unknown";
}

auto SignatureVerifier::PkeyDeleter::operator()(EVP_PKEY* p) const noexcept -> void {
    EVP_PKEY_free(p);
}

auto SignatureVerifier::create(std::span<const ControllerKey> keys)
    -> std::expected<SignatureVerifier, KeyTableError> {
    if (keys.empty()) {
        return std::unexpected(KeyTableError::empty);
    }
    if (keys.size() > max_controller_keys) {
        return std::unexpected(KeyTableError::too_many_keys);
    }
    std::vector<Entry> entries;
    entries.reserve(keys.size());
    for (const auto& k : keys) {
        if (std::ranges::any_of(entries, [&](const Entry& e) { return e.id == k.id; })) {
            return std::unexpected(KeyTableError::duplicate_key_id);
        }
        std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey{
            EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, as_uchar(k.key), k.key.size())};
        if (!pkey) {
            ERR_clear_error();
            return std::unexpected(KeyTableError::invalid_key);
        }
        entries.push_back(Entry{.id = k.id, .pkey = std::move(pkey)});
    }
    return SignatureVerifier{std::move(entries)};
}

auto SignatureVerifier::verify(std::span<const std::byte> message, Signature signature,
                               KeyId key_id) const -> std::expected<void, VerifyError> {
    const auto it = std::ranges::find(_keys, key_id, &Entry::id);
    if (it == _keys.end()) {
        return std::unexpected(VerifyError::unknown_key);
    }
    const std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx{EVP_MD_CTX_new()};
    // Ed25519 is a one-shot scheme: no digest is named, and the whole
    // message goes to EVP_DigestVerify in one call.
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, it->pkey.get()) != 1) {
        ERR_clear_error();
        return std::unexpected(VerifyError::crypto_failure);
    }
    const int rc = EVP_DigestVerify(ctx.get(), as_uchar(signature), signature.size(),
                                    as_uchar(message), message.size());
    if (rc == 1) {
        return {};
    }
    // 0 is a signature that does not verify; OpenSSL also reports some
    // malformed signatures (e.g. S >= L) as a negative error. Both are
    // rejections; only the caller's log tells them apart, so fold them.
    ERR_clear_error();
    return std::unexpected(VerifyError::bad_signature);
}

auto SignatureVerifier::verify_slot(const helm::mailbox::Slot& slot, KeyId key_id) const
    -> std::expected<void, VerifyError> {
    const std::span<const std::byte> bytes{slot};
    return verify(bytes.first<helm::mailbox::signature_offset>(),
                  bytes.subspan<helm::mailbox::signature_offset, ed25519_signature_size>(), key_id);
}

}  // namespace ak::hull
