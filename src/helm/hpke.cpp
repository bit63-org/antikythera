// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/hpke.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string_view>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace ak::helm::hpke {

namespace {

constexpr std::size_t hash_size = 32;   // Nh, SHA-256
constexpr std::size_t key_size = 32;    // Nk, AES-256
constexpr std::size_t nonce_size = 12;  // Nn
constexpr std::uint16_t kem_id = 0x0020;
constexpr std::uint16_t kdf_id = 0x0001;
constexpr std::uint16_t aead_id = 0x0002;
constexpr std::uint8_t mode_base = 0x00;

using Bytes = std::vector<std::byte>;

// Wiped on destruction: every intermediate secret goes in one of these.
class Secret {
public:
    Secret() = default;
    explicit Secret(std::size_t n) : _b(n) {}
    Secret(const Secret&) = delete;
    auto operator=(const Secret&) -> Secret& = delete;
    Secret(Secret&&) noexcept = default;
    auto operator=(Secret&&) noexcept -> Secret& = default;
    ~Secret() { secure_zero(_b); }
    [[nodiscard]] auto span() noexcept -> std::span<std::byte> { return _b; }
    [[nodiscard]] auto span() const noexcept -> std::span<const std::byte> { return _b; }
    auto append(std::span<const std::byte> s) -> void { _b.insert(_b.end(), s.begin(), s.end()); }

private:
    Bytes _b;
};

auto put_u16(Secret& s, std::uint16_t v) -> void {
    const std::array<std::byte, 2> b{static_cast<std::byte>(v >> 8U), static_cast<std::byte>(v)};
    s.append(b);
}

auto text(std::string_view s) -> std::span<const std::byte> {
    return std::as_bytes(std::span{s.data(), s.size()});
}

auto kem_suite(Secret& s) -> void {
    s.append(text("KEM"));
    put_u16(s, kem_id);
}

auto hpke_suite(Secret& s) -> void {
    s.append(text("HPKE"));
    put_u16(s, kem_id);
    put_u16(s, kdf_id);
    put_u16(s, aead_id);
}

using Suite = void (*)(Secret&);

auto hmac(std::span<const std::byte> key, std::span<const std::byte> data,
          std::span<std::byte, hash_size> out) -> bool {
    unsigned int len = 0;
    // An empty key is the RFC 5869 default salt: HMAC pads it to zeros.
    static constexpr std::array<unsigned char, 1> none{};
    const auto* k = key.empty() ? none.data() : reinterpret_cast<const unsigned char*>(key.data());
    const auto* d =
        data.empty() ? none.data() : reinterpret_cast<const unsigned char*>(data.data());
    return HMAC(EVP_sha256(), k, static_cast<int>(key.size()), d, data.size(),
                reinterpret_cast<unsigned char*>(out.data()), &len) != nullptr &&
           len == hash_size;
}

// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite || label || ikm)
auto labeled_extract(Suite suite, std::span<const std::byte> salt, std::string_view label,
                     std::span<const std::byte> ikm) -> std::expected<Secret, Error> {
    Secret msg;
    msg.append(text("HPKE-v1"));
    suite(msg);
    msg.append(text(label));
    msg.append(ikm);
    Secret prk{hash_size};
    if (!hmac(salt, msg.span(), prk.span().first<hash_size>())) {
        return std::unexpected(Error::crypto_failure);
    }
    return prk;
}

// LabeledExpand(prk, label, info, L) =
//   HKDF-Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite || label || info, L)
auto labeled_expand(Suite suite, std::span<const std::byte> prk, std::string_view label,
                    std::span<const std::byte> info, std::size_t length)
    -> std::expected<Secret, Error> {
    Secret labeled;
    put_u16(labeled, static_cast<std::uint16_t>(length));
    labeled.append(text("HPKE-v1"));
    suite(labeled);
    labeled.append(text(label));
    labeled.append(info);
    Secret out{length};
    Secret t;  // T(i-1)
    std::size_t done = 0;
    for (std::uint8_t i = 1; done < length; ++i) {
        Secret block;
        block.append(t.span());
        block.append(labeled.span());
        const std::array<std::byte, 1> counter{std::byte{i}};
        block.append(counter);
        Secret next{hash_size};
        if (!hmac(prk, block.span(), next.span().first<hash_size>())) {
            return std::unexpected(Error::crypto_failure);
        }
        const auto n = std::min(hash_size, length - done);
        std::ranges::copy(next.span().first(n), out.span().subspan(done).begin());
        done += n;
        t = std::move(next);
    }
    return out;
}

struct PkeyFree {
    auto operator()(EVP_PKEY* p) const noexcept -> void { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
struct PkeyCtxFree {
    auto operator()(EVP_PKEY_CTX* p) const noexcept -> void { EVP_PKEY_CTX_free(p); }
};
struct CipherCtxFree {
    auto operator()(EVP_CIPHER_CTX* p) const noexcept -> void { EVP_CIPHER_CTX_free(p); }
};

auto private_pkey(std::span<const std::byte> sk) -> Pkey {
    return Pkey{EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char*>(sk.data()), sk.size())};
}

auto public_of(EVP_PKEY* key) -> std::expected<PublicKey, Error> {
    PublicKey pk{};
    std::size_t len = pk.size();
    if (EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char*>(pk.data()), &len) != 1 ||
        len != pk.size()) {
        return std::unexpected(Error::crypto_failure);
    }
    return pk;
}

// X25519(sk, pk); an all-zero result (a low-order pk) is refused.
auto dh(std::span<const std::byte> sk, std::span<const std::byte, public_key_size> pk)
    -> std::expected<Secret, Error> {
    const auto priv = private_pkey(sk);
    const Pkey peer{EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char*>(pk.data()), pk.size())};
    if (!priv || !peer) {
        return std::unexpected(Error::crypto_failure);
    }
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> ctx{EVP_PKEY_CTX_new(priv.get(), nullptr)};
    Secret out{public_key_size};
    std::size_t len = public_key_size;
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char*>(out.span().data()), &len) !=
            1 ||
        len != public_key_size) {
        return std::unexpected(Error::bad_public_key);  // OpenSSL refuses a zero result too
    }
    if (std::ranges::all_of(out.span(), [](std::byte b) { return b == std::byte{0}; })) {
        return std::unexpected(Error::bad_public_key);
    }
    return out;
}

// DHKEM ExtractAndExpand(dh, enc || pkR).
auto shared_secret(std::span<const std::byte> dh_out, std::span<const std::byte> enc,
                   std::span<const std::byte> pk_r) -> std::expected<Secret, Error> {
    auto prk = labeled_extract(kem_suite, {}, "eae_prk", dh_out);
    if (!prk) {
        return std::unexpected(prk.error());
    }
    Secret context;
    context.append(enc);
    context.append(pk_r);
    return labeled_expand(kem_suite, prk->span(), "shared_secret", context.span(), hash_size);
}

struct Context {
    Secret key;
    Secret nonce;
};

// KeySchedule for mode_base (no PSK).
auto key_schedule(std::span<const std::byte> shared, std::span<const std::byte> info)
    -> std::expected<Context, Error> {
    auto psk_id_hash = labeled_extract(hpke_suite, {}, "psk_id_hash", {});
    auto info_hash = labeled_extract(hpke_suite, {}, "info_hash", info);
    if (!psk_id_hash || !info_hash) {
        return std::unexpected(Error::crypto_failure);
    }
    Secret context;
    const std::array<std::byte, 1> mode{std::byte{mode_base}};
    context.append(mode);
    context.append(psk_id_hash->span());
    context.append(info_hash->span());
    auto secret = labeled_extract(hpke_suite, shared, "secret", {});
    if (!secret) {
        return std::unexpected(secret.error());
    }
    auto key = labeled_expand(hpke_suite, secret->span(), "key", context.span(), key_size);
    auto nonce =
        labeled_expand(hpke_suite, secret->span(), "base_nonce", context.span(), nonce_size);
    if (!key || !nonce) {
        return std::unexpected(Error::crypto_failure);
    }
    return Context{.key = std::move(*key), .nonce = std::move(*nonce)};
}

auto uc(std::span<const std::byte> s) -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(s.data());
}
auto uc(std::span<std::byte> s) -> unsigned char* {
    return reinterpret_cast<unsigned char*>(s.data());
}

auto aead(bool encrypt, const Context& c, std::span<const std::byte> aad,
          std::span<const std::byte> in, std::span<std::byte> out, std::span<std::byte> tag)
    -> std::expected<void, Error> {
    const std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree> ctx{EVP_CIPHER_CTX_new()};
    if (!ctx ||
        EVP_CipherInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr,
                          encrypt ? 1 : 0) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr) != 1 ||
        EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, uc(c.key.span()), uc(c.nonce.span()),
                          encrypt ? 1 : 0) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    int len = 0;
    if (!aad.empty() &&
        EVP_CipherUpdate(ctx.get(), nullptr, &len, uc(aad), static_cast<int>(aad.size())) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    if (!in.empty() &&
        EVP_CipherUpdate(ctx.get(), uc(out), &len, uc(in), static_cast<int>(in.size())) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    if (!encrypt &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data()) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    std::array<unsigned char, 16> tail{};
    if (EVP_CipherFinal_ex(ctx.get(), tail.data(), &len) != 1) {
        return std::unexpected(encrypt ? Error::crypto_failure : Error::open_failed);
    }
    if (encrypt &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag.data()) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    return {};
}

}  // namespace

auto to_string(Error e) noexcept -> const char* {
    switch (e) {
        case Error::crypto_failure:
            return "crypto failure";
        case Error::bad_public_key:
            return "bad public key";
        case Error::bad_size:
            return "bad size";
        case Error::open_failed:
            return "open failed";
    }
    return "unknown";
}

auto derive_key_pair(std::span<const std::byte> ikm) -> std::expected<KeyPair, Error> {
    auto prk = labeled_extract(kem_suite, {}, "dkp_prk", ikm);
    if (!prk) {
        return std::unexpected(prk.error());
    }
    auto sk = labeled_expand(kem_suite, prk->span(), "sk", {}, private_key_size);
    if (!sk) {
        return std::unexpected(sk.error());
    }
    const auto key = private_pkey(sk->span());
    if (!key) {
        return std::unexpected(Error::crypto_failure);
    }
    auto pk = public_of(key.get());
    if (!pk) {
        return std::unexpected(pk.error());
    }
    KeyPair pair;
    std::ranges::copy(sk->span(), pair.private_key.span().begin());
    pair.public_key = *pk;
    return pair;
}

auto seal(const PublicKey& recipient, std::span<const std::byte> info,
          std::span<const std::byte> aad, std::span<const std::byte> plaintext,
          std::span<const std::byte, ikm_size> ikm_e) -> std::expected<Sealed, Error> {
    auto eph = derive_key_pair(ikm_e);
    if (!eph) {
        return std::unexpected(eph.error());
    }
    auto d = dh(eph->private_key.span(), recipient);
    if (!d) {
        return std::unexpected(d.error());
    }
    auto shared = shared_secret(d->span(), eph->public_key, recipient);
    if (!shared) {
        return std::unexpected(shared.error());
    }
    auto ctx = key_schedule(shared->span(), info);
    if (!ctx) {
        return std::unexpected(ctx.error());
    }
    Sealed out{.enc = eph->public_key, .ciphertext = Bytes(plaintext.size() + tag_size)};
    const std::span<std::byte> ct{out.ciphertext};
    if (auto r = aead(true, *ctx, aad, plaintext, ct.first(plaintext.size()),
                      ct.subspan(plaintext.size()));
        !r) {
        return std::unexpected(r.error());
    }
    return out;
}

auto seal(const PublicKey& recipient, std::span<const std::byte> info,
          std::span<const std::byte> aad, std::span<const std::byte> plaintext)
    -> std::expected<Sealed, Error> {
    SecretBytes<ikm_size> ikm;
    if (RAND_bytes(uc(std::span<std::byte>{ikm.span()}), static_cast<int>(ikm_size)) != 1) {
        return std::unexpected(Error::crypto_failure);
    }
    return seal(recipient, info, aad, plaintext, ikm.span());
}

auto open(std::span<const std::byte, private_key_size> recipient_key,
          std::span<const std::byte, enc_size> enc, std::span<const std::byte> info,
          std::span<const std::byte> aad, std::span<const std::byte> ciphertext,
          std::span<std::byte> out) -> std::expected<void, Error> {
    if (ciphertext.size() < tag_size || out.size() != ciphertext.size() - tag_size) {
        secure_zero(out);
        return std::unexpected(Error::bad_size);
    }
    const auto result = [&]() -> std::expected<void, Error> {
        const auto key = private_pkey(recipient_key);
        if (!key) {
            return std::unexpected(Error::crypto_failure);
        }
        const auto pk_r = public_of(key.get());
        if (!pk_r) {
            return std::unexpected(pk_r.error());
        }
        auto d = dh(recipient_key, enc);
        if (!d) {
            return std::unexpected(d.error());
        }
        auto shared = shared_secret(d->span(), enc, *pk_r);
        if (!shared) {
            return std::unexpected(shared.error());
        }
        auto ctx = key_schedule(shared->span(), info);
        if (!ctx) {
            return std::unexpected(ctx.error());
        }
        std::array<std::byte, tag_size> tag{};
        std::ranges::copy(ciphertext.subspan(out.size()), tag.begin());
        return aead(false, *ctx, aad, ciphertext.first(out.size()), out, tag);
    }();
    if (!result) {
        secure_zero(out);
    }
    return result;
}

}  // namespace ak::helm::hpke
