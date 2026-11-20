// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/wireguard.hpp"

#include <algorithm>
#include <limits>
#include <memory>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "common/wire.hpp"

namespace ak::oar::net::wg {

namespace {

constexpr std::size_t header_size = 4;  // type and three reserved bytes
constexpr std::size_t nonce_size = 12;
constexpr std::size_t nonce_counter_offset = 4;
constexpr std::int64_t tai64_base = 0x400000000000000a;  // 2^62 + 10 (TAI - UTC in 1972)
constexpr std::int64_t ns_per_second = 1'000'000'000;
// Linux rounds the nanoseconds down to the largest power of two under
// 1 s / 50 (INITIATIONS_PER_SECOND): 2^24 ns, about 1/60 s.
constexpr std::int64_t timestamp_grain_ns = std::int64_t{1} << 24U;

struct MacDeleter {
    auto operator()(EVP_MAC_CTX* c) const noexcept -> void { EVP_MAC_CTX_free(c); }
};
struct PkeyDeleter {
    auto operator()(EVP_PKEY* k) const noexcept -> void { EVP_PKEY_free(k); }
};
struct PkeyCtxDeleter {
    auto operator()(EVP_PKEY_CTX* c) const noexcept -> void { EVP_PKEY_CTX_free(c); }
};
struct CipherDeleter {
    auto operator()(EVP_CIPHER_CTX* c) const noexcept -> void { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter>;

template<std::size_t E> auto u8p(std::span<const std::byte, E> s) noexcept -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(s.data());  // NOLINT(*-reinterpret-cast)
}
template<std::size_t E> auto u8p(std::span<std::byte, E> s) noexcept -> unsigned char* {
    return reinterpret_cast<unsigned char*>(s.data());  // NOLINT(*-reinterpret-cast)
}

// Fetched once; OpenSSL's fetch is thread-safe and the objects live forever.
auto blake2s_mac() -> EVP_MAC* {
    static EVP_MAC* const m = EVP_MAC_fetch(nullptr, "BLAKE2SMAC", nullptr);
    return m;
}
auto hmac_mac() -> EVP_MAC* {
    static EVP_MAC* const m = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    return m;
}
auto blake2s_md() -> const EVP_MD* {
    static EVP_MD* const md = EVP_MD_fetch(nullptr, "BLAKE2S-256", nullptr);
    return md;
}

auto hmac(std::span<const std::byte> key, std::initializer_list<std::span<const std::byte>> parts,
          std::span<std::byte, hash_size> out) -> void {
    const std::unique_ptr<EVP_MAC_CTX, MacDeleter> ctx{EVP_MAC_CTX_new(hmac_mac())};
    std::array<char, 16> digest{"BLAKE2S-256"};
    const std::array params{
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest.data(), 0),
        OSSL_PARAM_construct_end()};
    std::size_t len = 0;
    bool ok = ctx && EVP_MAC_init(ctx.get(), u8p(key), key.size(), params.data()) == 1;
    for (const auto part : parts) {
        ok = ok && EVP_MAC_update(ctx.get(), u8p(part), part.size()) == 1;
    }
    ok = ok && EVP_MAC_final(ctx.get(), u8p(out), &len, out.size()) == 1 && len == out.size();
    if (!ok) {
        // OpenSSL without BLAKE2s cannot run WireGuard at all; fail closed
        // with a key nobody else derives.
        wipe(out);
    }
}

auto nonce_for(std::uint64_t counter) -> std::array<std::byte, nonce_size> {
    std::array<std::byte, nonce_size> n{};
    for (std::size_t i = 0; i < sizeof(counter); ++i) {
        n[nonce_counter_offset + i] = static_cast<std::byte>((counter >> (8U * i)) & 0xFFU);
    }
    return n;
}

auto crypt(EVP_CIPHER_CTX* ctx, bool encrypt, std::uint64_t counter, std::span<const std::byte> in,
           std::span<const std::byte> ad, std::span<std::byte> out) -> bool {
    const auto nonce = nonce_for(counter);
    const std::size_t body = encrypt ? in.size() : in.size() - tag_size;
    if (in.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        (!encrypt && in.size() < tag_size) ||
        out.size() != (encrypt ? in.size() + tag_size : body)) {
        return false;
    }
    int len = 0;
    if (EVP_CipherInit_ex(ctx, nullptr, nullptr, nullptr, u8p(std::span{nonce}), encrypt ? 1 : 0) !=
        1) {
        return false;
    }
    if (!ad.empty() &&
        EVP_CipherUpdate(ctx, nullptr, &len, u8p(ad), static_cast<int>(ad.size())) != 1) {
        return false;
    }
    if (body > 0 && EVP_CipherUpdate(ctx, u8p(out), &len, u8p(in), static_cast<int>(body)) != 1) {
        return false;
    }
    if (!encrypt) {
        std::array<std::byte, tag_size> tag{};
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(body), tag_size, tag.begin());
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag.data()) != 1) {
            return false;
        }
    }
    std::array<unsigned char, tag_size> scratch{};
    if (EVP_CipherFinal_ex(ctx, scratch.data(), &len) != 1) {
        wipe(out);
        return false;
    }
    if (encrypt) {
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, u8p(out.subspan(body))) ==
               1;
    }
    return true;
}

auto make_cipher(std::span<const std::byte, key_size> key, bool encrypt) -> CipherCtx {
    CipherCtx ctx{EVP_CIPHER_CTX_new()};
    if (!ctx || EVP_CipherInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, u8p(key), nullptr,
                                  encrypt ? 1 : 0) != 1) {
        return {};
    }
    return ctx;
}

}  // namespace

auto to_string(ParseError e) noexcept -> const char* {
    switch (e) {
        case ParseError::empty:
            return "empty";
        case ParseError::unknown_type:
            return "unknown_type";
        case ParseError::reserved_not_zero:
            return "reserved_not_zero";
        case ParseError::bad_length:
            return "bad_length";
    }
    return "unknown";
}

auto parse(std::span<const std::byte> d) noexcept -> std::expected<Message, ParseError> {
    if (d.empty()) {
        return std::unexpected(ParseError::empty);
    }
    const auto type = std::to_integer<std::uint8_t>(d[0]);
    if (type < static_cast<std::uint8_t>(MessageType::initiation) ||
        type > static_cast<std::uint8_t>(MessageType::transport)) {
        return std::unexpected(ParseError::unknown_type);
    }
    if (d.size() < header_size) {
        return std::unexpected(ParseError::bad_length);
    }
    if (d[1] != std::byte{0} || d[2] != std::byte{0} || d[3] != std::byte{0}) {
        return std::unexpected(ParseError::reserved_not_zero);
    }
    wire::Reader r{d.subspan(header_size)};
    switch (static_cast<MessageType>(type)) {
        case MessageType::initiation: {
            if (d.size() != initiation_size) {
                return std::unexpected(ParseError::bad_length);
            }
            return Initiation{
                .sender = *r.le32(),
                .ephemeral = d.subspan(8).first<key_size>(),
                .encrypted_static = d.subspan(40).first<key_size + tag_size>(),
                .encrypted_timestamp = d.subspan(88).first<timestamp_size + tag_size>(),
                .mac1 = d.subspan(initiation_mac1_offset).first<mac_size>(),
                .mac2 = d.subspan(initiation_mac1_offset + mac_size).first<mac_size>(),
                .before_mac1 = d.first(initiation_mac1_offset)};
        }
        case MessageType::response: {
            if (d.size() != response_size) {
                return std::unexpected(ParseError::bad_length);
            }
            const auto sender = *r.le32();
            const auto receiver = *r.le32();
            return Response{.sender = sender,
                            .receiver = receiver,
                            .ephemeral = d.subspan(12).first<key_size>(),
                            .encrypted_empty = d.subspan(44).first<tag_size>(),
                            .mac1 = d.subspan(response_mac1_offset).first<mac_size>(),
                            .mac2 = d.subspan(response_mac1_offset + mac_size).first<mac_size>(),
                            .before_mac1 = d.first(response_mac1_offset)};
        }
        case MessageType::cookie_reply: {
            if (d.size() != cookie_reply_size) {
                return std::unexpected(ParseError::bad_length);
            }
            return CookieReply{.receiver = *r.le32(),
                               .nonce = d.subspan(8).first<cookie_nonce_size>(),
                               .encrypted_cookie = d.subspan(32).first<mac_size + tag_size>()};
        }
        case MessageType::transport: {
            if (d.size() < transport_overhead) {
                return std::unexpected(ParseError::bad_length);
            }
            const auto receiver = *r.le32();
            const auto counter = *r.le64();
            return Transport{.receiver = receiver,
                             .counter = counter,
                             .ciphertext = d.subspan(transport_header_size)};
        }
    }
    return std::unexpected(ParseError::unknown_type);
}

auto wipe(std::span<std::byte> bytes) noexcept -> void {
    if (!bytes.empty()) {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }
}

auto equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept -> bool {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

auto hash(std::initializer_list<std::span<const std::byte>> parts) -> Hash {
    Hash out{};
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(),
                                                                      &EVP_MD_CTX_free};
    unsigned int len = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx.get(), blake2s_md(), nullptr) == 1;
    for (const auto part : parts) {
        ok = ok && EVP_DigestUpdate(ctx.get(), part.data(), part.size()) == 1;
    }
    ok = ok && EVP_DigestFinal_ex(ctx.get(), u8p(std::span{out}), &len) == 1 && len == out.size();
    if (!ok) {
        wipe(out);
    }
    return out;
}

auto mac(std::span<const std::byte> key, std::span<const std::byte> data) -> Mac {
    Mac out{};
    const std::unique_ptr<EVP_MAC_CTX, MacDeleter> ctx{EVP_MAC_CTX_new(blake2s_mac())};
    std::size_t size = mac_size;
    const std::array params{OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size),
                            OSSL_PARAM_construct_end()};
    std::size_t len = 0;
    const bool ok = ctx && EVP_MAC_init(ctx.get(), u8p(key), key.size(), params.data()) == 1 &&
                    EVP_MAC_update(ctx.get(), u8p(data), data.size()) == 1 &&
                    EVP_MAC_final(ctx.get(), u8p(std::span{out}), &len, out.size()) == 1 &&
                    len == out.size();
    if (!ok) {
        wipe(out);
    }
    return out;
}

auto kdf(std::span<const std::byte, hash_size> key, std::span<const std::byte> input,
         std::initializer_list<std::span<std::byte, hash_size>> outputs) -> void {
    Secret<hash_size> tau0;
    hmac(key, {input}, tau0.span());
    std::span<const std::byte> previous;
    std::uint8_t i = 1;
    for (const auto out : outputs) {
        const std::array counter{std::byte{i}};
        hmac(tau0.span(), {previous, counter}, out);
        previous = out;
        ++i;
    }
}

auto generate_private_key() -> std::optional<SecretKey> {
    SecretKey k;
    if (RAND_bytes(u8p(k.span()), static_cast<int>(key_size)) != 1) {
        return std::nullopt;
    }
    return k;
}

auto public_key(std::span<const std::byte, key_size> private_key) -> std::optional<Key> {
    const std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey{EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, u8p(private_key), private_key.size())};
    Key out{};
    std::size_t len = out.size();
    if (!pkey || EVP_PKEY_get_raw_public_key(pkey.get(), u8p(std::span{out}), &len) != 1 ||
        len != out.size()) {
        return std::nullopt;
    }
    return out;
}

auto dh(std::span<const std::byte, key_size> private_key,
        std::span<const std::byte, key_size> public_key) -> std::optional<SecretKey> {
    const std::unique_ptr<EVP_PKEY, PkeyDeleter> priv{EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, u8p(private_key), private_key.size())};
    const std::unique_ptr<EVP_PKEY, PkeyDeleter> pub{
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, u8p(public_key), public_key.size())};
    if (!priv || !pub) {
        return std::nullopt;
    }
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx{
        EVP_PKEY_CTX_new_from_pkey(nullptr, priv.get(), nullptr)};
    SecretKey out;
    std::size_t len = key_size;
    // OpenSSL refuses an all-zero shared secret itself (RFC 7748 section
    // 6.1); the check below keeps that true whatever the provider does.
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) != 1 ||
        EVP_PKEY_derive(ctx.get(), u8p(out.span()), &len) != 1 || len != key_size) {
        return std::nullopt;
    }
    constexpr Key zero{};
    if (equal(out.span(), zero)) {
        return std::nullopt;
    }
    return out;
}

auto seal(std::span<const std::byte, key_size> key, std::uint64_t counter,
          std::span<const std::byte> plaintext, std::span<const std::byte> ad,
          std::span<std::byte> out) -> bool {
    const auto ctx = make_cipher(key, true);
    return ctx && crypt(ctx.get(), true, counter, plaintext, ad, out);
}

auto open(std::span<const std::byte, key_size> key, std::uint64_t counter,
          std::span<const std::byte> ciphertext, std::span<const std::byte> ad,
          std::span<std::byte> out) -> bool {
    const auto ctx = make_cipher(key, false);
    return ctx && crypt(ctx.get(), false, counter, ciphertext, ad, out);
}

auto tai64n(std::chrono::system_clock::time_point t) -> Timestamp {
    const auto ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
    std::int64_t seconds = ns / ns_per_second;
    std::int64_t frac = ns % ns_per_second;
    if (frac < 0) {
        --seconds;
        frac += ns_per_second;
    }
    frac -= frac % timestamp_grain_ns;
    Timestamp out{};
    std::vector<std::byte> buf;
    wire::Writer w{buf};
    w.be64(static_cast<std::uint64_t>(tai64_base + seconds));
    w.be32(static_cast<std::uint32_t>(frac));
    std::copy(buf.begin(), buf.end(), out.begin());
    return out;
}

// ---- Aead -----------------------------------------------------------------

auto Aead::create(std::span<const std::byte, key_size> key, bool encrypt) -> std::optional<Aead> {
    auto ctx = make_cipher(key, encrypt);
    if (!ctx) {
        return std::nullopt;
    }
    return Aead{ctx.release()};
}

Aead::Aead(Aead&& other) noexcept : _ctx{other._ctx} {
    other._ctx = nullptr;
}

auto Aead::operator=(Aead&& other) noexcept -> Aead& {
    if (this != &other) {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(_ctx));
        _ctx = other._ctx;
        other._ctx = nullptr;
    }
    return *this;
}

Aead::~Aead() {
    // EVP_CIPHER_CTX_free cleanses the key schedule.
    EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(_ctx));
}

auto Aead::seal(std::uint64_t counter, std::span<const std::byte> plaintext,
                std::span<std::byte> out) -> bool {
    return _ctx != nullptr &&
           crypt(static_cast<EVP_CIPHER_CTX*>(_ctx), true, counter, plaintext, {}, out);
}

auto Aead::open(std::uint64_t counter, std::span<const std::byte> ciphertext,
                std::span<std::byte> out) -> bool {
    return _ctx != nullptr &&
           crypt(static_cast<EVP_CIPHER_CTX*>(_ctx), false, counter, ciphertext, {}, out);
}

// ---- ReplayWindow ---------------------------------------------------------

namespace {
constexpr std::uint64_t words = ReplayWindow::bits_total / ReplayWindow::word_bits;
// Counters this close to the top would overflow the arithmetic below; the
// Tunnel stops using a session long before (reject_after_messages).
constexpr std::uint64_t counter_limit =
    std::numeric_limits<std::uint64_t>::max() - ReplayWindow::bits_total;
}  // namespace

auto ReplayWindow::may_accept(std::uint64_t counter) const noexcept -> bool {
    if (counter >= counter_limit) {
        return false;
    }
    const std::uint64_t their = counter + 1;
    if (window + their < _highest) {
        return false;
    }
    if (their > _highest) {
        return true;
    }
    const std::uint64_t index = (their / word_bits) & (words - 1);
    return (_bits[index] & (std::uint64_t{1} << (their % word_bits))) == 0;
}

auto ReplayWindow::accept(std::uint64_t counter) noexcept -> bool {
    if (counter >= counter_limit) {
        return false;
    }
    const std::uint64_t their = counter + 1;
    if (window + their < _highest) {
        return false;
    }
    const std::uint64_t index = their / word_bits;
    if (their > _highest) {
        const std::uint64_t current = _highest / word_bits;
        const std::uint64_t top = std::min(index - current, words);
        for (std::uint64_t i = 1; i <= top; ++i) {
            _bits[(current + i) & (words - 1)] = 0;
        }
        _highest = their;
    }
    auto& word = _bits[index & (words - 1)];
    const std::uint64_t bit = std::uint64_t{1} << (their % word_bits);
    if ((word & bit) != 0) {
        return false;
    }
    word |= bit;
    return true;
}

}  // namespace ak::oar::net::wg
