// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/xts_cipher.hpp"

#include <array>
#include <functional>
#include <limits>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace ak::oar::blk {

namespace {

constexpr std::size_t tweak_size = 16;
constexpr std::size_t aes256_key_size = xts_key_size / 2;
constexpr unsigned bits_per_byte = 8;

auto as_uchar(std::span<const std::byte> b) noexcept -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(b.data());
}

auto as_uchar(std::span<std::byte> b) noexcept -> unsigned char* {
    return reinterpret_cast<unsigned char*>(b.data());
}

// IEEE 1619 5.1: the tweak is the data unit number as a 128-bit
// little-endian integer.
auto tweak_for(std::uint64_t unit) noexcept -> std::array<unsigned char, tweak_size> {
    std::array<unsigned char, tweak_size> t{};
    for (std::size_t i = 0; i < sizeof(unit); ++i) {
        t.at(i) = static_cast<unsigned char>(unit >> (i * bits_per_byte));
    }
    return t;
}

// Exactly the same buffer (in place) or no shared byte at all. std::less
// gives a total order over unrelated pointers, which `<` does not promise.
auto aliasing_ok(std::span<const std::byte> in, std::span<std::byte> out) noexcept -> bool {
    const std::byte* i = in.data();
    const std::byte* o = out.data();
    if (i == o) {
        return true;
    }
    const std::less<const std::byte*> lt;
    return !lt(i, o + out.size()) || !lt(o, i + in.size());
}

}  // namespace

auto to_string(XtsError e) noexcept -> const char* {
    switch (e) {
        case XtsError::bad_data_unit_size:
            return "bad_data_unit_size";
        case XtsError::weak_key:
            return "weak_key";
        case XtsError::bad_length:
            return "bad_length";
        case XtsError::buffer_mismatch:
            return "buffer_mismatch";
        case XtsError::unit_number_overflow:
            return "unit_number_overflow";
        case XtsError::crypto_failure:
            return "crypto_failure";
    }
    return "unknown";
}

auto XtsCipher::CtxDeleter::operator()(EVP_CIPHER_CTX* c) const noexcept -> void {
    EVP_CIPHER_CTX_free(c);
}

auto XtsCipher::create(XtsKey key, std::size_t data_unit_size)
    -> std::expected<XtsCipher, XtsError> {
    if (data_unit_size != data_unit_512 && data_unit_size != data_unit_4k) {
        return std::unexpected(XtsError::bad_data_unit_size);
    }
    // XTS with equal halves degenerates (IEEE 1619-2018 5.1 requires them to
    // differ). OpenSSL refuses such a key only when encrypting, so a
    // decrypt-only cipher would accept it; check both directions here.
    if (CRYPTO_memcmp(key.data(), key.data() + aes256_key_size, aes256_key_size) == 0) {
        return std::unexpected(XtsError::weak_key);
    }
    Ctx enc{EVP_CIPHER_CTX_new()};
    Ctx dec{EVP_CIPHER_CTX_new()};
    const EVP_CIPHER* aes_xts = EVP_aes_256_xts();
    if (!enc || !dec || aes_xts == nullptr ||
        EVP_EncryptInit_ex2(enc.get(), aes_xts, as_uchar(key), nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex2(dec.get(), aes_xts, as_uchar(key), nullptr, nullptr) != 1) {
        ERR_clear_error();
        return std::unexpected(XtsError::crypto_failure);
    }
    return XtsCipher{std::move(enc), std::move(dec), data_unit_size};
}

auto XtsCipher::encrypt(std::uint64_t first_unit, std::span<const std::byte> in,
                        std::span<std::byte> out) -> std::expected<void, XtsError> {
    return run(_enc.get(), first_unit, in, out);
}

auto XtsCipher::decrypt(std::uint64_t first_unit, std::span<const std::byte> in,
                        std::span<std::byte> out) -> std::expected<void, XtsError> {
    return run(_dec.get(), first_unit, in, out);
}

auto XtsCipher::run(EVP_CIPHER_CTX* ctx, std::uint64_t first_unit, std::span<const std::byte> in,
                    std::span<std::byte> out) const -> std::expected<void, XtsError> {
    if (in.empty() || in.size() % _unit != 0) {
        return std::unexpected(XtsError::bad_length);
    }
    if (out.size() != in.size() || !aliasing_ok(in, out)) {
        return std::unexpected(XtsError::buffer_mismatch);
    }
    const std::uint64_t units = in.size() / _unit;
    if (units - 1 > std::numeric_limits<std::uint64_t>::max() - first_unit) {
        return std::unexpected(XtsError::unit_number_overflow);
    }
    for (std::uint64_t n = 0; n < units; ++n) {
        const auto tweak = tweak_for(first_unit + n);
        const auto src = in.subspan(n * _unit, _unit);
        const auto dst = out.subspan(n * _unit, _unit);
        // Re-initialising with only an IV keeps the key schedule and starts
        // a new data unit. XTS consumes a whole unit in one update call and
        // produces exactly that many bytes; there is nothing to finalise.
        int written = 0;
        if (EVP_CipherInit_ex2(ctx, nullptr, nullptr, tweak.data(), -1, nullptr) != 1 ||
            EVP_CipherUpdate(ctx, as_uchar(dst), &written, as_uchar(src),
                             static_cast<int>(_unit)) != 1 ||
            std::cmp_not_equal(written, _unit)) {
            ERR_clear_error();
            return std::unexpected(XtsError::crypto_failure);
        }
    }
    return {};
}

}  // namespace ak::oar::blk
