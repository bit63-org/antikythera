// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AES-256-XTS over whole data units (.kiro/specs/oar-blk-data-plane/
// Requirement 2.1, design "XtsCipher").
//
// Every data unit is encrypted independently under the volume key with its
// data unit number as the XTS tweak: the number goes into the 16-byte tweak
// as a little-endian integer, as IEEE 1619 specifies. Units are 512 bytes
// or 4 KiB; unit n of a 4 KiB volume covers 512-byte sectors 8n to 8n+7,
// and the caller passes n.
//
// The cipher keeps the expanded key only inside OpenSSL's cipher contexts,
// which OpenSSL cleanses when they are freed; it never copies the raw key.
// Holding and zeroizing the raw key is KeySlot's job (oar-blk task 2).
//
// An XtsCipher reuses its OpenSSL contexts for every call, so it must not
// be used from two threads at once; give each I/O queue its own.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>

#include <openssl/types.h>

namespace ak::oar::blk {

// Two AES-256 keys: the data key, then the tweak key.
inline constexpr std::size_t xts_key_size = 64;
inline constexpr std::size_t data_unit_512 = 512;
inline constexpr std::size_t data_unit_4k = 4096;

using XtsKey = std::span<const std::byte, xts_key_size>;

enum class XtsError : std::uint8_t {
    bad_data_unit_size,    // neither 512 nor 4096 bytes
    weak_key,              // the data key and tweak key are equal
    bad_length,            // empty, or not a whole number of data units
    buffer_mismatch,       // output size differs from input, or they partly overlap
    unit_number_overflow,  // the last data unit's number does not fit in 64 bits
    crypto_failure,        // OpenSSL failed
};

[[nodiscard]] auto to_string(XtsError e) noexcept -> const char*;

class XtsCipher {
public:
    [[nodiscard]] static auto create(XtsKey key, std::size_t data_unit_size)
        -> std::expected<XtsCipher, XtsError>;

    // Encrypts `in` into `out`: in.size() / data_unit_size() consecutive
    // data units, the first numbered `first_unit`. `out` must be the same
    // size as `in`, and is either exactly `in` (in place) or disjoint
    // from it. On error `out` may be partly written.
    [[nodiscard]] auto encrypt(std::uint64_t first_unit, std::span<const std::byte> in,
                               std::span<std::byte> out) -> std::expected<void, XtsError>;

    // The inverse of encrypt, with the same rules.
    [[nodiscard]] auto decrypt(std::uint64_t first_unit, std::span<const std::byte> in,
                               std::span<std::byte> out) -> std::expected<void, XtsError>;

    [[nodiscard]] auto data_unit_size() const noexcept -> std::size_t { return _unit; }

private:
    struct CtxDeleter {
        auto operator()(EVP_CIPHER_CTX* c) const noexcept -> void;
    };
    using Ctx = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

    XtsCipher(Ctx enc, Ctx dec, std::size_t unit) noexcept
        : _enc{std::move(enc)}, _dec{std::move(dec)}, _unit{unit} {}

    [[nodiscard]] auto run(EVP_CIPHER_CTX* ctx, std::uint64_t first_unit,
                           std::span<const std::byte> in, std::span<std::byte> out) const
        -> std::expected<void, XtsError>;

    Ctx _enc;
    Ctx _dec;
    std::size_t _unit;
};

}  // namespace ak::oar::blk
