// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Secret key buffers that zeroize themselves (.kiro/specs/helm-control-plane/
// Requirement 4.5 and the KeyStore section of design.md).
//
// SecretBytes<N> is a fixed-size, move-only buffer whose destructor, and
// whose move operations on the source, wipe it with OPENSSL_cleanse, which
// the optimizer may not elide. ScopedKey is the plaintext volume key handed
// out by the KeyStore: it can be created only by a SecureElement and read
// only by OarLink::deliver_key, so the type system keeps volume keys out of
// mailbox messages and every other host-visible path.

#include <array>
#include <cstddef>
#include <span>

namespace ak::helm {

// Wipes `bytes` in a way the compiler cannot optimize away.
auto secure_zero(std::span<std::byte> bytes) noexcept -> void;

template<std::size_t N> class SecretBytes {
public:
    static constexpr std::size_t size = N;

    SecretBytes() noexcept = default;
    ~SecretBytes() { secure_zero(_bytes); }

    SecretBytes(const SecretBytes&) = delete;
    auto operator=(const SecretBytes&) -> SecretBytes& = delete;

    SecretBytes(SecretBytes&& other) noexcept : _bytes{other._bytes} { secure_zero(other._bytes); }
    auto operator=(SecretBytes&& other) noexcept -> SecretBytes& {
        if (this != &other) {
            _bytes = other._bytes;
            secure_zero(other._bytes);
        }
        return *this;
    }

    [[nodiscard]] auto span() noexcept -> std::span<std::byte, N> { return _bytes; }
    [[nodiscard]] auto span() const noexcept -> std::span<const std::byte, N> { return _bytes; }

private:
    std::array<std::byte, N> _bytes{};
};

// AES-256-XTS takes two 256-bit keys (oar-blk Requirement 2).
inline constexpr std::size_t volume_key_size = 64;

class OarLink;
class SecureElement;
struct ScopedKeyTestAccess;

class ScopedKey {
public:
    ScopedKey(const ScopedKey&) = delete;
    auto operator=(const ScopedKey&) -> ScopedKey& = delete;
    ScopedKey(ScopedKey&& other) noexcept;
    auto operator=(ScopedKey&& other) noexcept -> ScopedKey&;
    ~ScopedKey() = default;

    // False once moved from: the bytes have already been wiped.
    [[nodiscard]] auto holds_key() const noexcept -> bool { return _holds_key; }

private:
    // Only a SecureElement unwraps keys, so only it creates them.
    friend class SecureElement;
    // The single consumer: the sideband link to the storage role
    // (Requirement 4.4), in OarLink::deliver_key and copy_volume.
    friend class OarLink;
    // Unit tests compare unwrapped keys; defined only in tests/.
    friend struct ScopedKeyTestAccess;

    explicit ScopedKey(std::span<const std::byte, volume_key_size> key) noexcept;

    [[nodiscard]] auto bytes() const noexcept -> std::span<const std::byte, volume_key_size> {
        return _key.span();
    }

    SecretBytes<volume_key_size> _key;
    bool _holds_key{false};
};

}  // namespace ak::helm
