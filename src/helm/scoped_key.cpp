// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/scoped_key.hpp"

#include <algorithm>
#include <utility>

#include <openssl/crypto.h>

namespace ak::helm {

auto secure_zero(std::span<std::byte> bytes) noexcept -> void {
    if (!bytes.empty()) {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }
}

ScopedKey::ScopedKey(std::span<const std::byte, volume_key_size> key) noexcept : _holds_key{true} {
    std::ranges::copy(key, _key.span().begin());
}

ScopedKey::ScopedKey(ScopedKey&& other) noexcept
    : _key{std::move(other._key)}, _holds_key{std::exchange(other._holds_key, false)} {}

auto ScopedKey::operator=(ScopedKey&& other) noexcept -> ScopedKey& {
    if (this != &other) {
        _key = std::move(other._key);
        _holds_key = std::exchange(other._holds_key, false);
    }
    return *this;
}

}  // namespace ak::helm
