// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/volume_key_seal.hpp"

#include <algorithm>

namespace ak::helm {

auto seal_volume_key(const hpke::PublicKey& recipient, proto::VolumeKey header,
                     std::span<const std::byte, proto::volume_data_key_size> key)
    -> std::expected<std::vector<std::byte>, hpke::Error> {
    // The AAD is the header alone, so encode it with a placeholder share
    // (the codec refuses an all-zero one) and seal over its first bytes.
    header.hpke_enc.fill(std::byte{1});
    auto draft = proto::encode_volume_key(header);
    if (!draft) {
        return std::unexpected(hpke::Error::bad_size);
    }
    const auto info = proto::volume_key_info;
    auto sealed = hpke::seal(recipient, std::as_bytes(std::span{info.data(), info.size()}),
                             proto::volume_key_aad(*draft), key);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    if (sealed->ciphertext.size() != header.wrapped_key.size()) {
        return std::unexpected(hpke::Error::bad_size);
    }
    std::ranges::copy(sealed->enc, header.hpke_enc.begin());
    std::ranges::copy(sealed->ciphertext, header.wrapped_key.begin());
    auto frame = proto::encode_volume_key(header);
    if (!frame) {
        return std::unexpected(hpke::Error::bad_size);
    }
    return std::move(*frame);
}

auto seal_image_key(const hpke::PublicKey& recipient, proto::ImageKey header,
                    std::span<const std::byte, proto::volume_data_key_size> key)
    -> std::expected<std::vector<std::byte>, hpke::Error> {
    header.hpke_enc.fill(std::byte{1});
    auto draft = proto::encode_image_key(header);
    if (!draft) {
        return std::unexpected(hpke::Error::bad_size);
    }
    const auto info = proto::image_key_info;
    auto sealed = hpke::seal(recipient, std::as_bytes(std::span{info.data(), info.size()}),
                             proto::image_key_aad(*draft), key);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    if (sealed->ciphertext.size() != header.wrapped_key.size()) {
        return std::unexpected(hpke::Error::bad_size);
    }
    std::ranges::copy(sealed->enc, header.hpke_enc.begin());
    std::ranges::copy(sealed->ciphertext, header.wrapped_key.begin());
    auto frame = proto::encode_image_key(header);
    if (!frame) {
        return std::unexpected(hpke::Error::bad_size);
    }
    return std::move(*frame);
}

auto seal_instance_secret(const hpke::PublicKey& recipient, std::uint64_t server, std::uint64_t vm,
                          std::string_view name, std::span<const std::byte> secret)
    -> std::expected<proto::InstanceSecret, hpke::Error> {
    const auto info = proto::instance_secret_info;
    auto sealed = hpke::seal(recipient, std::as_bytes(std::span{info.data(), info.size()}),
                             proto::instance_secret_aad(server, vm, name), secret);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    proto::InstanceSecret out{.name = std::string{name}, .hpke_enc = {}, .ciphertext = {}};
    std::ranges::copy(sealed->enc, out.hpke_enc.begin());
    out.ciphertext = std::move(sealed->ciphertext);
    return out;
}

}  // namespace ak::helm
