// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/key_store.hpp"

#include <utility>

namespace ak::helm {

namespace {

auto from_se(SeError e) noexcept -> KeyError {
    switch (e) {
        case SeError::authentication_failed:
            return KeyError::corrupt_key;
        case SeError::wrong_kind:
            return KeyError::wrong_kind;
        case SeError::wrong_vm_key:
            return KeyError::wrong_vm;
        case SeError::random_failure:
        case SeError::crypto_failure:
        case SeError::master_key_io:
        case SeError::master_key_insecure:
        case SeError::master_key_wrong_size:
            break;
    }
    return KeyError::secure_element;
}

}  // namespace

auto to_string(KeyError e) noexcept -> const char* {
    switch (e) {
        case KeyError::invalid_id:
            return "invalid_id";
        case KeyError::unknown_vm:
            return "unknown_vm";
        case KeyError::duplicate_vm:
            return "duplicate_vm";
        case KeyError::unknown_volume:
            return "unknown_volume";
        case KeyError::duplicate_volume:
            return "duplicate_volume";
        case KeyError::wrong_vm:
            return "wrong_vm";
        case KeyError::same_vm:
            return "same_vm";
        case KeyError::wrong_kind:
            return "wrong_kind";
        case KeyError::corrupt_key:
            return "corrupt_key";
        case KeyError::secure_element:
            return "secure_element";
        case KeyError::stale_generation:
            return "stale_generation";
        case KeyError::unknown_attachment:
            return "unknown_attachment";
        case KeyError::too_many_keys:
            return "too_many_keys";
    }
    return "unknown";
}

auto KeyStore::create_vm_key(VmId vm) -> std::expected<void, KeyError> {
    if (vm == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (_vm_keys.contains(vm)) {
        return std::unexpected(KeyError::duplicate_vm);
    }
    auto key = _se->create_vm_key(vm);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    _vm_keys.emplace(vm, std::move(*key));
    return {};
}

auto KeyStore::destroy_vm_key(VmId vm) -> std::expected<std::vector<VolumeId>, KeyError> {
    const auto it = _vm_keys.find(vm);
    if (it == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto erased = volumes_of(vm);
    for (const auto volume : erased) {
        _volume_keys.erase(volume);
    }
    _vm_keys.erase(it);
    std::erase_if(_image_keys, [vm](const auto& entry) {
        const auto k = proto::decode_image_key(entry.second);
        return !k || k->owner_vm == vm;
    });
    return erased;
}

auto KeyStore::create_volume_key(VolumeId volume, VmId owner) -> std::expected<void, KeyError> {
    if (volume == 0 || owner == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (_volume_keys.contains(volume)) {
        return std::unexpected(KeyError::duplicate_volume);
    }
    const auto vm = _vm_keys.find(owner);
    if (vm == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->create_volume_key(vm->second, volume);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    _volume_keys.emplace(volume, std::move(*key));
    return {};
}

auto KeyStore::unwrap_volume_key(VolumeId volume, VmId requester)
    -> std::expected<ScopedKey, KeyError> {
    const auto vol = _volume_keys.find(volume);
    if (vol == _volume_keys.end()) {
        return std::unexpected(KeyError::unknown_volume);
    }
    if (vol->second.owner != requester) {
        return std::unexpected(KeyError::wrong_vm);
    }
    const auto vm = _vm_keys.find(requester);
    if (vm == _vm_keys.end()) {
        // Unreachable through this API: destroy_vm_key drops the VM's volumes.
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->unwrap_volume_key(vm->second, vol->second);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    return std::move(*key);
}

auto KeyStore::create_ephemeral_key() -> std::expected<ScopedKey, KeyError> {
    auto key = _se->create_ephemeral_key();
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    return std::move(*key);
}

namespace {

auto open_frame(SecureElement& se, std::span<const std::byte> frame, const proto::VolumeKey& k)
    -> std::expected<ScopedKey, KeyError> {
    auto key = se.open_volume_key(proto::volume_key_aad(frame), k.hpke_enc, k.wrapped_key);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    return std::move(*key);
}

}  // namespace

auto KeyStore::put_attachment_key(std::span<const std::byte> frame)
    -> std::expected<void, KeyError> {
    const auto k = proto::decode_volume_key(frame);
    if (!k) {
        return std::unexpected(KeyError::corrupt_key);
    }
    const auto it = _attachment_keys.find(k->attachment_id);
    if (it != _attachment_keys.end()) {
        const auto kept = proto::decode_volume_key(it->second);
        if (kept && kept->generation > k->generation) {
            return std::unexpected(KeyError::stale_generation);
        }
    } else if (_attachment_keys.size() >= max_attachment_keys) {
        return std::unexpected(KeyError::too_many_keys);
    }
    if (auto opened = open_frame(*_se, frame, *k); !opened) {
        return std::unexpected(opened.error());
    }  // the plaintext is wiped here
    _attachment_keys[k->attachment_id] = {frame.begin(), frame.end()};
    return {};
}

auto KeyStore::open_instance_secret(std::uint64_t server, VmId vm,
                                    const proto::InstanceSecret& secret, std::span<std::byte> out)
    -> std::expected<void, KeyError> {
    if (secret.ciphertext.size() <= hpke::tag_size ||
        out.size() != secret.ciphertext.size() - hpke::tag_size) {
        return std::unexpected(KeyError::corrupt_key);
    }
    const auto aad = proto::instance_secret_aad(server, vm, secret.name);
    if (auto ok = _se->open_instance_secret(aad, secret.hpke_enc, secret.ciphertext, out); !ok) {
        return std::unexpected(ok.error() == SeError::authentication_failed
                                   ? KeyError::corrupt_key
                                   : KeyError::secure_element);
    }
    return {};
}

auto KeyStore::open_attachment_key(AttachmentId attachment, std::uint32_t generation)
    -> std::expected<ScopedKey, KeyError> {
    const auto it = _attachment_keys.find(attachment);
    if (it == _attachment_keys.end()) {
        return std::unexpected(KeyError::unknown_attachment);
    }
    const auto k = proto::decode_volume_key(it->second);
    if (!k) {
        return std::unexpected(KeyError::corrupt_key);
    }
    if (k->generation != generation) {
        return std::unexpected(k->generation > generation ? KeyError::stale_generation
                                                          : KeyError::unknown_attachment);
    }
    return open_frame(*_se, it->second, *k);
}

auto KeyStore::attachment_key(AttachmentId attachment) const -> std::optional<proto::VolumeKey> {
    const auto it = _attachment_keys.find(attachment);
    if (it == _attachment_keys.end()) {
        return std::nullopt;
    }
    auto k = proto::decode_volume_key(it->second);
    if (!k) {
        return std::nullopt;
    }
    return *k;
}

auto KeyStore::drop_attachment_key(AttachmentId attachment) -> void {
    _attachment_keys.erase(attachment);
}

auto KeyStore::put_image_key(std::span<const std::byte> frame) -> std::expected<void, KeyError> {
    const auto k = proto::decode_image_key(frame);
    if (!k) {
        return std::unexpected(KeyError::corrupt_key);
    }
    if (!_image_keys.contains(k->volume_id) && _image_keys.size() >= max_image_keys) {
        return std::unexpected(KeyError::too_many_keys);
    }
    if (auto ok = _se->check_image_key(proto::image_key_aad(frame), k->hpke_enc, k->wrapped_key);
        !ok) {
        return std::unexpected(from_se(ok.error()));
    }
    _image_keys[k->volume_id] = {frame.begin(), frame.end()};
    return {};
}

auto KeyStore::image_key(VolumeId volume) const -> std::optional<proto::ImageKey> {
    const auto it = _image_keys.find(volume);
    if (it == _image_keys.end()) {
        return std::nullopt;
    }
    auto k = proto::decode_image_key(it->second);
    if (!k) {
        return std::nullopt;
    }
    return *k;
}

auto KeyStore::import_image_key(VolumeId volume, VmId owner) -> std::expected<void, KeyError> {
    if (volume == 0 || owner == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    const auto it = _image_keys.find(volume);
    if (it == _image_keys.end()) {
        return std::unexpected(KeyError::unknown_volume);
    }
    const auto k = proto::decode_image_key(it->second);
    if (!k) {
        return std::unexpected(KeyError::corrupt_key);
    }
    if (k->owner_vm != owner) {
        return std::unexpected(KeyError::wrong_vm);
    }
    if (_volume_keys.contains(volume)) {
        return std::unexpected(KeyError::duplicate_volume);
    }
    const auto vm = _vm_keys.find(owner);
    if (vm == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->import_image_key(vm->second, volume, proto::image_key_aad(it->second),
                                     k->hpke_enc, k->wrapped_key);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    _volume_keys.emplace(volume, std::move(*key));
    _image_keys.erase(it);
    return {};
}

auto KeyStore::drop_image_key(VolumeId volume) -> void {
    _image_keys.erase(volume);
}

auto KeyStore::rewrap(VolumeId volume, VmId new_owner) -> std::expected<void, KeyError> {
    const auto vol = _volume_keys.find(volume);
    if (vol == _volume_keys.end()) {
        return std::unexpected(KeyError::unknown_volume);
    }
    if (vol->second.owner == new_owner) {
        return std::unexpected(KeyError::same_vm);
    }
    const auto to = _vm_keys.find(new_owner);
    if (to == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    const auto from = _vm_keys.find(vol->second.owner);
    if (from == _vm_keys.end()) {
        return std::unexpected(KeyError::unknown_vm);
    }
    auto key = _se->rewrap_volume_key(from->second, to->second, vol->second);
    if (!key) {
        return std::unexpected(from_se(key.error()));
    }
    vol->second = std::move(*key);
    return {};
}

auto KeyStore::destroy_volume_key(VolumeId volume) -> std::expected<void, KeyError> {
    if (_volume_keys.erase(volume) == 0) {
        return std::unexpected(KeyError::unknown_volume);
    }
    return {};
}

auto KeyStore::import_vm_key(WrappedVmKey key) -> std::expected<void, KeyError> {
    if (key.vm == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (key.key.kind() != KeyKind::vm) {
        return std::unexpected(KeyError::wrong_kind);
    }
    if (_vm_keys.contains(key.vm)) {
        return std::unexpected(KeyError::duplicate_vm);
    }
    const auto vm = key.vm;
    _vm_keys.emplace(vm, std::move(key));
    return {};
}

auto KeyStore::import_volume_key(WrappedVolumeKey key) -> std::expected<void, KeyError> {
    if (key.volume == 0 || key.owner == 0) {
        return std::unexpected(KeyError::invalid_id);
    }
    if (key.key.kind() != KeyKind::volume) {
        return std::unexpected(KeyError::wrong_kind);
    }
    if (_volume_keys.contains(key.volume)) {
        return std::unexpected(KeyError::duplicate_volume);
    }
    if (!_vm_keys.contains(key.owner)) {
        return std::unexpected(KeyError::unknown_vm);
    }
    const auto volume = key.volume;
    _volume_keys.emplace(volume, std::move(key));
    return {};
}

auto KeyStore::find_vm_key(VmId vm) const -> std::optional<WrappedVmKey> {
    const auto it = _vm_keys.find(vm);
    if (it == _vm_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

auto KeyStore::find_volume_key(VolumeId volume) const -> std::optional<WrappedVolumeKey> {
    const auto it = _volume_keys.find(volume);
    if (it == _volume_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

auto KeyStore::owner(VolumeId volume) const -> std::optional<VmId> {
    const auto it = _volume_keys.find(volume);
    if (it == _volume_keys.end()) {
        return std::nullopt;
    }
    return it->second.owner;
}

auto KeyStore::volumes_of(VmId vm) const -> std::vector<VolumeId> {
    std::vector<VolumeId> out;
    for (const auto& [volume, key] : _volume_keys) {
        if (key.owner == vm) {
            out.push_back(volume);
        }
    }
    return out;
}

auto KeyStore::destroy_all() -> std::expected<void, KeyError> {
    // VM keys first, as DESTROY_VM would: each takes its volumes' keys.
    while (!_vm_keys.empty()) {
        (void)destroy_vm_key(_vm_keys.begin()->first);
    }
    _volume_keys.clear();
    _attachment_keys.clear();
    _image_keys.clear();
    if (!_se->destroy_master_key()) {
        return std::unexpected(KeyError::secure_element);
    }
    return {};
}

}  // namespace ak::helm
