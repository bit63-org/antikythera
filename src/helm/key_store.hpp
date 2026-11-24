// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// KeyStore: helm's table of wrapped VM and volume keys, in front of the
// secure element (.kiro/specs/helm-control-plane/ Requirement 4 and the
// KeyStore section of design.md).
//
// It enforces the hierarchy's rules:
//   - a volume's key unwraps only for the VM that owns it (4.4);
//   - moving a volume needs rewrap(), never a silent owner change (4.7);
//   - destroy_volume_key() forgets the wrapped key (DELETE_VOLUME, 4.6);
//   - destroy_vm_key() forgets the VM key and every volume key it wraps,
//     crypto-erasing them, for DESTROY_VM with persist_volumes = false (4.6).
//
// The KeyStore holds only wrapped keys; the plaintext volume key it hands
// out is a ScopedKey only OarLink can read (4.5). The import_* and find_*
// calls let helm persist the wrapped keys (VM keys on helm's own storage,
// volume keys on the media) and reload them after a restart; imported blobs
// are authenticated on first use, not on import.
//
// Network volume keys (.kiro/specs/block-volume-service/ design "VolumeKey")
// are kept per attachment, still wrapped: put_attachment_key() takes the
// controller's VolumeKey frame, opens it once in the secure element to
// refuse a bad one up front, and keeps the frame; open_attachment_key()
// opens it again for each delivery (an attach, or oar-blk restarting), so
// the plaintext exists only on its way to OarLink. A newer generation of
// the attachment replaces the older; drop_attachment_key() forgets it at
// detach. At most max_attachment_keys are kept.
//
// Encrypted images (.kiro/specs/oar-blk-data-plane/ task 15): the
// controller sends K_img as an ImageKey frame for the image volume a
// CREATE_VOLUME is about to create. put_image_key() opens it once to
// refuse a bad one and keeps the frame, still wrapped to the transport
// key, under the volume ID. import_image_key() then (at that CREATE_VOLUME)
// re-wraps it in the secure element under the owner's VM key, after
// checking the frame names the same owner, and keeps the result as the
// volume's ordinary volume key: unwrap, rewrap, destroy and import all
// treat it as one. The frame is forgotten once imported, or by
// drop_image_key(); a newer frame for the volume replaces an older one,
// and destroy_vm_key() drops the frames naming that VM. At most
// max_image_keys frames are kept.

#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <vector>

#include "helm/secure_element.hpp"
#include "proto/image_key.hpp"
#include "proto/volume_key.hpp"

namespace ak::helm {

enum class KeyError : std::uint8_t {
    invalid_id,  // vm_id or volume_id is zero (ids are never zero)
    unknown_vm,
    duplicate_vm,
    unknown_volume,
    duplicate_volume,
    wrong_vm,        // the VM asking for a volume key does not own it
    same_vm,         // rewrap to the volume's current owner
    wrong_kind,      // an imported blob of the wrong KeyKind
    corrupt_key,     // a wrapped key failed authentication
    secure_element,  // the secure element failed (RNG, crypto)
    // Attachment keys.
    stale_generation,  // older than the attachment's key already kept
    unknown_attachment,
    too_many_keys,  // max_attachment_keys are kept already
};

inline constexpr std::size_t max_attachment_keys = 4096;
inline constexpr std::size_t max_image_keys = 4096;

using AttachmentId = std::uint64_t;

[[nodiscard]] auto to_string(KeyError e) noexcept -> const char*;

class KeyStore {
public:
    // `se` must outlive the KeyStore.
    explicit KeyStore(SecureElement& se) noexcept : _se{&se} {}

    auto create_vm_key(VmId vm) -> std::expected<void, KeyError>;
    // Forgets the VM key and every volume key wrapped by it. Returns those
    // volumes, now crypto-erased, in id order.
    auto destroy_vm_key(VmId vm) -> std::expected<std::vector<VolumeId>, KeyError>;

    auto create_volume_key(VolumeId volume, VmId owner) -> std::expected<void, KeyError>;
    auto unwrap_volume_key(VolumeId volume, VmId requester) -> std::expected<ScopedKey, KeyError>;
    auto rewrap(VolumeId volume, VmId new_owner) -> std::expected<void, KeyError>;
    auto destroy_volume_key(VolumeId volume) -> std::expected<void, KeyError>;
    // A fresh key for one attachment of an image volume, never wrapped or
    // kept (SecureElement::create_ephemeral_key).
    auto create_ephemeral_key() -> std::expected<ScopedKey, KeyError>;

    // Network volume keys, per attachment (see above). `frame` is the
    // encoded VolumeKey the controller sent.
    auto put_attachment_key(std::span<const std::byte> frame) -> std::expected<void, KeyError>;
    // The attachment's key, if `generation` is the one kept.
    auto open_attachment_key(AttachmentId attachment, std::uint32_t generation)
        -> std::expected<ScopedKey, KeyError>;
    // The kept key's header (volume and generation), without opening it.
    [[nodiscard]] auto attachment_key(AttachmentId attachment) const
        -> std::optional<proto::VolumeKey>;
    auto drop_attachment_key(AttachmentId attachment) -> void;
    [[nodiscard]] auto attachment_key_count() const noexcept -> std::size_t {
        return _attachment_keys.size();
    }

    // Encrypted images' keys, per volume until its CREATE_VOLUME (see
    // above). `frame` is the encoded ImageKey the controller sent.
    auto put_image_key(std::span<const std::byte> frame) -> std::expected<void, KeyError>;
    // The kept frame's header (volume and owner), without opening it.
    [[nodiscard]] auto image_key(VolumeId volume) const -> std::optional<proto::ImageKey>;
    // Re-wraps the volume's kept image key under `owner`'s VM key as the
    // volume's key and forgets the frame. unknown_volume without a frame,
    // wrong_vm if the frame names another owner.
    auto import_image_key(VolumeId volume, VmId owner) -> std::expected<void, KeyError>;
    auto drop_image_key(VolumeId volume) -> void;
    [[nodiscard]] auto image_key_count() const noexcept -> std::size_t {
        return _image_keys.size();
    }

    // Reload persisted wrapped keys. A volume key's owner must already be
    // known.
    auto import_vm_key(WrappedVmKey key) -> std::expected<void, KeyError>;
    auto import_volume_key(WrappedVolumeKey key) -> std::expected<void, KeyError>;

    [[nodiscard]] auto find_vm_key(VmId vm) const -> std::optional<WrappedVmKey>;
    [[nodiscard]] auto find_volume_key(VolumeId volume) const -> std::optional<WrappedVolumeKey>;
    [[nodiscard]] auto owner(VolumeId volume) const -> std::optional<VmId>;
    [[nodiscard]] auto volumes_of(VmId vm) const -> std::vector<VolumeId>;
    [[nodiscard]] auto vm_count() const noexcept -> std::size_t { return _vm_keys.size(); }
    [[nodiscard]] auto volume_count() const noexcept -> std::size_t { return _volume_keys.size(); }

private:
    SecureElement* _se;
    std::map<VmId, WrappedVmKey> _vm_keys;
    std::map<VolumeId, WrappedVolumeKey> _volume_keys;
    std::map<AttachmentId, std::vector<std::byte>> _attachment_keys;  // VolumeKey frames
    std::map<VolumeId, std::vector<std::byte>> _image_keys;           // ImageKey frames
};

}  // namespace ak::helm
