// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The secure element behind helm's key hierarchy
// (.kiro/specs/helm-control-plane/ Requirement 4):
//
//   master key (never leaves the secure element)
//     └─ VM key       wrapped by the master key, bound to vm_id
//          └─ volume key  wrapped by its owner's VM key, bound to
//                         (volume_id, owner vm_id)
//
// Every operation takes wrapped keys in and gives wrapped keys out, so a
// plaintext VM key exists only inside the secure element. The one
// plaintext that leaves is a volume key, as a ScopedKey that only OarLink
// can read.
//
// Wrapping is AES-256-GCM with a fresh random 96-bit nonce. The additional
// authenticated data binds the blob's header and its identity (vm_id, or
// volume_id and owner), so a wrapped volume key copied onto another volume,
// or presented as another VM's, fails authentication: moving a volume
// between VMs needs an explicit rewrap (Requirement 4.7).
//
// Wrapped key wire format (stored by helm and on the media, so untrusted):
//
//   version u8 (1) | kind u8 | key_len u8 | nonce[12] | ciphertext[key_len] | tag[16]
//
// kind 1 = VM key (key_len 32), kind 2 = volume key (key_len 64).
//
// Network volume keys (.kiro/specs/block-volume-service/ design "VolumeKey")
// do not use this hierarchy: kythira KMS wraps each one with HPKE (hpke.hpp)
// to the secure element's X25519 transport key, and open_volume_key()
// unwraps it straight into a ScopedKey. The transport private key never
// leaves the secure element; enrollment registers transport_public_key().
//
// An encrypted image's key (oar-blk task 15, proto::ImageKey) arrives the
// same way, under its own HPKE info, and import_image_key() re-wraps it
// under the owning VM's key as that image volume's volume key, again
// without the plaintext leaving the secure element. From then on it is an
// ordinary wrapped volume key.
//
// SoftwareSecureElement is the harbor stand-in: the master key is a 32-byte
// file, created 0600 on first use and refused if anyone else can read it.
// Its transport key is derived from the master key (HPKE DeriveKeyPair over
// HMAC-SHA256(master, "antikythera se transport key v1")), so it is stable
// across restarts and dies with the master key.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "helm/device_pool.hpp"
#include "helm/hpke.hpp"
#include "helm/scoped_key.hpp"

namespace ak::helm {

using VolumeId = std::uint64_t;

inline constexpr std::size_t master_key_size = 32;
inline constexpr std::size_t vm_key_size = 32;

// Values are stored in wrapped keys: never renumber.
enum class KeyKind : std::uint8_t {
    vm = 1,
    volume = 2,
};

[[nodiscard]] constexpr auto key_size(KeyKind k) noexcept -> std::size_t {
    return k == KeyKind::vm ? vm_key_size : volume_key_size;
}

enum class WrappedKeyError : std::uint8_t {
    wrong_size,           // not the exact size its header implies
    unsupported_version,  // version byte is not 1
    unknown_kind,         // kind byte is not a KeyKind
    wrong_key_length,     // key_len does not match the kind
};

[[nodiscard]] auto to_string(WrappedKeyError e) noexcept -> const char*;

// A validated wrapped-key blob. Holds the encoded bytes; the ciphertext is
// useless without the wrapping key, but the bytes are still wiped on
// destruction so a destroyed key does not linger in helm's memory.
class WrappedKey {
public:
    static constexpr std::uint8_t format_version = 1;
    static constexpr std::size_t header_size = 3;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;

    [[nodiscard]] static constexpr auto encoded_size(KeyKind k) noexcept -> std::size_t {
        return header_size + nonce_size + key_size(k) + tag_size;
    }

    [[nodiscard]] static auto decode(std::span<const std::byte> bytes)
        -> std::expected<WrappedKey, WrappedKeyError>;

    WrappedKey(const WrappedKey&) = default;
    auto operator=(const WrappedKey&) -> WrappedKey& = default;
    WrappedKey(WrappedKey&&) noexcept = default;
    auto operator=(WrappedKey&&) noexcept -> WrappedKey& = default;
    ~WrappedKey();

    [[nodiscard]] auto kind() const noexcept -> KeyKind { return _kind; }
    [[nodiscard]] auto bytes() const noexcept -> std::span<const std::byte> { return _bytes; }
    [[nodiscard]] auto header() const noexcept -> std::span<const std::byte, header_size>;
    [[nodiscard]] auto nonce() const noexcept -> std::span<const std::byte, nonce_size>;
    [[nodiscard]] auto ciphertext() const noexcept -> std::span<const std::byte>;
    [[nodiscard]] auto tag() const noexcept -> std::span<const std::byte, tag_size>;

    friend auto operator==(const WrappedKey& a, const WrappedKey& b) -> bool {
        return a._bytes == b._bytes;
    }

private:
    WrappedKey(KeyKind kind, std::vector<std::byte> bytes) noexcept
        : _kind{kind}, _bytes{std::move(bytes)} {}

    KeyKind _kind;
    std::vector<std::byte> _bytes;
};

struct WrappedVmKey {
    VmId vm{0};
    WrappedKey key;
};

struct WrappedVolumeKey {
    VolumeId volume{0};
    VmId owner{0};
    WrappedKey key;
};

enum class SeError : std::uint8_t {
    random_failure,         // the RNG failed; nothing was created
    crypto_failure,         // OpenSSL failed outside authentication
    authentication_failed,  // wrong wrapping key, wrong identity, or tampered blob
    wrong_kind,             // a VM key where a volume key belongs, or vice versa
    wrong_vm_key,           // the VM key given is not the volume's owner's
    master_key_io,          // master key file could not be read or written
    master_key_insecure,    // master key file is not a 0600-or-tighter regular file
    master_key_wrong_size,  // master key file is not exactly master_key_size bytes
};

[[nodiscard]] auto to_string(SeError e) noexcept -> const char*;

class SecureElement {
public:
    SecureElement() = default;
    SecureElement(const SecureElement&) = delete;
    auto operator=(const SecureElement&) -> SecureElement& = delete;
    virtual ~SecureElement() = default;

    // Generates a VM key and returns it wrapped by the master key.
    virtual auto create_vm_key(VmId vm) -> std::expected<WrappedVmKey, SeError> = 0;

    // Generates a volume key and returns it wrapped by `owner`'s VM key.
    virtual auto create_volume_key(const WrappedVmKey& owner, VolumeId volume)
        -> std::expected<WrappedVolumeKey, SeError> = 0;

    // Unwraps a volume key for delivery to its storage role.
    virtual auto unwrap_volume_key(const WrappedVmKey& owner, const WrappedVolumeKey& volume)
        -> std::expected<ScopedKey, SeError> = 0;

    // Re-wraps `volume` from `from` (its current owner) to `to`, without the
    // volume key leaving the secure element.
    virtual auto rewrap_volume_key(const WrappedVmKey& from, const WrappedVmKey& to,
                                   const WrappedVolumeKey& volume)
        -> std::expected<WrappedVolumeKey, SeError> = 0;

    // The X25519 public key network volume keys are wrapped to.
    virtual auto transport_public_key() -> std::expected<hpke::PublicKey, SeError> = 0;

    // Opens a VolumeKey's wrapped key (HPKE, info proto::volume_key_info,
    // `aad` the frame header). authentication_failed if it was wrapped to
    // another key or for another header, or was changed.
    virtual auto open_volume_key(
        std::span<const std::byte> aad, std::span<const std::byte, hpke::enc_size> enc,
        std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped)
        -> std::expected<ScopedKey, SeError> = 0;

    // Encrypted images (proto::ImageKey: HPKE, info proto::image_key_info,
    // `aad` the frame header). check_image_key() only checks that the key
    // opens; import_image_key() opens it and returns it wrapped by
    // `owner`'s VM key as `volume`'s key, as create_volume_key() would.
    virtual auto check_image_key(
        std::span<const std::byte> aad, std::span<const std::byte, hpke::enc_size> enc,
        std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped)
        -> std::expected<void, SeError> = 0;
    virtual auto import_image_key(
        const WrappedVmKey& owner, VolumeId volume, std::span<const std::byte> aad,
        std::span<const std::byte, hpke::enc_size> enc,
        std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped)
        -> std::expected<WrappedVolumeKey, SeError> = 0;

    // Opens a standing instance's secret (cold-start Requirement 5.4: HPKE,
    // info proto::instance_secret_info, `aad` proto::instance_secret_aad of
    // its server, VM and name) into `out`, which must be ciphertext.size()
    // - hpke::tag_size bytes and is zeroed on failure. authentication_failed
    // if it was sealed to another key or for another instance or name.
    virtual auto open_instance_secret(std::span<const std::byte> aad,
                                      std::span<const std::byte, hpke::enc_size> enc,
                                      std::span<const std::byte> ciphertext,
                                      std::span<std::byte> out) -> std::expected<void, SeError> = 0;

    // Draws a fresh random volume key that is never wrapped or stored: an
    // image volume's attachment key (oar-blk Requirement 8.6), gone once
    // delivered. The default draws it from OpenSSL's RNG.
    virtual auto create_ephemeral_key() -> std::expected<ScopedKey, SeError>;

    // Destroys the master key (server-provisioning Requirement 5.2,
    // decommission): every VM key wrapped by it, every volume key under
    // those, and the transport key derived from it can no longer be
    // opened. The element carries on under a fresh random master key, so
    // a decommission interrupted after this step finds an element that
    // opens and simply holds nothing of the old keys.
    virtual auto destroy_master_key() -> std::expected<void, SeError> = 0;

protected:
    SecureElement(SecureElement&&) noexcept = default;
    auto operator=(SecureElement&&) noexcept -> SecureElement& = default;

    // ScopedKey's constructor is private to this base, so every
    // implementation creates keys through here.
    [[nodiscard]] static auto make_scoped_key(std::span<const std::byte, volume_key_size> key)
        -> ScopedKey {
        return ScopedKey{key};
    }
};

class SoftwareSecureElement final : public SecureElement {
public:
    // Opens the master key file at `path`, creating it (0600, random) if it
    // does not exist. Refuses symlinks, non-regular files, files readable or
    // writable by group or others, and files of the wrong size.
    [[nodiscard]] static auto open(const std::filesystem::path& path)
        -> std::expected<SoftwareSecureElement, SeError>;

    // A random master key held only in memory (tests, throwaway harbor runs).
    [[nodiscard]] static auto ephemeral() -> std::expected<SoftwareSecureElement, SeError>;

    SoftwareSecureElement(SoftwareSecureElement&&) noexcept = default;
    auto operator=(SoftwareSecureElement&&) noexcept -> SoftwareSecureElement& = default;
    ~SoftwareSecureElement() override = default;

    auto create_vm_key(VmId vm) -> std::expected<WrappedVmKey, SeError> override;
    auto create_volume_key(const WrappedVmKey& owner, VolumeId volume)
        -> std::expected<WrappedVolumeKey, SeError> override;
    auto unwrap_volume_key(const WrappedVmKey& owner, const WrappedVolumeKey& volume)
        -> std::expected<ScopedKey, SeError> override;
    auto rewrap_volume_key(const WrappedVmKey& from, const WrappedVmKey& to,
                           const WrappedVolumeKey& volume)
        -> std::expected<WrappedVolumeKey, SeError> override;
    auto transport_public_key() -> std::expected<hpke::PublicKey, SeError> override;
    auto open_instance_secret(std::span<const std::byte> aad,
                              std::span<const std::byte, hpke::enc_size> enc,
                              std::span<const std::byte> ciphertext, std::span<std::byte> out)
        -> std::expected<void, SeError> override;
    auto open_volume_key(std::span<const std::byte> aad,
                         std::span<const std::byte, hpke::enc_size> enc,
                         std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped)
        -> std::expected<ScopedKey, SeError> override;
    auto check_image_key(std::span<const std::byte> aad,
                         std::span<const std::byte, hpke::enc_size> enc,
                         std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped)
        -> std::expected<void, SeError> override;
    // A file-backed element replaces the file's key (written beside it,
    // synced, renamed over it). The old bytes may survive on the flash
    // underneath a file system; a hardware element destroys the key in
    // place.
    auto destroy_master_key() -> std::expected<void, SeError> override;
    auto import_image_key(const WrappedVmKey& owner, VolumeId volume,
                          std::span<const std::byte> aad,
                          std::span<const std::byte, hpke::enc_size> enc,
                          std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped)
        -> std::expected<WrappedVolumeKey, SeError> override;

private:
    explicit SoftwareSecureElement(
        SecretBytes<master_key_size> master,
        std::optional<std::filesystem::path> path = std::nullopt) noexcept
        : _master{std::move(master)}, _path{std::move(path)} {}

    [[nodiscard]] auto unwrap_vm_key(const WrappedVmKey& vm) const
        -> std::expected<SecretBytes<vm_key_size>, SeError>;
    [[nodiscard]] auto transport_key() const -> std::expected<hpke::KeyPair, SeError>;
    // Opens an HPKE-wrapped 64-byte key under `info` into `out`.
    [[nodiscard]] auto open_transport(
        std::string_view info, std::span<const std::byte> aad,
        std::span<const std::byte, hpke::enc_size> enc,
        std::span<const std::byte, volume_key_size + hpke::tag_size> wrapped,
        std::span<std::byte, volume_key_size> out) const -> std::expected<void, SeError>;

    SecretBytes<master_key_size> _master;
    std::optional<std::filesystem::path> _path;  // nullopt: ephemeral
};

}  // namespace ak::helm
