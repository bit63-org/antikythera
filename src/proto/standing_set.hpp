// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// StandingSet: the signed list of pinned instances a server's helm starts
// after power returns, with no controller (.kiro/specs/cold-start/
// Requirement 4, design "Records"; kythira .kiro/specs/az-cold-start/
// Requirements 2 and 3). Link record type 23, controller -> helm.
//
// helm keeps the newest set in its sealed store and, after a power loss,
// hands hull each instance as a standing start: these signed bytes plus
// the instance's index. hull verifies the signature against its compiled-in
// controller keys exactly as it does an envelope, then runs the instance's
// commands as if each were a signed mailbox command (without consuming a
// command sequence number). helm takes the volumes, NICs and secrets from
// the same entry: it sends each volume's frame to the storage role and
// unwraps its VolumeKey in the secure element as for a live attach, keeps
// the newest network frames for the listed NICs, and delivers each secret
// only through the instance's metadata.
//
// The whole set is one full snapshot at `generation`: a newer generation
// replaces it, an empty one unpins every instance on the server, and helm
// refuses any generation at or below the one anchored in its secure
// element's monotonic counter, so an old set cannot be replayed even from
// a restored copy of the store. Its server and key IDs are inside the
// signed bytes, so it cannot be moved to another server.
//
// Layout (little-endian):
//   0x00  magic       u32  'AKSS'
//   0x04  version     u16  frame format version (1)
//   0x06  key_id      u16  controller key that signed it; non-zero
//   0x08  server_id   u64  target server; non-zero
//   0x10  generation  u64  standing_generation; non-zero, increases on every change
//   0x18  time_floor  u64  Unix seconds the controller's clock had passed (0 = none)
//   0x20  count       u16  instances, at most max_standing_instances
//   0x22  reserved    [6]  zero
//   0x28  instances   count entries, vm_id strictly ascending:
//     +0x00  vm_id            u64  non-zero; the CREATE_VM's vm_id
//     +0x08  manifest_digest  [32] the image chunk manifest's digest; never all zero
//     +0x28  command_count    u8   1 .. max_standing_commands
//     +0x29  volume_count     u8   at most max_standing_volumes
//     +0x2A  nic_count        u8   at most max_standing_nics
//     +0x2B  secret_count     u8   at most max_instance_secrets
//     +0x2C  reserved         u32  zero
//     +0x30  commands  command_count x (type u16 | body_len u16 | body [body_len]):
//              a mailbox command body (at most 160 bytes), CREATE_VM first and
//              only first, then ATTACH_VOLUME and ATTACH_DEVICE in the order
//              hull runs them
//     then   volumes   volume_count x, attachment IDs strictly ascending:
//              frame_type u16 (8 replica_config, 17 volume_layout) | rsvd u16
//              frame_len u32 | frame [frame_len] (the signed frame, strictly
//              decodable) | volume_key [152] (a VolumeKey for this server)
//     then   nics      nic_count x (nic_id u64 | vni u32 | rsvd u32), NIC IDs
//              strictly ascending
//     then   secrets   secret_count x, names strictly ascending:
//              name_len u8 | rsvd u8 | ciphertext_len u16 | rsvd u32
//              hpke_enc [32] | name [name_len] | ciphertext [ciphertext_len]
//   then  signature   64 bytes, Ed25519 over every byte before it
//
// Instance secrets (kythira az-cold-start Requirement 3.3: HSM node unseal
// shares, bootstrap credentials) are HPKE-wrapped to this server's
// secure-element transport key like a VolumeKey, with their own info,
// instance_secret_info, and the AAD instance_secret_aad(server, vm, name),
// so a secret opens only for the instance and name it was wrapped for and
// cannot be passed off as a volume or image key. A name is 1 to 64 bytes
// of [A-Za-z0-9._-]; a secret's plaintext is 1 to max_secret_size bytes.
//
// The embedded volume frames are decoded strictly here, but their
// signatures are the storage role's to verify, as for a live frame; each
// frame and its VolumeKey must name this set's server. Command bodies are
// opaque here: hull decodes and checks them as it decodes any command,
// and refuses a CREATE_VM whose vm_id is not the entry's.
//
// Tunnel keys between tier-0 servers (cold-start Requirement 5.3) are not
// carried: fleet-scale-networking derives stable tunnel keys from the
// secure element, so they survive power loss without the controller.
//
// A set is at most max_standing_set_size bytes, under
// proto::max_record_payload; helm receives it over OarLink in chunks.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"
#include "proto/volume_key.hpp"
#include "proto/volume_layout.hpp"

namespace ak::proto {

inline constexpr std::uint32_t standing_set_magic = 0x5353'4B41;  // "AKSS" as little-endian bytes
inline constexpr std::uint16_t standing_set_version = 1;
inline constexpr std::size_t standing_set_header_size = 0x28;
inline constexpr std::size_t standing_instance_fixed_size = 0x30;
inline constexpr std::size_t standing_command_header_size = 4;
inline constexpr std::size_t standing_volume_header_size = 8;
inline constexpr std::size_t standing_nic_size = 16;
inline constexpr std::size_t instance_secret_header_size = 8 + hpke_enc_size;
inline constexpr std::size_t image_digest_size = 32;

inline constexpr std::size_t max_standing_instances = 16;
inline constexpr std::size_t max_standing_commands = 16;
inline constexpr std::size_t max_standing_volumes = 8;
inline constexpr std::size_t max_standing_nics = 8;
inline constexpr std::size_t max_instance_secrets = 8;
// The mailbox body limit (helm/mailbox.hpp max_body); a test pins them.
inline constexpr std::size_t max_standing_command_body = 160;
inline constexpr std::size_t max_secret_name_size = 64;
inline constexpr std::size_t max_secret_size = 4096;
inline constexpr std::size_t max_secret_ciphertext_size = max_secret_size + aead_tag_size;
inline constexpr std::size_t min_standing_set_size =
    standing_set_header_size + ed25519_signature_size;
inline constexpr std::size_t max_standing_set_size = 384 * 1024;

inline constexpr std::string_view instance_secret_info = "antikythera instance secret v1";

// The mailbox command types a standing start may run. Values equal
// helm::mailbox::Type's; tests/proto_standing_set_test.cpp pins them.
enum class StandingCommandType : std::uint16_t {
    create_vm = 0x0001,
    attach_device = 0x0010,
    attach_volume = 0x0022,
};

// The frame a standing volume's storage role is given. Values equal
// RecordType's (link.hpp); tests/proto_standing_set_test.cpp pins them.
enum class StandingVolumeFrame : std::uint16_t {
    replica_config = 8,
    volume_layout = 17,
};

using ImageDigest = std::array<std::byte, image_digest_size>;

struct StandingCommand {
    StandingCommandType type{StandingCommandType::create_vm};
    std::vector<std::byte> body;  // a mailbox command body, at most 160 bytes
    friend auto operator==(const StandingCommand&, const StandingCommand&) -> bool = default;
};

struct StandingVolume {
    StandingVolumeFrame frame_type{StandingVolumeFrame::volume_layout};
    std::vector<std::byte> frame;  // the signed frame, as the controller sent it
    VolumeKey key{};               // names the attachment: volume, attachment ID, generation
    friend auto operator==(const StandingVolume&, const StandingVolume&) -> bool = default;
};

struct StandingNic {
    std::uint64_t nic_id{0};
    std::uint32_t vni{0};
    friend auto operator==(const StandingNic&, const StandingNic&) -> bool = default;
};

struct InstanceSecret {
    std::string name;
    HpkeEnc hpke_enc{};
    std::vector<std::byte> ciphertext;  // AES-256-GCM ciphertext and tag
    friend auto operator==(const InstanceSecret&, const InstanceSecret&) -> bool = default;
};

struct StandingInstance {
    std::uint64_t vm_id{0};
    ImageDigest manifest_digest{};
    std::vector<StandingCommand> commands;  // CREATE_VM first
    std::vector<StandingVolume> volumes;    // attachment IDs strictly ascending
    std::vector<StandingNic> nics;          // NIC IDs strictly ascending
    std::vector<InstanceSecret> secrets;    // names strictly ascending
    friend auto operator==(const StandingInstance&, const StandingInstance&) -> bool = default;
};

struct StandingSet {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint64_t generation{0};
    std::uint64_t time_floor{0};
    std::vector<StandingInstance> instances;  // vm_id strictly ascending; empty unpins all
    Ed25519Signature signature{};
    friend auto operator==(const StandingSet&, const StandingSet&) -> bool = default;
};

// The bytes a StandingSet signature covers: all but the trailing 64.
[[nodiscard]] inline auto standing_set_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

inline auto set_standing_set_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= min_standing_set_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

// The HPKE AAD of an instance secret: server_id u64 | vm_id u64 | name.
[[nodiscard]] inline auto instance_secret_aad(std::uint64_t server_id, std::uint64_t vm_id,
                                              std::string_view name) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(16 + name.size());
    wire::Writer w{out};
    w.le64(server_id);
    w.le64(vm_id);
    for (char c : name) {
        w.u8(static_cast<std::uint8_t>(c));
    }
    return out;
}

namespace detail {

[[nodiscard]] constexpr auto known(StandingCommandType t) noexcept -> bool {
    return t == StandingCommandType::create_vm || t == StandingCommandType::attach_device ||
           t == StandingCommandType::attach_volume;
}

[[nodiscard]] constexpr auto known(StandingVolumeFrame f) noexcept -> bool {
    return f == StandingVolumeFrame::replica_config || f == StandingVolumeFrame::volume_layout;
}

[[nodiscard]] constexpr auto valid_secret_name(std::string_view name) noexcept -> bool {
    if (name.empty() || name.size() > max_secret_name_size) {
        return false;
    }
    return std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '_' || c == '-';
    });
}

// Decodes the embedded frame strictly; it must be for this set's server.
[[nodiscard]] inline auto check_standing_volume_frame(const StandingVolume& v,
                                                      std::uint64_t server_id) noexcept
    -> std::expected<void, DecodeError> {
    std::uint64_t frame_server = 0;
    switch (v.frame_type) {
        case StandingVolumeFrame::replica_config: {
            auto c = v.frame.size() <= max_replica_config_size
                         ? decode_replica_config(v.frame)
                         : std::unexpected(DecodeError::trailing_bytes);
            if (!c) {
                return std::unexpected(DecodeError::bad_standing_entry);
            }
            frame_server = c->server_id;
            break;
        }
        case StandingVolumeFrame::volume_layout: {
            auto l = v.frame.size() <= max_volume_layout_size
                         ? decode_volume_layout(v.frame)
                         : std::unexpected(DecodeError::trailing_bytes);
            if (!l) {
                return std::unexpected(DecodeError::bad_standing_entry);
            }
            frame_server = l->server_id;
            break;
        }
    }
    if (frame_server != server_id) {
        return std::unexpected(DecodeError::server_id_mismatch);
    }
    return {};
}

[[nodiscard]] inline auto standing_instance_size(const StandingInstance& in) noexcept
    -> std::size_t {
    std::size_t n = standing_instance_fixed_size;
    for (const auto& c : in.commands) {
        n += standing_command_header_size + c.body.size();
    }
    for (const auto& v : in.volumes) {
        n += standing_volume_header_size + v.frame.size() + volume_key_size;
    }
    n += in.nics.size() * standing_nic_size;
    for (const auto& s : in.secrets) {
        n += instance_secret_header_size + s.name.size() + s.ciphertext.size();
    }
    return n;
}

[[nodiscard]] inline auto check_standing_instance(const StandingInstance& in,
                                                  std::uint64_t server_id) noexcept
    -> std::expected<void, DecodeError> {
    if (in.vm_id == 0 || all_zero(in.manifest_digest)) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (in.commands.empty() || in.commands.size() > max_standing_commands ||
        in.volumes.size() > max_standing_volumes || in.nics.size() > max_standing_nics ||
        in.secrets.size() > max_instance_secrets) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < in.commands.size(); ++i) {
        const auto& c = in.commands[i];
        if (!known(c.type)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        // CREATE_VM first and only first: hull creates the VM, then attaches.
        if ((i == 0) != (c.type == StandingCommandType::create_vm) ||
            c.body.size() > max_standing_command_body) {
            return std::unexpected(DecodeError::bad_standing_entry);
        }
    }
    for (std::size_t i = 0; i < in.volumes.size(); ++i) {
        const auto& v = in.volumes[i];
        if (!known(v.frame_type)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (auto ok = check_volume_key(v.key); !ok) {
            return std::unexpected(ok.error());
        }
        if (v.key.server_id != server_id) {
            return std::unexpected(DecodeError::server_id_mismatch);
        }
        if (i > 0 && in.volumes[i - 1].key.attachment_id >= v.key.attachment_id) {
            return std::unexpected(DecodeError::not_ascending);
        }
        if (auto ok = check_standing_volume_frame(v, server_id); !ok) {
            return ok;
        }
    }
    for (std::size_t i = 0; i < in.nics.size(); ++i) {
        const auto& n = in.nics[i];
        if (n.nic_id == 0) {
            return std::unexpected(DecodeError::bad_nic_id);
        }
        if (n.vni == 0 || n.vni > max_vni) {
            return std::unexpected(DecodeError::bad_vni);
        }
        if (i > 0 && in.nics[i - 1].nic_id >= n.nic_id) {
            return std::unexpected(DecodeError::nic_ids_not_ascending);
        }
    }
    for (std::size_t i = 0; i < in.secrets.size(); ++i) {
        const auto& s = in.secrets[i];
        // An all-zero X25519 share is the identity point, which HPKE refuses.
        if (!valid_secret_name(s.name) || all_zero(s.hpke_enc) ||
            s.ciphertext.size() <= aead_tag_size ||
            s.ciphertext.size() > max_secret_ciphertext_size) {
            return std::unexpected(DecodeError::bad_standing_entry);
        }
        if (i > 0 && !(in.secrets[i - 1].name < s.name)) {
            return std::unexpected(DecodeError::not_ascending);
        }
    }
    return {};
}

[[nodiscard]] inline auto check_standing_set(const StandingSet& s) noexcept
    -> std::expected<void, DecodeError> {
    if (s.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (s.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (s.generation == 0) {
        return std::unexpected(DecodeError::bad_generation);
    }
    if (s.instances.size() > max_standing_instances) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    std::size_t size = min_standing_set_size;
    for (std::size_t i = 0; i < s.instances.size(); ++i) {
        if (auto ok = check_standing_instance(s.instances[i], s.server_id); !ok) {
            return ok;
        }
        if (i > 0 && s.instances[i - 1].vm_id >= s.instances[i].vm_id) {
            return std::unexpected(DecodeError::not_ascending);
        }
        size += standing_instance_size(s.instances[i]);
    }
    if (size > max_standing_set_size) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    return {};
}

[[nodiscard]] inline auto decode_standing_instance(wire::Reader& r)
    -> std::expected<StandingInstance, DecodeError> {
    auto vm_id = r.le64();
    auto digest = r.bytes(image_digest_size);
    auto command_count = r.u8();
    auto volume_count = r.u8();
    auto nic_count = r.u8();
    auto secret_count = r.u8();
    auto reserved = r.le32();
    if (!vm_id || !digest || !command_count || !volume_count || !nic_count || !secret_count ||
        !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    // Counts first, so a hostile header cannot make us reserve much.
    if (*command_count > max_standing_commands || *volume_count > max_standing_volumes ||
        *nic_count > max_standing_nics || *secret_count > max_instance_secrets) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    StandingInstance in{};
    in.vm_id = *vm_id;
    std::ranges::copy(*digest, in.manifest_digest.begin());
    in.commands.reserve(*command_count);
    for (std::uint8_t i = 0; i < *command_count; ++i) {
        auto type = r.le16();
        auto len = r.le16();
        if (!type || !len) {
            return std::unexpected(DecodeError::truncated);
        }
        if (*len > max_standing_command_body) {
            return std::unexpected(DecodeError::bad_standing_entry);
        }
        auto body = r.bytes(*len);
        if (!body) {
            return std::unexpected(DecodeError::truncated);
        }
        in.commands.push_back({.type = static_cast<StandingCommandType>(*type),
                               .body = std::vector<std::byte>(body->begin(), body->end())});
    }
    in.volumes.reserve(*volume_count);
    for (std::uint8_t i = 0; i < *volume_count; ++i) {
        auto type = r.le16();
        auto pad = r.le16();
        auto len = r.le32();
        if (!type || !pad || !len) {
            return std::unexpected(DecodeError::truncated);
        }
        if (*pad != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        if (*len > std::max(max_replica_config_size, max_volume_layout_size)) {
            return std::unexpected(DecodeError::bad_standing_entry);
        }
        auto frame = r.bytes(*len);
        auto key = r.bytes(volume_key_size);
        if (!frame || !key) {
            return std::unexpected(DecodeError::truncated);
        }
        auto k = decode_volume_key(*key);
        if (!k) {
            return std::unexpected(k.error());
        }
        in.volumes.push_back({.frame_type = static_cast<StandingVolumeFrame>(*type),
                              .frame = std::vector<std::byte>(frame->begin(), frame->end()),
                              .key = *k});
    }
    in.nics.reserve(*nic_count);
    for (std::uint8_t i = 0; i < *nic_count; ++i) {
        auto nic_id = r.le64();
        auto vni = r.le32();
        auto pad = r.le32();
        if (!nic_id || !vni || !pad) {
            return std::unexpected(DecodeError::truncated);
        }
        if (*pad != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        in.nics.push_back({.nic_id = *nic_id, .vni = *vni});
    }
    in.secrets.reserve(*secret_count);
    for (std::uint8_t i = 0; i < *secret_count; ++i) {
        auto name_len = r.u8();
        auto pad1 = r.u8();
        auto ct_len = r.le16();
        auto pad2 = r.le32();
        auto enc = r.bytes(hpke_enc_size);
        if (!name_len || !pad1 || !ct_len || !pad2 || !enc) {
            return std::unexpected(DecodeError::truncated);
        }
        if (*pad1 != 0 || *pad2 != 0) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        auto name = r.bytes(*name_len);
        auto ct = r.bytes(*ct_len);
        if (!name || !ct) {
            return std::unexpected(DecodeError::truncated);
        }
        InstanceSecret& s = in.secrets.emplace_back();
        s.name.reserve(name->size());
        for (std::byte b : *name) {
            s.name.push_back(static_cast<char>(std::to_integer<std::uint8_t>(b)));
        }
        std::ranges::copy(*enc, s.hpke_enc.begin());
        s.ciphertext.assign(ct->begin(), ct->end());
    }
    return in;
}

inline auto write_standing_instance(wire::Writer& w, const StandingInstance& in)
    -> std::expected<void, DecodeError> {
    w.le64(in.vm_id);
    w.bytes(in.manifest_digest);
    w.u8(static_cast<std::uint8_t>(in.commands.size()));
    w.u8(static_cast<std::uint8_t>(in.volumes.size()));
    w.u8(static_cast<std::uint8_t>(in.nics.size()));
    w.u8(static_cast<std::uint8_t>(in.secrets.size()));
    w.le32(0);
    for (const auto& c : in.commands) {
        w.le16(static_cast<std::uint16_t>(c.type));
        w.le16(static_cast<std::uint16_t>(c.body.size()));
        w.bytes(c.body);
    }
    for (const auto& v : in.volumes) {
        auto key = encode_volume_key(v.key);
        if (!key) {
            return std::unexpected(key.error());
        }
        w.le16(static_cast<std::uint16_t>(v.frame_type));
        w.le16(0);
        w.le32(static_cast<std::uint32_t>(v.frame.size()));
        w.bytes(v.frame);
        w.bytes(*key);
    }
    for (const auto& n : in.nics) {
        w.le64(n.nic_id);
        w.le32(n.vni);
        w.le32(0);
    }
    for (const auto& s : in.secrets) {
        w.u8(static_cast<std::uint8_t>(s.name.size()));
        w.u8(0);
        w.le16(static_cast<std::uint16_t>(s.ciphertext.size()));
        w.le32(0);
        w.bytes(s.hpke_enc);
        for (char c : s.name) {
            w.u8(static_cast<std::uint8_t>(c));
        }
        w.bytes(s.ciphertext);
    }
    return {};
}

}  // namespace detail

// Strict decode. Does not verify the signature: the receiver verifies
// standing_set_signed_bytes(frame) against `signature` under `key_id`
// before acting on anything else in the result.
[[nodiscard]] inline auto decode_standing_set(std::span<const std::byte> bytes)
    -> std::expected<StandingSet, DecodeError> {
    if (bytes.size() > max_standing_set_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    auto server_id = r.le64();
    auto generation = r.le64();
    auto time_floor = r.le64();
    auto count = r.le16();
    auto reserved = r.bytes(6);
    if (!magic || !version || !key_id || !server_id || !generation || !time_floor || !count ||
        !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != standing_set_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != standing_set_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!detail::all_zero(*reserved)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*count > max_standing_instances) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    StandingSet out{};
    out.server_id = *server_id;
    out.key_id = *key_id;
    out.generation = *generation;
    out.time_floor = *time_floor;
    out.instances.reserve(*count);
    for (std::uint16_t i = 0; i < *count; ++i) {
        auto in = detail::decode_standing_instance(r);
        if (!in) {
            return std::unexpected(in.error());
        }
        out.instances.push_back(std::move(*in));
    }
    auto signature = r.bytes(ed25519_signature_size);
    if (!signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = detail::check_standing_set(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes a StandingSet (with whatever is in `signature`), enforcing every
// rule decode_standing_set checks.
[[nodiscard]] inline auto encode_standing_set(const StandingSet& s)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_standing_set(s); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    std::size_t size = min_standing_set_size;
    for (const auto& in : s.instances) {
        size += detail::standing_instance_size(in);
    }
    out.reserve(size);
    wire::Writer w{out};
    w.le32(standing_set_magic);
    w.le16(standing_set_version);
    w.le16(s.key_id);
    w.le64(s.server_id);
    w.le64(s.generation);
    w.le64(s.time_floor);
    w.le16(static_cast<std::uint16_t>(s.instances.size()));
    w.bytes(std::array<std::byte, 6>{});
    for (const auto& in : s.instances) {
        if (auto ok = detail::write_standing_instance(w, in); !ok) {
            return std::unexpected(ok.error());
        }
    }
    w.bytes(s.signature);
    return out;
}

}  // namespace ak::proto
