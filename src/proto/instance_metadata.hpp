// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// InstanceMetadata: the controller's instance metadata record for one
// attached NIC (.kiro/specs/controller-interface/ Requirement 11, design
// "InstanceMetadata"; oar-net Requirements 13.4-13.8). helm forwards it
// unmodified to the NIC's network role, which checks the signature and
// answers the guest's metadata requests (169.254.169.254, IMDSv1 and v2)
// from it.
//
// The record carries only what the server cannot derive: the NIC's MAC
// and addresses come from its signed mapping entry and the subnet prefix
// from VpcConfig, so the metadata service and the data plane never
// disagree. It is a full snapshot at `metadata_version` (per NIC, from 1),
// so a role that missed versions catches up from the newest alone. Its
// server, key and NIC IDs are inside the signed bytes, so it cannot be
// replayed to another server or NIC.
//
// Layout (little-endian):
//   0x00  magic            u32  'AKIM'
//   0x04  version          u16  frame format version (1)
//   0x06  key_id           u16  controller key that signed it; non-zero
//   0x08  server_id        u64  target server; non-zero
//   0x10  nic_id           u64  the NIC the record answers for; non-zero
//   0x18  metadata_version u64  per NIC, starts at 1, increases on every change
//   0x20  vni              u32  the NIC's VPC; non-zero, 24 bits
//   0x24  http_endpoint    u8   0 disabled, 1 enabled
//   0x25  http_tokens      u8   0 optional, 1 required (IMDSv2 only)
//   0x26  put_hop_limit    u8   1..64: the token response's IP TTL / hop limit
//   0x27  device_index     u8
//   0x28  launch_index     u32
//   0x2C  user_data_size   u16  at most max_user_data_size
//   0x2E  reserved         u16  zero
//   0x30  pending_time     u64  Unix seconds
//   0x38  strings, in order: instance_id, image_id, instance_type,
//         account_id, local_hostname, availability_zone, region,
//         interface_id, vpc_id; each { size u8 (1..255) | bytes }
//   then  user_data        user_data_size bytes, served verbatim
//   then  signature        64 bytes, Ed25519 over every byte before it
//
// Strings are printable ASCII without spaces (0x21..0x7E); local_hostname
// is an RFC 1123 host name. The IDs keep EC2's prefixes (`i-`, `ami-`,
// `eni-`, `vpc-`) because guests and SDKs parse them. The largest frame
// (nine 255-byte strings, 16 KiB of user data) is max_instance_metadata_size
// (18,808) bytes, which helm forwards in OarLink chunks like a MapUpdate.

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
#include "proto/vpc_config.hpp"

namespace ak::proto {

inline constexpr std::uint32_t instance_metadata_magic = 0x4D49'4B41;  // "AKIM" as LE bytes
inline constexpr std::uint16_t instance_metadata_version = 1;
inline constexpr std::size_t instance_metadata_header_size = 0x38;
inline constexpr std::size_t instance_metadata_strings = 9;
inline constexpr std::size_t max_metadata_string_size = 255;
inline constexpr std::size_t max_user_data_size = 16384;  // EC2's limit
inline constexpr std::uint8_t min_put_hop_limit = 1;
inline constexpr std::uint8_t max_put_hop_limit = 64;

// Values are part of the wire protocol: never renumber.
enum class MetadataEndpoint : std::uint8_t {
    disabled = 0,
    enabled = 1,
};

enum class MetadataTokens : std::uint8_t {
    optional = 0,  // IMDSv1 and v2
    required = 1,  // IMDSv2 only
};

struct InstanceMetadata {
    std::uint64_t server_id{0};
    KeyId key_id{no_key_id};
    std::uint64_t nic_id{0};
    std::uint64_t metadata_version{0};
    std::uint32_t vni{0};
    // EC2's defaults: enabled, optional, 1.
    MetadataEndpoint http_endpoint{MetadataEndpoint::enabled};
    MetadataTokens http_tokens{MetadataTokens::optional};
    std::uint8_t put_hop_limit{1};
    std::uint8_t device_index{0};
    std::uint32_t launch_index{0};
    std::uint64_t pending_time{0};  // Unix seconds
    std::string instance_id{};      // i-...
    std::string image_id{};         // ami-...
    std::string instance_type{};
    std::string account_id{};
    std::string local_hostname{};
    std::string availability_zone{};
    std::string region{};
    std::string interface_id{};  // eni-...
    std::string vpc_id{};        // vpc-...
    std::vector<std::byte> user_data{};
    Ed25519Signature signature{};

    friend auto operator==(const InstanceMetadata&, const InstanceMetadata&) -> bool = default;
};

[[nodiscard]] inline constexpr auto instance_metadata_size(std::size_t string_bytes,
                                                           std::size_t user_data) noexcept
    -> std::size_t {
    return instance_metadata_header_size + instance_metadata_strings + string_bytes + user_data +
           ed25519_signature_size;
}

// Every string at least one byte.
inline constexpr std::size_t min_instance_metadata_size =
    instance_metadata_size(instance_metadata_strings, 0);
inline constexpr std::size_t max_instance_metadata_size = instance_metadata_size(
    instance_metadata_strings * max_metadata_string_size, max_user_data_size);
static_assert(max_instance_metadata_size == 18808);

// The bytes an InstanceMetadata signature covers: all but the trailing 64.
[[nodiscard]] inline auto instance_metadata_signed_bytes(std::span<const std::byte> frame) noexcept
    -> std::span<const std::byte> {
    return frame.first(
        frame.size() >= ed25519_signature_size ? frame.size() - ed25519_signature_size : 0);
}

inline auto set_instance_metadata_signature(
    std::span<std::byte> frame,
    std::span<const std::byte, ed25519_signature_size> signature) noexcept -> void {
    if (frame.size() >= min_instance_metadata_size) {
        std::ranges::copy(signature, frame.end() - ed25519_signature_size);
    }
}

namespace detail {

// The record's strings in wire order.
[[nodiscard]] inline auto metadata_strings(const InstanceMetadata& m) noexcept
    -> std::array<const std::string*, instance_metadata_strings> {
    return {&m.instance_id,       &m.image_id, &m.instance_type, &m.account_id, &m.local_hostname,
            &m.availability_zone, &m.region,   &m.interface_id,  &m.vpc_id};
}

[[nodiscard]] inline auto metadata_strings(InstanceMetadata& m) noexcept
    -> std::array<std::string*, instance_metadata_strings> {
    return {&m.instance_id,       &m.image_id, &m.instance_type, &m.account_id, &m.local_hostname,
            &m.availability_zone, &m.region,   &m.interface_id,  &m.vpc_id};
}

[[nodiscard]] inline auto metadata_token(std::string_view s) noexcept -> bool {
    return !s.empty() && s.size() <= max_metadata_string_size &&
           std::ranges::all_of(s, [](char c) { return c >= '!' && c <= '~'; });
}

// An ID with EC2's prefix and something after it.
[[nodiscard]] inline auto metadata_id(std::string_view s, std::string_view prefix) noexcept
    -> bool {
    return metadata_token(s) && s.size() > prefix.size() && s.starts_with(prefix);
}

[[nodiscard]] inline auto check_instance_metadata(const InstanceMetadata& m) noexcept
    -> std::expected<void, DecodeError> {
    if (m.key_id == no_key_id) {
        return std::unexpected(DecodeError::bad_key_id);
    }
    if (m.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (m.nic_id == 0) {
        return std::unexpected(DecodeError::bad_nic_id);
    }
    if (m.metadata_version == 0) {
        return std::unexpected(DecodeError::bad_metadata_version);
    }
    if (m.vni == 0 || m.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if ((m.http_endpoint != MetadataEndpoint::disabled &&
         m.http_endpoint != MetadataEndpoint::enabled) ||
        (m.http_tokens != MetadataTokens::optional && m.http_tokens != MetadataTokens::required)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (m.put_hop_limit < min_put_hop_limit || m.put_hop_limit > max_put_hop_limit ||
        m.user_data.size() > max_user_data_size) {
        return std::unexpected(DecodeError::bad_metadata);
    }
    for (const auto* s : metadata_strings(m)) {
        if (!metadata_token(*s)) {
            return std::unexpected(DecodeError::bad_metadata);
        }
    }
    if (!metadata_id(m.instance_id, "i-") || !metadata_id(m.image_id, "ami-") ||
        !metadata_id(m.interface_id, "eni-") || !metadata_id(m.vpc_id, "vpc-") ||
        !vpc_valid_domain(m.local_hostname)) {
        return std::unexpected(DecodeError::bad_metadata);
    }
    return {};
}

}  // namespace detail

[[nodiscard]] inline auto decode_instance_metadata(std::span<const std::byte> frame)
    -> std::expected<InstanceMetadata, DecodeError> {
    wire::Reader r{frame};
    auto magic = r.le32();
    auto version = r.le16();
    auto key_id = r.le16();
    if (!magic || !version || !key_id) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != instance_metadata_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != instance_metadata_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    auto server_id = r.le64();
    auto nic_id = r.le64();
    auto metadata_version = r.le64();
    auto vni = r.le32();
    auto endpoint = r.u8();
    auto tokens = r.u8();
    auto hop_limit = r.u8();
    auto device_index = r.u8();
    auto launch_index = r.le32();
    auto user_data_size = r.le16();
    auto reserved = r.le16();
    auto pending_time = r.le64();
    if (!server_id || !nic_id || !metadata_version || !vni || !endpoint || !tokens || !hop_limit ||
        !device_index || !launch_index || !user_data_size || !reserved || !pending_time) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*user_data_size > max_user_data_size) {
        return std::unexpected(DecodeError::bad_metadata);
    }
    InstanceMetadata out{.server_id = *server_id,
                         .key_id = *key_id,
                         .nic_id = *nic_id,
                         .metadata_version = *metadata_version,
                         .vni = *vni,
                         .http_endpoint = static_cast<MetadataEndpoint>(*endpoint),
                         .http_tokens = static_cast<MetadataTokens>(*tokens),
                         .put_hop_limit = *hop_limit,
                         .device_index = *device_index,
                         .launch_index = *launch_index,
                         .pending_time = *pending_time};
    for (auto* s : detail::metadata_strings(out)) {
        auto size = r.u8();
        if (!size) {
            return std::unexpected(DecodeError::truncated);
        }
        auto bytes = r.bytes(*size);
        if (!bytes) {
            return std::unexpected(DecodeError::truncated);
        }
        s->resize(*size);
        std::ranges::transform(*bytes, s->begin(),
                               [](std::byte b) { return static_cast<char>(b); });
    }
    auto user_data = r.bytes(*user_data_size);
    auto signature = r.bytes(ed25519_signature_size);
    if (!user_data || !signature) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    out.user_data.assign(user_data->begin(), user_data->end());
    std::ranges::copy(*signature, out.signature.begin());
    if (auto ok = detail::check_instance_metadata(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// Encodes an InstanceMetadata frame (with whatever is in `signature`),
// enforcing every rule decode_instance_metadata checks.
[[nodiscard]] inline auto encode_instance_metadata(const InstanceMetadata& m)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_instance_metadata(m); !ok) {
        return std::unexpected(ok.error());
    }
    std::size_t string_bytes = 0;
    for (const auto* s : detail::metadata_strings(m)) {
        string_bytes += s->size();
    }
    std::vector<std::byte> out;
    out.reserve(instance_metadata_size(string_bytes, m.user_data.size()));
    wire::Writer w{out};
    w.le32(instance_metadata_magic);
    w.le16(instance_metadata_version);
    w.le16(m.key_id);
    w.le64(m.server_id);
    w.le64(m.nic_id);
    w.le64(m.metadata_version);
    w.le32(m.vni);
    w.u8(static_cast<std::uint8_t>(m.http_endpoint));
    w.u8(static_cast<std::uint8_t>(m.http_tokens));
    w.u8(m.put_hop_limit);
    w.u8(m.device_index);
    w.le32(m.launch_index);
    w.le16(static_cast<std::uint16_t>(m.user_data.size()));
    w.le16(0);
    w.le64(m.pending_time);
    for (const auto* s : detail::metadata_strings(m)) {
        w.u8(static_cast<std::uint8_t>(s->size()));
        for (const char c : *s) {
            w.u8(static_cast<std::uint8_t>(c));
        }
    }
    w.bytes(m.user_data);
    w.bytes(m.signature);
    return out;
}

}  // namespace ak::proto
