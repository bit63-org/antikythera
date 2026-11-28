// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The boot function's disk: what the host's UEFI firmware boots hull from
// (.kiro/specs/server-provisioning/ Requirement 4, design "The boot
// function"). The host has no NIC of its own, so helm presents a read-only
// block function on the control slot holding a GPT disk with two
// partitions:
//
//   1  EFI system partition, FAT32, holding the hull UKI as the removable
//      media boot path (\EFI\BOOT\BOOTX64.EFI or BOOTAA64.EFI), which
//      firmware boots with no boot entry configured
//   2  "ak-provisioning": helm's Provisioning frame (proto/provisioning.hpp)
//      at its first byte, zero-padded; hull-init finds it by its GPT name,
//      measures it into a PCR, and only then reads it
//
// Layout (512-byte sectors): protective MBR, primary GPT header and 128
// entries, partitions aligned to 1 MiB, backup entries and header in the
// last 33 sectors. The ESP is at least big enough for FAT32's minimum
// cluster count, using one sector per cluster. Every byte of the disk is
// written (unused space as zeros), so the same UKI and frame always give
// the same disk.
//
// The disk is written through the Flash interface: a file that harbor's
// QEMU attaches read-only, or the function's backing store on a board.
// Its size depends only on the UKI's: boot_disk_size().

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "helm/flash.hpp"
#include "proto/provisioning.hpp"

namespace ak::helm {

inline constexpr std::size_t boot_sector_size = 512;
inline constexpr std::string_view provisioning_partition_name = "ak-provisioning";

// The host's firmware architecture, which names the removable boot path.
enum class BootArch : std::uint8_t {
    x86_64,
    aarch64,
};

[[nodiscard]] auto removable_boot_name(BootArch arch) noexcept -> std::string_view;

// GPT partition type GUIDs, in their textual form.
inline constexpr std::string_view esp_type_guid = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
inline constexpr std::string_view provisioning_type_guid = "8f3a5ac6-1b4e-4c7e-9d35-616b70726f76";

// The disk size for a UKI of `uki_size` bytes.
[[nodiscard]] auto boot_disk_size(std::uint64_t uki_size) noexcept -> std::uint64_t;

enum class BootDiskError : std::uint8_t {
    wrong_size,        // the target is not boot_disk_size(uki.size()) bytes
    empty_uki,         // no UKI
    bad_provisioning,  // the provisioning frame does not encode (server ID or epoch 0)
    flash,             // the target failed
};

[[nodiscard]] auto to_string(BootDiskError e) noexcept -> const char*;

// Writes the whole disk to `target` and syncs it.
auto write_boot_disk(Flash& target, std::span<const std::byte> uki,
                     const proto::Provisioning& provisioning, BootArch arch = BootArch::x86_64)
    -> std::expected<void, BootDiskError>;

// The IEEE 802.3 CRC-32 GPT uses (exposed for tests).
[[nodiscard]] auto gpt_crc32(std::span<const std::byte> data) noexcept -> std::uint32_t;

// A GUID's 16 on-disk bytes (the first three fields little-endian), from
// its textual form; all zero if it does not parse (exposed for tests).
[[nodiscard]] auto guid_bytes(std::string_view text) noexcept -> std::array<std::byte, 16>;

}  // namespace ak::helm
