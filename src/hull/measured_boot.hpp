// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The provisioning partition and its measurement
// (.kiro/specs/server-provisioning/ Requirement 4, design "The boot
// function"; kythira .kiro/specs/metal-host-lifecycle/ design "Per-host
// settings in a measured provisioning file").
//
// helm's boot function carries hull's Provisioning frame in a GPT
// partition named "ak-provisioning". hull-init finds that partition by its
// name in sysfs (exactly one may exist), reads the frame, and extends PCR
// provisioning_pcr with its SHA-256 before it decodes or uses a byte of
// it, so the quote at enrollment covers the server ID, boot epoch and
// sequence floor as well as the image. A boot that cannot measure the
// frame does not start: a server ID the TPM never saw would be one helm
// could change without the controller noticing.
//
// PCR 15 is the one systemd uses for the system's identity; hull runs no
// systemd, so nothing else extends it.
//
// The TPM is spoken to directly: one TPM2_PCR_Extend command with a
// password session (the PCR has no auth value) through the kernel's
// resource manager, /dev/tpmrm0. The command and response framing are
// separate functions so tests can check them byte for byte.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "hull/host_setup.hpp"

namespace ak::hull {

inline constexpr std::uint32_t provisioning_pcr = 15;
inline constexpr std::string_view provisioning_partition = "ak-provisioning";

using Sha256Digest = std::array<std::byte, 32>;

// The block device (its DEVNAME, e.g. "vda2") whose sysfs uevent under
// <sysfs>/class/block names the partition `partname`. Fails if none or
// more than one does.
[[nodiscard]] auto find_partition(const std::filesystem::path& sysfs, std::string_view partname)
    -> std::expected<std::string, SetupFailure>;

// TPM2_PCR_Extend(pcr, SHA-256 digest) with a password session.
[[nodiscard]] auto pcr_extend_command(std::uint32_t pcr, const Sha256Digest& digest)
    -> std::vector<std::byte>;

// The response code of a complete TPM response (0 is success), or nullopt
// if it is not a well-formed response header of exactly its stated size.
[[nodiscard]] auto tpm_response_code(std::span<const std::byte> response)
    -> std::optional<std::uint32_t>;

[[nodiscard]] auto sha256(std::span<const std::byte> data) -> std::optional<Sha256Digest>;

// Sends the extend to the TPM at `device` and checks its answer.
[[nodiscard]] auto extend_pcr(const std::filesystem::path& device, std::uint32_t pcr,
                              const Sha256Digest& digest) -> std::expected<void, SetupFailure>;

// Finds the provisioning partition, reads its first
// proto::provisioning_size bytes from <dev>/<DEVNAME>, extends
// provisioning_pcr with their digest through `tpm`, then decodes them.
[[nodiscard]] auto read_measured_provisioning(const std::filesystem::path& sysfs,
                                              const std::filesystem::path& dev,
                                              const std::filesystem::path& tpm)
    -> std::expected<proto::Provisioning, SetupFailure>;

}  // namespace ak::hull
