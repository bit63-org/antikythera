// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What hull's init does before the agent starts (.kiro/specs/hull-host-agent/
// task 3, Requirements 3.1, 4.4, 5.1, 5.2, 5.3; design.md "Init").
//
// The host's allow-list is a file inside the signed, measured initramfs
// (/etc/hull/hull.conf), so it is part of the image Secure Boot checked,
// not something a running system can change. It names:
//
//   mailbox <vendor>:<device>
//       the control mailbox function (exactly one line);
//   slot <n> port <bdf> type <type> id <vendor>:<device>
//       one backplane slot: the PCIe downstream port it sits behind, the
//       kind of function it carries (nic_vf, blk_fn, gpu_whole, gpu_vf),
//       and the IDs those functions have. Every matching function below
//       the port belongs to the slot, numbered 0, 1, ... in PCI address
//       order;
//   sriov port <bdf> pf <vendor>:<device> vfs <n>
//       an SR-IOV board (Requirement 5.3): the one physical function with
//       that ID below the port is bound to vfio-pci only so that init can
//       write sriov_numvfs = n (1 to 65535); the VFs it makes are then
//       handed out by the slot lines like any other function. The PF itself
//       is never in the inventory, never opened and never given a DMA
//       mapping, so its ID may not also be a slot's ID on that port;
//   server-id cmdline | server-id file <absolute path>
//       where the agent's server ID comes from: the kernel command line's
//       hull.server_id= (part of the signed UKI), or a provisioning file
//       (a measured one in production).
//
// `#` starts a comment; blank lines are ignored; anything else is an
// error. The parser is strict and fuzzed (fuzz/fuzz_host_config.cpp).
//
// From it init (hull-init):
//   0. for each sriov line, finds the PF, binds it to vfio-pci, turns on
//      vfio-pci's SR-IOV support and sets the PF's VF count;
//   1. finds the mailbox and every slot's functions in sysfs, refusing a
//      mailbox that is missing or ambiguous;
//   2. binds each of them to vfio-pci (driver_override, unbind from any
//      other driver, drivers_probe) and checks the binding took;
//   3. checks that each is alone in its IOMMU group, failing closed;
//   4. writes the inventory (slot, type, function, address, group, reset
//      method) to a file the agent reads, and execs the agent.
//
// Every sysfs path is relative to a root argument so the whole sequence
// runs against a fake tree in tests.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "helm/mailbox.hpp"
#include "hull/device_inventory.hpp"
#include "hull/signature_verifier.hpp"

namespace ak::hull {

struct PciId {
    std::uint16_t vendor{0};
    std::uint16_t device{0};
    friend auto operator==(const PciId&, const PciId&) -> bool = default;
};

struct SlotRule {
    std::uint8_t slot{0};
    std::string port;  // the downstream port's PCI address
    helm::mailbox::DeviceType type{helm::mailbox::DeviceType::nic_vf};
    PciId id;
    friend auto operator==(const SlotRule&, const SlotRule&) -> bool = default;
};

struct SriovRule {
    std::string port;  // the downstream port the PF sits behind
    PciId pf;          // the physical function's IDs
    std::uint16_t vfs{0};
    friend auto operator==(const SriovRule&, const SriovRule&) -> bool = default;
};

enum class ServerIdSource : std::uint8_t {
    cmdline,  // hull.server_id= on the kernel command line
    file,     // a provisioning file holding the ID in decimal
};

struct HostConfig {
    PciId mailbox;
    std::vector<SlotRule> slots;
    std::vector<SriovRule> sriov;
    ServerIdSource server_id_source{ServerIdSource::cmdline};
    std::filesystem::path server_id_file;  // for ServerIdSource::file
    friend auto operator==(const HostConfig&, const HostConfig&) -> bool = default;
};

struct ParseFailure {
    std::size_t line{0};  // 1-based; 0 for a whole-file problem
    std::string reason;
};

inline constexpr std::size_t max_config_bytes = 64U * 1024U;

[[nodiscard]] auto parse_host_config(std::string_view text)
    -> std::expected<HostConfig, ParseFailure>;

// A canonical PCI address: "dddd:bb:dd.f", lower-case hex.
[[nodiscard]] auto valid_bdf(std::string_view bdf) noexcept -> bool;

// The server ID from /proc/cmdline's text (the last hull.server_id=, as
// the kernel's own parameters work), or from a file's text: a decimal
// number, 1 to 2^64-1, optionally followed by one newline.
[[nodiscard]] auto server_id_from_cmdline(std::string_view cmdline)
    -> std::optional<helm::mailbox::ServerId>;
[[nodiscard]] auto server_id_from_text(std::string_view text)
    -> std::optional<helm::mailbox::ServerId>;

// --- Discovery and binding over sysfs -----------------------------------------

struct HostDiscovery {
    std::string mailbox_bdf;
    std::vector<InventoryEntry> functions;  // iommu_group not yet filled
};

struct SetupFailure {
    std::string step;    // "mailbox", "bind", "iommu", ...
    std::string detail;  // the function or path involved
    int sys_errno{0};
};

// Finds the mailbox and each slot's functions under <sysfs>/bus/pci/devices.
// A VF (it has a physfn link) is reset by FLR, anything else by a bus reset.
[[nodiscard]] auto discover(const HostConfig& config, const std::filesystem::path& sysfs)
    -> std::expected<HostDiscovery, SetupFailure>;

// The one function with the rule's PF ID below the rule's port; refuses
// none or more than one.
[[nodiscard]] auto find_sriov_pf(const SriovRule& rule, const std::filesystem::path& sysfs)
    -> std::expected<std::string, SetupFailure>;

// Gives the PF `pf` (already vfio-pci's) `count` VFs (Requirement 5.3):
// checks the count against sriov_totalvfs, does nothing when sriov_numvfs
// already says `count`, otherwise turns on vfio-pci's enable_sriov module
// parameter, clears any other VF count first (the kernel refuses to change
// one non-zero count into another) and writes the new one, then reads it
// back. Nothing here opens the PF, so it gets no DMA mapping.
[[nodiscard]] auto create_vfs(const std::string& pf, std::uint16_t count,
                              const std::filesystem::path& sysfs)
    -> std::expected<void, SetupFailure>;

// Writes driver_override, unbinds `bdf` from any other driver, and asks the
// PCI core to probe it again.
[[nodiscard]] auto bind_to_vfio(const std::string& bdf, const std::filesystem::path& sysfs)
    -> std::expected<void, SetupFailure>;
// Whether `bdf`'s driver link names vfio-pci.
[[nodiscard]] auto bound_to_vfio(const std::string& bdf, const std::filesystem::path& sysfs)
    -> bool;

// `bdf`'s IOMMU group, which must hold `bdf` and nothing else
// (Requirement 5.2).
[[nodiscard]] auto isolated_group(const std::string& bdf, const std::filesystem::path& sysfs)
    -> std::expected<std::uint32_t, SetupFailure>;

// --- The inventory file -----------------------------------------------------------
//
// One function per line: "<slot> <type> <function> <bdf> <group> <reset>",
// for example "3 nic_vf 1 0000:03:00.1 11 flr". Written by init, read by the
// agent, strictly.

[[nodiscard]] auto format_inventory(const std::vector<InventoryEntry>& entries) -> std::string;
[[nodiscard]] auto parse_inventory(std::string_view text)
    -> std::expected<std::vector<InventoryEntry>, ParseFailure>;

[[nodiscard]] auto to_string(helm::mailbox::DeviceType t) noexcept -> const char*;

// --- The controller's keys ------------------------------------------------------
//
// The agent's controller public keys are compiled in (Requirement 4.1) from
// the CMake cache variable AK_HULL_CONTROLLER_KEYS: "<id>:<64 hex digits>"
// entries separated by ';', key IDs 1 to 65535. This parses that text.

[[nodiscard]] auto parse_controller_keys(std::string_view text)
    -> std::expected<std::vector<ControllerKey>, ParseFailure>;

}  // namespace ak::hull
