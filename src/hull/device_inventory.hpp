// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The boot inventory and function resets (.kiro/specs/hull-host-agent/
// Requirements 5.4 and 6.3; design.md "Reset").
//
// DeviceInventory is the fixed set of assignable PCI functions the agent
// learned at boot, each with the backplane name commands use for it (slot,
// type, function), its PCI address, its IOMMU group and how to reset it.
// A command naming anything else is refused (unknown_device). The init
// binary (task 3) builds it from sysfs; the supervisor only looks things
// up.
//
// FunctionResetter returns a function to a clean state after a VM let go
// of it: a secondary bus reset through the slot's downstream port for a
// whole-slot function, an FLR for a VF. SysfsFunctionResetter does it the
// way the kernel exposes it, by selecting the method in reset_method and
// writing 1 to reset; the kernel holds the device lock across the reset
// and restores config space afterwards.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "helm/mailbox.hpp"

namespace ak::hull {

enum class ResetMethod : std::uint8_t {
    bus,  // secondary bus reset on the slot's downstream port
    flr,  // function-level reset (SR-IOV VFs)
};

struct InventoryEntry {
    helm::mailbox::DeviceRef ref;
    std::string bdf;  // "0000:03:00.1"
    std::uint32_t iommu_group{0};
    ResetMethod reset{ResetMethod::bus};

    friend auto operator==(const InventoryEntry&, const InventoryEntry&) -> bool = default;
};

class DeviceInventory {
public:
    DeviceInventory() = default;
    // Entries naming the same function twice keep the first.
    explicit DeviceInventory(std::vector<InventoryEntry> entries);

    // The entry whose slot, type and function all match, or nullptr.
    [[nodiscard]] auto find(const helm::mailbox::DeviceRef& ref) const noexcept
        -> const InventoryEntry*;
    [[nodiscard]] auto entries() const noexcept -> const std::vector<InventoryEntry>& {
        return _entries;
    }

private:
    std::vector<InventoryEntry> _entries;
};

// The function's directory under sysfs: <sysfs>/bus/pci/devices/<bdf>.
[[nodiscard]] auto pci_device_path(const std::filesystem::path& sysfs, const std::string& bdf)
    -> std::filesystem::path;

class FunctionResetter {
public:
    FunctionResetter() = default;
    FunctionResetter(const FunctionResetter&) = delete;
    auto operator=(const FunctionResetter&) -> FunctionResetter& = delete;
    FunctionResetter(FunctionResetter&&) = delete;
    auto operator=(FunctionResetter&&) -> FunctionResetter& = delete;
    virtual ~FunctionResetter() = default;

    // True when the function was reset. A false result is reported to helm
    // as DEVICE_RELEASED with reset failed, and helm faults the function.
    [[nodiscard]] virtual auto reset(const InventoryEntry& function) -> bool = 0;
};

class SysfsFunctionResetter final : public FunctionResetter {
public:
    explicit SysfsFunctionResetter(std::filesystem::path sysfs = "/sys")
        : _sysfs{std::move(sysfs)} {}

    [[nodiscard]] auto reset(const InventoryEntry& function) -> bool override;

private:
    std::filesystem::path _sysfs;
};

}  // namespace ak::hull
