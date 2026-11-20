// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VfioMailbox: the mailbox function opened through VFIO
// (.kiro/specs/hull-host-agent/ task 4, Requirement 3).
//
// Opens the function's IOMMU group in a type1 container, sets the IOMMU
// (which gives the function an empty DMA domain) and never issues
// VFIO_IOMMU_MAP_DMA, so the control plane cannot reach a byte of host
// memory (3.3). BAR0 is mapped read-write when VFIO allows it, otherwise
// accessed with pread/pwrite on the device fd; either way every access is a
// single aligned 32-bit load or store. MSI-X vector 0 is wired to an eventfd
// the agent polls; memory space and bus mastering are enabled in the command
// register because an MSI-X message is a write by the function.
//
// The initramfs (task 3) has already bound the function to vfio-pci and
// checked that its group holds nothing else.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

#include "hull/mailbox_client.hpp"

namespace ak::hull {

struct VfioMailboxError {
    std::string step;  // what failed, e.g. "VFIO_GROUP_GET_DEVICE_FD"
    int error{0};      // errno, or 0 for a check that failed without one
};

[[nodiscard]] auto to_string(const VfioMailboxError& e) -> std::string;

class VfioMailbox final : public MmioWindow {
public:
    // `bdf` is the function's PCI address, e.g. "0000:01:00.0". `sysfs` and
    // `dev` are the roots of /sys and /dev (tests point them elsewhere).
    [[nodiscard]] static auto open(const std::string& bdf, const std::string& sysfs = "/sys",
                                   const std::string& dev = "/dev")
        -> std::expected<std::unique_ptr<VfioMailbox>, VfioMailboxError>;

    VfioMailbox(const VfioMailbox&) = delete;
    auto operator=(const VfioMailbox&) -> VfioMailbox& = delete;
    VfioMailbox(VfioMailbox&&) = delete;
    auto operator=(VfioMailbox&&) -> VfioMailbox& = delete;
    ~VfioMailbox() override;

    [[nodiscard]] auto read32(std::size_t offset) -> std::uint32_t override;
    auto write32(std::size_t offset, std::uint32_t value) -> void override;

    // Readable when MSI-X vector 0 fired; read 8 bytes to clear it, then
    // call MailboxClient::service().
    [[nodiscard]] auto irq_fd() const noexcept -> int { return _irq; }

private:
    VfioMailbox() = default;

    int _container{-1};
    int _group{-1};
    int _device{-1};
    int _irq{-1};
    void* _bar0{nullptr};           // mmap of BAR0, or null to use pread/pwrite
    std::uint64_t _bar0_offset{0};  // region offset in the device fd
};

// The IOMMU group number of `bdf`, from its sysfs iommu_group link.
[[nodiscard]] auto iommu_group_of(const std::string& bdf, const std::string& sysfs = "/sys")
    -> std::expected<std::string, VfioMailboxError>;

}  // namespace ak::hull
