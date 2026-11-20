// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/vfio_mailbox.hpp"

#include <array>
#include <bit>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <system_error>

#include <fcntl.h>
#include <linux/pci_regs.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "helm/mailbox.hpp"

namespace ak::hull {

namespace {

namespace mb = helm::mailbox;

// BAR0 is little-endian and is read with native 32-bit loads.
static_assert(std::endian::native == std::endian::little);

constexpr std::uint32_t all_ones = 0xFFFF'FFFF;  // what a failed PCIe read returns
constexpr std::uint32_t command_vector = 0;
constexpr std::uint32_t command_vectors = 1;

auto fail(std::string step, int error = errno) -> std::unexpected<VfioMailboxError> {
    return std::unexpected(VfioMailboxError{.step = std::move(step), .error = error});
}

}  // namespace

auto to_string(const VfioMailboxError& e) -> std::string {
    if (e.error == 0) {
        return e.step;
    }
    return std::format("{}: {}", e.step, std::strerror(e.error));
}

auto iommu_group_of(const std::string& bdf, const std::string& sysfs)
    -> std::expected<std::string, VfioMailboxError> {
    std::error_code ec;
    const auto link = std::filesystem::read_symlink(
        std::filesystem::path{sysfs} / "bus/pci/devices" / bdf / "iommu_group", ec);
    if (ec) {
        return fail("read iommu_group link of " + bdf, ec.value());
    }
    auto group = link.filename().string();
    if (group.empty() || group.find_first_not_of("0123456789") != std::string::npos) {
        return fail("iommu_group link of " + bdf + " names no group", 0);
    }
    return group;
}

auto VfioMailbox::open(const std::string& bdf, const std::string& sysfs, const std::string& dev)
    -> std::expected<std::unique_ptr<VfioMailbox>, VfioMailboxError> {
    const auto group = iommu_group_of(bdf, sysfs);
    if (!group) {
        return std::unexpected(group.error());
    }
    std::unique_ptr<VfioMailbox> m{new VfioMailbox()};

    m->_container = ::open((dev + "/vfio/vfio").c_str(), O_RDWR | O_CLOEXEC);
    if (m->_container < 0) {
        return fail("open /dev/vfio/vfio");
    }
    if (::ioctl(m->_container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        return fail("VFIO_GET_API_VERSION", 0);
    }
    if (::ioctl(m->_container, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU) <= 0) {
        return fail("VFIO_CHECK_EXTENSION(TYPE1v2)", 0);
    }
    m->_group = ::open((dev + "/vfio/" + *group).c_str(), O_RDWR | O_CLOEXEC);
    if (m->_group < 0) {
        return fail("open /dev/vfio/" + *group);
    }
    vfio_group_status status{.argsz = sizeof(vfio_group_status), .flags = 0};
    if (::ioctl(m->_group, VFIO_GROUP_GET_STATUS, &status) < 0) {
        return fail("VFIO_GROUP_GET_STATUS");
    }
    if ((status.flags & VFIO_GROUP_FLAGS_VIABLE) == 0) {
        return fail("group " + *group + " is not viable (a member is bound to a host driver)", 0);
    }
    if (::ioctl(m->_group, VFIO_GROUP_SET_CONTAINER, &m->_container) < 0) {
        return fail("VFIO_GROUP_SET_CONTAINER");
    }
    // Creates the function's IOMMU domain, empty: no VFIO_IOMMU_MAP_DMA is
    // ever issued on this container (Requirement 3.3).
    if (::ioctl(m->_container, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU) < 0) {
        return fail("VFIO_SET_IOMMU");
    }
    m->_device = ::ioctl(m->_group, VFIO_GROUP_GET_DEVICE_FD, bdf.c_str());
    if (m->_device < 0) {
        return fail("VFIO_GROUP_GET_DEVICE_FD");
    }

    vfio_region_info bar0{};
    bar0.argsz = sizeof(bar0);
    bar0.index = VFIO_PCI_BAR0_REGION_INDEX;
    if (::ioctl(m->_device, VFIO_DEVICE_GET_REGION_INFO, &bar0) < 0) {
        return fail("VFIO_DEVICE_GET_REGION_INFO(BAR0)");
    }
    constexpr std::uint32_t rw = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
    if ((bar0.flags & rw) != rw || bar0.size < mb::reg::bar0_size) {
        return fail("BAR0 is not a read-write region of at least 4 KiB", 0);
    }
    m->_bar0_offset = bar0.offset;
    if ((bar0.flags & VFIO_REGION_INFO_FLAG_MMAP) != 0) {
        void* p = ::mmap(nullptr, mb::reg::bar0_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                         m->_device, static_cast<off_t>(bar0.offset));
        if (p != MAP_FAILED) {
            m->_bar0 = p;
        }
        // Otherwise fall back to pread/pwrite: slower, same semantics.
    }

    // Memory space for BAR0, bus mastering for the MSI-X message write.
    vfio_region_info config{};
    config.argsz = sizeof(config);
    config.index = VFIO_PCI_CONFIG_REGION_INDEX;
    if (::ioctl(m->_device, VFIO_DEVICE_GET_REGION_INFO, &config) < 0) {
        return fail("VFIO_DEVICE_GET_REGION_INFO(config)");
    }
    std::uint16_t command = 0;
    const auto command_at = static_cast<off_t>(config.offset + PCI_COMMAND);
    if (::pread(m->_device, &command, sizeof(command), command_at) !=
        static_cast<ssize_t>(sizeof(command))) {
        return fail("read PCI_COMMAND");
    }
    command = static_cast<std::uint16_t>(command | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
    if (::pwrite(m->_device, &command, sizeof(command), command_at) !=
        static_cast<ssize_t>(sizeof(command))) {
        return fail("write PCI_COMMAND");
    }

    m->_irq = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (m->_irq < 0) {
        return fail("eventfd");
    }
    // struct vfio_irq_set ends in a flexible data[] array: build it in a
    // suitably aligned buffer with room for one eventfd.
    alignas(vfio_irq_set) std::array<std::byte, sizeof(vfio_irq_set) + sizeof(int)> buf{};
    vfio_irq_set set{};
    set.argsz = static_cast<std::uint32_t>(buf.size());
    set.flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    set.index = VFIO_PCI_MSIX_IRQ_INDEX;
    set.start = command_vector;
    set.count = command_vectors;
    std::memcpy(buf.data(), &set, sizeof(set));
    std::memcpy(buf.data() + sizeof(set), &m->_irq, sizeof(int));
    if (::ioctl(m->_device, VFIO_DEVICE_SET_IRQS, buf.data()) < 0) {
        return fail("VFIO_DEVICE_SET_IRQS(MSI-X)");
    }
    return m;
}

VfioMailbox::~VfioMailbox() {
    if (_bar0 != nullptr) {
        ::munmap(_bar0, mb::reg::bar0_size);
    }
    for (const int fd : {_irq, _device, _group, _container}) {
        if (fd >= 0) {
            ::close(fd);
        }
    }
}

auto VfioMailbox::read32(std::size_t offset) -> std::uint32_t {
    if (offset % sizeof(std::uint32_t) != 0 || offset >= mb::reg::bar0_size) {
        return all_ones;
    }
    if (_bar0 != nullptr) {
        // One aligned 32-bit load from device memory.
        const auto* reg = static_cast<const volatile std::uint32_t*>(_bar0) + offset / 4;
        return *reg;
    }
    std::uint32_t v = 0;
    if (::pread(_device, &v, sizeof(v), static_cast<off_t>(_bar0_offset + offset)) !=
        static_cast<ssize_t>(sizeof(v))) {
        return all_ones;
    }
    return v;
}

auto VfioMailbox::write32(std::size_t offset, std::uint32_t value) -> void {
    if (offset % sizeof(std::uint32_t) != 0 || offset >= mb::reg::bar0_size) {
        return;
    }
    if (_bar0 != nullptr) {
        auto* reg = static_cast<volatile std::uint32_t*>(_bar0) + offset / 4;
        *reg = value;
        return;
    }
    // A failed write is dropped, as a lost posted write would be.
    [[maybe_unused]] const ssize_t n =
        ::pwrite(_device, &value, sizeof(value), static_cast<off_t>(_bar0_offset + offset));
}

}  // namespace ak::hull
