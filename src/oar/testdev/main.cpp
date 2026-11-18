// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-testdev: a minimal vfio-user PCIe endpoint for harbor phase 1.
//
// Stands in for an endpoint board so the emulated backplane can be proven
// end to end before any real device logic exists:
//
//   L0 QEMU (vfio-user-pci client) --socket--> ak-testdev
//   L1 host binds it to vfio-pci, Cloud Hypervisor passes it to an L2 guest,
//   and the guest pokes BAR0 to exercise MMIO, MSI-X, DMA and reset.
//
// BAR0 (4 KiB, 32-bit little-endian registers):
//   0x00 MAGIC        RO  'AKTD'
//   0x04 VERSION      RO
//   0x08 SCRATCH      RW
//   0x0C IRQ_DOORBELL WO  write N -> raise MSI-X vector N
//   0x10 RESET_COUNT  RO  incremented on every device reset/FLR
//   0x14 SLOT_ID      RO  from --slot, so tests can tell slots apart
//   0x20 DMA_ADDR_LO  RW  guest IOVA of a buffer
//   0x24 DMA_ADDR_HI  RW
//   0x28 DMA_LEN      RW  bytes, max 4096
//   0x2C DMA_PATTERN  RW  low byte is the fill pattern
//   0x30 DMA_CTRL     WO  write 1 -> fill [ADDR, ADDR+LEN) with PATTERN
//   0x34 DMA_STATUS   RO  0 idle, 1 done, 2 error
//
// BAR2 holds the MSI-X table (offset 0) and PBA (offset 0x800). QEMU's
// vfio-user client emulates the table itself, as vfio-pci does.

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

#include "oar/vfu/libvfio_user.hpp"

namespace {

constexpr std::uint32_t reg_magic_value = 0x4454'4B41;  // "AKTD" read as little-endian bytes
constexpr std::uint32_t reg_version_value = 1;
constexpr std::size_t bar0_size = 0x1000;
constexpr std::size_t bar2_size = 0x1000;
constexpr std::uint32_t msix_vectors = 4;
constexpr std::uint32_t msix_pba_offset = 0x800;
constexpr std::uint32_t dma_max = 0x1000;

// Placeholder IDs from the "experimental" convention; replace with a
// registered vendor ID before any device leaves the lab.
constexpr std::uint16_t vendor_id = 0x1de5;
constexpr std::uint16_t device_id = 0xa001;

namespace reg {
constexpr loff_t magic = 0x00;
constexpr loff_t version = 0x04;
constexpr loff_t scratch = 0x08;
constexpr loff_t irq_doorbell = 0x0C;
constexpr loff_t reset_count = 0x10;
constexpr loff_t slot_id = 0x14;
constexpr loff_t dma_addr_lo = 0x20;
constexpr loff_t dma_addr_hi = 0x24;
constexpr loff_t dma_len = 0x28;
constexpr loff_t dma_pattern = 0x2C;
constexpr loff_t dma_ctrl = 0x30;
constexpr loff_t dma_status = 0x34;
}  // namespace reg

enum class DmaStatus : std::uint32_t { idle = 0, done = 1, error = 2 };

struct Device {
    std::uint32_t slot{0};
    std::uint32_t scratch{0};
    std::uint32_t reset_count{0};
    std::uint64_t dma_addr{0};
    std::uint32_t dma_len{0};
    std::uint32_t dma_pattern{0};
    DmaStatus dma_status{DmaStatus::idle};

    void reset() noexcept {
        scratch = 0;
        dma_addr = 0;
        dma_len = 0;
        dma_pattern = 0;
        dma_status = DmaStatus::idle;
        ++reset_count;
    }
};

Device& device_of(vfu_ctx_t* ctx) { return *static_cast<Device*>(vfu_get_private(ctx)); }

DmaStatus run_dma_fill(vfu_ctx_t* ctx, const Device& dev) {
    if (dev.dma_len == 0 || dev.dma_len > dma_max) {
        return DmaStatus::error;
    }
    std::vector<std::byte> sg_storage(dma_sg_size());
    auto* sg = reinterpret_cast<dma_sg_t*>(sg_storage.data());
    // The client registered guest memory with us; translation through the
    // (v)IOMMU already happened on the client side, so this is an IOVA.
    if (vfu_addr_to_sgl(ctx, reinterpret_cast<vfu_dma_addr_t>(dev.dma_addr), dev.dma_len, sg, 1, PROT_WRITE) != 1) {
        return DmaStatus::error;
    }
    std::vector<std::byte> fill(dev.dma_len, static_cast<std::byte>(dev.dma_pattern & 0xFFu));
    if (vfu_sgl_write(ctx, sg, 1, fill.data(), 0) != 0) {
        return DmaStatus::error;
    }
    return DmaStatus::done;
}

ssize_t bar0_access(vfu_ctx_t* ctx, char* buf, size_t count, loff_t offset, bool is_write) {
    // 32-bit aligned accesses only; anything else is an error, not a guess.
    if (count != sizeof(std::uint32_t) || (offset % 4) != 0 || offset < 0 ||
        static_cast<std::size_t>(offset) + count > bar0_size) {
        errno = EINVAL;
        return -1;
    }
    Device& dev = device_of(ctx);
    std::uint32_t value = 0;
    if (is_write) {
        std::memcpy(&value, buf, sizeof(value));
        switch (offset) {
            case reg::scratch: dev.scratch = value; break;
            case reg::irq_doorbell:
                if (value >= msix_vectors || vfu_irq_trigger(ctx, value) != 0) {
                    std::println(stderr, "ak-testdev[{}]: irq_trigger({}) failed", dev.slot, value);
                }
                break;
            case reg::dma_addr_lo: dev.dma_addr = (dev.dma_addr & 0xFFFF'FFFF'0000'0000ull) | value; break;
            case reg::dma_addr_hi:
                dev.dma_addr = (dev.dma_addr & 0x0000'0000'FFFF'FFFFull) | (std::uint64_t{value} << 32);
                break;
            case reg::dma_len: dev.dma_len = value; break;
            case reg::dma_pattern: dev.dma_pattern = value; break;
            case reg::dma_ctrl:
                if (value == 1) {
                    dev.dma_status = run_dma_fill(ctx, dev);
                }
                break;
            default: break;  // writes to RO/unknown registers are ignored
        }
        return static_cast<ssize_t>(count);
    }
    switch (offset) {
        case reg::magic: value = reg_magic_value; break;
        case reg::version: value = reg_version_value; break;
        case reg::scratch: value = dev.scratch; break;
        case reg::reset_count: value = dev.reset_count; break;
        case reg::slot_id: value = dev.slot; break;
        case reg::dma_addr_lo: value = static_cast<std::uint32_t>(dev.dma_addr); break;
        case reg::dma_addr_hi: value = static_cast<std::uint32_t>(dev.dma_addr >> 32); break;
        case reg::dma_len: value = dev.dma_len; break;
        case reg::dma_pattern: value = dev.dma_pattern; break;
        case reg::dma_status: value = static_cast<std::uint32_t>(dev.dma_status); break;
        default: value = 0; break;
    }
    std::memcpy(buf, &value, sizeof(value));
    return static_cast<ssize_t>(count);
}

// MSI-X table/PBA live in BAR2, but QEMU emulates them; reads return zero.
ssize_t bar2_access(vfu_ctx_t*, char* buf, size_t count, loff_t offset, bool is_write) {
    if (offset < 0 || static_cast<std::size_t>(offset) + count > bar2_size) {
        errno = EINVAL;
        return -1;
    }
    if (!is_write) {
        std::memset(buf, 0, count);
    }
    return static_cast<ssize_t>(count);
}

int reset_cb(vfu_ctx_t* ctx, vfu_reset_type_t type) {
    Device& dev = device_of(ctx);
    dev.reset();
    std::println(stderr, "ak-testdev[{}]: reset type={} count={}", dev.slot, static_cast<int>(type), dev.reset_count);
    return 0;
}

void log_cb(vfu_ctx_t* ctx, int /*level*/, const char* msg) {
    std::println(stderr, "ak-testdev[{}]: {}", device_of(ctx).slot, msg);
}

struct CtxDeleter {
    void operator()(vfu_ctx_t* ctx) const noexcept { vfu_destroy_ctx(ctx); }
};
using CtxPtr = std::unique_ptr<vfu_ctx_t, CtxDeleter>;

[[noreturn]] void die(std::string_view what) {
    std::println(stderr, "ak-testdev: {}: {}", what, std::strerror(errno));
    std::exit(EXIT_FAILURE);
}

void check(int rc, std::string_view what) {
    if (rc < 0) {
        die(what);
    }
}

void usage() { std::println(stderr, "usage: ak-testdev --socket PATH [--slot N]"); }

}  // namespace

int main(int argc, char** argv) {
    std::string socket_path;
    Device dev;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--socket" && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (arg == "--slot" && i + 1 < argc) {
            dev.slot = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        } else {
            usage();
            return EXIT_FAILURE;
        }
    }
    if (socket_path.empty()) {
        usage();
        return EXIT_FAILURE;
    }
    ::unlink(socket_path.c_str());  // stale socket from a previous run

    CtxPtr ctx{vfu_create_ctx(VFU_TRANS_SOCK, socket_path.c_str(), 0, &dev, VFU_DEV_TYPE_PCI)};
    if (!ctx) {
        die("vfu_create_ctx");
    }
    check(vfu_setup_log(ctx.get(), log_cb, LOG_INFO), "vfu_setup_log");
    check(vfu_pci_init(ctx.get(), VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, 0), "vfu_pci_init");
    vfu_pci_set_id(ctx.get(), vendor_id, device_id, vendor_id, device_id);
    vfu_pci_set_class(ctx.get(), 0xFF, 0x00, 0x00);  // "unassigned class"

    // PCI Express capability with FLR, so the L1 host can reset the function.
    pxcap px{};
    px.hdr.id = PCI_CAP_ID_EXP;
    px.pxcaps.ver = 2;
    px.pxdcap.flrc = 1;
    check(static_cast<int>(vfu_pci_add_capability(ctx.get(), 0, 0, &px)), "add PCIe capability");

    msixcap msix{};
    msix.hdr.id = PCI_CAP_ID_MSIX;
    msix.mxc.ts = msix_vectors - 1;
    msix.mtab.tbir = 2;
    msix.mtab.to = 0;
    msix.mpba.pbir = 2;
    msix.mpba.pbao = msix_pba_offset >> 3;
    check(static_cast<int>(vfu_pci_add_capability(ctx.get(), 0, 0, &msix)), "add MSI-X capability");

    check(vfu_setup_region(ctx.get(), VFU_PCI_DEV_BAR0_REGION_IDX, bar0_size, bar0_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0),
          "setup BAR0");
    check(vfu_setup_region(ctx.get(), VFU_PCI_DEV_BAR2_REGION_IDX, bar2_size, bar2_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0),
          "setup BAR2");
    check(vfu_setup_device_nr_irqs(ctx.get(), VFU_DEV_MSIX_IRQ, msix_vectors), "setup MSI-X irqs");
    check(vfu_setup_device_reset_cb(ctx.get(), reset_cb), "setup reset callback");
    check(vfu_setup_device_dma(ctx.get(), 64, nullptr, nullptr), "setup DMA");
    check(vfu_realize_ctx(ctx.get()), "vfu_realize_ctx");

    std::println(stderr, "ak-testdev[{}]: waiting for client on {}", dev.slot, socket_path);
    for (;;) {
        check(vfu_attach_ctx(ctx.get()), "vfu_attach_ctx");
        std::println(stderr, "ak-testdev[{}]: client attached", dev.slot);
        // Blocking context: vfu_run_ctx serves requests until the client
        // goes away, then we wait for the next one (QEMU restarts are fine).
        while (vfu_run_ctx(ctx.get()) >= 0) {
        }
        if (errno != ENOTCONN) {
            die("vfu_run_ctx");
        }
        std::println(stderr, "ak-testdev[{}]: client disconnected", dev.slot);
    }
}
