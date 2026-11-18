// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-testdev: a minimal vfio-user PCIe endpoint for harbor phase 1
// (.kiro/specs/harbor-virt-on-virt/ Requirement 5).
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
constexpr std::uint32_t msix_table_bar = 2;
constexpr std::uint32_t msix_table_offset = 0;
constexpr std::uint32_t msix_pba_offset = 0x800;
constexpr unsigned msix_offset_shift = 3;  // MSI-X table/PBA offsets are in 8-byte units
constexpr std::uint32_t dma_max = 0x1000;
constexpr std::size_t dma_max_regions = 64;
constexpr std::uint32_t dma_ctrl_fill = 1;
constexpr std::uint32_t dma_pattern_mask = 0xFF;
constexpr std::uint8_t pcie_cap_version = 2;
constexpr int pci_revision = 0;
constexpr int sgl_flags_none = 0;
constexpr int numeric_base_auto = 0;

constexpr std::uint64_t low_half_mask = 0x0000'0000'FFFF'FFFFull;
constexpr std::uint64_t high_half_mask = ~low_half_mask;
constexpr unsigned half_shift = 32;

// PCI class "unassigned" (base 0xFF): this device has no standard class.
constexpr std::uint8_t pci_class_unassigned = 0xFF;
constexpr std::uint8_t pci_subclass_none = 0x00;
constexpr std::uint8_t pci_progif_none = 0x00;

// Placeholder IDs; replace with a registered vendor ID before any device
// leaves the lab.
constexpr std::uint16_t vendor_id = 0x1de5;
constexpr std::uint16_t device_id = 0xa001;

constexpr std::string_view arg_socket = "--socket";
constexpr std::string_view arg_slot = "--slot";

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

enum class DmaStatus : std::uint32_t {
    idle = 0,
    done = 1,
    error = 2
};

class Device {
public:
    explicit Device(std::uint32_t slot) noexcept : _slot{slot} {}

    [[nodiscard]] auto slot() const noexcept -> std::uint32_t { return _slot; }
    [[nodiscard]] auto reset_count() const noexcept -> std::uint32_t { return _reset_count; }

    auto reset() noexcept -> void {
        _scratch = 0;
        _dma_addr = 0;
        _dma_len = 0;
        _dma_pattern = 0;
        _dma_status = DmaStatus::idle;
        ++_reset_count;
    }

    auto read(vfu_ctx_t* ctx, loff_t offset) const noexcept -> std::uint32_t;
    auto write(vfu_ctx_t* ctx, loff_t offset, std::uint32_t value) -> void;

private:
    [[nodiscard]] auto run_dma_fill(vfu_ctx_t* ctx) const -> DmaStatus;

    std::uint32_t _slot{0};
    std::uint32_t _scratch{0};
    std::uint32_t _reset_count{0};
    std::uint64_t _dma_addr{0};
    std::uint32_t _dma_len{0};
    std::uint32_t _dma_pattern{0};
    DmaStatus _dma_status{DmaStatus::idle};
};

auto device_of(vfu_ctx_t* ctx) -> Device& {
    return *static_cast<Device*>(vfu_get_private(ctx));
}

auto Device::run_dma_fill(vfu_ctx_t* ctx) const -> DmaStatus {
    if (_dma_len == 0 || _dma_len > dma_max) {
        return DmaStatus::error;
    }
    std::vector<std::byte> sg_storage(dma_sg_size());
    auto* sg = reinterpret_cast<dma_sg_t*>(sg_storage.data());
    // The client registered guest memory with us; translation through the
    // (v)IOMMU already happened on the client side, so this is an IOVA.
    // libvfio-user types an IOVA as void*; it is never dereferenced as a
    // pointer in this process, only looked up in the client's DMA map.
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    auto* const iova = reinterpret_cast<vfu_dma_addr_t>(_dma_addr);
    if (vfu_addr_to_sgl(ctx, iova, _dma_len, sg, 1, PROT_WRITE) != 1) {
        return DmaStatus::error;
    }
    std::vector<std::byte> fill(_dma_len, static_cast<std::byte>(_dma_pattern & dma_pattern_mask));
    if (vfu_sgl_write(ctx, sg, 1, fill.data(), sgl_flags_none) != 0) {
        return DmaStatus::error;
    }
    return DmaStatus::done;
}

auto Device::read(vfu_ctx_t* /*ctx*/, loff_t offset) const noexcept -> std::uint32_t {
    switch (offset) {
        case reg::magic:
            return reg_magic_value;
        case reg::version:
            return reg_version_value;
        case reg::scratch:
            return _scratch;
        case reg::reset_count:
            return _reset_count;
        case reg::slot_id:
            return _slot;
        case reg::dma_addr_lo:
            return static_cast<std::uint32_t>(_dma_addr & low_half_mask);
        case reg::dma_addr_hi:
            return static_cast<std::uint32_t>(_dma_addr >> half_shift);
        case reg::dma_len:
            return _dma_len;
        case reg::dma_pattern:
            return _dma_pattern;
        case reg::dma_status:
            return static_cast<std::uint32_t>(_dma_status);
        default:
            return 0;
    }
}

auto Device::write(vfu_ctx_t* ctx, loff_t offset, std::uint32_t value) -> void {
    switch (offset) {
        case reg::scratch:
            _scratch = value;
            break;
        case reg::irq_doorbell:
            if (value >= msix_vectors || vfu_irq_trigger(ctx, value) != 0) {
                std::println(stderr, "ak-testdev[{}]: irq_trigger({}) failed", _slot, value);
            }
            break;
        case reg::dma_addr_lo:
            _dma_addr = (_dma_addr & high_half_mask) | value;
            break;
        case reg::dma_addr_hi:
            _dma_addr = (_dma_addr & low_half_mask) | (std::uint64_t{value} << half_shift);
            break;
        case reg::dma_len:
            _dma_len = value;
            break;
        case reg::dma_pattern:
            _dma_pattern = value;
            break;
        case reg::dma_ctrl:
            if (value == dma_ctrl_fill) {
                _dma_status = run_dma_fill(ctx);
            }
            break;
        default:
            break;  // writes to RO/unknown registers are ignored
    }
}

auto bar0_access(vfu_ctx_t* ctx, char* buf, size_t count, loff_t offset, bool is_write) -> ssize_t {
    // 32-bit aligned accesses only; anything else is an error, not a guess.
    if (count != sizeof(std::uint32_t) ||
        (offset % static_cast<loff_t>(sizeof(std::uint32_t))) != 0 || offset < 0 ||
        static_cast<std::size_t>(offset) + count > bar0_size) {
        errno = EINVAL;
        return -1;
    }
    Device& dev = device_of(ctx);
    std::uint32_t value = 0;
    if (is_write) {
        std::memcpy(&value, buf, sizeof(value));
        dev.write(ctx, offset, value);
    } else {
        value = dev.read(ctx, offset);
        std::memcpy(buf, &value, sizeof(value));
    }
    return static_cast<ssize_t>(count);
}

// MSI-X table/PBA live in BAR2, but QEMU emulates them; reads return zero.
auto bar2_access(vfu_ctx_t* /*ctx*/, char* buf, size_t count, loff_t offset, bool is_write)
    -> ssize_t {
    if (offset < 0 || static_cast<std::size_t>(offset) + count > bar2_size) {
        errno = EINVAL;
        return -1;
    }
    if (!is_write) {
        std::memset(buf, 0, count);
    }
    return static_cast<ssize_t>(count);
}

auto reset_cb(vfu_ctx_t* ctx, vfu_reset_type_t type) -> int {
    Device& dev = device_of(ctx);
    dev.reset();
    std::println(stderr, "ak-testdev[{}]: reset type={} count={}", dev.slot(),
                 static_cast<int>(type), dev.reset_count());
    return 0;
}

auto log_cb(vfu_ctx_t* ctx, int /*level*/, const char* msg) -> void {
    std::println(stderr, "ak-testdev[{}]: {}", device_of(ctx).slot(), msg);
}

struct CtxDeleter {
    auto operator()(vfu_ctx_t* ctx) const noexcept -> void { vfu_destroy_ctx(ctx); }
};
using CtxPtr = std::unique_ptr<vfu_ctx_t, CtxDeleter>;

[[noreturn]] auto die(std::string_view what) -> void {
    std::println(stderr, "ak-testdev: {}: {}", what, std::strerror(errno));
    std::exit(EXIT_FAILURE);
}

auto check(long rc, std::string_view what) -> void {
    if (rc < 0) {
        die(what);
    }
}

auto usage() -> void {
    std::println(stderr, "usage: ak-testdev {} PATH [{} N]", arg_socket, arg_slot);
}

auto add_capabilities(vfu_ctx_t* ctx) -> void {
    // PCI Express capability with FLR, so the L1 host can reset the function.
    pxcap px{};
    px.hdr.id = PCI_CAP_ID_EXP;
    px.pxcaps.ver = pcie_cap_version;
    px.pxdcap.flrc = 1;
    check(vfu_pci_add_capability(ctx, 0, 0, &px), "add PCIe capability");

    msixcap msix{};
    msix.hdr.id = PCI_CAP_ID_MSIX;
    msix.mxc.ts = msix_vectors - 1;  // table size is encoded as N-1
    msix.mtab.tbir = msix_table_bar;
    msix.mtab.to = msix_table_offset >> msix_offset_shift;
    msix.mpba.pbir = msix_table_bar;
    msix.mpba.pbao = msix_pba_offset >> msix_offset_shift;
    check(vfu_pci_add_capability(ctx, 0, 0, &msix), "add MSI-X capability");
}

auto setup_device(vfu_ctx_t* ctx) -> void {
    check(vfu_setup_log(ctx, log_cb, LOG_INFO), "vfu_setup_log");
    check(vfu_pci_init(ctx, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, pci_revision),
          "vfu_pci_init");
    vfu_pci_set_id(ctx, vendor_id, device_id, vendor_id, device_id);
    vfu_pci_set_class(ctx, pci_class_unassigned, pci_subclass_none, pci_progif_none);
    add_capabilities(ctx);
    check(vfu_setup_region(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, bar0_size, bar0_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0),
          "setup BAR0");
    check(vfu_setup_region(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, bar2_size, bar2_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0),
          "setup BAR2");
    check(vfu_setup_device_nr_irqs(ctx, VFU_DEV_MSIX_IRQ, msix_vectors), "setup MSI-X irqs");
    check(vfu_setup_device_reset_cb(ctx, reset_cb), "setup reset callback");
    check(vfu_setup_device_dma(ctx, dma_max_regions, nullptr, nullptr), "setup DMA");
    check(vfu_realize_ctx(ctx), "vfu_realize_ctx");
}

}  // namespace

auto main(int argc, char** argv) -> int {
    std::string socket_path;
    std::uint32_t slot = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == arg_socket && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (arg == arg_slot && i + 1 < argc) {
            slot = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, numeric_base_auto));
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

    Device dev{slot};
    CtxPtr ctx{vfu_create_ctx(VFU_TRANS_SOCK, socket_path.c_str(), 0, &dev, VFU_DEV_TYPE_PCI)};
    if (!ctx) {
        die("vfu_create_ctx");
    }
    setup_device(ctx.get());

    std::println(stderr, "ak-testdev[{}]: waiting for client on {}", slot, socket_path);
    for (;;) {
        check(vfu_attach_ctx(ctx.get()), "vfu_attach_ctx");
        std::println(stderr, "ak-testdev[{}]: client attached", slot);
        // Blocking context: vfu_run_ctx serves requests until the client
        // goes away, then we wait for the next one (QEMU restarts are fine).
        while (vfu_run_ctx(ctx.get()) >= 0) {
        }
        if (errno != ENOTCONN) {
            die("vfu_run_ctx");
        }
        std::println(stderr, "ak-testdev[{}]: client disconnected", slot);
    }
}
