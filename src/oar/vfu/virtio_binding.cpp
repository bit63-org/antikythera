// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/vfu/virtio_binding.hpp"

#include <cerrno>
#include <cstring>
#include <format>
#include <print>
#include <span>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

#include "oar/vfu/libvfio_user.hpp"

namespace ak::oar::vfu {

namespace {

constexpr std::size_t msix_bar_size = 0x1000;
constexpr std::uint32_t msix_bar_index = 2;
constexpr std::uint32_t msix_table_offset = 0;
constexpr std::uint32_t msix_pba_offset = 0x800;
constexpr unsigned msix_offset_shift = 3;         // table/PBA offsets are in 8-byte units
constexpr unsigned msix_table_size_mask = 0x7FF;  // 11-bit field
// Behind L1's vIOMMU the client registers one region per IOMMU mapping (an
// L2 guest's RAM arrives as hundreds of 2 MiB regions), so 64 is far too
// few; harbor phase 2 hit the limit with ak-testdev. The cap only guards
// against a runaway client.
constexpr std::size_t dma_max_regions = 65536;
constexpr std::uint8_t pcie_cap_version = 2;
// QEMU's choice for its own modern virtio devices; the spec asks for 0x40
// or higher on non-transitional devices (virtio spec 4.1.2.1).
constexpr std::uint16_t subsystem_id = 0x1100;

auto binding_of(vfu_ctx_t* ctx) -> VirtioBinding& {
    return *static_cast<VirtioBinding*>(vfu_get_private(ctx));
}

auto bar0_cb(vfu_ctx_t* ctx, char* buf, size_t count, loff_t offset, bool is_write) -> ssize_t {
    return binding_of(ctx).bar_access(buf, count, offset, is_write);
}

// MSI-X table and PBA: the client emulates them, so reads return zero.
auto msix_bar_cb(vfu_ctx_t* /*ctx*/, char* buf, size_t count, loff_t offset, bool is_write)
    -> ssize_t {
    if (offset < 0 || static_cast<std::size_t>(offset) + count > msix_bar_size) {
        errno = EINVAL;
        return -1;
    }
    if (!is_write) {
        std::memset(buf, 0, count);
    }
    return static_cast<ssize_t>(count);
}

auto dma_register_cb(vfu_ctx_t* ctx, vfu_dma_info_t* info) -> void {
    binding_of(ctx).dma_register(reinterpret_cast<std::uint64_t>(info->iova.iov_base), info->vaddr,
                                 info->iova.iov_len);
}

auto dma_unregister_cb(vfu_ctx_t* ctx, vfu_dma_info_t* info) -> void {
    binding_of(ctx).dma_unregister(reinterpret_cast<std::uint64_t>(info->iova.iov_base));
}

auto reset_cb(vfu_ctx_t* ctx, vfu_reset_type_t /*type*/) -> int {
    binding_of(ctx).device_reset();
    return 0;
}

auto log_cb(vfu_ctx_t* ctx, int /*level*/, const char* msg) -> void {
    binding_of(ctx).log(msg);
}

auto failed(std::string_view what) -> std::unexpected<std::string> {
    return std::unexpected(std::format("{}: {}", what, std::strerror(errno)));
}

}  // namespace

auto VirtioBinding::create(const std::string& socket_path, const std::string& log_name)
    -> std::expected<std::unique_ptr<VirtioBinding>, std::string> {
    ::unlink(socket_path.c_str());  // stale socket from a previous run
    // The binding must exist before the context so the context's private
    // pointer can name it; the constructor is private, hence no make_unique.
    std::unique_ptr<VirtioBinding> binding{new VirtioBinding(nullptr, log_name)};
    binding->_ctx = vfu_create_ctx(VFU_TRANS_SOCK, socket_path.c_str(), LIBVFIO_USER_FLAG_ATTACH_NB,
                                   binding.get(), VFU_DEV_TYPE_PCI);
    if (binding->_ctx == nullptr) {
        return failed("vfu_create_ctx");
    }
    return binding;
}

VirtioBinding::VirtioBinding(vfu_ctx* ctx, std::string log_name)
    : _ctx{ctx}, _log_name{std::move(log_name)} {}

VirtioBinding::~VirtioBinding() {
    if (_ctx != nullptr) {
        vfu_destroy_ctx(_ctx);
    }
}

auto VirtioBinding::bind(virtio::PciFunction& function) -> std::expected<void, std::string> {
    _function = &function;
    const virtio::PciIdentity& id = function.identity();
    if (vfu_setup_log(_ctx, log_cb, LOG_INFO) < 0) {
        return failed("vfu_setup_log");
    }
    // vfu_pci_init's revision argument is unused (v0.8), so the Revision ID
    // a modern-only virtio device needs is written into config space below.
    if (vfu_pci_init(_ctx, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, 0) < 0) {
        return failed("vfu_pci_init");
    }
    vfu_pci_get_config_space(_ctx)->hdr.rid = virtio::pci_revision_modern;
    vfu_pci_set_id(_ctx, virtio::pci_vendor_virtio, id.device_id, virtio::pci_vendor_virtio,
                   subsystem_id);
    vfu_pci_set_class(_ctx, id.class_code, id.subclass, id.prog_if);

    // PCI Express with FLR, so the L1 host can reset the function.
    pxcap px{};
    px.hdr.id = PCI_CAP_ID_EXP;
    px.pxcaps.ver = pcie_cap_version;
    px.pxdcap.flrc = 1;
    if (vfu_pci_add_capability(_ctx, 0, 0, &px) < 0) {
        return failed("add PCIe capability");
    }
    msixcap msix{};
    msix.hdr.id = PCI_CAP_ID_MSIX;
    // Table size is encoded as N-1 in an 11-bit field; at most 1025 queues
    // fit the notify window, so N-1 always fits.
    msix.mxc.ts = static_cast<std::uint16_t>(function.msix_vectors() - 1U) & msix_table_size_mask;
    msix.mtab.tbir = msix_bar_index;
    msix.mtab.to = msix_table_offset >> msix_offset_shift;
    msix.mpba.pbir = msix_bar_index;
    msix.mpba.pbao = msix_pba_offset >> msix_offset_shift;
    if (vfu_pci_add_capability(_ctx, 0, 0, &msix) < 0) {
        return failed("add MSI-X capability");
    }
    // Virtio vendor capabilities. The encoded bytes are a `struct vsc`
    // (id, next, length, ...); libvfio-user rewrites `next` as it links them.
    for (const auto& cap : function.capabilities()) {
        std::vector<std::byte> bytes = virtio::encode_capability(cap, 0);
        if (vfu_pci_add_capability(_ctx, 0, VFU_CAP_FLAG_READONLY, bytes.data()) < 0) {
            return failed("add virtio capability");
        }
    }

    if (vfu_setup_region(_ctx, VFU_PCI_DEV_BAR0_REGION_IDX, virtio::bar_layout::bar_size, bar0_cb,
                         VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0) < 0) {
        return failed("setup BAR0");
    }
    if (vfu_setup_region(_ctx, VFU_PCI_DEV_BAR2_REGION_IDX, msix_bar_size, msix_bar_cb,
                         VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0) < 0) {
        return failed("setup BAR2");
    }
    if (vfu_setup_device_nr_irqs(_ctx, VFU_DEV_MSIX_IRQ, function.msix_vectors()) < 0) {
        return failed("setup MSI-X irqs");
    }
    if (vfu_setup_device_reset_cb(_ctx, reset_cb) < 0) {
        return failed("setup reset callback");
    }
    if (vfu_setup_device_dma(_ctx, dma_max_regions, dma_register_cb, dma_unregister_cb) < 0) {
        return failed("setup DMA");
    }
    if (vfu_realize_ctx(_ctx) < 0) {
        return failed("vfu_realize_ctx");
    }
    return {};
}

auto VirtioBinding::poll_fd() const -> int {
    return vfu_get_poll_fd(_ctx);
}

auto VirtioBinding::attach() -> std::expected<bool, std::string> {
    if (vfu_attach_ctx(_ctx) == 0) {
        return true;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
    }
    return failed("vfu_attach_ctx");
}

auto VirtioBinding::run() -> std::expected<bool, std::string> {
    if (vfu_run_ctx(_ctx) >= 0) {
        return true;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EBUSY) {
        return true;
    }
    if (errno == ENOTCONN) {
        // The client went away; its mappings and our queues go with it.
        device_reset();
        return false;
    }
    return failed("vfu_run_ctx");
}

auto VirtioBinding::raise(std::uint16_t vector) -> void {
    if (vfu_irq_trigger(_ctx, vector) != 0) {
        std::println(stderr, "{}: irq_trigger({}) failed: {}", _log_name, vector,
                     std::strerror(errno));
    }
}

auto VirtioBinding::bar_access(char* buf, std::size_t count, std::int64_t offset, bool is_write)
    -> long {
    // Any width the function knows; the bus is little-endian, and so is
    // every host harbor runs on.
    if (offset < 0 || count == 0 || count > sizeof(std::uint64_t) || _function == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const auto at = static_cast<std::uint32_t>(offset);
    if (is_write) {
        std::uint64_t value = 0;
        std::memcpy(&value, buf, count);
        if (auto ok = _function->bar_write(at, count, value); !ok) {
            std::println(stderr, "{}: BAR0 write {:#x}/{} refused: {}", _log_name, at, count,
                         virtio::to_string(ok.error()));
        }
    } else {
        std::uint64_t value = 0;
        if (auto v = _function->bar_read(at, count); v) {
            value = *v;
        } else {
            std::println(stderr, "{}: BAR0 read {:#x}/{} refused: {}", _log_name, at, count,
                         virtio::to_string(v.error()));
        }
        std::memcpy(buf, &value, count);
    }
    // A refused access still completes, so a confused driver cannot wedge
    // the client (pci.hpp).
    return static_cast<long>(count);
}

auto VirtioBinding::dma_register(std::uint64_t iova, void* vaddr, std::size_t len) -> void {
    if (vaddr == nullptr) {
        // Not shared with us (no file descriptor): the device cannot reach it.
        std::println(stderr, "{}: DMA region {:#x}+{:#x} not mappable, ignored", _log_name, iova,
                     len);
        return;
    }
    auto ok = _memory.add_region(iova, std::span{static_cast<std::byte*>(vaddr), len});
    if (!ok) {
        std::println(stderr, "{}: DMA region {:#x}+{:#x} refused: {}", _log_name, iova, len,
                     virtio::to_string(ok.error()));
    }
}

auto VirtioBinding::dma_unregister(std::uint64_t iova) -> void {
    if (_function != nullptr) {
        _function->memory_changing();
    }
    static_cast<void>(_memory.remove_region(iova));  // not_found: it was never added
}

auto VirtioBinding::device_reset() -> void {
    if (_on_reset) {
        _on_reset();
    } else if (_function != nullptr) {
        _function->reset();
    }
}

auto VirtioBinding::set_reset_handler(std::function<void()> handler) -> void {
    _on_reset = std::move(handler);
}

auto VirtioBinding::retarget(virtio::PciFunction& function) -> std::expected<void, std::string> {
    if (_function == nullptr) {
        return std::unexpected(std::string{"retarget before bind"});
    }
    const auto& a = _function->identity();
    const auto& b = function.identity();
    const auto caps = [](const virtio::PciFunction& f) {
        std::vector<std::vector<std::byte>> out;
        for (const auto& cap : f.capabilities()) {
            out.push_back(virtio::encode_capability(cap, 0));
        }
        return out;
    };
    if (a.device_id != b.device_id || a.class_code != b.class_code || a.subclass != b.subclass ||
        a.prog_if != b.prog_if || _function->msix_vectors() != function.msix_vectors() ||
        caps(*_function) != caps(function)) {
        return std::unexpected(std::string{"retarget: the function's PCI shape differs"});
    }
    _function = &function;
    return {};
}

auto VirtioBinding::log(const char* message) const -> void {
    std::println(stderr, "{}: {}", _log_name, message);
}

}  // namespace ak::oar::vfu
