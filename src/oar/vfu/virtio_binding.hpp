// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Binds a virtio::PciFunction to libvfio-user: the harbor side of the
// transport seam (.kiro/specs/oar-net-data-plane/ Requirement 1.4,
// .kiro/steering/structure.md "One transport seam per device"). Every oar
// device server uses this; the pci-epf binding on hardware is its sibling.
//
// What it presents to the vfio-user client (QEMU's vfio-user-pci in L0):
//
//   - virtio vendor/device IDs from the function, revision 1 (modern only);
//   - a PCI Express capability with FLR (Requirement 1.3), MSI-X with one
//     vector per queue plus config (Requirement 1.1), and the virtio vendor
//     capabilities from PciFunction::capabilities(), read-only;
//   - BAR0 routed to bar_read()/bar_write(), BAR2 holding the MSI-X table
//     and PBA (the client emulates them, as vfio-pci does);
//   - DMA map/unmap feeding GuestMemory; unmapping tells the function first,
//     since live queues hold spans into the region.
//
// Not provided: VIRTIO_PCI_CAP_PCI_CFG (the config-space window onto the
// BARs). Linux, the only guest harbor runs, never uses it.
//
// Single-threaded: run() serves requests on the caller's thread, and the
// function's callbacks run inside it.

#include <cstdint>
#include <expected>
#include <memory>
#include <string>

#include "oar/virtio/function.hpp"
#include "oar/virtio/guest_memory.hpp"

struct vfu_ctx;

namespace ak::oar::vfu {

class VirtioBinding final : public virtio::InterruptSink {
public:
    // Creates a non-blocking vfio-user context listening on `socket_path`
    // (a stale socket file there is removed first).
    [[nodiscard]] static auto create(const std::string& socket_path, const std::string& log_name)
        -> std::expected<std::unique_ptr<VirtioBinding>, std::string>;

    VirtioBinding(const VirtioBinding&) = delete;
    auto operator=(const VirtioBinding&) -> VirtioBinding& = delete;
    VirtioBinding(VirtioBinding&&) = delete;
    auto operator=(VirtioBinding&&) -> VirtioBinding& = delete;
    ~VirtioBinding() override;

    // The guest memory the client maps; hand it to the device before bind().
    [[nodiscard]] auto memory() noexcept -> virtio::GuestMemory& { return _memory; }

    // Describes `function` to libvfio-user and realizes the context. Call
    // once; `function` must outlive the binding.
    [[nodiscard]] auto bind(virtio::PciFunction& function) -> std::expected<void, std::string>;

    // The descriptor to poll for readability (it changes after attach()).
    [[nodiscard]] auto poll_fd() const -> int;
    // Accepts a client if one is waiting: true attached, false not yet.
    [[nodiscard]] auto attach() -> std::expected<bool, std::string>;
    // Serves every request that is ready: true still connected, false the
    // client went away (attach() again for the next one).
    [[nodiscard]] auto run() -> std::expected<bool, std::string>;

    // virtio::InterruptSink
    auto raise(std::uint16_t vector) -> void override;

    // Internal: libvfio-user's C callbacks reach the binding through these.
    auto bar_access(char* buf, std::size_t count, std::int64_t offset, bool is_write) -> long;
    auto dma_register(std::uint64_t iova, void* vaddr, std::size_t len) -> void;
    auto dma_unregister(std::uint64_t iova) -> void;
    auto device_reset() -> void;
    auto log(const char* message) const -> void;

private:
    VirtioBinding(vfu_ctx* ctx, std::string log_name);

    vfu_ctx* _ctx;
    std::string _log_name;
    virtio::GuestMemory _memory;
    virtio::PciFunction* _function{nullptr};
};

}  // namespace ak::oar::vfu
