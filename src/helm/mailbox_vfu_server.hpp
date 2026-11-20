// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The MailboxDevice served over vfio-user: harbor's placement of helm's
// mailbox function (.kiro/specs/helm-control-plane/ task 8). L0 QEMU's
// vfio-user-pci client connects to the socket and presents the function to
// L1, where the initramfs binds it to vfio-pci and hull maps BAR0.
//
// The function exposes:
//   - BAR0 (4 KiB, memory): the MailboxDevice register file.
//   - BAR2 (4 KiB, memory): the MSI-X table and PBA, which the client
//     emulates as vfio-pci does.
//   - One MSI-X vector (0: a new command), a PCIe capability with FLR, and a
//     reset callback that clears the register file.
// It never sets up DMA, so libvfio-user ignores the client's DMA map and
// unmap requests and the server holds no guest memory at all
// (Requirement 1.2).
//
// Built only with libvfio-user (AK_HAS_LIBVFIO_USER).

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

#include "helm/mailbox_device.hpp"

namespace ak::helm {

inline constexpr std::uint16_t mailbox_vendor_id = 0x1de5;  // placeholder, as ak-testdev
inline constexpr std::uint16_t mailbox_device_id = 0xa010;

class MailboxVfuServer {
public:
    // Listens on `socket_path` (a stale socket file is removed). Slots the
    // host rings for go to `on_host_slot`, on the thread running serve().
    [[nodiscard]] static auto create(const std::string& socket_path,
                                     MailboxDevice::HostSlotHandler on_host_slot)
        -> std::expected<std::unique_ptr<MailboxVfuServer>, std::string>;

    MailboxVfuServer(const MailboxVfuServer&) = delete;
    auto operator=(const MailboxVfuServer&) -> MailboxVfuServer& = delete;
    MailboxVfuServer(MailboxVfuServer&&) = delete;
    auto operator=(MailboxVfuServer&&) -> MailboxVfuServer& = delete;
    ~MailboxVfuServer();

    // The HostPort for the CommandRouter; safe to use from any thread,
    // including from the host-slot handler.
    [[nodiscard]] auto host_port() noexcept -> HostPort&;
    // The register file itself, for statistics.
    [[nodiscard]] auto device() noexcept -> MailboxDevice& { return _device; }

    // Serves clients one after another until stop(): waits for a client,
    // serves it until it disconnects (a QEMU restart is fine), repeats.
    // Returns an error only if libvfio-user fails for another reason.
    [[nodiscard]] auto serve() -> std::expected<void, std::string>;

    // Makes serve() return; callable from any thread or a signal handler.
    auto stop() noexcept -> void;

private:
    struct Impl;

    explicit MailboxVfuServer(MailboxDevice::HostSlotHandler on_host_slot);

    std::unique_ptr<Impl> _impl;
    MailboxDevice _device;
};

}  // namespace ak::helm
