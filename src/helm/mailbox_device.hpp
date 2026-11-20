// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MailboxDevice: helm's side of the control mailbox, the BAR0 register file
// laid out in helm/mailbox.hpp (.kiro/specs/helm-control-plane/ task 8,
// Requirement 1).
//
// The register file is transport-free: a transport (the vfio-user server in
// harbor, a pci-epf function on hardware) forwards each BAR0 access to
// read()/write() and supplies the MSI-X trigger. Nothing here can reach
// host memory: the device holds the three slots itself and the host copies
// them with MMIO, so the transport never needs a DMA mapping (1.2).
//
// Access rules (the hull agent uses aligned 32-bit accesses only):
//   - Every access is 1, 2, 4 or 8 bytes, naturally aligned, inside BAR0.
//     Anything else fails, so a transport can report an error to the host.
//   - Reads: MAGIC, VERSION, CMD_DOORBELL and the three slots read back their
//     contents; write-only doorbells and unassigned space read as zero.
//   - Writes land only in RSP_SLOT and EVT_SLOT. Writes to read-only
//     registers, CMD_SLOT and unassigned space are dropped, as hardware drops
//     them, and counted.
//   - A 32-bit write to RSP_DOORBELL or EVT_DOORBELL hands a copy of that
//     slot to the host-slot callback. The value written is ignored. Other
//     widths at a doorbell are dropped and counted.
//
// post_command() is the HostPort the CommandRouter uses: it writes the whole
// slot, increments CMD_DOORBELL and raises MSI-X vector 0 under one lock, so
// the host can never observe the doorbell before the slot (1.3). If the
// interrupt cannot be raised (no host attached, vectors not enabled) the
// doorbell and slot are restored and post_command() returns false: a command
// the router believes failed must never be visible to the host.
//
// Thread safety: read(), write(), reset() and post_command() may be called
// from different threads (the transport's thread and helm's main thread).
// Callbacks run without the lock held, so they may call back in.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <span>

#include "helm/command_router.hpp"
#include "helm/mailbox.hpp"

namespace ak::helm {

struct MailboxDeviceStats {
    std::uint64_t commands_posted{0};
    std::uint64_t commands_unposted{0};  // interrupt failed, command withdrawn
    std::uint64_t responses{0};          // RSP_DOORBELL rings
    std::uint64_t events{0};             // EVT_DOORBELL rings
    std::uint64_t dropped_writes{0};     // read-only or unassigned space
    std::uint64_t bad_accesses{0};       // width, alignment or bounds
    std::uint64_t resets{0};
};

// Which slot the host rang for.
enum class HostSlotKind : std::uint8_t {
    response,  // RSP_SLOT, after RSP_DOORBELL
    event,     // EVT_SLOT, after EVT_DOORBELL
};

class MailboxDevice final : public HostPort {
public:
    // Raises MSI-X vector 0; false if it could not be raised.
    using RaiseCommandIrq = std::function<bool()>;
    // A slot the host wrote and rang for. Runs on the transport's thread.
    using HostSlotHandler = std::function<void(HostSlotKind, const mailbox::Slot&)>;

    MailboxDevice(RaiseCommandIrq raise, HostSlotHandler on_host_slot);

    // HostPort.
    auto post_command(const mailbox::Slot& slot) -> bool override;

    // One BAR0 access. False for a bad width, alignment or range; nothing is
    // read or changed then.
    [[nodiscard]] auto read(std::size_t offset, std::span<std::byte> out) -> bool;
    [[nodiscard]] auto write(std::size_t offset, std::span<const std::byte> in) -> bool;

    // Function-level or bus reset: every slot and doorbell back to zero.
    auto reset() -> void;

    [[nodiscard]] auto stats() const -> MailboxDeviceStats;

private:
    auto read_locked(std::size_t offset, std::span<std::byte> out) const -> void;

    RaiseCommandIrq _raise;
    HostSlotHandler _on_host_slot;

    mutable std::mutex _mutex;
    std::uint32_t _cmd_doorbell{0};
    mailbox::Slot _cmd_slot{};
    mailbox::Slot _rsp_slot{};
    mailbox::Slot _evt_slot{};
    MailboxDeviceStats _stats;
};

// True for an access MailboxDevice accepts: 1, 2, 4 or 8 bytes, naturally
// aligned, inside BAR0.
[[nodiscard]] auto valid_bar0_access(std::size_t offset, std::size_t size) noexcept -> bool;

}  // namespace ak::helm
