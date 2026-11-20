// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes helm's MailboxDevice register file with arbitrary host accesses
// (.kiro/specs/helm-control-plane/ task 8): each 4-byte record is an
// offset, a width, a direction and a data byte. Whatever the host does, the
// identity registers and the posted command never change, and every slot
// the device hands to helm is exactly what the host last wrote there.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "helm/mailbox.hpp"
#include "helm/mailbox_device.hpp"

namespace mb = ak::helm::mailbox;

namespace {

constexpr std::size_t record_size = 4;
constexpr std::byte command_fill{0xC3};

auto u32_at(ak::helm::MailboxDevice& device, std::size_t offset) -> std::uint32_t {
    std::array<std::byte, 4> b{};
    if (!device.read(offset, b)) {
        std::abort();
    }
    return static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8U) |
           (static_cast<std::uint32_t>(b[2]) << 16U) | (static_cast<std::uint32_t>(b[3]) << 24U);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Shadow copies of what the host wrote into RSP_SLOT and EVT_SLOT.
    mb::Slot rsp{};
    mb::Slot evt{};
    ak::helm::MailboxDevice device{
        [] { return true; },
        [&](ak::helm::HostSlotKind kind, const mb::Slot& slot) {
            if (slot != (kind == ak::helm::HostSlotKind::response ? rsp : evt)) {
                std::abort();
            }
        }};
    mb::Slot command{};
    command.fill(command_fill);
    if (!device.post_command(command)) {
        std::abort();
    }
    constexpr std::array<std::size_t, 4> widths{1, 2, 4, 8};
    for (std::size_t i = 0; i + record_size <= size; i += record_size) {
        const std::size_t offset = static_cast<std::size_t>(data[i]) |
                                   (static_cast<std::size_t>(data[i + 1] & 0x1F) << 8U);
        const std::size_t width = widths[data[i + 2] & 0x3];
        const bool is_write = (data[i + 2] & 0x4) != 0;
        std::array<std::byte, 8> buf{};
        buf.fill(static_cast<std::byte>(data[i + 3]));
        const std::span access{buf.data(), width};
        const bool valid = ak::helm::valid_bar0_access(offset, width);
        const bool ok = is_write ? device.write(offset, access) : device.read(offset, access);
        if (ok != valid) {
            std::abort();
        }
        if (ok && is_write) {
            for (std::size_t b = 0; b < width; ++b) {
                const std::size_t at = offset + b;
                if (at >= mb::reg::rsp_slot && at < mb::reg::rsp_slot + mb::slot_size) {
                    rsp[at - mb::reg::rsp_slot] = access[b];
                } else if (at >= mb::reg::evt_slot && at < mb::reg::evt_slot + mb::slot_size) {
                    evt[at - mb::reg::evt_slot] = access[b];
                }
            }
        }
    }
    if (u32_at(device, mb::reg::magic) != mb::magic ||
        u32_at(device, mb::reg::version) != mb::protocol_version ||
        u32_at(device, mb::reg::cmd_doorbell) != 1) {
        std::abort();
    }
    for (std::size_t off = 0; off < mb::slot_size; off += 4) {
        if (u32_at(device, mb::reg::cmd_slot + off) != 0xC3C3'C3C3U) {
            std::abort();
        }
    }
    return 0;
}
