// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/mailbox_device.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <optional>
#include <utility>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

namespace mb = mailbox;

constexpr std::size_t reg_size = sizeof(std::uint32_t);
constexpr std::array<std::size_t, 4> access_sizes{1, 2, 4, 8};

auto le32_bytes(std::uint32_t v) -> std::array<std::byte, reg_size> {
    std::array<std::byte, reg_size> out{};
    wire::SpanWriter w{out};
    (void)w.write(v, wire::Order::little);
    return out;
}

// Copies the part of [base, base + src.size()) that overlaps
// [offset, offset + out.size()) into out.
auto overlay(std::size_t base, std::span<const std::byte> src, std::size_t offset,
             std::span<std::byte> out) -> void {
    const std::size_t lo = std::max(base, offset);
    const std::size_t hi = std::min(base + src.size(), offset + out.size());
    if (lo < hi) {
        std::ranges::copy(src.subspan(lo - base, hi - lo),
                          std::next(out.begin(), static_cast<std::ptrdiff_t>(lo - offset)));
    }
}

auto in_slot(std::size_t slot_base, std::size_t offset) -> bool {
    return offset >= slot_base && offset < slot_base + mb::slot_size;
}

}  // namespace

auto valid_bar0_access(std::size_t offset, std::size_t size) noexcept -> bool {
    return std::ranges::find(access_sizes, size) != access_sizes.end() && offset % size == 0 &&
           offset < mb::reg::bar0_size && size <= mb::reg::bar0_size - offset;
}

MailboxDevice::MailboxDevice(RaiseCommandIrq raise, HostSlotHandler on_host_slot)
    : _raise{std::move(raise)}, _on_host_slot{std::move(on_host_slot)} {}

auto MailboxDevice::post_command(const mb::Slot& slot) -> bool {
    const std::scoped_lock lock{_mutex};
    const auto previous_slot = _cmd_slot;
    const auto previous_doorbell = _cmd_doorbell;
    _cmd_slot = slot;
    ++_cmd_doorbell;  // wraps; the host compares for change, not order
    // The interrupt is raised under the lock so the host cannot read the
    // doorbell between a failed raise and the rollback.
    if (!_raise || !_raise()) {
        _cmd_slot = previous_slot;
        _cmd_doorbell = previous_doorbell;
        ++_stats.commands_unposted;
        return false;
    }
    ++_stats.commands_posted;
    return true;
}

auto MailboxDevice::read_locked(std::size_t offset, std::span<std::byte> out) const -> void {
    std::ranges::fill(out, std::byte{0});
    overlay(mb::reg::magic, le32_bytes(mb::magic), offset, out);
    overlay(mb::reg::version, le32_bytes(mb::protocol_version), offset, out);
    overlay(mb::reg::cmd_doorbell, le32_bytes(_cmd_doorbell), offset, out);
    overlay(mb::reg::cmd_slot, _cmd_slot, offset, out);
    overlay(mb::reg::rsp_slot, _rsp_slot, offset, out);
    overlay(mb::reg::evt_slot, _evt_slot, offset, out);
}

auto MailboxDevice::read(std::size_t offset, std::span<std::byte> out) -> bool {
    const std::scoped_lock lock{_mutex};
    if (!valid_bar0_access(offset, out.size())) {
        ++_stats.bad_accesses;
        return false;
    }
    read_locked(offset, out);
    return true;
}

auto MailboxDevice::write(std::size_t offset, std::span<const std::byte> in) -> bool {
    std::optional<std::pair<HostSlotKind, mb::Slot>> rang;
    {
        const std::scoped_lock lock{_mutex};
        if (!valid_bar0_access(offset, in.size())) {
            ++_stats.bad_accesses;
            return false;
        }
        // Natural alignment and a width of at most 8 keep an access inside
        // one register or one 256-byte slot.
        if (in_slot(mb::reg::rsp_slot, offset)) {
            std::ranges::copy(in, std::next(_rsp_slot.begin(), static_cast<std::ptrdiff_t>(
                                                                   offset - mb::reg::rsp_slot)));
        } else if (in_slot(mb::reg::evt_slot, offset)) {
            std::ranges::copy(in, std::next(_evt_slot.begin(), static_cast<std::ptrdiff_t>(
                                                                   offset - mb::reg::evt_slot)));
        } else if (offset == mb::reg::rsp_doorbell && in.size() == reg_size) {
            ++_stats.responses;
            rang.emplace(HostSlotKind::response, _rsp_slot);
        } else if (offset == mb::reg::evt_doorbell && in.size() == reg_size) {
            ++_stats.events;
            rang.emplace(HostSlotKind::event, _evt_slot);
        } else {
            ++_stats.dropped_writes;
        }
    }
    if (rang && _on_host_slot) {
        _on_host_slot(rang->first, rang->second);
    }
    return true;
}

auto MailboxDevice::reset() -> void {
    const std::scoped_lock lock{_mutex};
    _cmd_doorbell = 0;
    _cmd_slot = {};
    _rsp_slot = {};
    _evt_slot = {};
    ++_stats.resets;
}

auto MailboxDevice::stats() const -> MailboxDeviceStats {
    const std::scoped_lock lock{_mutex};
    return _stats;
}

}  // namespace ak::helm
