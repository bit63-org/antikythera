// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/virtio/function.hpp"

#include <utility>

namespace ak::oar::virtio {

namespace {

constexpr std::size_t isr_width = 1;
constexpr std::size_t notify_width = 2;

[[nodiscard]] constexpr auto in_window(std::uint32_t offset, std::uint32_t base,
                                       std::uint32_t length) noexcept -> bool {
    return offset >= base && offset - base < length;
}

}  // namespace

auto to_string(FunctionError e) noexcept -> const char* {
    switch (e) {
        case FunctionError::bad_config:
            return "bad_config";
        case FunctionError::device_config_size:
            return "device_config_size";
        case FunctionError::too_many_queues:
            return "too_many_queues";
    }
    return "unknown";
}

auto PciFunction::create(Device& device, const GuestMemory& memory, InterruptSink& interrupts,
                         const PciFunctionParams& params)
    -> std::expected<std::unique_ptr<PciFunction>, FunctionError> {
    if (params.device_config_size > bar_layout::device_max_length) {
        return std::unexpected(FunctionError::device_config_size);
    }
    if (std::uint32_t{params.num_queues} * bar_layout::notify_off_multiplier >
        bar_layout::notify_max_length) {
        return std::unexpected(FunctionError::too_many_queues);
    }
    auto common = CommonConfig::create({.device_features = params.device_features,
                                        .num_queues = params.num_queues,
                                        .max_queue_size = params.max_queue_size});
    if (!common) {
        return std::unexpected(FunctionError::bad_config);
    }
    // The constructor is private, so make_unique cannot reach it.
    return std::unique_ptr<PciFunction>(
        new PciFunction(device, memory, interrupts, params, std::move(*common)));
}

PciFunction::PciFunction(Device& device, const GuestMemory& memory, InterruptSink& interrupts,
                         const PciFunctionParams& params, CommonConfig common)
    : _device{&device},
      _memory{&memory},
      _interrupts{&interrupts},
      _params{params},
      _common{std::move(common)},
      _queues(params.num_queues) {}

auto PciFunction::capabilities() const -> std::vector<PciCapability> {
    using namespace bar_layout;
    return {
        {.type = CfgType::common,
         .bar = bar_index,
         .offset = common_offset,
         .length = common_cfg::size},
        {.type = CfgType::notify,
         .bar = bar_index,
         .offset = notify_offset,
         .length = std::uint32_t{_params.num_queues} * notify_off_multiplier,
         .notify_off_multiplier = notify_off_multiplier},
        {.type = CfgType::isr, .bar = bar_index, .offset = isr_offset, .length = isr_length},
        {.type = CfgType::device,
         .bar = bar_index,
         .offset = device_offset,
         .length = _params.device_config_size},
    };
}

auto PciFunction::bar_read(std::uint32_t offset, std::size_t width)
    -> std::expected<std::uint64_t, AccessError> {
    using namespace bar_layout;
    if (in_window(offset, common_offset, common_cfg::size)) {
        return _common.read(offset - common_offset, width);
    }
    if (in_window(offset, isr_offset, isr_length)) {
        if (width != isr_width) {
            return std::unexpected(AccessError::bad_width);
        }
        // Read-to-clear (spec 4.1.4.5): the read also acknowledges.
        return std::exchange(_isr, std::uint8_t{0});
    }
    if (in_window(offset, device_offset, _params.device_config_size)) {
        const std::uint32_t at = offset - device_offset;
        if (width == 0 || width > _params.device_config_size - at) {
            return std::unexpected(AccessError::bad_width);
        }
        return _device->read_config(at, width);
    }
    return std::unexpected(AccessError::bad_offset);
}

auto PciFunction::bar_write(std::uint32_t offset, std::size_t width, std::uint64_t value)
    -> std::expected<void, AccessError> {
    using namespace bar_layout;
    if (in_window(offset, common_offset, common_cfg::size)) {
        auto written = _common.write(offset - common_offset, width, value);
        if (written) {
            after_common_write();
        }
        return written;
    }
    if (in_window(offset, isr_offset, isr_length)) {
        return std::unexpected(AccessError::read_only);
    }
    if (in_window(offset, device_offset, _params.device_config_size)) {
        const std::uint32_t at = offset - device_offset;
        if (width == 0 || width > _params.device_config_size - at) {
            return std::unexpected(AccessError::bad_width);
        }
        return _device->write_config(at, width, value);
    }
    const std::uint32_t notify_length = std::uint32_t{_params.num_queues} * notify_off_multiplier;
    if (in_window(offset, notify_offset, notify_length)) {
        const std::uint32_t at = offset - notify_offset;
        if (at % notify_off_multiplier != 0) {
            return std::unexpected(AccessError::bad_offset);
        }
        if (width != notify_width) {
            return std::unexpected(AccessError::bad_width);
        }
        // The value is the queue index (spec 4.1.5.2); the address already
        // says which queue, so a driver writing something else changes
        // nothing that matters.
        const auto index = static_cast<std::uint16_t>(at / notify_off_multiplier);
        if (_live && _queues[index].has_value()) {
            _device->queue_notified(index);
        }
        return {};
    }
    return std::unexpected(AccessError::bad_offset);
}

auto PciFunction::after_common_write() -> void {
    if (_common.take_reset()) {
        // The driver wrote 0 to device_status.
        _isr = 0;
        drop_queues();
        return;
    }
    const std::uint8_t s = _common.status();
    if (!_live && (s & status_driver_ok) != 0 && (s & status_device_needs_reset) == 0) {
        activate();
    }
}

auto PciFunction::activate() -> void {
    for (std::uint16_t i = 0; i < _params.num_queues; ++i) {
        const auto config = _common.queue(i);
        if (!config) {
            continue;  // a driver need not enable every queue
        }
        auto q = SplitQueue::create(*_memory, *config);
        if (!q) {
            fail();
            return;
        }
        _queues[i].emplace(std::move(*q));
    }
    _live = true;
}

auto PciFunction::drop_queues() -> void {
    const bool had_queues = _live;
    _live = false;
    for (auto& q : _queues) {
        q.reset();
    }
    if (had_queues) {
        _device->queues_dropped();
    }
}

auto PciFunction::reset() -> void {
    _common.reset();
    static_cast<void>(_common.take_reset());
    _isr = 0;
    drop_queues();
}

auto PciFunction::memory_changing() -> void {
    if (_live) {
        fail();
    }
}

auto PciFunction::poll() -> bool {
    return _live && _device->poll();
}

auto PciFunction::queue(std::uint16_t index) -> SplitQueue* {
    if (!_live || index >= _queues.size() || !_queues[index].has_value()) {
        return nullptr;
    }
    return &*_queues[index];
}

auto PciFunction::signal(std::uint16_t index) -> void {
    SplitQueue* q = queue(index);
    if (q == nullptr || !q->needs_interrupt()) {
        return;
    }
    _isr |= isr_queue;
    const std::uint16_t vector = _common.queue_msix_vector(index);
    if (vector != msix_no_vector) {
        _interrupts->raise(vector);
    }
}

auto PciFunction::fail() -> void {
    _common.set_needs_reset();
    drop_queues();
    raise_config();
}

auto PciFunction::config_changed() -> void {
    _common.bump_config_generation();
    raise_config();
}

auto PciFunction::raise_config() -> void {
    _isr |= isr_config;
    const std::uint16_t vector = _common.config_msix_vector();
    if (vector != msix_no_vector) {
        _interrupts->raise(vector);
    }
}

}  // namespace ak::oar::virtio
