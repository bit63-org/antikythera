// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/virtio/pci.hpp"

#include <bit>

#include "common/wire.hpp"

namespace ak::oar::virtio {

namespace {

constexpr std::size_t width8 = 1;
constexpr std::size_t width16 = 2;
constexpr std::size_t width32 = 4;
constexpr std::size_t width64 = 8;
constexpr unsigned bits_per_word = 32;
constexpr std::uint64_t low_word_mask = 0xFFFF'FFFF;
constexpr std::uint32_t feature_words = 2;  // 64 feature bits, two select windows

// Status bits a driver may write (everything but the device-owned
// DEVICE_NEEDS_RESET).
constexpr std::uint8_t driver_status_bits =
    status_acknowledge | status_driver | status_driver_ok | status_features_ok | status_failed;

}  // namespace

auto to_string(ConfigError e) noexcept -> const char* {
    switch (e) {
        case ConfigError::no_version_1:
            return "no_version_1";
        case ConfigError::no_queues:
            return "no_queues";
        case ConfigError::bad_queue_size:
            return "bad_queue_size";
    }
    return "unknown";
}

auto to_string(AccessError e) noexcept -> const char* {
    switch (e) {
        case AccessError::bad_offset:
            return "bad_offset";
        case AccessError::bad_width:
            return "bad_width";
        case AccessError::read_only:
            return "read_only";
        case AccessError::not_now:
            return "not_now";
        case AccessError::bad_value:
            return "bad_value";
    }
    return "unknown";
}

auto encode_capability(const PciCapability& cap, std::uint8_t next, std::uint32_t flags)
    -> std::vector<std::byte> {
    if (cap.type == CfgType::vendor) {
        std::vector<std::byte> out;
        wire::Writer w{out};
        w.u8(pci_cap_id_vendor);
        w.u8(next);
        w.u8(static_cast<std::uint8_t>(vendor_data::size));
        w.u8(static_cast<std::uint8_t>(cap.type));
        w.le16(vendor_data::vendor_id);
        w.u8(vendor_data::version);
        w.u8(0);
        w.bytes(vendor_data::magic);
        w.le32(flags);
        return out;
    }
    const bool notify = cap.type == CfgType::notify;
    const std::size_t len = notify ? virtio_pci_notify_cap_size : virtio_pci_cap_size;
    std::vector<std::byte> out;
    wire::Writer w{out};
    w.u8(pci_cap_id_vendor);
    w.u8(next);
    w.u8(static_cast<std::uint8_t>(len));
    w.u8(static_cast<std::uint8_t>(cap.type));
    w.u8(cap.bar);
    w.u8(0);  // id: only one structure of each type
    w.u8(0);  // padding
    w.u8(0);
    w.le32(cap.offset);
    w.le32(cap.length);
    if (notify) {
        w.le32(cap.notify_off_multiplier);
    }
    return out;
}

// --- CommonConfig --------------------------------------------------------

auto CommonConfig::create(const CommonConfigParams& params)
    -> std::expected<CommonConfig, ConfigError> {
    if ((params.device_features & feature_bit(feature_version_1)) == 0) {
        return std::unexpected(ConfigError::no_version_1);
    }
    if (params.num_queues == 0) {
        return std::unexpected(ConfigError::no_queues);
    }
    if (params.max_queue_size == 0 || params.max_queue_size > max_queue_size ||
        !std::has_single_bit(params.max_queue_size)) {
        return std::unexpected(ConfigError::bad_queue_size);
    }
    return CommonConfig{params};
}

CommonConfig::CommonConfig(const CommonConfigParams& params)
    : _params{params}, _queues(params.num_queues, Queue{.size = params.max_queue_size}) {}

auto CommonConfig::reset() -> void {
    _device_feature_select = 0;
    _driver_feature_select = 0;
    _driver_features = 0;
    _config_msix_vector = msix_no_vector;
    _status = 0;
    _queue_select = 0;
    _queues.assign(_params.num_queues, Queue{.size = _params.max_queue_size});
    _reset_pending = true;
    // config_generation is deliberately kept: it only ever moves forward.
}

auto CommonConfig::take_reset() noexcept -> bool {
    const bool pending = _reset_pending;
    _reset_pending = false;
    return pending;
}

auto CommonConfig::set_needs_reset() noexcept -> void {
    _status |= status_device_needs_reset;
}

auto CommonConfig::selected() const -> const Queue* {
    return _queue_select < _queues.size() ? &_queues[_queue_select] : nullptr;
}

auto CommonConfig::selected() -> Queue* {
    return _queue_select < _queues.size() ? &_queues[_queue_select] : nullptr;
}

auto CommonConfig::queue(std::uint16_t index) const -> std::optional<QueueConfig> {
    if (index >= _queues.size() || !_queues[index].enabled) {
        return std::nullopt;
    }
    const Queue& q = _queues[index];
    return QueueConfig{
        .size = q.size,
        .desc = q.desc,
        .driver = q.driver,
        .device = q.device,
        .event_idx = (_driver_features & feature_bit(feature_event_idx)) != 0,
        .indirect_desc = (_driver_features & feature_bit(feature_indirect_desc)) != 0,
    };
}

auto CommonConfig::queue_msix_vector(std::uint16_t index) const -> std::uint16_t {
    return index < _queues.size() ? _queues[index].msix_vector : msix_no_vector;
}

auto CommonConfig::read(std::uint32_t offset, std::size_t width) const
    -> std::expected<std::uint64_t, AccessError> {
    auto exact = [&](std::size_t want) -> std::expected<void, AccessError> {
        if (width != want) {
            return std::unexpected(AccessError::bad_width);
        }
        return {};
    };
    auto feature_word = [](std::uint64_t features, std::uint32_t select) -> std::uint64_t {
        return select < feature_words ? (features >> (select * bits_per_word)) & low_word_mask : 0;
    };
    // 64-bit queue addresses: whole, or either 32-bit half.
    auto address = [&](Gpa Queue::* field,
                       std::uint32_t base) -> std::expected<std::uint64_t, AccessError> {
        const Queue* q = selected();
        const Gpa v = q != nullptr ? q->*field : 0;
        if (offset == base && width == width64) {
            return v;
        }
        if (width != width32) {
            return std::unexpected(AccessError::bad_width);
        }
        return offset == base ? v & low_word_mask : v >> bits_per_word;
    };

    const Queue* q = selected();
    switch (offset) {
        case common_cfg::device_feature_select:
            return exact(width32).transform([&] { return std::uint64_t{_device_feature_select}; });
        case common_cfg::device_feature:
            return exact(width32).transform(
                [&] { return feature_word(_params.device_features, _device_feature_select); });
        case common_cfg::driver_feature_select:
            return exact(width32).transform([&] { return std::uint64_t{_driver_feature_select}; });
        case common_cfg::driver_feature:
            return exact(width32).transform(
                [&] { return feature_word(_driver_features, _driver_feature_select); });
        case common_cfg::config_msix_vector:
            return exact(width16).transform([&] { return std::uint64_t{_config_msix_vector}; });
        case common_cfg::num_queues:
            return exact(width16).transform([&] { return std::uint64_t{_params.num_queues}; });
        case common_cfg::device_status:
            return exact(width8).transform([&] { return std::uint64_t{_status}; });
        case common_cfg::config_generation:
            return exact(width8).transform([&] { return std::uint64_t{_config_generation}; });
        case common_cfg::queue_select:
            return exact(width16).transform([&] { return std::uint64_t{_queue_select}; });
        case common_cfg::queue_size:
            // 0 tells the driver the selected queue does not exist.
            return exact(width16).transform(
                [&] { return std::uint64_t{q != nullptr ? q->size : 0U}; });
        case common_cfg::queue_msix_vector:
            return exact(width16).transform(
                [&] { return std::uint64_t{q != nullptr ? q->msix_vector : msix_no_vector}; });
        case common_cfg::queue_enable:
            return exact(width16).transform(
                [&] { return std::uint64_t{q != nullptr && q->enabled ? 1U : 0U}; });
        case common_cfg::queue_notify_off:
            // Each queue notifies at its own index times the multiplier.
            return exact(width16).transform([&] { return std::uint64_t{_queue_select}; });
        case common_cfg::queue_desc:
        case common_cfg::queue_desc + width32:
            return address(&Queue::desc, common_cfg::queue_desc);
        case common_cfg::queue_driver:
        case common_cfg::queue_driver + width32:
            return address(&Queue::driver, common_cfg::queue_driver);
        case common_cfg::queue_device:
        case common_cfg::queue_device + width32:
            return address(&Queue::device, common_cfg::queue_device);
        case common_cfg::queue_notify_data:
        case common_cfg::queue_reset:
            // Neither VIRTIO_F_NOTIF_CONFIG_DATA nor VIRTIO_F_RING_RESET is
            // offered, so both read as zero.
            return exact(width16).transform([] { return std::uint64_t{0}; });
        default:
            return std::unexpected(AccessError::bad_offset);
    }
}

auto CommonConfig::write_status(std::uint8_t value) -> std::expected<void, AccessError> {
    if (value == 0) {
        reset();
        return {};
    }
    if ((value & ~driver_status_bits) != 0) {
        return std::unexpected(AccessError::bad_value);
    }
    const std::uint8_t driver_bits = _status & driver_status_bits;
    // Only a reset clears bits (spec 2.1.1).
    if ((value & driver_bits) != driver_bits) {
        return std::unexpected(AccessError::bad_value);
    }
    std::uint8_t accepted = value;
    const bool features_ok_new =
        (value & status_features_ok) != 0 && (_status & status_features_ok) == 0;
    if (features_ok_new) {
        // Spec 3.1.1 step 5: the device refuses FEATURES_OK for features it
        // did not offer or without VERSION_1; the driver re-reads and sees
        // the bit clear.
        const bool subset = (_driver_features & ~_params.device_features) == 0;
        const bool modern = (_driver_features & feature_bit(feature_version_1)) != 0;
        if (!subset || !modern) {
            accepted = static_cast<std::uint8_t>(accepted & ~status_features_ok);
        }
    }
    if ((accepted & status_driver_ok) != 0 && (accepted & status_features_ok) == 0) {
        return std::unexpected(AccessError::not_now);
    }
    _status = static_cast<std::uint8_t>(accepted | (_status & status_device_needs_reset));
    return {};
}

auto CommonConfig::write_queue_address(Gpa Queue::* field, std::uint32_t at, std::size_t width,
                                       std::uint64_t value) -> std::expected<void, AccessError> {
    Queue* q = selected();
    if (q == nullptr || q->enabled) {
        return std::unexpected(AccessError::not_now);
    }
    const bool high = (at % width64) != 0;
    if (width == width64 && !high) {
        q->*field = value;
        return {};
    }
    if (width != width32) {
        return std::unexpected(AccessError::bad_width);
    }
    const Gpa old = q->*field;
    q->*field = high ? (old & low_word_mask) | (value << bits_per_word)
                     : (old & ~low_word_mask) | (value & low_word_mask);
    return {};
}

auto CommonConfig::write(std::uint32_t offset, std::size_t width, std::uint64_t value)
    -> std::expected<void, AccessError> {
    auto natural = [&](std::size_t want) -> bool { return width == want; };
    // Values arrive zero-extended from the access width; anything wider is
    // a transport bug, refused the same way.
    if (width < width64 && (value >> (width * 8U)) != 0) {
        return std::unexpected(AccessError::bad_value);
    }
    // Queue configuration may change only while the driver is setting the
    // device up: after FEATURES_OK and before DRIVER_OK (spec 3.1.1 step 7).
    auto queue_setup_allowed = [&]() -> bool {
        return (_status & status_features_ok) != 0 && (_status & status_driver_ok) == 0;
    };

    switch (offset) {
        case common_cfg::device_feature_select:
            if (!natural(width32)) {
                return std::unexpected(AccessError::bad_width);
            }
            _device_feature_select = static_cast<std::uint32_t>(value);
            return {};
        case common_cfg::driver_feature_select:
            if (!natural(width32)) {
                return std::unexpected(AccessError::bad_width);
            }
            _driver_feature_select = static_cast<std::uint32_t>(value);
            return {};
        case common_cfg::driver_feature: {
            if (!natural(width32)) {
                return std::unexpected(AccessError::bad_width);
            }
            if ((_status & status_features_ok) != 0) {
                return std::unexpected(AccessError::not_now);
            }
            if (_driver_feature_select >= feature_words) {
                return value == 0 ? std::expected<void, AccessError>{}
                                  : std::unexpected(AccessError::bad_value);
            }
            const unsigned shift = _driver_feature_select * bits_per_word;
            _driver_features = (_driver_features & ~(low_word_mask << shift)) | (value << shift);
            return {};
        }
        case common_cfg::config_msix_vector:
            if (!natural(width16)) {
                return std::unexpected(AccessError::bad_width);
            }
            _config_msix_vector = static_cast<std::uint16_t>(value);
            return {};
        case common_cfg::device_status:
            if (!natural(width8)) {
                return std::unexpected(AccessError::bad_width);
            }
            return write_status(static_cast<std::uint8_t>(value));
        case common_cfg::queue_select:
            if (!natural(width16)) {
                return std::unexpected(AccessError::bad_width);
            }
            // Out-of-range selects are legal: the driver probes with them
            // and reads queue_size 0.
            _queue_select = static_cast<std::uint16_t>(value);
            return {};
        case common_cfg::queue_size: {
            if (!natural(width16)) {
                return std::unexpected(AccessError::bad_width);
            }
            Queue* q = selected();
            if (q == nullptr || q->enabled || !queue_setup_allowed()) {
                return std::unexpected(AccessError::not_now);
            }
            const auto size = static_cast<std::uint16_t>(value);
            if (size == 0 || size > _params.max_queue_size || !std::has_single_bit(size)) {
                return std::unexpected(AccessError::bad_value);
            }
            q->size = size;
            return {};
        }
        case common_cfg::queue_msix_vector: {
            if (!natural(width16)) {
                return std::unexpected(AccessError::bad_width);
            }
            Queue* q = selected();
            if (q == nullptr) {
                return std::unexpected(AccessError::not_now);
            }
            q->msix_vector = static_cast<std::uint16_t>(value);
            return {};
        }
        case common_cfg::queue_enable: {
            if (!natural(width16)) {
                return std::unexpected(AccessError::bad_width);
            }
            Queue* q = selected();
            if (q == nullptr || !queue_setup_allowed()) {
                return std::unexpected(AccessError::not_now);
            }
            // Only 1 may be written (spec 4.1.4.3.2); disabling is a reset.
            if (value != 1) {
                return std::unexpected(AccessError::bad_value);
            }
            q->enabled = true;
            return {};
        }
        case common_cfg::queue_desc:
        case common_cfg::queue_desc + width32:
        case common_cfg::queue_driver:
        case common_cfg::queue_driver + width32:
        case common_cfg::queue_device:
        case common_cfg::queue_device + width32: {
            if (!queue_setup_allowed()) {
                return std::unexpected(AccessError::not_now);
            }
            Gpa Queue::* field = offset < common_cfg::queue_driver   ? &Queue::desc
                                 : offset < common_cfg::queue_device ? &Queue::driver
                                                                     : &Queue::device;
            return write_queue_address(field, offset, width, value);
        }
        case common_cfg::device_feature:
        case common_cfg::num_queues:
        case common_cfg::config_generation:
        case common_cfg::queue_notify_off:
        case common_cfg::queue_notify_data:
        case common_cfg::queue_reset:
            return std::unexpected(AccessError::read_only);
        default:
            return std::unexpected(AccessError::bad_offset);
    }
}

}  // namespace ak::oar::virtio
