// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The transport-independent part of a modern virtio PCI device (virtio spec
// 4.1): the vendor-specific capabilities that tell the driver where each
// configuration structure lives, and the common configuration structure's
// register behaviour. A transport (vfio-user in harbor, pci-epf on
// hardware) owns config space and BARs and forwards accesses here
// (.kiro/specs/oar-net-data-plane/ Requirement 1.4,
// .kiro/steering/structure.md "One transport seam per device").
//
// Every register write comes from the guest driver. Accesses at an unknown
// offset or with the wrong width, writes to read-only fields, and writes
// the spec forbids at that moment are refused with an AccessError and
// change nothing; the transport logs them and completes the access (reads
// as zero), so a misbehaving driver cannot wedge the device.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <vector>

#include "oar/virtio/split_queue.hpp"

namespace ak::oar::virtio {

// Feature bits (spec 6) the core itself cares about.
inline constexpr unsigned feature_indirect_desc = 28;
inline constexpr unsigned feature_event_idx = 29;
inline constexpr unsigned feature_version_1 = 32;
inline constexpr unsigned feature_access_platform = 33;

[[nodiscard]] constexpr auto feature_bit(unsigned bit) noexcept -> std::uint64_t {
    return std::uint64_t{1} << bit;
}

// Device status bits (spec 2.1).
inline constexpr std::uint8_t status_acknowledge = 1;
inline constexpr std::uint8_t status_driver = 2;
inline constexpr std::uint8_t status_driver_ok = 4;
inline constexpr std::uint8_t status_features_ok = 8;
inline constexpr std::uint8_t status_device_needs_reset = 64;
inline constexpr std::uint8_t status_failed = 128;

inline constexpr std::uint16_t msix_no_vector = 0xFFFF;

// --- Capabilities (spec 4.1.4) -------------------------------------------

enum class CfgType : std::uint8_t {
    common = 1,
    notify = 2,
    isr = 3,
    device = 4,
    pci = 5,
    vendor = 9,  // VIRTIO_PCI_CAP_VENDOR_CFG (virtio 1.2 4.1.4.10)
};

inline constexpr std::uint8_t pci_cap_id_vendor = 0x09;
inline constexpr std::size_t virtio_pci_cap_size = 16;
inline constexpr std::size_t virtio_pci_notify_cap_size = 20;

// antikythera's vendor-data capability (VIRTIO_PCI_CAP_VENDOR_CFG), the
// host's side of cooperative detach (.kiro/specs/block-volume-service/
// design "Detach blocked while mounted"). It lives in config space, where
// the guest helper reads it through sysfs, and standard drivers skip it:
//
//   0  cap_vndr 0x09 | cap_next | cap_len 16 | cfg_type 9
//   4  vendor_id le16 (0x1AF4, the function's own vendor) | version u8 (1) |
//      reserved u8
//   8  magic "AKVD"
//   12 flags le32: bit 0 eject_requested
//
// The vendor ID is the function's, since antikythera has none of its own;
// the magic tells this capability from any other vendor data.
namespace vendor_data {
inline constexpr std::size_t size = 16;
inline constexpr std::uint16_t vendor_id = 0x1AF4;
inline constexpr std::uint8_t version = 1;
inline constexpr std::array<std::byte, 4> magic{std::byte{'A'}, std::byte{'K'}, std::byte{'V'},
                                                std::byte{'D'}};
inline constexpr std::size_t flags_offset = 12;
inline constexpr std::uint32_t flag_eject_requested = 1;
}  // namespace vendor_data

struct PciCapability {
    CfgType type{CfgType::common};
    std::uint8_t bar{0};
    std::uint32_t offset{0};  // within the BAR
    std::uint32_t length{0};
    std::uint32_t notify_off_multiplier{0};  // notify capability only
};

// Encodes one capability as it appears in config space, with `next` the
// config-space offset of the following capability (0 for the last). A
// vendor capability is the vendor-data layout above with `flags`; the
// others ignore it.
[[nodiscard]] auto encode_capability(const PciCapability& cap, std::uint8_t next,
                                     std::uint32_t flags = 0) -> std::vector<std::byte>;

// --- Common configuration (spec 4.1.4.3) ---------------------------------

namespace common_cfg {
inline constexpr std::uint32_t device_feature_select = 0;
inline constexpr std::uint32_t device_feature = 4;
inline constexpr std::uint32_t driver_feature_select = 8;
inline constexpr std::uint32_t driver_feature = 12;
inline constexpr std::uint32_t config_msix_vector = 16;
inline constexpr std::uint32_t num_queues = 18;
inline constexpr std::uint32_t device_status = 20;
inline constexpr std::uint32_t config_generation = 21;
inline constexpr std::uint32_t queue_select = 22;
inline constexpr std::uint32_t queue_size = 24;
inline constexpr std::uint32_t queue_msix_vector = 26;
inline constexpr std::uint32_t queue_enable = 28;
inline constexpr std::uint32_t queue_notify_off = 30;
inline constexpr std::uint32_t queue_desc = 32;
inline constexpr std::uint32_t queue_driver = 40;
inline constexpr std::uint32_t queue_device = 48;
inline constexpr std::uint32_t queue_notify_data = 56;
inline constexpr std::uint32_t queue_reset = 58;
inline constexpr std::uint32_t size = 60;
}  // namespace common_cfg

enum class ConfigError : std::uint8_t {
    no_version_1,    // device features must include VIRTIO_F_VERSION_1
    no_queues,       // num_queues == 0
    bad_queue_size,  // max queue size 0, not a power of two, or > 32768
};

enum class AccessError : std::uint8_t {
    bad_offset,  // no field starts there
    bad_width,   // not the field's natural width (64-bit fields: 4 or 8)
    read_only,   // write to a field only the device sets
    not_now,     // write the spec forbids in the current state
    bad_value,   // value the field cannot take
};

[[nodiscard]] auto to_string(ConfigError e) noexcept -> const char*;
[[nodiscard]] auto to_string(AccessError e) noexcept -> const char*;

struct CommonConfigParams {
    std::uint64_t device_features{0};
    std::uint16_t num_queues{0};
    std::uint16_t max_queue_size{0};
};

class CommonConfig {
public:
    [[nodiscard]] static auto create(const CommonConfigParams& params)
        -> std::expected<CommonConfig, ConfigError>;

    // A driver access of `width` bytes (1, 2, 4 or 8) at `offset` in the
    // common configuration structure. Values are host-order integers; the
    // transport handles the little-endian bus.
    [[nodiscard]] auto read(std::uint32_t offset, std::size_t width) const
        -> std::expected<std::uint64_t, AccessError>;
    [[nodiscard]] auto write(std::uint32_t offset, std::size_t width, std::uint64_t value)
        -> std::expected<void, AccessError>;

    [[nodiscard]] auto status() const noexcept -> std::uint8_t { return _status; }
    // Features the driver accepted; meaningful once FEATURES_OK is set.
    [[nodiscard]] auto negotiated_features() const noexcept -> std::uint64_t {
        return _driver_features;
    }
    [[nodiscard]] auto device_features() const noexcept -> std::uint64_t {
        return _params.device_features;
    }
    [[nodiscard]] auto num_queues() const noexcept -> std::uint16_t { return _params.num_queues; }

    // The ring configuration of an enabled queue, nullopt otherwise.
    [[nodiscard]] auto queue(std::uint16_t index) const -> std::optional<QueueConfig>;
    [[nodiscard]] auto queue_msix_vector(std::uint16_t index) const -> std::uint16_t;
    [[nodiscard]] auto config_msix_vector() const noexcept -> std::uint16_t {
        return _config_msix_vector;
    }

    // True once after the driver wrote 0 to device_status (or after FLR via
    // reset()): the device must drop every queue and in-flight buffer.
    [[nodiscard]] auto take_reset() noexcept -> bool;
    // Device-initiated reset of all register state (FLR, power-on).
    auto reset() -> void;

    // The device hit a guest error it cannot recover from (a broken queue).
    auto set_needs_reset() noexcept -> void;
    // Device-specific configuration changed (spec 4.1.4.3.1).
    auto bump_config_generation() noexcept -> void { ++_config_generation; }

private:
    struct Queue {
        std::uint16_t size{0};
        std::uint16_t msix_vector{msix_no_vector};
        bool enabled{false};
        Gpa desc{0};
        Gpa driver{0};
        Gpa device{0};
    };

    explicit CommonConfig(const CommonConfigParams& params);

    auto write_status(std::uint8_t value) -> std::expected<void, AccessError>;
    auto write_queue_address(Gpa Queue::* field, std::uint32_t at, std::size_t width,
                             std::uint64_t value) -> std::expected<void, AccessError>;
    [[nodiscard]] auto selected() const -> const Queue*;
    [[nodiscard]] auto selected() -> Queue*;

    CommonConfigParams _params;
    std::uint32_t _device_feature_select{0};
    std::uint32_t _driver_feature_select{0};
    std::uint64_t _driver_features{0};
    std::uint16_t _config_msix_vector{msix_no_vector};
    std::uint8_t _status{0};
    std::uint8_t _config_generation{0};
    std::uint16_t _queue_select{0};
    std::vector<Queue> _queues;
    bool _reset_pending{false};
};

}  // namespace ak::oar::virtio
