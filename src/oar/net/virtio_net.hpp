// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VirtioNetFunction: one tenant NIC, a modern virtio-net device (virtio
// spec 5.1) on the shared virtio core
// (.kiro/specs/oar-net-data-plane/ Requirement 1, task 6).
//
// Offered features: VERSION_1, MAC, MTU, STATUS (link always up),
// EVENT_IDX and INDIRECT_DESC; no offloads, no mergeable RX buffers, no
// control queue, one RX/TX pair (queue 0 receive, queue 1 transmit). With
// VERSION_1 every frame carries the 12-byte virtio_net_hdr.
//
// Identity is the trust anchor (Requirement 2.1, 3.4): the NIC ID, MAC and
// MTU come only from helm through NicIdentity. The device configuration
// window is read-only to the guest (Requirement 1.2), and every transmitted
// frame is handed on tagged with this function's NIC ID, never anything the
// guest wrote.
//
// Transmit (guest -> data plane): each TX chain is copied out of guest
// memory once into a private buffer, then checked: a header that asks for
// an offload we never offered, a frame shorter than an Ethernet header or
// longer than the MTU allows, or a source MAC other than the assigned one
// (Requirement 2.3) is dropped and counted. Guest VLAN tags are payload
// (Requirement 2.2), so a frame may be 4 bytes longer than MTU plus the
// Ethernet header. Accepted frames go to the FrameSink synchronously.
//
// Receive (data plane -> guest): deliver() copies one frame into the next
// posted RX buffer after a zeroed header (num_buffers 1). The data plane
// queues nothing: with no buffer posted, or a buffer too small, the frame is
// dropped and counted, as a physical NIC would.
//
// A ring error from the guest puts the function in DEVICE_NEEDS_RESET
// (function.hpp). Data-path problems are counted, never thrown
// (design.md "Error handling").

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/vtep_policy.hpp"
#include "oar/virtio/function.hpp"

namespace ak::oar::net {

// Virtio device type 1 (spec 5.1.1); feature bits (spec 5.1.3).
inline constexpr std::uint16_t virtio_net_device_type = 1;
inline constexpr unsigned virtio_net_f_mtu = 3;
inline constexpr unsigned virtio_net_f_mac = 5;
inline constexpr unsigned virtio_net_f_status = 16;
inline constexpr std::uint16_t virtio_net_s_link_up = 1;

inline constexpr std::uint16_t virtio_net_rx_queue = 0;
inline constexpr std::uint16_t virtio_net_tx_queue = 1;
inline constexpr std::uint16_t virtio_net_num_queues = 2;

// struct virtio_net_hdr with num_buffers (always present under VERSION_1).
inline constexpr std::size_t virtio_net_hdr_size = 12;

// Device configuration layout (spec 5.1.4) up to and including mtu.
namespace net_cfg {
inline constexpr std::uint32_t mac = 0;
inline constexpr std::uint32_t status = 6;
inline constexpr std::uint32_t max_virtqueue_pairs = 8;
inline constexpr std::uint32_t mtu = 10;
inline constexpr std::uint32_t size = 12;
}  // namespace net_cfg

inline constexpr std::size_t ethernet_header_size = 14;
inline constexpr std::size_t vlan_tag_size = 4;
inline constexpr std::uint16_t min_mtu = 68;  // RFC 791 minimum for IPv4

// What helm assigns (Requirement 2.1, 8.1).
struct NicIdentity {
    geneve::NicId nic_id{};
    MacAddress mac{};
    std::uint16_t mtu{0};
};

// A frame the guest transmitted. `frame` aliases a buffer owned by the
// function and is valid only during FrameSink::transmit().
struct TxFrame {
    geneve::NicId source;  // the function's NIC ID, never guest data
    std::span<const std::byte> frame;
};

class FrameSink {
public:
    FrameSink() = default;
    FrameSink(const FrameSink&) = delete;
    auto operator=(const FrameSink&) -> FrameSink& = delete;
    FrameSink(FrameSink&&) = delete;
    auto operator=(FrameSink&&) -> FrameSink& = delete;
    virtual ~FrameSink() = default;

    virtual auto transmit(const TxFrame& frame) -> void = 0;
};

enum class RxResult : std::uint8_t {
    delivered,
    not_ready,         // driver not live or RX queue not enabled
    no_buffer,         // the guest has no RX buffer posted
    buffer_too_small,  // the posted buffer cannot hold header + frame
    frame_too_large,   // longer than the advertised MTU allows
    frame_too_short,   // shorter than an Ethernet header
    queue_error,       // the guest broke the RX ring (function reset)
};

[[nodiscard]] auto to_string(RxResult r) noexcept -> const char*;

enum class NetConfigError : std::uint8_t {
    invalid_nic_id,  // 0 or the broadcast ID
    bad_mac,         // group (multicast) or all-zero MAC
    bad_mtu,         // below min_mtu
    bad_queue_size,  // rejected by the virtio core
};

[[nodiscard]] auto to_string(NetConfigError e) noexcept -> const char*;

struct NetCounters {
    std::uint64_t tx_frames{0};
    std::uint64_t tx_bytes{0};
    std::uint64_t tx_drop_short{0};       // less than header + Ethernet header
    std::uint64_t tx_drop_too_long{0};    // more than MTU + Ethernet + one VLAN tag
    std::uint64_t tx_drop_bad_header{0};  // offload flags or GSO we did not offer
    std::uint64_t tx_drop_spoofed{0};     // source MAC is not the assigned one
    std::uint64_t rx_frames{0};
    std::uint64_t rx_bytes{0};
    std::uint64_t rx_drop_not_ready{0};
    std::uint64_t rx_drop_no_buffer{0};
    std::uint64_t rx_drop_buffer_too_small{0};
    std::uint64_t rx_drop_bad_frame{0};  // too short or too large to deliver
    std::uint64_t queue_errors{0};       // ring errors that reset the function
};

struct NetParams {
    NicIdentity identity;
    std::uint16_t queue_size{256};
    std::size_t tx_budget{256};  // TX chains per notification before deferring to poll()
};

class VirtioNetFunction final : public virtio::Device {
public:
    [[nodiscard]] static auto create(const NetParams& params, const virtio::GuestMemory& memory,
                                     virtio::InterruptSink& interrupts, FrameSink& sink)
        -> std::expected<std::unique_ptr<VirtioNetFunction>, NetConfigError>;

    VirtioNetFunction(const VirtioNetFunction&) = delete;
    auto operator=(const VirtioNetFunction&) -> VirtioNetFunction& = delete;
    VirtioNetFunction(VirtioNetFunction&&) = delete;
    auto operator=(VirtioNetFunction&&) -> VirtioNetFunction& = delete;
    ~VirtioNetFunction() override = default;

    // The transport seam.
    [[nodiscard]] auto pci() noexcept -> virtio::PciFunction& { return *_pci; }

    // Hands one frame to the guest (data plane -> guest).
    auto deliver(std::span<const std::byte> frame) -> RxResult;

    // helm reassigns the NIC (detach to the dead VPC, or a new attachment).
    // Resets the function like an FLR first, so nothing from the previous
    // identity survives (Requirement 8.2).
    [[nodiscard]] auto reassign(const NicIdentity& identity) -> std::expected<void, NetConfigError>;

    [[nodiscard]] auto identity() const noexcept -> const NicIdentity& { return _identity; }
    [[nodiscard]] auto counters() const noexcept -> const NetCounters& { return _counters; }
    // Largest Ethernet frame (no virtio header) either direction accepts.
    [[nodiscard]] auto max_frame() const noexcept -> std::size_t;

    // virtio::Device
    [[nodiscard]] auto read_config(std::uint32_t offset, std::size_t width) const
        -> std::expected<std::uint64_t, virtio::AccessError> override;
    [[nodiscard]] auto write_config(std::uint32_t offset, std::size_t width, std::uint64_t value)
        -> std::expected<void, virtio::AccessError> override;
    auto queue_notified(std::uint16_t index) -> void override;
    [[nodiscard]] auto poll() -> bool override;
    auto queues_dropped() -> void override;

private:
    VirtioNetFunction(const NetParams& params, FrameSink& sink);

    // Drains up to the budget; true if TX work remains.
    auto process_tx() -> bool;
    // Copies and checks one TX chain; the frame's size in _tx_buffer after
    // the header, or nullopt if it was dropped.
    auto copy_tx(const virtio::Chain& chain) -> std::optional<std::size_t>;
    auto queue_error() -> void;

    std::unique_ptr<virtio::PciFunction> _pci;
    FrameSink* _sink;
    NicIdentity _identity;
    std::size_t _tx_budget;
    std::vector<std::byte> _tx_buffer;
    NetCounters _counters;
    bool _tx_pending{false};
};

[[nodiscard]] auto validate(const NicIdentity& identity) -> std::expected<void, NetConfigError>;

}  // namespace ak::oar::net
