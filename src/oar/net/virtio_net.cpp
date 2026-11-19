// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/virtio_net.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>

#include "common/wire.hpp"

namespace ak::oar::net {

namespace {

namespace virtio = ak::oar::virtio;

constexpr std::uint8_t pci_class_network = 0x02;
constexpr std::uint8_t pci_subclass_ethernet = 0x00;
constexpr std::uint8_t pci_prog_if_none = 0x00;
constexpr std::uint16_t max_virtqueue_pairs = 1;
constexpr std::byte mac_group_bit{0x01};
constexpr std::size_t mac_source_offset = 6;  // after the destination MAC
constexpr std::size_t hdr_flags_offset = 0;
constexpr std::size_t hdr_gso_type_offset = 1;
constexpr std::size_t hdr_num_buffers_offset = 10;
constexpr unsigned bits_per_byte = 8;

constexpr std::uint64_t offered_features =
    virtio::feature_bit(virtio::feature_version_1) | virtio::feature_bit(virtio_net_f_mac) |
    virtio::feature_bit(virtio_net_f_mtu) | virtio::feature_bit(virtio_net_f_status) |
    virtio::feature_bit(virtio::feature_event_idx) |
    virtio::feature_bit(virtio::feature_indirect_desc);

// Copies `src` into a chain's writable spans, continuing where the last
// call stopped.
class ChainWriter {
public:
    explicit ChainWriter(const std::vector<std::span<std::byte>>& spans) : _spans{&spans} {}

    auto write(std::span<const std::byte> src) -> void {
        while (!src.empty() && _index < _spans->size()) {
            const std::span<std::byte> dst = (*_spans)[_index].subspan(_offset);
            const std::size_t n = std::min(dst.size(), src.size());
            std::memcpy(dst.data(), src.data(), n);
            src = src.subspan(n);
            _offset += n;
            if (_offset == (*_spans)[_index].size()) {
                ++_index;
                _offset = 0;
            }
        }
    }

private:
    const std::vector<std::span<std::byte>>* _spans;
    std::size_t _index{0};
    std::size_t _offset{0};
};

}  // namespace

auto to_string(RxResult r) noexcept -> const char* {
    switch (r) {
        case RxResult::delivered:
            return "delivered";
        case RxResult::not_ready:
            return "not_ready";
        case RxResult::no_buffer:
            return "no_buffer";
        case RxResult::buffer_too_small:
            return "buffer_too_small";
        case RxResult::frame_too_large:
            return "frame_too_large";
        case RxResult::frame_too_short:
            return "frame_too_short";
        case RxResult::queue_error:
            return "queue_error";
    }
    return "unknown";
}

auto to_string(NetConfigError e) noexcept -> const char* {
    switch (e) {
        case NetConfigError::invalid_nic_id:
            return "invalid_nic_id";
        case NetConfigError::bad_mac:
            return "bad_mac";
        case NetConfigError::bad_mtu:
            return "bad_mtu";
        case NetConfigError::bad_queue_size:
            return "bad_queue_size";
    }
    return "unknown";
}

auto validate(const NicIdentity& identity) -> std::expected<void, NetConfigError> {
    if (identity.nic_id == geneve::nic_invalid || identity.nic_id == geneve::nic_broadcast) {
        return std::unexpected(NetConfigError::invalid_nic_id);
    }
    const bool zero =
        std::ranges::all_of(identity.mac, [](std::byte b) { return b == std::byte{0}; });
    if (zero || (identity.mac[0] & mac_group_bit) != std::byte{0}) {
        return std::unexpected(NetConfigError::bad_mac);
    }
    if (identity.mtu < min_mtu) {
        return std::unexpected(NetConfigError::bad_mtu);
    }
    return {};
}

auto VirtioNetFunction::create(const NetParams& params, const virtio::GuestMemory& memory,
                               virtio::InterruptSink& interrupts, FrameSink& sink)
    -> std::expected<std::unique_ptr<VirtioNetFunction>, NetConfigError> {
    if (auto ok = validate(params.identity); !ok) {
        return std::unexpected(ok.error());
    }
    // The constructor is private, so make_unique cannot reach it.
    std::unique_ptr<VirtioNetFunction> fn{new VirtioNetFunction(params, sink)};
    auto pci = virtio::PciFunction::create(
        *fn, memory, interrupts,
        {.identity = {.device_id = static_cast<std::uint16_t>(virtio::pci_device_id_modern_base +
                                                              virtio_net_device_type),
                      .class_code = pci_class_network,
                      .subclass = pci_subclass_ethernet,
                      .prog_if = pci_prog_if_none},
         .device_features = offered_features,
         .num_queues = virtio_net_num_queues,
         .max_queue_size = params.queue_size,
         .device_config_size = net_cfg::size});
    if (!pci) {
        return std::unexpected(NetConfigError::bad_queue_size);
    }
    fn->_pci = std::move(*pci);
    return fn;
}

VirtioNetFunction::VirtioNetFunction(const NetParams& params, FrameSink& sink)
    : _sink{&sink},
      _identity{params.identity},
      _tx_budget{std::max<std::size_t>(params.tx_budget, 1)} {
    _tx_buffer.resize(virtio_net_hdr_size + max_frame());
}

auto VirtioNetFunction::max_frame() const noexcept -> std::size_t {
    return ethernet_header_size + vlan_tag_size + _identity.mtu;
}

auto VirtioNetFunction::reassign(const NicIdentity& identity)
    -> std::expected<void, NetConfigError> {
    if (auto ok = validate(identity); !ok) {
        return ok;
    }
    _pci->reset();
    _identity = identity;
    _tx_buffer.assign(virtio_net_hdr_size + max_frame(), std::byte{0});
    return {};
}

// --- Device configuration (Requirement 1.2) ------------------------------

auto VirtioNetFunction::read_config(std::uint32_t offset, std::size_t width) const
    -> std::expected<std::uint64_t, virtio::AccessError> {
    if (width != 1 && width != 2 && width != 4) {
        return std::unexpected(virtio::AccessError::bad_width);
    }
    if (offset + width > net_cfg::size) {
        return std::unexpected(virtio::AccessError::bad_offset);
    }
    std::array<std::byte, net_cfg::size> image{};
    wire::SpanWriter w{image};
    // Writes into a fixed image of exactly this size cannot fail.
    static_cast<void>(w.bytes(_identity.mac));
    static_cast<void>(w.write(std::uint16_t{virtio_net_s_link_up}, wire::Order::little));
    static_cast<void>(w.write(std::uint16_t{max_virtqueue_pairs}, wire::Order::little));
    static_cast<void>(w.write(std::uint16_t{_identity.mtu}, wire::Order::little));
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= std::uint64_t{std::to_integer<std::uint8_t>(image[offset + i])}
                 << (bits_per_byte * i);
    }
    return value;
}

auto VirtioNetFunction::write_config(std::uint32_t /*offset*/, std::size_t /*width*/,
                                     std::uint64_t /*value*/)
    -> std::expected<void, virtio::AccessError> {
    // MAC and MTU belong to helm; no writable field is offered
    // (VIRTIO_NET_F_CTRL_MAC_ADDR is not negotiated).
    return std::unexpected(virtio::AccessError::read_only);
}

// --- Queues ---------------------------------------------------------------

auto VirtioNetFunction::queue_notified(std::uint16_t index) -> void {
    if (index == virtio_net_tx_queue) {
        _tx_pending = process_tx();
    }
    // An RX kick means buffers were posted; nothing is queued waiting for
    // them, so there is nothing to do.
}

auto VirtioNetFunction::poll() -> bool {
    if (_tx_pending) {
        _tx_pending = process_tx();
    }
    return _tx_pending;
}

auto VirtioNetFunction::queues_dropped() -> void {
    _tx_pending = false;
}

auto VirtioNetFunction::queue_error() -> void {
    ++_counters.queue_errors;
    _pci->fail();
}

auto VirtioNetFunction::process_tx() -> bool {
    virtio::SplitQueue* q = _pci->queue(virtio_net_tx_queue);
    if (q == nullptr) {
        return false;
    }
    q->set_notifications(false);
    for (std::size_t done = 0;; ++done) {
        if (done == _tx_budget) {
            // Notifications stay off; the transport calls poll() for the rest.
            _pci->signal(virtio_net_tx_queue);
            return true;
        }
        auto chain = q->pop();
        if (chain && !chain->has_value()) {
            // Re-enable, then look again: a buffer posted before the driver
            // saw the change would otherwise never be noticed.
            q->set_notifications(true);
            chain = q->pop();
            if (chain && !chain->has_value()) {
                break;
            }
            q->set_notifications(false);
        }
        if (!chain) {
            queue_error();
            return false;
        }
        const std::uint16_t head = (*chain)->head;
        const std::optional<std::size_t> frame_size = copy_tx(**chain);
        // The frame is in our buffer now; the guest gets its buffer back
        // before the sink runs, which may re-enter this function.
        if (!q->push(head, 0)) {
            queue_error();
            return false;
        }
        if (frame_size) {
            ++_counters.tx_frames;
            _counters.tx_bytes += *frame_size;
            _sink->transmit({.source = _identity.nic_id,
                             .frame = std::span<const std::byte>{_tx_buffer}.subspan(
                                 virtio_net_hdr_size, *frame_size)});
            q = _pci->queue(virtio_net_tx_queue);
            if (q == nullptr) {
                return false;  // the sink's delivery reset the function
            }
        }
    }
    _pci->signal(virtio_net_tx_queue);
    return false;
}

auto VirtioNetFunction::copy_tx(const virtio::Chain& chain) -> std::optional<std::size_t> {
    if (chain.readable_bytes < virtio_net_hdr_size + ethernet_header_size) {
        ++_counters.tx_drop_short;
        return std::nullopt;
    }
    if (chain.readable_bytes > _tx_buffer.size()) {
        ++_counters.tx_drop_too_long;
        return std::nullopt;
    }
    // Copy once; every check below reads our copy, never guest memory.
    std::size_t at = 0;
    for (const auto& part : chain.readable) {
        std::memcpy(_tx_buffer.data() + at, part.data(), part.size());
        at += part.size();
    }
    // No checksum or segmentation offload was offered, so the driver must
    // send flags 0 and GSO_NONE (spec 5.1.6.2).
    if (_tx_buffer[hdr_flags_offset] != std::byte{0} ||
        _tx_buffer[hdr_gso_type_offset] != std::byte{0}) {
        ++_counters.tx_drop_bad_header;
        return std::nullopt;
    }
    const std::span<const std::byte> frame = std::span<const std::byte>{_tx_buffer}.subspan(
        virtio_net_hdr_size, at - virtio_net_hdr_size);
    if (!std::ranges::equal(frame.subspan(mac_source_offset, _identity.mac.size()),
                            _identity.mac)) {
        ++_counters.tx_drop_spoofed;
        return std::nullopt;
    }
    return frame.size();
}

auto VirtioNetFunction::deliver(std::span<const std::byte> frame) -> RxResult {
    if (frame.size() < ethernet_header_size) {
        ++_counters.rx_drop_bad_frame;
        return RxResult::frame_too_short;
    }
    if (frame.size() > max_frame()) {
        ++_counters.rx_drop_bad_frame;
        return RxResult::frame_too_large;
    }
    virtio::SplitQueue* q = _pci->queue(virtio_net_rx_queue);
    if (q == nullptr) {
        ++_counters.rx_drop_not_ready;
        return RxResult::not_ready;
    }
    auto chain = q->pop();
    if (!chain) {
        queue_error();
        return RxResult::queue_error;
    }
    if (!chain->has_value()) {
        ++_counters.rx_drop_no_buffer;
        return RxResult::no_buffer;
    }
    const virtio::Chain& c = **chain;
    const std::size_t total = virtio_net_hdr_size + frame.size();
    std::uint32_t written = 0;
    RxResult result = RxResult::buffer_too_small;
    if (c.writable_bytes >= total) {
        std::array<std::byte, virtio_net_hdr_size> header{};
        header[hdr_num_buffers_offset] = std::byte{1};  // le16 1: one buffer
        ChainWriter out{c.writable};
        out.write(header);
        out.write(frame);
        written = static_cast<std::uint32_t>(total);
        result = RxResult::delivered;
    }
    // A buffer too small goes back empty; the driver counts a length error
    // and reposts it.
    if (!q->push(c.head, written)) {
        queue_error();
        return RxResult::queue_error;
    }
    _pci->signal(virtio_net_rx_queue);
    if (result == RxResult::delivered) {
        ++_counters.rx_frames;
        _counters.rx_bytes += frame.size();
    } else {
        ++_counters.rx_drop_buffer_too_small;
    }
    return result;
}

}  // namespace ak::oar::net
