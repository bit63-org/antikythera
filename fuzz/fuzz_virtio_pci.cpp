// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the virtio common configuration with arbitrary driver register
// accesses, and checks the device-side invariants after each one.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "oar/virtio/pci.hpp"

namespace {

namespace virtio = ak::oar::virtio;

constexpr std::uint16_t num_queues = 3;
constexpr std::uint16_t max_size = 256;
constexpr std::uint64_t offered = virtio::feature_bit(virtio::feature_version_1) |
                                  virtio::feature_bit(virtio::feature_event_idx) |
                                  virtio::feature_bit(virtio::feature_indirect_desc) |
                                  virtio::feature_bit(virtio::feature_access_platform) | 0x3F;
constexpr std::size_t op_bytes = 11;  // kind, offset, width, value (8)
constexpr std::uint8_t offset_mask = 0x3F;
constexpr unsigned width_shift_mask = 0x03;
constexpr std::uint8_t kind_write = 0x01;
constexpr std::uint8_t kind_needs_reset = 0x80;
constexpr unsigned bits_per_byte = 8;

auto check(const virtio::CommonConfig& c) -> void {
    const std::uint8_t status = c.status();
    if ((status & virtio::status_features_ok) != 0) {
        const std::uint64_t f = c.negotiated_features();
        if ((f & ~offered) != 0 || (f & virtio::feature_bit(virtio::feature_version_1)) == 0) {
            std::abort();
        }
    }
    if ((status & virtio::status_driver_ok) != 0 && (status & virtio::status_features_ok) == 0) {
        std::abort();
    }
    for (std::uint16_t i = 0; i < num_queues; ++i) {
        if (auto q = c.queue(i)) {
            if (q->size == 0 || q->size > max_size || !std::has_single_bit(q->size)) {
                std::abort();
            }
        }
    }
    if (c.queue(num_queues)) {
        std::abort();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto c = virtio::CommonConfig::create(
        {.device_features = offered, .num_queues = num_queues, .max_queue_size = max_size});
    if (!c) {
        std::abort();
    }
    for (std::size_t at = 0; at + op_bytes <= size; at += op_bytes) {
        const std::uint8_t kind = data[at];
        const std::uint32_t offset = data[at + 1] & offset_mask;
        const std::size_t width = std::size_t{1} << (data[at + 2] & width_shift_mask);
        std::uint64_t value = 0;
        std::memcpy(&value, data + at + 3, sizeof value);
        if (width < sizeof value) {
            value &= (std::uint64_t{1} << (width * bits_per_byte)) - 1;
        }
        if ((kind & kind_needs_reset) != 0) {
            c->set_needs_reset();
        }
        if ((kind & kind_write) != 0) {
            (void)c->write(offset, width, value);
        } else {
            auto r = c->read(offset, width);
            if (r && width < sizeof value && (*r >> (width * bits_per_byte)) != 0) {
                std::abort();  // a read never returns more than its width
            }
        }
        check(*c);
        (void)c->take_reset();
    }
    return 0;
}
