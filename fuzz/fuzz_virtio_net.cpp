// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes VirtioNetFunction as a hostile guest would drive it: the fuzzer
// owns guest RAM (both rings, descriptors, TX frames and headers) and a
// script of BAR accesses, kicks, deliveries, polls and resets. Checks that
// every frame reaching the data plane carries the function's NIC ID, the
// assigned source MAC and a legal length (Requirement 2.1, 2.3, 3.4).

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

#include "oar/net/virtio_net.hpp"
#include "oar/virtio/function.hpp"
#include "oar/virtio/guest_memory.hpp"

namespace {

namespace net = ak::oar::net;
namespace virtio = ak::oar::virtio;
namespace cc = virtio::common_cfg;

constexpr virtio::Gpa ram_base = 0x1000;
constexpr std::size_t ram_size = 0x4000;
constexpr std::uint16_t queue_size = 8;
// Driver-written areas first so short inputs reach them.
constexpr virtio::Gpa rx_avail = ram_base;
constexpr virtio::Gpa tx_avail = ram_base + 0x40;
constexpr virtio::Gpa rx_desc = ram_base + 0x80;
constexpr virtio::Gpa tx_desc = ram_base + 0x100;
constexpr virtio::Gpa rx_used = ram_base + 0x3000;
constexpr virtio::Gpa tx_used = ram_base + 0x3100;
constexpr std::uint64_t nic_value = 0x00AB'CDEF'0123'4567ULL;
constexpr std::uint16_t mtu = 1500;
constexpr std::size_t header_bytes = 2;
constexpr std::size_t ram_image_max = 0x3000;  // not the used rings
constexpr std::size_t max_ops = 256;
constexpr std::uint8_t mode_event_idx = 0x01;
constexpr std::uint8_t mode_indirect = 0x02;
constexpr std::size_t width8 = 1;
constexpr std::size_t width16 = 2;
constexpr std::size_t width32 = 4;
constexpr std::size_t width64 = 8;
constexpr std::array<std::size_t, 4> widths{width8, width16, width32, width64};

const net::MacAddress nic_mac{std::byte{0x02}, std::byte{0x11}, std::byte{0x22},
                              std::byte{0x33}, std::byte{0x44}, std::byte{0x55}};

class NullInterrupts final : public virtio::InterruptSink {
public:
    auto raise(std::uint16_t /*vector*/) -> void override {}
};

class CheckingSink final : public net::FrameSink {
public:
    explicit CheckingSink(std::size_t max_frame) : _max_frame{max_frame} {}
    auto transmit(const net::TxFrame& f) -> void override {
        if (f.source.value != nic_value || f.frame.size() < net::ethernet_header_size ||
            f.frame.size() > _max_frame ||
            !std::ranges::equal(f.frame.subspan(6, nic_mac.size()), nic_mac)) {
            std::abort();
        }
    }

private:
    std::size_t _max_frame;
};

class Input {
public:
    explicit Input(std::span<const std::uint8_t> d) : _d{d} {}
    [[nodiscard]] auto empty() const -> bool { return _d.empty(); }
    auto u8() -> std::uint8_t {
        if (_d.empty()) {
            return 0;
        }
        const std::uint8_t v = _d[0];
        _d = _d.subspan(1);
        return v;
    }
    auto u16() -> std::uint16_t {
        return static_cast<std::uint16_t>(u8() | (static_cast<unsigned>(u8()) << 8U));
    }
    auto u32() -> std::uint32_t { return u16() | (static_cast<std::uint32_t>(u16()) << 16U); }

private:
    std::span<const std::uint8_t> _d;
};

auto bring_up(virtio::PciFunction& fn, std::uint64_t features) -> void {
    auto w = [&](std::uint32_t off, std::size_t width, std::uint64_t v) {
        static_cast<void>(fn.bar_write(virtio::bar_layout::common_offset + off, width, v));
    };
    const std::uint8_t s = virtio::status_acknowledge | virtio::status_driver;
    w(cc::device_status, width8, 0);
    w(cc::device_status, width8, virtio::status_acknowledge);
    w(cc::device_status, width8, s);
    w(cc::driver_feature_select, width32, 0);
    w(cc::driver_feature, width32, features & 0xFFFF'FFFFU);
    w(cc::driver_feature_select, width32, 1);
    w(cc::driver_feature, width32, features >> 32U);
    w(cc::device_status, width8, s | virtio::status_features_ok);
    const std::array<std::array<virtio::Gpa, 3>, 2> rings{
        {{rx_desc, rx_avail, rx_used}, {tx_desc, tx_avail, tx_used}}};
    for (std::uint16_t q = 0; q < rings.size(); ++q) {
        w(cc::queue_select, width16, q);
        w(cc::queue_size, width16, queue_size);
        w(cc::queue_msix_vector, width16, q);
        w(cc::queue_desc, width64, rings[q][0]);
        w(cc::queue_driver, width64, rings[q][1]);
        w(cc::queue_device, width64, rings[q][2]);
        w(cc::queue_enable, width16, 1);
    }
    w(cc::device_status, width8, s | virtio::status_features_ok | virtio::status_driver_ok);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < header_bytes) {
        return 0;
    }
    const std::uint8_t mode = data[0];
    const std::size_t image = std::min<std::size_t>(data[1] * 0x40U, ram_image_max);
    Input in{std::span{data, size}.subspan(header_bytes)};

    std::vector<std::byte> ram(ram_size);
    for (std::size_t i = 0; i < image && !in.empty(); ++i) {
        ram[i] = static_cast<std::byte>(in.u8());
    }
    virtio::GuestMemory memory;
    if (!memory.add_region(ram_base, ram)) {
        std::abort();
    }
    NullInterrupts irq;
    const net::NicIdentity id{.nic_id = net::geneve::NicId{nic_value}, .mac = nic_mac, .mtu = mtu};
    CheckingSink sink{net::ethernet_header_size + net::vlan_tag_size + mtu};
    auto fn = net::VirtioNetFunction::create(
        {.identity = id, .queue_size = queue_size, .tx_budget = 4}, memory, irq, sink);
    if (!fn) {
        std::abort();
    }
    std::uint64_t features = virtio::feature_bit(virtio::feature_version_1) |
                             virtio::feature_bit(net::virtio_net_f_mac) |
                             virtio::feature_bit(net::virtio_net_f_mtu);
    if ((mode & mode_event_idx) != 0) {
        features |= virtio::feature_bit(virtio::feature_event_idx);
    }
    if ((mode & mode_indirect) != 0) {
        features |= virtio::feature_bit(virtio::feature_indirect_desc);
    }
    virtio::PciFunction& pci = (*fn)->pci();
    bring_up(pci, features);

    std::vector<std::byte> frame;
    for (std::size_t op = 0; op < max_ops && !in.empty(); ++op) {
        switch (in.u8() % 8) {
            case 0:
                static_cast<void>(pci.bar_write(
                    virtio::bar_layout::notify_offset +
                        (net::virtio_net_tx_queue * virtio::bar_layout::notify_off_multiplier),
                    width16, net::virtio_net_tx_queue));
                break;
            case 1: {
                frame.assign(in.u16() % 0x800U, std::byte{0x5A});
                static_cast<void>((*fn)->deliver(frame));
                break;
            }
            case 2: {
                const std::uint32_t off = in.u16() % virtio::bar_layout::bar_size;
                static_cast<void>(pci.bar_read(off, widths[in.u8() % widths.size()]));
                break;
            }
            case 3: {
                const std::uint32_t off = in.u16() % virtio::bar_layout::bar_size;
                const std::size_t width = widths[in.u8() % widths.size()];
                std::uint64_t v = in.u32();
                if (width < width64) {
                    v &= (std::uint64_t{1} << (width * 8U)) - 1U;
                }
                static_cast<void>(pci.bar_write(off, width, v));
                break;
            }
            case 4:
                static_cast<void>(pci.poll());
                break;
            case 5:
                pci.reset();
                break;
            case 6:
                bring_up(pci, features);
                break;
            default: {
                // The guest rewrites a byte of its own RAM mid-run.
                const std::size_t at = in.u16() % ram_image_max;
                ram[at] = static_cast<std::byte>(in.u8());
                break;
            }
        }
    }
    return 0;
}
