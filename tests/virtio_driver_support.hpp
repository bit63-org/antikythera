// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Plays a virtio driver against a PciFunction through its BAR only, the way
// a guest would: owns guest RAM, negotiates features, lays out split rings
// at fixed guest addresses and posts buffers. Shared by the virtio function
// and virtio-net tests.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <vector>

#include "oar/virtio/function.hpp"
#include "oar/virtio/guest_memory.hpp"
#include "oar/virtio/pci.hpp"
#include "oar/virtio/split_queue.hpp"

namespace ak::test {

namespace vio = ak::oar::virtio;

inline constexpr vio::Gpa guest_ram_base = 0x10'0000;
inline constexpr std::size_t guest_ram_size = 0x4'0000;
// Queue N's rings and buffers live in their own 64 KiB window.
inline constexpr vio::Gpa queue_window = 0x1'0000;
inline constexpr vio::Gpa desc_offset = 0x0000;
inline constexpr vio::Gpa avail_offset = 0x1000;
inline constexpr vio::Gpa used_offset = 0x2000;
inline constexpr vio::Gpa data_offset = 0x4000;
inline constexpr std::uint16_t test_queue_size = 8;
inline constexpr std::size_t ring_header = 4;  // flags + idx
inline constexpr std::size_t used_elem_size = 8;
inline constexpr std::size_t width8 = 1;
inline constexpr std::size_t width16 = 2;
inline constexpr std::size_t width32 = 4;
inline constexpr std::size_t width64 = 8;

class GuestRam {
public:
    GuestRam() : _bytes(guest_ram_size) {
        static_cast<void>(_memory.add_region(guest_ram_base, _bytes));
    }
    GuestRam(const GuestRam&) = delete;
    auto operator=(const GuestRam&) -> GuestRam& = delete;
    GuestRam(GuestRam&&) = delete;
    auto operator=(GuestRam&&) -> GuestRam& = delete;
    ~GuestRam() = default;

    [[nodiscard]] auto memory() -> vio::GuestMemory& { return _memory; }

    template<typename T> auto put(vio::Gpa gpa, T v) -> void {
        std::memcpy(at(gpa), &v, sizeof v);  // little-endian host
    }
    template<typename T> [[nodiscard]] auto get(vio::Gpa gpa) const -> T {
        T v{};
        std::memcpy(&v, _bytes.data() + (gpa - guest_ram_base), sizeof v);
        return v;
    }
    auto put_bytes(vio::Gpa gpa, std::span<const std::byte> b) -> void {
        std::memcpy(at(gpa), b.data(), b.size());
    }
    [[nodiscard]] auto bytes(vio::Gpa gpa, std::size_t n) const -> std::vector<std::byte> {
        const auto* p = _bytes.data() + (gpa - guest_ram_base);
        return {p, p + n};
    }

private:
    auto at(vio::Gpa gpa) -> std::byte* { return _bytes.data() + (gpa - guest_ram_base); }

    std::vector<std::byte> _bytes;
    vio::GuestMemory _memory;
};

class RecordingInterrupts final : public vio::InterruptSink {
public:
    auto raise(std::uint16_t vector) -> void override { raised.push_back(vector); }
    std::vector<std::uint16_t> raised;
};

struct Buffer {
    std::uint32_t len{0};
    bool writable{false};
};

class VirtioDriver {
public:
    VirtioDriver(GuestRam& ram, vio::PciFunction& fn) : _ram{&ram}, _fn{&fn} {}

    [[nodiscard]] static auto desc_gpa(std::uint16_t q) -> vio::Gpa {
        return guest_ram_base + (queue_window * q) + desc_offset;
    }
    [[nodiscard]] static auto avail_gpa(std::uint16_t q) -> vio::Gpa {
        return guest_ram_base + (queue_window * q) + avail_offset;
    }
    [[nodiscard]] static auto used_gpa(std::uint16_t q) -> vio::Gpa {
        return guest_ram_base + (queue_window * q) + used_offset;
    }
    [[nodiscard]] static auto data_gpa(std::uint16_t q) -> vio::Gpa {
        return guest_ram_base + (queue_window * q) + data_offset;
    }

    auto common_write(std::uint32_t off, std::size_t width, std::uint64_t v)
        -> std::expected<void, vio::AccessError> {
        return _fn->bar_write(vio::bar_layout::common_offset + off, width, v);
    }
    [[nodiscard]] auto common_read(std::uint32_t off, std::size_t width)
        -> std::expected<std::uint64_t, vio::AccessError> {
        return _fn->bar_read(vio::bar_layout::common_offset + off, width);
    }

    // Full init sequence (spec 3.1.1). Queues in `enable` get rings in their
    // window and MSI-X vector == queue index; config changes use vector
    // `num_queues`. Returns whether every step was accepted.
    auto bring_up(std::uint64_t features, const std::vector<std::uint16_t>& enable,
                  std::uint16_t size = test_queue_size) -> bool {
        namespace cc = vio::common_cfg;
        bool ok = common_write(cc::device_status, width8, 0).has_value();
        ok = ok && common_write(cc::device_status, width8, vio::status_acknowledge).has_value();
        _status = vio::status_acknowledge | vio::status_driver;
        ok = ok && common_write(cc::device_status, width8, _status).has_value();
        for (std::uint32_t word = 0; word < 2; ++word) {
            ok = ok && common_write(cc::driver_feature_select, width32, word).has_value();
            ok = ok && common_write(cc::driver_feature, width32,
                                    (features >> (32U * word)) & 0xFFFF'FFFFU)
                           .has_value();
        }
        _status |= vio::status_features_ok;
        ok = ok && common_write(cc::device_status, width8, _status).has_value();
        const auto num = common_read(cc::num_queues, width16);
        ok = ok && num.has_value();
        if (ok) {
            ok = common_write(cc::config_msix_vector, width16, *num).has_value();
        }
        for (const std::uint16_t q : enable) {
            ok = ok && common_write(cc::queue_select, width16, q).has_value();
            ok = ok && common_write(cc::queue_size, width16, size).has_value();
            ok = ok && common_write(cc::queue_msix_vector, width16, q).has_value();
            ok = ok && common_write(cc::queue_desc, width64, desc_gpa(q)).has_value();
            ok = ok && common_write(cc::queue_driver, width64, avail_gpa(q)).has_value();
            ok = ok && common_write(cc::queue_device, width64, used_gpa(q)).has_value();
            ok = ok && common_write(cc::queue_enable, width16, 1).has_value();
            _sizes.resize(std::max<std::size_t>(_sizes.size(), q + 1U), 0);
            _avail.resize(_sizes.size(), 0);
            _next_desc.resize(_sizes.size(), 0);
            _next_data.resize(_sizes.size(), 0);
            // A fresh driver starts from zeroed rings.
            _ram->put<std::uint32_t>(avail_gpa(q), 0);
            _ram->put<std::uint32_t>(used_gpa(q), 0);
            _sizes[q] = size;
            _avail[q] = 0;
            _next_desc[q] = 0;
            _next_data[q] = 0;
        }
        _status |= vio::status_driver_ok;
        ok = ok && common_write(cc::device_status, width8, _status).has_value();
        return ok;
    }

    // Posts one chain of fresh buffers; returns the head and the guest
    // address of each buffer in `gpas`.
    auto post(std::uint16_t q, const std::vector<Buffer>& bufs,
              std::vector<vio::Gpa>* gpas = nullptr) -> std::uint16_t {
        const std::uint16_t head = _next_desc[q];
        for (std::size_t i = 0; i < bufs.size(); ++i) {
            const auto idx = static_cast<std::uint16_t>((head + i) % _sizes[q]);
            if (_next_data[q] + bufs[i].len > queue_window - data_offset) {
                _next_data[q] = 0;  // wrap; earlier buffers are long consumed
            }
            const vio::Gpa addr = data_gpa(q) + _next_data[q];
            _next_data[q] = (_next_data[q] + bufs[i].len + 0xF) & ~vio::Gpa{0xF};
            const bool last = i + 1 == bufs.size();
            std::uint16_t flags = bufs[i].writable ? vio::desc_f_write : 0;
            if (!last) {
                flags |= vio::desc_f_next;
            }
            put_desc(q, idx, addr, bufs[i].len, flags,
                     static_cast<std::uint16_t>((idx + 1) % _sizes[q]));
            if (gpas != nullptr) {
                gpas->push_back(addr);
            }
        }
        _next_desc[q] = static_cast<std::uint16_t>((head + bufs.size()) % _sizes[q]);
        publish(q, head);
        return head;
    }

    auto put_desc(std::uint16_t q, std::uint16_t idx, vio::Gpa addr, std::uint32_t len,
                  std::uint16_t flags, std::uint16_t next) -> void {
        const vio::Gpa d = desc_gpa(q) + (vio::descriptor_size * idx);
        _ram->put<std::uint64_t>(d, addr);
        _ram->put<std::uint32_t>(d + 8, len);
        _ram->put<std::uint16_t>(d + 12, flags);
        _ram->put<std::uint16_t>(d + 14, next);
    }

    auto publish(std::uint16_t q, std::uint16_t head) -> void {
        _ram->put<std::uint16_t>(avail_gpa(q) + ring_header + (2U * (_avail[q] % _sizes[q])), head);
        ++_avail[q];
        _ram->put<std::uint16_t>(avail_gpa(q) + 2, _avail[q]);
    }

    auto notify(std::uint16_t q) -> std::expected<void, vio::AccessError> {
        return _fn->bar_write(
            vio::bar_layout::notify_offset + (q * vio::bar_layout::notify_off_multiplier), width16,
            q);
    }

    [[nodiscard]] auto used_idx(std::uint16_t q) const -> std::uint16_t {
        return _ram->get<std::uint16_t>(used_gpa(q) + 2);
    }
    [[nodiscard]] auto used_id(std::uint16_t q, std::uint16_t slot) const -> std::uint32_t {
        return _ram->get<std::uint32_t>(used_gpa(q) + ring_header + (used_elem_size * slot));
    }
    [[nodiscard]] auto used_len(std::uint16_t q, std::uint16_t slot) const -> std::uint32_t {
        return _ram->get<std::uint32_t>(used_gpa(q) + ring_header + (used_elem_size * slot) + 4);
    }

private:
    GuestRam* _ram;
    vio::PciFunction* _fn;
    std::uint8_t _status{0};
    std::vector<std::uint16_t> _sizes;
    std::vector<std::uint16_t> _avail;
    std::vector<std::uint16_t> _next_desc;
    std::vector<vio::Gpa> _next_data;
};

}  // namespace ak::test
