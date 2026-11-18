// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the split virtqueue with a guest RAM image the fuzzer controls
// (rings, descriptors, indirect tables). Checks that every buffer handed
// to the device lies inside guest RAM and that push() bookkeeping holds.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

#include "oar/virtio/guest_memory.hpp"
#include "oar/virtio/split_queue.hpp"

namespace {

namespace virtio = ak::oar::virtio;

constexpr virtio::Gpa ram_base = 0x1000;
constexpr std::size_t ram_size = 0x4000;
// Driver-written areas first so short inputs reach them; the used ring,
// which only the device writes, goes last.
constexpr virtio::Gpa avail_gpa = ram_base;          // up to 6 + 2 * 128
constexpr virtio::Gpa desc_gpa = ram_base + 0x110;   // up to 128 * 16 = 0x800
constexpr virtio::Gpa used_gpa = ram_base + 0x3000;  // up to 6 + 8 * 128
constexpr std::size_t header_bytes = 2;
constexpr unsigned size_shift_mask = 0x07;  // queue size 1..128
constexpr std::uint8_t flag_event_idx = 0x08;
constexpr std::uint8_t flag_indirect = 0x10;
constexpr std::uint8_t flag_notify_off = 0x20;
constexpr unsigned pops_per_entry = 4;
constexpr std::uint64_t max_written = 1500;  // one Ethernet frame

auto inside(std::span<const std::byte> s, const std::vector<std::byte>& ram) -> bool {
    const auto* lo = ram.data();
    const auto* hi = ram.data() + ram.size();
    return s.empty() || (s.data() >= lo && s.data() + s.size() <= hi);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < header_bytes) {
        return 0;
    }
    const std::uint8_t mode = data[0];
    const std::uint8_t keep_mask = data[1];  // which pops are pushed straight back

    std::vector<std::byte> ram(ram_size);
    std::memcpy(ram.data(), data + header_bytes, std::min(size - header_bytes, ram_size));
    virtio::GuestMemory memory;
    if (!memory.add_region(ram_base, ram)) {
        std::abort();
    }

    const auto qsize = static_cast<std::uint16_t>(1U << (mode & size_shift_mask));
    auto q = virtio::SplitQueue::create(memory, {.size = qsize,
                                                 .desc = desc_gpa,
                                                 .driver = avail_gpa,
                                                 .device = used_gpa,
                                                 .event_idx = (mode & flag_event_idx) != 0,
                                                 .indirect_desc = (mode & flag_indirect) != 0});
    if (!q) {
        std::abort();  // the fixed layout is valid for every size
    }
    q->set_notifications((mode & flag_notify_off) == 0);

    std::vector<std::uint16_t> held;
    for (unsigned i = 0; i < pops_per_entry * qsize; ++i) {
        auto r = q->pop();
        if (!r) {
            if (!q->broken()) {
                std::abort();  // every pop error latches
            }
            break;
        }
        if (!r->has_value()) {
            break;
        }
        const virtio::Chain& c = **r;
        std::uint64_t readable = 0;
        std::uint64_t writable = 0;
        for (auto s : c.readable) {
            if (!inside(s, ram)) {
                std::abort();
            }
            readable += s.size();
        }
        for (auto s : c.writable) {
            if (!inside(s, ram)) {
                std::abort();
            }
            writable += s.size();
        }
        if (c.head >= qsize || readable != c.readable_bytes || writable != c.writable_bytes) {
            std::abort();
        }
        if (((keep_mask >> (i % 8)) & 1U) != 0) {
            held.push_back(c.head);
            continue;
        }
        const auto written = static_cast<std::uint32_t>(std::min(writable, max_written));
        if (!q->push(c.head, written) || q->push(c.head, 0)) {
            std::abort();  // a fresh head must push once, and only once
        }
    }
    if (!q->broken()) {
        if (q->in_flight() != held.size()) {
            std::abort();
        }
        for (auto head : held) {
            if (!q->push(head, 0)) {
                std::abort();
            }
        }
    }
    (void)q->needs_interrupt();
    return 0;
}
