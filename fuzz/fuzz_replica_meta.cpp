// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes a hold replica's `meta` decoders (.kiro/specs/block-volume-
// service/ task 5), which read back a disk an attacker with the storage
// board may have written. The first byte picks a decoder:
//
//   0  decode_replica_meta: an accepted slot re-encodes to identical bytes
//      and its layout fits inside the largest volume's meta file;
//   1  decode_meta_slots: the result is one of the two slots, the newest
//      that decodes;
//   2  decode_intent: an accepted entry re-encodes to identical bytes and
//      lies inside the capacity it was checked against.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "hold/store/replica_meta.hpp"

namespace store = ak::hold::store;

namespace {

auto check_slot(std::span<const std::byte> bytes) -> void {
    const auto m = store::decode_replica_meta(bytes);
    if (!m) {
        return;
    }
    const auto again = store::encode_replica_meta(*m);
    const auto l = store::layout(*m);
    if (!again || !std::ranges::equal(*again, bytes) || l.chunks == 0 ||
        l.end > (std::uint64_t{1} << 40U) || l.checksums >= l.unhydrated ||
        l.unhydrated >= l.changed || l.changed >= l.intents || l.intents >= l.end) {
        std::abort();
    }
}

auto check_slots(std::span<const std::byte> bytes) -> void {
    const auto m = store::decode_meta_slots(bytes);
    if (!m) {
        return;
    }
    const auto a = store::decode_replica_meta(bytes.first(store::meta_slot_size));
    const auto b =
        store::decode_replica_meta(bytes.subspan(store::meta_slot_size, store::meta_slot_size));
    const bool from_a = a && *a == *m && (!b || a->header_seq >= b->header_seq);
    const bool from_b = b && *b == *m && (!a || b->header_seq >= a->header_seq);
    if (!from_a && !from_b) {
        std::abort();
    }
}

auto check_intent(std::span<const std::byte> bytes) -> void {
    if (bytes.size() < 8) {
        return;
    }
    std::uint64_t capacity = 0;
    for (std::size_t k = 0; k < 8; ++k) {
        capacity |= std::to_integer<std::uint64_t>(bytes[k]) << (8U * k);
    }
    capacity %= store::max_capacity_blocks + 1;
    const auto entry = bytes.subspan(8);
    const auto i = store::decode_intent(entry, capacity);
    if (!i) {
        return;
    }
    if (!std::ranges::equal(store::encode_intent(*i), entry) || i->seq == 0 || i->blocks == 0 ||
        i->lba >= capacity || i->blocks > capacity - i->lba) {
        std::abort();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::span bytes{reinterpret_cast<const std::byte*>(data) + 1, size - 1};
    switch (data[0] % 3) {
        case 0:
            check_slot(bytes);
            break;
        case 1:
            check_slots(bytes);
            break;
        default:
            check_intent(bytes);
            break;
    }
    return 0;
}
