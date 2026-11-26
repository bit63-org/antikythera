// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the MapUpdate decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical) and its entries must satisfy
// the invariants oar-net's MappingTable and ARP/ND proxy rely on. Version 4
// flags and subnet IDs ride along in the re-encode check: a flag bit the
// decoder accepted but the encoder dropped, or a subnet ID read from the
// wrong offset, changes the bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/map_update.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto m = ak::proto::decode_map_update(bytes);
    if (!m) {
        return 0;
    }
    auto again = ak::proto::encode_map_update(*m);
    if (!again || !std::ranges::equal(*again, bytes) ||
        m->entries.size() > ak::proto::max_map_entries ||
        !std::ranges::is_sorted(m->entries, std::ranges::less{}, &ak::proto::MapEntry::nic_id) ||
        std::ranges::adjacent_find(m->entries, std::ranges::equal_to{},
                                   &ak::proto::MapEntry::nic_id) != m->entries.end() ||
        m->ipv4.size() > ak::proto::max_guest_addresses ||
        m->ipv6.size() > ak::proto::max_guest_addresses ||
        std::ranges::adjacent_find(m->ipv4, std::ranges::equal_to{},
                                   &ak::proto::GuestIpv4::address) != m->ipv4.end() ||
        std::ranges::adjacent_find(m->ipv6, std::ranges::equal_to{},
                                   &ak::proto::GuestIpv6::address) != m->ipv6.end()) {
        std::abort();
    }
    return 0;
}
