// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the IGMP/MLD snooping reader on guest frames: it must never read
// past the frame, and every join or leave it returns must name a group
// oar-net replicates.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/igmp.hpp"
#include "oar/net/packet.hpp"

namespace igmp = ak::oar::net::igmp;
namespace pk = ak::oar::net::packet;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    const auto p = pk::parse(bytes);
    if (!p) {
        return 0;
    }
    const auto kind = igmp::classify(*p);
    if (!kind || *kind != igmp::Kind::report) {
        return 0;
    }
    const auto changes = igmp::parse_report(*p);
    if (!changes) {
        return 0;
    }
    for (const auto& c : *changes) {
        if (!igmp::replicable(c.group)) {
            std::abort();
        }
    }
    return 0;
}
