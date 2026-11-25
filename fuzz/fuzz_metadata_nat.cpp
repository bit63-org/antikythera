// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the metadata service's address translation
// (.kiro/specs/oar-net-data-plane/ Requirements 13.3 and 13.5): guests
// build the packets to_kernel reads, and the kernel's replies to an alias
// go through to_guest. A translated packet is never longer than its input,
// keeps its source or destination on the metadata address, and comes back
// to the NIC it went out from.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <utility>

#include "oar/net/metadata_nat.hpp"
#include "oar/net/vswitch.hpp"

namespace net = ak::oar::net;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto raw = std::as_bytes(std::span{data, size});
    net::AliasTable aliases;
    const auto now = net::AliasTable::Clock::time_point{} + std::chrono::hours{1};
    const net::geneve::NicId nic{7};

    const auto out = net::to_kernel(nic, raw, aliases, now);
    if (out) {
        if (out->size() > size || aliases.size() != 1) {
            std::abort();
        }
        // The kernel's echo of it (addresses and ports swapped) comes back
        // to the same NIC, with the guest's address restored.
        auto echo = *out;
        const bool v6 = (std::to_integer<unsigned>(echo[0]) >> 4U) == 6;
        const std::size_t src = v6 ? 8 : 12;
        const std::size_t len = v6 ? 16 : 4;
        const std::size_t tcp = v6 ? 40 : (std::to_integer<std::size_t>(echo[0]) & 0x0FU) * 4U;
        for (std::size_t i = 0; i < len; ++i) {
            std::swap(echo[src + i], echo[src + len + i]);
        }
        std::swap(echo[tcp], echo[tcp + 2]);
        std::swap(echo[tcp + 1], echo[tcp + 3]);
        const auto back = net::to_guest(echo, aliases);
        if (!back || back->nic != nic || back->packet.size() != echo.size() ||
            !std::equal(raw.begin() + static_cast<std::ptrdiff_t>(src),
                        raw.begin() + static_cast<std::ptrdiff_t>(src + len),
                        back->packet.begin() + static_cast<std::ptrdiff_t>(src + len))) {
            std::abort();
        }
    }
    (void)net::to_guest(raw, aliases);
    return 0;
}
