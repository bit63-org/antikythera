// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the L3/L4 packet parser (oar-net Requirement 11.2, task 15).
//
// The input is one Ethernet frame. When it parses, every view the parser
// returns must lie inside the one before it (frame > IP packet > L4 data >
// payload), an L4 header only appears in an unfragmented packet or a first
// fragment, and addresses of the other family stay zero.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/packet.hpp"

namespace {

namespace pk = ak::oar::net::packet;

auto inside(std::span<const std::byte> inner, std::span<const std::byte> outer) -> bool {
    if (inner.empty()) {
        return true;
    }
    return inner.data() >= outer.data() &&
           inner.data() + inner.size() <= outer.data() + outer.size();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::byte> frame{reinterpret_cast<const std::byte*>(data), size};
    const auto p = pk::parse(frame);
    if (!p) {
        return 0;
    }
    if (!inside(p->ip, frame) || !inside(p->l4_data, p->ip) || !inside(p->payload, p->l4_data)) {
        std::abort();
    }
    if (p->l4.has_value() != !p->l4_data.empty()) {
        std::abort();
    }
    if (p->l4 && !p->first_fragment) {
        std::abort();
    }
    if (p->family == pk::IpFamily::ipv4) {
        if (!pk::is_unspecified(p->src6) || !pk::is_unspecified(p->dst6) ||
            p->ip.size() < pk::ipv4_min_header_size) {
            std::abort();
        }
    } else if (!pk::is_unspecified(p->src4) || !pk::is_unspecified(p->dst4) ||
               p->ip.size() < pk::ipv6_header_size) {
        std::abort();
    }
    return 0;
}
