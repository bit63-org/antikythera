// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the DHCPv4 codec (oar-net Requirement 12.3, task 17).
//
// The input is one client message (a UDP payload). When it parses, the
// server's reply to it is built: the reply must echo the transaction ID
// and client MAC, be at least the BOOTP minimum, carry option 53, and never
// parse as a client message itself.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/dhcp4.hpp"

namespace {

namespace d4 = ak::oar::net::dhcp4;

constexpr std::size_t xid_offset = 4;
constexpr std::size_t chaddr_offset = 28;
constexpr std::size_t options_offset = 240;
constexpr std::uint8_t opt_message_type = 53;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::byte> in{reinterpret_cast<const std::byte*>(data), size};
    const auto m = d4::parse(in);
    if (!m) {
        return 0;
    }
    const d4::Ipv4Address server{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}};
    const auto type = (size % 3 == 0)   ? d4::MessageType::offer
                      : (size % 3 == 1) ? d4::MessageType::ack
                                        : d4::MessageType::nak;
    const auto out = d4::build_reply(*m, {.type = type,
                                          .yiaddr = m->ciaddr,
                                          .server = server,
                                          .subnet_mask = server,
                                          .router = server,
                                          .dns = {server},
                                          .domain = "a.b",
                                          .mtu = 1500,
                                          .lease_seconds = 60});
    if (out.size() < d4::min_message_size || d4::parse(out).has_value()) {
        std::abort();
    }
    if (!std::equal(in.begin() + xid_offset, in.begin() + xid_offset + 4,
                    out.begin() + xid_offset) ||
        !std::equal(m->chaddr.begin(), m->chaddr.end(), out.begin() + chaddr_offset) ||
        std::to_integer<std::uint8_t>(out[options_offset]) != opt_message_type) {
        std::abort();
    }
    return 0;
}
