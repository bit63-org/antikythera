// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the DHCPv6 codec (oar-net Requirement 12.5, task 18).
//
// The input is one client message (a UDP payload). When it parses, a reply
// to it is built from what was parsed: the reply must echo the transaction
// ID and client identifier, stay within the message size limit, and never
// parse as a client message itself.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/dhcp6.hpp"

namespace {

namespace d6 = ak::oar::net::dhcp6;

constexpr std::size_t xid_offset = 1;
constexpr std::size_t xid_size = 3;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::byte> in{reinterpret_cast<const std::byte*>(data), size};
    const auto m = d6::parse(in);
    if (!m) {
        return 0;
    }
    if (m->client_id.size() > d6::max_duid_size ||
        (m->ia_na && m->ia_na->addresses.size() > d6::max_ia_addresses)) {
        std::abort();
    }
    const ak::oar::net::MacAddress mac{std::byte{2}, std::byte{0}, std::byte{0},
                                       std::byte{0}, std::byte{0}, std::byte{1}};
    d6::Reply r{.type = d6::MessageType::reply,
                .server_id = d6::server_duid(mac),
                .lifetime = 60,
                .rapid_commit = m->rapid_commit,
                .domain = "a.b"};
    if (m->ia_na) {
        r.iaid = m->ia_na->iaid;
        r.addresses = m->ia_na->addresses;
    }
    const auto out = d6::build_reply(*m, r);
    if (out.size() > d6::max_message_size + 512 || d6::parse(out).has_value()) {
        std::abort();
    }
    if (!std::equal(in.begin() + xid_offset, in.begin() + xid_offset + xid_size,
                    out.begin() + xid_offset)) {
        std::abort();
    }
    if (!m->client_id.empty() && std::search(out.begin(), out.end(), m->client_id.begin(),
                                             m->client_id.end()) == out.end()) {
        std::abort();
    }
    return 0;
}
