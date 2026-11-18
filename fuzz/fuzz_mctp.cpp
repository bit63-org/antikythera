// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the MCTP SMBus packet decoder, the reassembler and the vendor
// message decoder. The input is a stream of packets, each prefixed by a
// one-byte length, fed through one Assembler so that sequences of packets
// (not just single ones) are explored. Checks that an accepted packet, and
// an accepted vendor message, re-encode to identical bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "helm/mctp.hpp"

namespace mctp = ak::helm::mctp;

namespace {

constexpr std::uint8_t local_eid = 0x09;
constexpr std::size_t small_limit = 512;  // reach message_too_long without huge inputs

auto check_vendor(std::span<const std::byte> message) -> void {
    auto v = mctp::decode_vendor(message);
    if (!v) {
        return;
    }
    auto again = mctp::encode_vendor(v->header, v->body);
    if (!again || !std::ranges::equal(*again, message)) {
        std::abort();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span input{reinterpret_cast<const std::byte*>(data), size};
    mctp::Assembler assembler{local_eid, small_limit};

    // Every input is also tried as one whole message.
    check_vendor(input.first(std::min(input.size(), mctp::max_message_size)));

    std::size_t pos = 0;
    while (pos < input.size()) {
        const auto len = std::to_integer<std::size_t>(input[pos]);
        ++pos;
        const auto chunk = input.subspan(pos, std::min(len, input.size() - pos));
        pos += chunk.size();

        auto packet = mctp::decode_packet(chunk);
        if (!packet) {
            continue;
        }
        auto again = mctp::encode_packet(packet->dest_addr, packet->src_addr, packet->header,
                                         packet->payload());
        if (!again || !std::ranges::equal(*again, chunk)) {
            std::abort();
        }

        auto result = assembler.push(*packet);
        if (result && result->has_value()) {
            const auto& msg = **result;
            if (msg.bytes.empty() || msg.bytes.size() > small_limit) {
                std::abort();
            }
            check_vendor(msg.bytes);
        }
    }
    return 0;
}
