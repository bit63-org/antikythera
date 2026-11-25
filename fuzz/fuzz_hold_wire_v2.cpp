// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the hold wire version 2 decoder (kythira khold-block-service
// Requirement 16.3): an accepted frame must re-encode to identical bytes,
// decode the same way when streamed (header, then payload), keep its block
// data inside the protocol's bounds, carry a group ID on every block
// opcode and redirect, and never be accepted by the version 1 decoder.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <variant>

#include "proto/hold_wire.hpp"
#include "proto/hold_wire_v2.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto f = proto::decode_hold_v2_frame(bytes);
    if (!f) {
        return 0;
    }
    auto again = proto::encode_hold_v2_frame(*f);
    if (!again || !std::ranges::equal(*again, bytes) || proto::decode_hold_frame(bytes)) {
        std::abort();
    }
    auto h = proto::decode_hold_v2_header(bytes.first(proto::hold_v2_header_size));
    if (!h || !(*h == f->header)) {
        std::abort();
    }
    auto p = proto::decode_hold_v2_payload(*h, bytes.subspan(proto::hold_v2_header_size));
    if (!p || !(*p == f->payload)) {
        std::abort();
    }
    if ((proto::is_block_opcode(h->opcode) || h->opcode == proto::HoldV2Opcode::redirect) &&
        h->group_id == 0) {
        std::abort();
    }
    if (const auto* d = std::get_if<proto::BlockData>(&f->payload)) {
        if (d->data.size() > proto::max_hold_data_bytes ||
            d->crcs.size() != std::size_t{h->blocks} * proto::hold_block_crc_size ||
            d->data.size() != std::size_t{h->blocks} * d->block_size ||
            proto::first_bad_block(*d) > h->blocks) {
            std::abort();
        }
    }
    return 0;
}
