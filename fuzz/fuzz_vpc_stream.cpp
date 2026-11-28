// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VpcStream decoder (.kiro/specs/fleet-scale-networking/
// task 5): stream frames come from the controller, the frame store and
// helm, none of which the network role trusts until the signature
// checks. Anything accepted must re-encode to exactly the input, and
// every record must pass its own put or remove rules again.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/vpc_stream.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto raw = std::as_bytes(std::span{data, size});
    const auto s = proto::decode_vpc_stream(raw);
    if (!s) {
        return 0;
    }
    const auto again = proto::encode_vpc_stream(*s);
    if (!again || again->size() != size || !std::equal(again->begin(), again->end(), raw.begin())) {
        std::abort();
    }
    for (const auto& r : s->records) {
        const auto ok = r.op == proto::StreamOp::put
                            ? proto::detail::check_stream_put(r.type, r.body)
                            : proto::detail::check_stream_remove(r.type, r.body);
        if (!ok ||
            (r.op == proto::StreamOp::remove && r.body.size() != proto::stream_key_size(r.type))) {
            std::abort();
        }
    }
    return 0;
}
