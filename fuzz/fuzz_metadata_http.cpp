// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the metadata service's request parser, token decoder and path
// table (.kiro/specs/oar-net-data-plane/ Requirements 13.5 to 13.7): every
// byte comes from a guest. An accepted head must lie inside the input and
// the head limit; a request is answered without a crash, and a token a
// guest made up never checks out.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

#include "oar/net/metadata_http.hpp"

namespace net = ak::oar::net;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto raw = std::as_bytes(std::span{data, size});
    static const net::TokenKey key{std::array<std::byte, net::token_key_size>{}};
    static const ak::proto::InstanceMetadata record = [] {
        ak::proto::InstanceMetadata m;
        m.nic_id = 1;
        m.instance_id = "i-0123456789abcdef0";
        m.user_data = {std::byte{'x'}};
        return m;
    }();

    const auto request = net::parse_request(raw);
    if (request) {
        if (request->head_bytes > size || request->head_bytes > net::max_request_head ||
            request->path.empty() || request->path.front() != '/') {
            std::abort();
        }
        const net::MetadataView view{.record = &record, .network = {}};
        const auto response = net::answer(*request, view, key, 1000);
        if (response.reset || response.status < 200 || response.status > 599) {
            std::abort();
        }
        (void)net::render(response, request->method == net::HttpMethod::head);
    } else if (net::status_for(request.error()) == 0 &&
               request.error() != net::RequestError::incomplete) {
        std::abort();
    }

    const std::string_view text{reinterpret_cast<const char*>(data), size};
    (void)net::decode_token(text);
    if (key.check(text, 1, record.instance_id, 1000)) {
        std::abort();  // forged without the key
    }
    return 0;
}
