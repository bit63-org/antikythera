// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VpcConfig decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical), stay within the size the
// sideband carries in one message, and satisfy the rules the network role
// relies on when it applies the config and its routes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/vpc_config.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto c = proto::decode_vpc_config(bytes);
    if (!c) {
        return 0;
    }
    auto again = proto::encode_vpc_config(*c);
    if (!again || !std::ranges::equal(*again, bytes) || bytes.size() > proto::max_vpc_config_size ||
        bytes.size() < proto::min_vpc_config_size || c->server_id == 0 ||
        c->key_id == proto::no_key_id || c->vni == 0 || c->vni > proto::max_vni ||
        c->config_version == 0 || c->dns4.size() > proto::max_vpc_dns ||
        c->dns6.size() > proto::max_vpc_dns || c->domain.size() > proto::max_vpc_domain_size ||
        c->routes.size() > proto::max_vpc_routes ||
        c->lease_seconds < proto::min_vpc_lease_seconds ||
        c->ipv4_length < proto::min_vpc_ipv4_length ||
        c->ipv4_length > proto::max_vpc_ipv4_length) {
        std::abort();
    }
    for (std::size_t i = 0; i < c->routes.size(); ++i) {
        const auto& r = c->routes[i];
        const std::size_t bits = r.family == proto::RouteFamily::ipv4 ? 32 : 128;
        if (r.target_nic == 0 || r.target_nic == proto::vpc_route_nic_broadcast ||
            r.length > bits || (i > 0 && !proto::detail::vpc_route_key_less(c->routes[i - 1], r))) {
            std::abort();
        }
    }
    return 0;
}
