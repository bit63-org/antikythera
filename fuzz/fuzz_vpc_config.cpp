// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VpcConfig version 2 decoder: an accepted frame must re-encode
// to identical bytes (the encoding is canonical), stay within the bounds
// helm reassembles it into, and satisfy the rules the network role relies
// on when it builds subnets and route tables from it
// (.kiro/specs/vpc-subnets-routing/ design "VpcConfig version 2").

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/vpc_config.hpp"

namespace proto = ak::proto;

namespace {

auto check_tables(const proto::VpcConfigFrame& c) -> bool {
    const std::size_t blocks = c.ipv4_blocks.size() + (c.ipv6_block ? std::size_t{1} : 0);
    std::size_t mains = 0;
    std::size_t total = 0;
    for (std::size_t t = 0; t < c.tables.size(); ++t) {
        const auto& table = c.tables[t];
        if (t > 0 && c.tables[t - 1].table >= table.table) {
            return false;
        }
        if (table.main) {
            ++mains;
        }
        total += table.routes.size();
        std::size_t locals = 0;
        std::size_t nics = 0;
        for (std::size_t i = 0; i < table.routes.size(); ++i) {
            const auto& r = table.routes[i];
            const std::size_t bits = r.family == proto::RouteFamily::ipv4 ? 32 : 128;
            if (r.length > bits ||
                (i > 0 && !proto::detail::vpc_route_key_less(table.routes[i - 1], r))) {
                return false;
            }
            if (r.kind == proto::RouteKind::local) {
                if (r.target_nic != 0 || !proto::detail::vpc_is_block_route(c, r)) {
                    return false;
                }
                ++locals;
            } else if (r.kind == proto::RouteKind::nic) {
                if (r.target_nic == 0 || r.target_nic == proto::vpc_route_nic_broadcast ||
                    proto::detail::vpc_is_block_route(c, r)) {
                    return false;
                }
                ++nics;
            } else {
                return false;
            }
        }
        if (locals != blocks || nics > proto::max_vpc_nic_routes) {
            return false;
        }
    }
    return mains == 1 && total <= proto::max_vpc_routes;
}

auto check_subnets(const proto::VpcConfigFrame& c) -> bool {
    for (std::size_t i = 0; i < c.subnets.size(); ++i) {
        const auto& s = c.subnets[i];
        if (s.subnet_id == 0 || (i > 0 && c.subnets[i - 1].subnet_id >= s.subnet_id) ||
            (s.ipv6_prefix && !c.ipv6_block) ||
            !std::ranges::binary_search(c.tables, s.table, std::ranges::less{},
                                        &proto::VpcRouteTable::table) ||
            std::ranges::none_of(c.ipv4_blocks, [&](const proto::VpcIpv4Block& b) {
                return proto::detail::vpc_inside4(s.ipv4_prefix, s.ipv4_length, b.prefix, b.length);
            })) {
            return false;
        }
        // The subnet's gateway (base + 1) lies inside the subnet.
        if (!proto::detail::vpc_inside4(proto::vpc_subnet_gateway(s), 32, s.ipv4_prefix,
                                        s.ipv4_length)) {
            return false;
        }
    }
    return true;
}

}  // namespace

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
        c->config_version == 0 || c->ipv4_blocks.empty() ||
        c->ipv4_blocks.size() > proto::max_vpc_ipv4_blocks || c->subnets.empty() ||
        c->subnets.size() > proto::max_vpc_subnets || c->tables.empty() ||
        c->tables.size() > proto::max_vpc_tables || c->dns4.size() > proto::max_vpc_dns ||
        c->dns6.size() > proto::max_vpc_dns || c->domain.size() > proto::max_vpc_domain_size ||
        c->lease_seconds < proto::min_vpc_lease_seconds || !check_tables(*c) ||
        !check_subnets(*c)) {
        std::abort();
    }
    // A decoded frame decodes again to the same value.
    auto back = proto::decode_vpc_config(*again);
    if (!back || !(*back == *c)) {
        std::abort();
    }
    return 0;
}
