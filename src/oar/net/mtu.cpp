// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/mtu.hpp"

namespace ak::oar::net {

auto to_string(MtuError e) noexcept -> const char* {
    switch (e) {
        case MtuError::underlay_too_small:
            return "underlay_too_small";
        case MtuError::underlay_too_large:
            return "underlay_too_large";
        case MtuError::guest_too_small:
            return "guest_too_small";
    }
    return "unknown";
}

auto plan_mtu(std::uint32_t underlay_mtu, std::uint32_t tunnel_overhead)
    -> std::expected<MtuPlan, MtuError> {
    if (underlay_mtu < min_underlay_mtu) {
        return std::unexpected(MtuError::underlay_too_small);
    }
    if (underlay_mtu > max_underlay_mtu) {
        return std::unexpected(MtuError::underlay_too_large);
    }
    // 64-bit so a huge tunnel_overhead cannot wrap.
    const std::uint64_t overhead = std::uint64_t{tunnel_overhead} + encapsulation_overhead;
    if (underlay_mtu < overhead + min_mtu) {
        return std::unexpected(MtuError::guest_too_small);
    }
    const std::uint64_t guest = underlay_mtu - overhead;
    return MtuPlan{
        .underlay_mtu = underlay_mtu,
        .tunnel_overhead = tunnel_overhead,
        .max_geneve_payload =
            static_cast<std::uint32_t>(underlay_mtu - tunnel_overhead - outer_header_size),
        .guest_mtu = static_cast<std::uint16_t>(guest),
    };
}

}  // namespace ak::oar::net
