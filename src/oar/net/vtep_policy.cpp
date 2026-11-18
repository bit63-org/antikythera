// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/vtep_policy.hpp"

#include <algorithm>

namespace ak::oar::net {

namespace {

constexpr std::size_t dst_mac_offset = 0;
constexpr std::size_t src_mac_offset = 6;
constexpr std::byte group_bit{0x01};

auto mac_at(std::span<const std::byte> frame, std::size_t offset) noexcept -> MacAddress {
    MacAddress mac{};
    std::copy_n(frame.begin() + static_cast<std::ptrdiff_t>(offset), mac.size(), mac.begin());
    return mac;
}

}  // namespace

auto to_string(PolicyError e) noexcept -> const char* {
    switch (e) {
        case PolicyError::oam_not_data:
            return "oam_not_data";
        case PolicyError::unknown_src:
            return "unknown_src";
        case PolicyError::src_wrong_vni:
            return "src_wrong_vni";
        case PolicyError::src_wrong_vtep:
            return "src_wrong_vtep";
        case PolicyError::src_mac_mismatch:
            return "src_mac_mismatch";
        case PolicyError::unknown_dst:
            return "unknown_dst";
        case PolicyError::dst_not_local:
            return "dst_not_local";
        case PolicyError::dst_wrong_vni:
            return "dst_wrong_vni";
        case PolicyError::dst_mac_mismatch:
            return "dst_mac_mismatch";
        case PolicyError::broadcast_not_group:
            return "broadcast_not_group";
    }
    return "unknown";
}

auto check_ingress(const geneve::Packet& pkt, const Ipv6Address& outer_src,
                   const MappingView& mappings) -> std::expected<geneve::NicId, PolicyError> {
    // decode() guarantees non-OAM packets carry a NIC pair and a full
    // Ethernet header; re-check rather than trust a caller-built Packet.
    if (pkt.oam || !pkt.nics || pkt.inner.size() < geneve::ethernet_header_size) {
        return std::unexpected(PolicyError::oam_not_data);
    }
    const auto [src_id, dst_id] = *pkt.nics;

    const auto src = mappings.lookup(src_id);
    if (!src) {
        return std::unexpected(PolicyError::unknown_src);
    }
    if (src->vni != pkt.vni) {
        return std::unexpected(PolicyError::src_wrong_vni);
    }
    if (src->owner_vtep != outer_src) {
        return std::unexpected(PolicyError::src_wrong_vtep);
    }
    if (mac_at(pkt.inner, src_mac_offset) != src->mac) {
        return std::unexpected(PolicyError::src_mac_mismatch);
    }

    const MacAddress inner_dst = mac_at(pkt.inner, dst_mac_offset);

    if (dst_id == geneve::nic_broadcast) {
        if ((inner_dst[0] & group_bit) != group_bit) {
            return std::unexpected(PolicyError::broadcast_not_group);
        }
        return dst_id;
    }

    const auto dst = mappings.lookup(dst_id);
    if (!dst) {
        return std::unexpected(PolicyError::unknown_dst);
    }
    if (!mappings.is_local(dst_id)) {
        return std::unexpected(PolicyError::dst_not_local);
    }
    if (dst->vni != pkt.vni) {
        return std::unexpected(PolicyError::dst_wrong_vni);
    }
    if (inner_dst != dst->mac) {
        return std::unexpected(PolicyError::dst_mac_mismatch);
    }
    return dst_id;
}

}  // namespace ak::oar::net
