// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Ingress policy for a receiving VTEP: decides whether a structurally valid
// Geneve packet is believable given the controller's mappings. VTEPs never
// learn addresses from traffic; every binding comes from the controller.
//
// Checks, in order (any failure drops the packet):
//   1. source NIC exists, is in the packet's VNI, and is owned by the VTEP
//      the packet came from (outer IPv6 source)         -- anti-spoofing
//   2. inner Ethernet source MAC == the source NIC's assigned MAC
//   3. destination is a NIC local to this VTEP in this VNI, or broadcast
//   4. unicast: inner destination MAC == destination NIC's MAC;
//      broadcast: inner destination MAC is a group address

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include "oar/net/geneve.hpp"

namespace ak::oar::net {

using MacAddress = std::array<std::byte, 6>;
using Ipv6Address = std::array<std::byte, 16>;

struct NicBinding {
    std::uint32_t vni{0};
    MacAddress mac{};
    Ipv6Address owner_vtep{};
};

// Read-only view of the controller-pushed mapping table.
class MappingView {
public:
    virtual ~MappingView() = default;
    [[nodiscard]] virtual std::optional<NicBinding> lookup(geneve::NicId id) const = 0;
    // True if the NIC is attached to a function on this VTEP.
    [[nodiscard]] virtual bool is_local(geneve::NicId id) const = 0;

protected:
    MappingView() = default;
    MappingView(const MappingView&) = default;
    MappingView& operator=(const MappingView&) = default;
    MappingView(MappingView&&) = default;
    MappingView& operator=(MappingView&&) = default;
};

enum class PolicyError : std::uint8_t {
    oam_not_data,         // OAM packets are handled by the VTEP, never delivered
    unknown_src,
    src_wrong_vni,
    src_wrong_vtep,
    src_mac_mismatch,
    unknown_dst,
    dst_not_local,
    dst_wrong_vni,
    dst_mac_mismatch,
    broadcast_not_group,  // broadcast NIC ID but unicast inner destination MAC
};

[[nodiscard]] const char* to_string(PolicyError e) noexcept;

// Returns the destination (a local NIC, or nic_broadcast) on success.
[[nodiscard]] std::expected<geneve::NicId, PolicyError> check_ingress(const geneve::Packet& pkt,
                                                                     const Ipv6Address& outer_src,
                                                                     const MappingView& mappings);

}  // namespace ak::oar::net
