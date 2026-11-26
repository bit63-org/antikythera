// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the GroupPolicy decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical) and satisfy the rules the
// network role relies on when it applies the limits to the VSwitch, in
// either version (one VNI-wide policy, or one entry per subnet).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/group_policy.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto p = proto::decode_group_policy(bytes);
    if (!p) {
        return 0;
    }
    auto again = proto::encode_group_policy(*p);
    if (!again || !std::ranges::equal(*again, bytes) || p->server_id == 0 ||
        p->key_id == proto::no_key_id || p->vni == 0 || p->vni > proto::max_vni ||
        p->policy_version == 0) {
        std::abort();
    }
    const auto drop_fields = [&] {
        return p->mode == proto::GroupMode::drop &&
               (p->rate_frames | p->burst_frames | p->max_remote_vteps | p->max_groups_per_nic) ==
                   0 &&
               (p->rate_bytes | p->burst_bytes) == 0;
    };
    const auto limits = [](std::uint32_t rate_frames, std::uint32_t burst_frames,
                           std::uint64_t rate_bytes, std::uint64_t burst_bytes,
                           std::uint32_t remote_vteps, std::uint16_t groups) {
        return rate_frames - 1 < proto::max_group_rate_frames &&
               burst_frames - 1 < proto::max_group_burst_frames &&
               rate_bytes - 1 < proto::max_group_rate_bytes &&
               burst_bytes - 1 < proto::max_group_burst_bytes &&
               remote_vteps - 1 < proto::max_group_remote_vteps &&
               groups <= proto::max_group_groups_per_nic;
    };
    if (p->format == proto::group_policy_version_subnets) {
        // Version 2: the VPC-wide fields stay at drop and every entry
        // names a distinct subnet, in ascending order, with usable limits.
        if (bytes.size() != proto::min_group_policy_v2_size +
                                p->subnets.size() * proto::group_policy_entry_size ||
            p->subnets.size() > proto::max_group_policy_subnets || !drop_fields()) {
            std::abort();
        }
        std::uint64_t previous = 0;
        for (const auto& e : p->subnets) {
            if (e.subnet_id <= previous ||
                !limits(e.rate_frames, e.burst_frames, e.rate_bytes, e.burst_bytes,
                        e.max_remote_vteps, e.max_groups_per_nic)) {
                std::abort();
            }
            previous = e.subnet_id;
        }
        return 0;
    }
    if (p->format != proto::group_policy_version || bytes.size() != proto::group_policy_size ||
        !p->subnets.empty()) {
        std::abort();
    }
    const bool limits_ok = p->mode == proto::GroupMode::drop
                               ? drop_fields()
                               : limits(p->rate_frames, p->burst_frames, p->rate_bytes,
                                        p->burst_bytes, p->max_remote_vteps, p->max_groups_per_nic);
    if (!limits_ok) {
        std::abort();
    }
    return 0;
}
