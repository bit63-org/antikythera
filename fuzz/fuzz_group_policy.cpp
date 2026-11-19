// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the GroupPolicy decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical) and satisfy the rules the
// network role relies on when it applies the limits to the VSwitch.

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
    if (!again || !std::ranges::equal(*again, bytes) || bytes.size() != proto::group_policy_size ||
        p->server_id == 0 || p->key_id == proto::no_key_id || p->vni == 0 ||
        p->vni > proto::max_vni || p->policy_version == 0) {
        std::abort();
    }
    const bool limits_ok = p->mode == proto::GroupMode::drop
                               ? (p->rate_frames | p->burst_frames | p->max_remote_vteps |
                                  p->max_groups_per_nic) == 0 &&
                                     (p->rate_bytes | p->burst_bytes) == 0
                               : p->rate_frames - 1 < proto::max_group_rate_frames &&
                                     p->burst_frames - 1 < proto::max_group_burst_frames &&
                                     p->rate_bytes - 1 < proto::max_group_rate_bytes &&
                                     p->burst_bytes - 1 < proto::max_group_burst_bytes &&
                                     p->max_remote_vteps - 1 < proto::max_group_remote_vteps;
    if (!limits_ok) {
        std::abort();
    }
    return 0;
}
