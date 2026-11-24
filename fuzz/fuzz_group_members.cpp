// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the GroupMembers decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical), stay within the size the
// sideband carries in one message, and satisfy the rules the network role
// relies on when it hands the lists to the VSwitch.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/group_members.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto m = proto::decode_group_members(bytes);
    if (!m) {
        return 0;
    }
    auto again = proto::encode_group_members(*m);
    if (!again || !std::ranges::equal(*again, bytes) ||
        bytes.size() > proto::max_group_members_size ||
        bytes.size() < proto::min_group_members_size || m->server_id == 0 ||
        m->key_id == proto::no_key_id || m->vni == 0 || m->vni > proto::max_vni ||
        m->members_version == 0 || m->groups.size() > proto::max_member_groups) {
        std::abort();
    }
    std::size_t vteps = 0;
    for (std::size_t i = 0; i < m->groups.size(); ++i) {
        const auto& g = m->groups[i];
        vteps += g.vteps.size();
        if (!proto::detail::valid_member_group(g.family, g.group) || g.vteps.empty() ||
            g.vteps.size() > proto::max_group_vteps ||
            (i > 0 && !proto::detail::member_group_less(m->groups[i - 1], g)) ||
            !std::ranges::is_sorted(g.vteps)) {
            std::abort();
        }
    }
    if (vteps > proto::max_member_vteps) {
        std::abort();
    }
    return 0;
}
