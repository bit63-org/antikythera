// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VolumeLayout decoder (kythira khold-block-service
// Requirement 16.3): an accepted frame must re-encode to identical bytes
// (the encoding is canonical), fit max_volume_layout_size, and satisfy the
// invariants khold nodes and the initiator rely on: 1 to 64 stripe groups
// with unique non-zero IDs, 1 to 5 members per group on distinct servers
// with at least one data member and at most one witness, every block
// mapping to a group, and a single read-write attachment unless
// multi-attach is set.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/volume_layout.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto l = proto::decode_volume_layout(bytes);
    if (!l) {
        return 0;
    }
    auto again = proto::encode_volume_layout(*l);
    if (!again || !std::ranges::equal(*again, bytes) ||
        bytes.size() > proto::max_volume_layout_size || l->groups.empty() ||
        l->groups.size() > proto::max_stripe_width) {
        std::abort();
    }
    for (const auto& g : l->groups) {
        const auto data_members =
            std::ranges::count(g.members, proto::MemberKind::data, &proto::LayoutMember::kind);
        const auto witnesses =
            std::ranges::count(g.members, proto::MemberKind::witness, &proto::LayoutMember::kind);
        if (g.group_id == 0 || g.members.empty() || g.members.size() > proto::max_group_members ||
            data_members == 0 || witnesses > 1 ||
            std::ranges::adjacent_find(g.members, std::ranges::greater_equal{},
                                       &proto::LayoutMember::server_id) != g.members.end() ||
            proto::find_member(*l, g.group_id, g.members.front().server_id) == nullptr) {
            std::abort();
        }
    }
    if (proto::group_index_of(*l, l->capacity_blocks - 1) >= l->groups.size()) {
        std::abort();
    }
    const auto writers =
        std::ranges::count(l->attachments, proto::AttachMode::rw, &proto::VolumeAttachment::mode);
    if (writers > 1 && (l->flags & proto::layout_flags::multi_attach) == 0) {
        std::abort();
    }
    return 0;
}
