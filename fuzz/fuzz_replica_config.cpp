// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the ReplicaConfig decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical) and must satisfy the
// invariants hold and oar-blk rely on: at most one primary (exactly one
// unless I/O is suspended), unique members and attachments, and a single
// read-write attachment unless multi-attach is set.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/replica_config.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto c = proto::decode_replica_config(bytes);
    if (!c) {
        return 0;
    }
    auto again = proto::encode_replica_config(*c);
    const auto primaries =
        std::ranges::count(c->members, proto::ReplicaRole::primary, &proto::ReplicaMember::role);
    const auto writers =
        std::ranges::count(c->attachments, proto::AttachMode::rw, &proto::VolumeAttachment::mode);
    const bool suspended = (c->flags & proto::replica_flags::io_suspended) != 0;
    const bool multi = (c->flags & proto::replica_flags::multi_attach) != 0;
    if (!again || !std::ranges::equal(*again, bytes) || c->members.empty() ||
        c->members.size() > proto::max_replica_members ||
        c->attachments.size() > proto::max_volume_attachments || primaries > 1 ||
        (primaries == 0 && !suspended) || (writers > 1 && !multi) ||
        std::ranges::adjacent_find(c->members, std::ranges::greater_equal{},
                                   &proto::ReplicaMember::server_id) != c->members.end() ||
        std::ranges::adjacent_find(c->attachments, std::ranges::greater_equal{},
                                   &proto::VolumeAttachment::attachment_id) !=
            c->attachments.end()) {
        std::abort();
    }
    return 0;
}
