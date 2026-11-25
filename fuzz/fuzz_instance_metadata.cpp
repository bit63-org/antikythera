// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the InstanceMetadata decoder: an accepted frame must re-encode to
// identical bytes (the encoding is canonical), stay within the size helm
// forwards, and satisfy the rules the metadata service relies on when it
// serves the strings to guests.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "proto/instance_metadata.hpp"

namespace proto = ak::proto;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto m = proto::decode_instance_metadata(bytes);
    if (!m) {
        return 0;
    }
    auto again = proto::encode_instance_metadata(*m);
    if (!again || !std::ranges::equal(*again, bytes) ||
        bytes.size() > proto::max_instance_metadata_size ||
        bytes.size() < proto::min_instance_metadata_size || m->server_id == 0 ||
        m->key_id == proto::no_key_id || m->nic_id == 0 || m->metadata_version == 0 ||
        m->vni == 0 || m->vni > proto::max_vni || m->put_hop_limit < proto::min_put_hop_limit ||
        m->put_hop_limit > proto::max_put_hop_limit ||
        m->user_data.size() > proto::max_user_data_size) {
        std::abort();
    }
    for (const auto* s : proto::detail::metadata_strings(*m)) {
        if (s->empty() || s->size() > proto::max_metadata_string_size ||
            !std::ranges::all_of(*s, [](char c) { return c > ' ' && c < '\x7F'; })) {
            std::abort();
        }
    }
    return 0;
}
