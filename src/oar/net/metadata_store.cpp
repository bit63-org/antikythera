// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/metadata_store.hpp"

#include <utility>

namespace ak::oar::net {

auto to_string(MetadataResult r) noexcept -> const char* {
    switch (r) {
        case MetadataResult::kept:
            return "kept";
        case MetadataResult::redelivered:
            return "redelivered";
        case MetadataResult::undecodable:
            return "undecodable";
        case MetadataResult::wrong_server:
            return "wrong_server";
        case MetadataResult::bad_signature:
            return "bad_signature";
        case MetadataResult::stale:
            return "stale";
        case MetadataResult::full:
            return "full";
    }
    return "unknown";
}

MetadataStore::MetadataStore(std::uint64_t server_id, std::size_t capacity,
                             MetadataVerifier verifier)
    : _server_id{server_id}, _capacity{capacity}, _verifier{std::move(verifier)} {}

auto MetadataStore::put(std::span<const std::byte> frame) -> MetadataResult {
    auto record = proto::decode_instance_metadata(frame);
    if (!record) {
        ++_counters.undecodable;
        return MetadataResult::undecodable;
    }
    if (record->server_id != _server_id) {
        ++_counters.wrong_server;
        return MetadataResult::wrong_server;
    }
    if (!_verifier || !_verifier(proto::instance_metadata_signed_bytes(frame), record->signature,
                                 record->key_id)) {
        ++_counters.bad_signature;
        return MetadataResult::bad_signature;
    }
    // Versions are looked at only after the signature, as for map_update.
    const auto it = _records.find(record->nic_id);
    if (it != _records.end()) {
        if (it->second.metadata_version == record->metadata_version) {
            ++_counters.redelivered;
            return MetadataResult::redelivered;
        }
        if (it->second.metadata_version > record->metadata_version) {
            ++_counters.stale;
            return MetadataResult::stale;
        }
        it->second = std::move(*record);
    } else {
        if (_records.size() >= _capacity) {
            ++_counters.full;
            return MetadataResult::full;
        }
        const auto nic = record->nic_id;
        _records.emplace(nic, std::move(*record));
    }
    ++_counters.kept;
    return MetadataResult::kept;
}

auto MetadataStore::drop(std::uint64_t nic_id) -> bool {
    if (_records.erase(nic_id) == 0) {
        return false;
    }
    ++_counters.dropped;
    return true;
}

auto MetadataStore::find(std::uint64_t nic_id) const -> const proto::InstanceMetadata* {
    const auto it = _records.find(nic_id);
    return it == _records.end() ? nullptr : &it->second;
}

}  // namespace ak::oar::net
