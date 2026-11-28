// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/boot_state.hpp"

#include <vector>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

auto store_failure(StoreError e) -> BootStateFailure {
    return BootStateFailure{.error = BootStateError::store, .store_error = e};
}

auto anchor_failure(AnchorError e) -> BootStateFailure {
    return BootStateFailure{.error = BootStateError::anchor, .anchor_error = e};
}

}  // namespace

auto to_string(BootStateError e) noexcept -> const char* {
    switch (e) {
        case BootStateError::store:
            return "sealed store failed";
        case BootStateError::anchor:
            return "secure element failed";
        case BootStateError::corrupt:
            return "recorded sequence number is corrupt";
        case BootStateError::bad_server:
            return "server ID is 0";
    }
    return "unknown";
}

auto load_sequence_floor(SealedStore& store) -> std::expected<std::uint64_t, BootStateFailure> {
    auto data = store.get(last_command_seq_object);
    if (!data) {
        return std::unexpected(store_failure(data.error()));
    }
    if (!*data) {
        return 0;
    }
    if ((*data)->size() != sizeof(std::uint64_t)) {
        return std::unexpected(BootStateFailure{.error = BootStateError::corrupt});
    }
    wire::Reader r{**data};
    return r.le64().value_or(0);
}

auto begin_host_boot(SealedStore& store, StoreAnchor& anchor, std::uint64_t server_id)
    -> std::expected<proto::Provisioning, BootStateFailure> {
    if (server_id == 0) {
        return std::unexpected(BootStateFailure{.error = BootStateError::bad_server});
    }
    const auto floor = load_sequence_floor(store);
    if (!floor) {
        return std::unexpected(floor.error());
    }
    const auto epoch = anchor.counter(Counter::boot_epoch);
    if (!epoch) {
        return std::unexpected(anchor_failure(epoch.error()));
    }
    if (*epoch == UINT64_MAX) {
        return std::unexpected(anchor_failure(AnchorError::not_monotonic));
    }
    if (auto ok = anchor.advance(Counter::boot_epoch, *epoch + 1); !ok) {
        return std::unexpected(anchor_failure(ok.error()));
    }
    return proto::Provisioning{
        .server_id = server_id, .boot_epoch = *epoch + 1, .sequence_floor = *floor};
}

auto StoreSequenceRecorder::record(std::uint64_t seq) -> bool {
    if (seq <= _recorded) {
        return true;
    }
    std::vector<std::byte> bytes;
    wire::Writer w{bytes};
    w.le64(seq);
    if (auto ok = _store->put(last_command_seq_object, bytes); !ok) {
        ++_failures;
        _last_error = ok.error();
        return false;
    }
    _recorded = seq;
    return true;
}

}  // namespace ak::helm
