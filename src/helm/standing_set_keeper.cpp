// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/standing_set_keeper.hpp"

#include <algorithm>
#include <utility>

namespace ak::helm {

auto to_string(StandingVerdict v) noexcept -> const char* {
    switch (v) {
        case StandingVerdict::kept:
            return "kept";
        case StandingVerdict::none:
            return "none stored";
        case StandingVerdict::stale:
            return "generation not newer than the one anchored";
        case StandingVerdict::wrong_server:
            return "names another server";
        case StandingVerdict::bad_signature:
            return "signature does not verify";
        case StandingVerdict::corrupt:
            return "does not decode";
        case StandingVerdict::rolled_back:
            return "stored set is older than the anchored generation";
        case StandingVerdict::store_failed:
            return "sealed store failed";
        case StandingVerdict::anchor_failed:
            return "kept, but the secure element's counter did not advance";
        case StandingVerdict::anchor_unreadable:
            return "secure element's counter cannot be read";
    }
    return "unknown";
}

StandingSetKeeper::StandingSetKeeper(std::uint64_t server_id, SealedStore* store,
                                     StoreAnchor* anchor, const RecordVerifier* verifier) noexcept
    : _server_id{server_id}, _store{store}, _anchor{anchor}, _verifier{verifier} {}

auto StandingSetKeeper::verified(const proto::StandingSet& s,
                                 std::span<const std::byte> frame) const -> bool {
    return _verifier != nullptr &&
           _verifier->verify(proto::standing_set_signed_bytes(frame), s.signature, s.key_id);
}

auto StandingSetKeeper::anchored() -> std::optional<std::uint64_t> {
    if (_anchor == nullptr) {
        return _anchored;
    }
    auto c = _anchor->counter(Counter::standing_generation);
    if (!c) {
        return std::nullopt;
    }
    _anchored = *c;
    return _anchored;
}

auto StandingSetKeeper::anchor(std::uint64_t generation) -> bool {
    if (_anchor != nullptr && !_anchor->advance(Counter::standing_generation, generation)) {
        return false;
    }
    _anchored = generation;
    return true;
}

auto StandingSetKeeper::generation() const noexcept -> std::uint64_t {
    return std::max(_anchored, _current ? _current->generation : 0);
}

auto StandingSetKeeper::load() -> StandingVerdict {
    if (_store == nullptr) {
        return StandingVerdict::none;
    }
    if (_store->rolled_back() || _store->degraded()) {
        // Requirement 1.5: an older copy of the partition may hold an older
        // set, so none is trusted until the controller sends one.
        if (_store->contains(standing_set_object)) {
            (void)_store->remove(standing_set_object);
        }
        return StandingVerdict::none;
    }
    auto data = _store->get(standing_set_object);
    if (!data) {
        return StandingVerdict::store_failed;
    }
    if (!*data) {
        return StandingVerdict::none;
    }
    const auto set = proto::decode_standing_set(**data);
    if (!set) {
        return StandingVerdict::corrupt;
    }
    if (set->server_id != _server_id) {
        return StandingVerdict::wrong_server;
    }
    // Checked again: a key retired since it was stored no longer counts.
    if (!verified(*set, **data)) {
        return StandingVerdict::bad_signature;
    }
    const auto counter = anchored();
    if (!counter) {
        return StandingVerdict::anchor_unreadable;
    }
    if (set->generation < *counter) {
        // A copy older than the newest set this element ever accepted.
        (void)_store->remove(standing_set_object);
        return StandingVerdict::rolled_back;
    }
    _current = *set;
    _frame = std::move(**data);
    // The counter lags when an earlier offer() could not advance it.
    if (set->generation > *counter && !anchor(set->generation)) {
        return StandingVerdict::anchor_failed;
    }
    return StandingVerdict::kept;
}

auto StandingSetKeeper::offer(std::span<const std::byte> frame) -> StandingVerdict {
    const auto set = proto::decode_standing_set(frame);
    if (!set) {
        return StandingVerdict::corrupt;
    }
    if (set->server_id != _server_id) {
        return StandingVerdict::wrong_server;
    }
    const auto counter = anchored();
    if (!counter) {
        return StandingVerdict::anchor_unreadable;
    }
    if (set->generation <= std::max(*counter, _current ? _current->generation : 0)) {
        return StandingVerdict::stale;
    }
    if (!verified(*set, frame)) {
        return StandingVerdict::bad_signature;
    }
    // Stored first: a counter advanced past a set that was never stored
    // would refuse every copy helm could still find.
    if (_store != nullptr && !_store->put(standing_set_object, frame)) {
        return StandingVerdict::store_failed;
    }
    _current = *set;
    _frame.assign(frame.begin(), frame.end());
    return anchor(set->generation) ? StandingVerdict::kept : StandingVerdict::anchor_failed;
}

}  // namespace ak::helm
