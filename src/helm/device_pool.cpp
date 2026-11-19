// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/device_pool.hpp"

#include <algorithm>

namespace ak::helm {

namespace {

constexpr auto rows_overlap(const Transition& a, const Transition& b) noexcept -> bool {
    return a.from == b.from && a.event == b.event && (a.types & b.types) != 0;
}

constexpr auto table_is_deterministic() noexcept -> bool {
    for (std::size_t i = 0; i < transition_table.size(); ++i) {
        for (std::size_t j = i + 1; j < transition_table.size(); ++j) {
            if (rows_overlap(transition_table[i], transition_table[j])) {
                return false;
            }
        }
    }
    return true;
}

constexpr auto table_masks_are_valid() noexcept -> bool {
    return std::ranges::all_of(transition_table, [](const Transition& t) {
        return t.types != 0 && (t.types & static_cast<TypeMask>(~any_type)) == 0;
    });
}

static_assert(table_is_deterministic(), "transition_table has two rows for one move");
static_assert(table_masks_are_valid(), "transition_table row with an empty or unknown type mask");

}  // namespace

auto next_state(FunctionType type, FunctionState from, PoolEvent event) noexcept
    -> std::optional<FunctionState> {
    const auto bit = type_bit(type);
    for (const auto& row : transition_table) {
        if (row.from == from && row.event == event && (row.types & bit) != 0) {
            return row.to;
        }
    }
    return std::nullopt;
}

auto cleaning_action(FunctionType t) noexcept -> CleaningAction {
    switch (t) {
        case FunctionType::nic_vf:
            return CleaningAction::reset_nic_vf;
        case FunctionType::blk_fn:
            return CleaningAction::drop_volume_key;
        case FunctionType::gpu_whole:
            return CleaningAction::scrub_gpu;
        case FunctionType::gpu_vf:
            return CleaningAction::scrub_gpu_vf;
    }
    // Unreachable for valid enumerators; the most thorough action is the
    // safe default for a corrupted value.
    return CleaningAction::scrub_gpu;
}

auto to_string(FunctionType t) noexcept -> const char* {
    switch (t) {
        case FunctionType::nic_vf:
            return "nic_vf";
        case FunctionType::blk_fn:
            return "blk_fn";
        case FunctionType::gpu_whole:
            return "gpu_whole";
        case FunctionType::gpu_vf:
            return "gpu_vf";
    }
    return "unknown";
}

auto to_string(FunctionState s) noexcept -> const char* {
    switch (s) {
        case FunctionState::free:
            return "free";
        case FunctionState::assigned:
            return "assigned";
        case FunctionState::releasing:
            return "releasing";
        case FunctionState::cleaning:
            return "cleaning";
        case FunctionState::faulted:
            return "faulted";
    }
    return "unknown";
}

auto to_string(PoolEvent e) noexcept -> const char* {
    switch (e) {
        case PoolEvent::assign:
            return "assign";
        case PoolEvent::release:
            return "release";
        case PoolEvent::device_released:
            return "device_released";
        case PoolEvent::reset_failed:
            return "reset_failed";
        case PoolEvent::clean_done:
            return "clean_done";
        case PoolEvent::scrub_done:
            return "scrub_done";
        case PoolEvent::clean_failed:
            return "clean_failed";
        case PoolEvent::timed_out:
            return "timed_out";
        case PoolEvent::power_cycle_done:
            return "power_cycle_done";
        case PoolEvent::attach_failed:
            return "attach_failed";
    }
    return "unknown";
}

auto to_string(CleaningAction a) noexcept -> const char* {
    switch (a) {
        case CleaningAction::reset_nic_vf:
            return "reset_nic_vf";
        case CleaningAction::drop_volume_key:
            return "drop_volume_key";
        case CleaningAction::scrub_gpu:
            return "scrub_gpu";
        case CleaningAction::scrub_gpu_vf:
            return "scrub_gpu_vf";
    }
    return "unknown";
}

auto to_string(PoolError e) noexcept -> const char* {
    switch (e) {
        case PoolError::unknown_function:
            return "unknown_function";
        case PoolError::duplicate_function:
            return "duplicate_function";
        case PoolError::illegal_transition:
            return "illegal_transition";
        case PoolError::wrong_vm:
            return "wrong_vm";
    }
    return "unknown";
}

auto DevicePool::step(FunctionId id, PoolEvent event) -> std::expected<Entry*, PoolError> {
    const auto it = _functions.find(id);
    if (it == _functions.end()) {
        return std::unexpected(PoolError::unknown_function);
    }
    auto& entry = it->second;
    const auto to = next_state(entry.type, entry.state, event);
    if (!to) {
        return std::unexpected(PoolError::illegal_transition);
    }
    entry.state = *to;
    // Ownership follows the state: a VM holds the function from assign
    // until hull confirms the reset.
    if (entry.state != FunctionState::assigned && entry.state != FunctionState::releasing) {
        entry.owner.reset();
    }
    return &entry;
}

auto DevicePool::add(FunctionId id, FunctionType type) -> std::expected<CleaningAction, PoolError> {
    const auto [it, inserted] =
        _functions.try_emplace(id, Entry{type, FunctionState::cleaning, std::nullopt});
    if (!inserted) {
        return std::unexpected(PoolError::duplicate_function);
    }
    return cleaning_action(type);
}

auto DevicePool::assign(FunctionId id, VmId vm) -> std::expected<void, PoolError> {
    auto entry = step(id, PoolEvent::assign);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    (*entry)->owner = vm;
    return {};
}

auto DevicePool::release(FunctionId id, VmId vm) -> std::expected<void, PoolError> {
    const auto it = _functions.find(id);
    if (it == _functions.end()) {
        return std::unexpected(PoolError::unknown_function);
    }
    // Check the owner before moving, so a wrong-VM release changes nothing.
    if (it->second.state == FunctionState::assigned && it->second.owner != vm) {
        return std::unexpected(PoolError::wrong_vm);
    }
    auto entry = step(id, PoolEvent::release);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    return {};
}

auto DevicePool::device_released(FunctionId id) -> std::expected<CleaningAction, PoolError> {
    auto entry = step(id, PoolEvent::device_released);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    return cleaning_action((*entry)->type);
}

auto DevicePool::power_cycle_done(FunctionId id) -> std::expected<CleaningAction, PoolError> {
    auto entry = step(id, PoolEvent::power_cycle_done);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    return cleaning_action((*entry)->type);
}

auto DevicePool::apply(FunctionId id, PoolEvent event) -> std::expected<FunctionState, PoolError> {
    if (event == PoolEvent::assign || event == PoolEvent::release) {
        // These carry a VM; use assign() / release().
        return std::unexpected(PoolError::illegal_transition);
    }
    auto entry = step(id, event);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    return (*entry)->state;
}

auto DevicePool::release_all(VmId vm) -> std::vector<FunctionId> {
    auto ids = held_by(vm);
    std::erase_if(ids, [&](FunctionId id) {
        return _functions.at(id).state != FunctionState::assigned || !release(id, vm);
    });
    return ids;
}

auto DevicePool::find(FunctionId id) const -> std::optional<FunctionInfo> {
    const auto it = _functions.find(id);
    if (it == _functions.end()) {
        return std::nullopt;
    }
    return FunctionInfo{id, it->second.type, it->second.state, it->second.owner};
}

auto DevicePool::held_by(VmId vm) const -> std::vector<FunctionId> {
    std::vector<FunctionId> ids;
    for (const auto& [id, entry] : _functions) {
        if (entry.owner == vm) {
            ids.push_back(id);
        }
    }
    return ids;
}

auto DevicePool::all() const -> std::vector<FunctionInfo> {
    std::vector<FunctionInfo> out;
    out.reserve(_functions.size());
    for (const auto& [id, entry] : _functions) {
        out.push_back(FunctionInfo{id, entry.type, entry.state, entry.owner});
    }
    return out;
}

auto DevicePool::first_free(FunctionType type) const -> std::optional<FunctionId> {
    for (const auto& [id, entry] : _functions) {
        if (entry.type == type && entry.state == FunctionState::free) {
            return id;
        }
    }
    return std::nullopt;
}

}  // namespace ak::helm
