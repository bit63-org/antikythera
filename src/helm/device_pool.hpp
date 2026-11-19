// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// DevicePool: helm's inventory of every assignable function and the state
// machine that guarantees a function is never in two VMs and never handed
// out dirty (.kiro/specs/helm-control-plane/ Requirement 3,
// .kiro/specs/oar-gpu-data-plane/ Requirements 2.2 and 3).
//
//            assign                VM release / detach
//   free ──────────────► assigned ─────────────────────► releasing
//    ▲                                                       │ hull: DEVICE_RELEASED
//    │  oar: clean ok (NIC, blk) / SCRUB_DONE (GPU)          ▼
//    └────────────────────────────────────────────────── cleaning
//                                                            │ error / timeout
//                                                            ▼
//            cleaning ◄── slot power-cycle ok ──────────── faulted
//
// An attach that fails after helm reserved and prepared the function (the
// role refused, or hull answered with an error) moves it from `assigned`
// straight to `cleaning` (attach_failed): hull never handed it to the VM,
// so there is no reset to wait for, but the role may already hold the
// VM's configuration or volume key, so it is cleaned before reuse.
//
// Every legal move is one row of `transition_table`; anything not in the
// table is illegal and leaves the function untouched. A power-cycled
// function goes back through `cleaning` rather than straight to `free`:
// a power cycle is not a guaranteed wipe (VRAM in particular), so the
// function is cleaned again before it can be reassigned.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <vector>

namespace ak::helm {

// Function types. Values are shared with the wire protocol (ATTACH_DEVICE
// and the sideband function inventory): never renumber.
enum class FunctionType : std::uint8_t {
    nic_vf = 1,
    blk_fn = 2,
    gpu_whole = 3,
    gpu_vf = 4,
};

inline constexpr std::array all_function_types{
    FunctionType::nic_vf,
    FunctionType::blk_fn,
    FunctionType::gpu_whole,
    FunctionType::gpu_vf,
};

[[nodiscard]] constexpr auto is_gpu(FunctionType t) noexcept -> bool {
    return t == FunctionType::gpu_whole || t == FunctionType::gpu_vf;
}

enum class FunctionState : std::uint8_t {
    free,
    assigned,
    releasing,  // VM let go; waiting for hull's DEVICE_RELEASED (reset done)
    cleaning,   // data-plane role is wiping, crypto-erasing or scrubbing it
    faulted,    // cleaning or reset failed; held until a slot power-cycle
};

inline constexpr std::array all_function_states{
    FunctionState::free,     FunctionState::assigned, FunctionState::releasing,
    FunctionState::cleaning, FunctionState::faulted,
};

enum class PoolEvent : std::uint8_t {
    assign,            // controller: attach to a VM
    release,           // controller: detach, or the VM was destroyed
    device_released,   // hull: function reset complete
    reset_failed,      // hull: function reset failed (Requirement 4.1, oar-gpu)
    clean_done,        // oar-net / oar-blk: clean confirmed
    scrub_done,        // GPU manager or scrubber VM: memory cleared
    clean_failed,      // data-plane role reported a cleaning error
    timed_out,         // reset or cleaning did not finish in time
    power_cycle_done,  // PowerSequencer: slot power-cycle succeeded
    attach_failed,     // CommandRouter: an attach failed after the function was prepared
};

inline constexpr std::array all_pool_events{
    PoolEvent::assign,        PoolEvent::release,    PoolEvent::device_released,
    PoolEvent::reset_failed,  PoolEvent::clean_done, PoolEvent::scrub_done,
    PoolEvent::clean_failed,  PoolEvent::timed_out,  PoolEvent::power_cycle_done,
    PoolEvent::attach_failed,
};

// What the data-plane role must do to a function in `cleaning`.
enum class CleaningAction : std::uint8_t {
    reset_nic_vf,     // oar-net: dead VPC, clear queues and MAC
    drop_volume_key,  // oar-blk: drop the key from memory
    scrub_gpu,        // scrubber VM clears VRAM, then reset
    scrub_gpu_vf,     // manager VM's PF driver clears the VF
};

[[nodiscard]] auto cleaning_action(FunctionType t) noexcept -> CleaningAction;

[[nodiscard]] auto to_string(FunctionType t) noexcept -> const char*;
[[nodiscard]] auto to_string(FunctionState s) noexcept -> const char*;
[[nodiscard]] auto to_string(PoolEvent e) noexcept -> const char*;
[[nodiscard]] auto to_string(CleaningAction a) noexcept -> const char*;

// Bit per FunctionType, for the `types` column of the transition table.
using TypeMask = std::uint8_t;

[[nodiscard]] constexpr auto type_bit(FunctionType t) noexcept -> TypeMask {
    return static_cast<TypeMask>(1U << static_cast<unsigned>(t));
}

inline constexpr TypeMask any_type =
    type_bit(FunctionType::nic_vf) | type_bit(FunctionType::blk_fn) |
    type_bit(FunctionType::gpu_whole) | type_bit(FunctionType::gpu_vf);
inline constexpr TypeMask gpu_types =
    type_bit(FunctionType::gpu_whole) | type_bit(FunctionType::gpu_vf);
inline constexpr TypeMask non_gpu_types = any_type & static_cast<TypeMask>(~gpu_types);

struct Transition {
    FunctionState from;
    PoolEvent event;
    TypeMask types;
    FunctionState to;
};

// The whole state machine. Rows are unique on (from, event, type).
inline constexpr std::array transition_table{
    Transition{FunctionState::free, PoolEvent::assign, any_type, FunctionState::assigned},
    Transition{FunctionState::assigned, PoolEvent::release, any_type, FunctionState::releasing},
    Transition{FunctionState::assigned, PoolEvent::attach_failed, any_type,
               FunctionState::cleaning},
    Transition{FunctionState::releasing, PoolEvent::device_released, any_type,
               FunctionState::cleaning},
    Transition{FunctionState::releasing, PoolEvent::reset_failed, any_type, FunctionState::faulted},
    Transition{FunctionState::releasing, PoolEvent::timed_out, any_type, FunctionState::faulted},
    Transition{FunctionState::cleaning, PoolEvent::clean_done, non_gpu_types, FunctionState::free},
    Transition{FunctionState::cleaning, PoolEvent::scrub_done, gpu_types, FunctionState::free},
    Transition{FunctionState::cleaning, PoolEvent::clean_failed, any_type, FunctionState::faulted},
    Transition{FunctionState::cleaning, PoolEvent::timed_out, any_type, FunctionState::faulted},
    Transition{FunctionState::faulted, PoolEvent::power_cycle_done, any_type,
               FunctionState::cleaning},
};

// Pure lookup in `transition_table`; nullopt means the move is illegal.
[[nodiscard]] auto next_state(FunctionType type, FunctionState from, PoolEvent event) noexcept
    -> std::optional<FunctionState>;

enum class FunctionId : std::uint32_t {
};
using VmId = std::uint64_t;

// A function's pool ID from its backplane slot and its number in that slot
// (design, data models: FunctionId { slot, fn }): slot in bits 16-23.
[[nodiscard]] constexpr auto make_function_id(std::uint8_t slot, std::uint16_t fn) noexcept
    -> FunctionId {
    return FunctionId{(static_cast<std::uint32_t>(slot) << 16U) | fn};
}
[[nodiscard]] constexpr auto slot_of(FunctionId id) noexcept -> std::uint8_t {
    return static_cast<std::uint8_t>(static_cast<std::uint32_t>(id) >> 16U);
}
[[nodiscard]] constexpr auto function_number_of(FunctionId id) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(static_cast<std::uint32_t>(id) & 0xFFFFU);
}

enum class PoolError : std::uint8_t {
    unknown_function,
    duplicate_function,
    illegal_transition,
    wrong_vm,  // release by a VM that does not hold the function
};

[[nodiscard]] auto to_string(PoolError e) noexcept -> const char*;

struct FunctionInfo {
    FunctionId id{};
    FunctionType type{FunctionType::nic_vf};
    FunctionState state{FunctionState::free};
    std::optional<VmId> owner;  // set exactly while assigned or releasing
};

class DevicePool {
public:
    // Registers a function from a data-plane role's inventory. It starts in
    // `cleaning`: helm cannot know what a previous boot left in it.
    auto add(FunctionId id, FunctionType type) -> std::expected<CleaningAction, PoolError>;

    auto assign(FunctionId id, VmId vm) -> std::expected<void, PoolError>;
    auto release(FunctionId id, VmId vm) -> std::expected<void, PoolError>;
    // hull reported DEVICE_RELEASED; returns what the data-plane role must do.
    auto device_released(FunctionId id) -> std::expected<CleaningAction, PoolError>;
    // power_cycle_done also returns the cleaning action, since the function
    // goes back to `cleaning`.
    auto power_cycle_done(FunctionId id) -> std::expected<CleaningAction, PoolError>;
    // Any other event (reset_failed, clean_done, scrub_done, clean_failed,
    // timed_out, attach_failed). Rejects assign and release, which need a VM.
    auto apply(FunctionId id, PoolEvent event) -> std::expected<FunctionState, PoolError>;

    // Releases every function `vm` holds (DESTROY_VM). Returns them in id order.
    auto release_all(VmId vm) -> std::vector<FunctionId>;

    [[nodiscard]] auto find(FunctionId id) const -> std::optional<FunctionInfo>;
    [[nodiscard]] auto held_by(VmId vm) const -> std::vector<FunctionId>;
    // Every function, in id order.
    [[nodiscard]] auto all() const -> std::vector<FunctionInfo>;
    // First free function of `type`, in id order.
    [[nodiscard]] auto first_free(FunctionType type) const -> std::optional<FunctionId>;
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _functions.size(); }

private:
    struct Entry {
        FunctionType type;
        FunctionState state;
        std::optional<VmId> owner;
    };

    auto step(FunctionId id, PoolEvent event) -> std::expected<Entry*, PoolError>;

    std::map<FunctionId, Entry> _functions;
};

}  // namespace ak::helm
