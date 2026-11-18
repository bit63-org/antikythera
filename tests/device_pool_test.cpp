// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 3 and 10.2;
// .kiro/specs/oar-gpu-data-plane/ Requirements 2.2 and 3.

#define BOOST_TEST_MODULE device_pool_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <optional>
#include <random>
#include <set>
#include <vector>

#include "helm/device_pool.hpp"
#include "test_support.hpp"

using ak::helm::CleaningAction;
using ak::helm::DevicePool;
using ak::helm::FunctionId;
using ak::helm::FunctionState;
using ak::helm::FunctionType;
using ak::helm::PoolError;
using ak::helm::PoolEvent;
using ak::helm::VmId;
using ak::test::unit_timeout_seconds;

namespace {

constexpr FunctionId fn_a{7};
constexpr FunctionId fn_b{8};
constexpr FunctionId fn_c{9};
constexpr FunctionId missing_fn{404};
constexpr VmId vm_one = 1;
constexpr VmId vm_two = 2;

constexpr std::uint32_t random_seed = 20261118;
constexpr int random_steps = 20000;
constexpr std::uint32_t random_functions = 6;
constexpr VmId random_vms = 3;

// Independent statement of the legal moves (Requirement 3 and the design's
// diagram), written as a switch so it does not share code or shape with
// transition_table.
auto expected_next(FunctionType type, FunctionState from, PoolEvent event)
    -> std::optional<FunctionState> {
    const bool gpu = type == FunctionType::gpu_whole || type == FunctionType::gpu_vf;
    switch (from) {
        case FunctionState::free:
            if (event == PoolEvent::assign) {
                return FunctionState::assigned;
            }
            break;
        case FunctionState::assigned:
            if (event == PoolEvent::release) {
                return FunctionState::releasing;
            }
            break;
        case FunctionState::releasing:
            if (event == PoolEvent::device_released) {
                return FunctionState::cleaning;
            }
            if (event == PoolEvent::reset_failed || event == PoolEvent::timed_out) {
                return FunctionState::faulted;
            }
            break;
        case FunctionState::cleaning:
            if ((event == PoolEvent::clean_done && !gpu) ||
                (event == PoolEvent::scrub_done && gpu)) {
                return FunctionState::free;
            }
            if (event == PoolEvent::clean_failed || event == PoolEvent::timed_out) {
                return FunctionState::faulted;
            }
            break;
        case FunctionState::faulted:
            if (event == PoolEvent::power_cycle_done) {
                return FunctionState::cleaning;
            }
            break;
    }
    return std::nullopt;
}

auto finish_cleaning(FunctionType type) -> PoolEvent {
    return ak::helm::is_gpu(type) ? PoolEvent::scrub_done : PoolEvent::clean_done;
}

// Adds `id` and drives it into `target` through legal moves only.
auto pool_with(FunctionId id, FunctionType type, FunctionState target) -> DevicePool {
    DevicePool pool;
    BOOST_REQUIRE(pool.add(id, type));
    switch (target) {
        case FunctionState::cleaning:
            break;
        case FunctionState::faulted:
            BOOST_REQUIRE(pool.apply(id, PoolEvent::clean_failed));
            break;
        case FunctionState::free:
        case FunctionState::assigned:
        case FunctionState::releasing:
            BOOST_REQUIRE(pool.apply(id, finish_cleaning(type)));
            if (target != FunctionState::free) {
                BOOST_REQUIRE(pool.assign(id, vm_one));
            }
            if (target == FunctionState::releasing) {
                BOOST_REQUIRE(pool.release(id, vm_one));
            }
            break;
    }
    BOOST_REQUIRE(pool.find(id)->state == target);
    return pool;
}

// Sends `event` through whichever DevicePool entry point takes it.
auto send(DevicePool& pool, FunctionId id, PoolEvent event, VmId vm) -> bool {
    switch (event) {
        case PoolEvent::assign:
            return pool.assign(id, vm).has_value();
        case PoolEvent::release:
            return pool.release(id, vm).has_value();
        case PoolEvent::device_released:
            return pool.device_released(id).has_value();
        case PoolEvent::power_cycle_done:
            return pool.power_cycle_done(id).has_value();
        default:
            return pool.apply(id, event).has_value();
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(next_state_matches_the_spec_for_every_move,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto type : ak::helm::all_function_types) {
        for (const auto from : ak::helm::all_function_states) {
            for (const auto event : ak::helm::all_pool_events) {
                BOOST_TEST_CONTEXT(to_string(type)
                                   << " " << to_string(from) << " + " << to_string(event)) {
                    BOOST_TEST((ak::helm::next_state(type, from, event) ==
                                expected_next(type, from, event)));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(pool_applies_legal_moves_and_refuses_illegal_ones,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto type : ak::helm::all_function_types) {
        for (const auto from : ak::helm::all_function_states) {
            for (const auto event : ak::helm::all_pool_events) {
                BOOST_TEST_CONTEXT(to_string(type)
                                   << " " << to_string(from) << " + " << to_string(event)) {
                    auto pool = pool_with(fn_a, type, from);
                    const auto before = *pool.find(fn_a);
                    const auto want = expected_next(type, from, event);
                    BOOST_TEST(send(pool, fn_a, event, vm_one) == want.has_value());
                    const auto after = *pool.find(fn_a);
                    if (want) {
                        BOOST_TEST((after.state == *want));
                    } else {
                        // Illegal moves change nothing, owner included.
                        BOOST_TEST((after.state == before.state));
                        BOOST_TEST((after.owner == before.owner));
                    }
                    const bool held = after.state == FunctionState::assigned ||
                                      after.state == FunctionState::releasing;
                    BOOST_TEST(after.owner.has_value() == held);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(table_rows_name_a_type_and_change_state,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto& row : ak::helm::transition_table) {
        bool some_type = false;
        for (const auto type : ak::helm::all_function_types) {
            some_type = some_type || (row.types & ak::helm::type_bit(type)) != 0;
        }
        BOOST_TEST(some_type);
        BOOST_TEST((row.from != row.to));
    }
}

BOOST_AUTO_TEST_CASE(new_functions_start_in_cleaning,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    DevicePool pool;
    const auto action = pool.add(fn_a, FunctionType::blk_fn);
    BOOST_REQUIRE(action);
    BOOST_TEST((*action == CleaningAction::drop_volume_key));
    BOOST_TEST((pool.find(fn_a)->state == FunctionState::cleaning));
    BOOST_TEST(!pool.first_free(FunctionType::blk_fn).has_value());
    BOOST_TEST(!pool.assign(fn_a, vm_one));
}

BOOST_AUTO_TEST_CASE(duplicate_and_unknown_functions_are_rejected,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    DevicePool pool;
    BOOST_REQUIRE(pool.add(fn_a, FunctionType::nic_vf));
    const auto dup = pool.add(fn_a, FunctionType::gpu_vf);
    BOOST_REQUIRE(!dup);
    BOOST_TEST((dup.error() == PoolError::duplicate_function));
    BOOST_TEST((pool.find(fn_a)->type == FunctionType::nic_vf));
    BOOST_TEST(pool.size() == 1U);

    BOOST_TEST((pool.assign(missing_fn, vm_one).error() == PoolError::unknown_function));
    BOOST_TEST((pool.release(missing_fn, vm_one).error() == PoolError::unknown_function));
    BOOST_TEST((pool.device_released(missing_fn).error() == PoolError::unknown_function));
    BOOST_TEST((pool.power_cycle_done(missing_fn).error() == PoolError::unknown_function));
    BOOST_TEST(
        (pool.apply(missing_fn, PoolEvent::clean_done).error() == PoolError::unknown_function));
    BOOST_TEST(!pool.find(missing_fn).has_value());
}

BOOST_AUTO_TEST_CASE(a_function_is_never_in_two_vms,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pool = pool_with(fn_a, FunctionType::nic_vf, FunctionState::free);
    BOOST_REQUIRE(pool.assign(fn_a, vm_one));
    BOOST_TEST((pool.assign(fn_a, vm_two).error() == PoolError::illegal_transition));
    BOOST_TEST((pool.find(fn_a)->owner == vm_one));

    // Only the holder can release it.
    BOOST_TEST((pool.release(fn_a, vm_two).error() == PoolError::wrong_vm));
    BOOST_TEST((pool.find(fn_a)->state == FunctionState::assigned));
    BOOST_REQUIRE(pool.release(fn_a, vm_one));

    // Still owned (and not assignable) until hull confirms the reset.
    BOOST_TEST((pool.find(fn_a)->owner == vm_one));
    BOOST_TEST((pool.assign(fn_a, vm_two).error() == PoolError::illegal_transition));
}

BOOST_AUTO_TEST_CASE(release_cleans_before_free_for_every_type,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto action_for = [](FunctionType t) {
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
        return CleaningAction::scrub_gpu;
    };
    for (const auto type : ak::helm::all_function_types) {
        BOOST_TEST_CONTEXT(to_string(type)) {
            auto pool = pool_with(fn_a, type, FunctionState::releasing);
            const auto action = pool.device_released(fn_a);
            BOOST_REQUIRE(action);
            BOOST_TEST((*action == action_for(type)));
            BOOST_TEST((pool.find(fn_a)->state == FunctionState::cleaning));
            BOOST_TEST(!pool.find(fn_a)->owner.has_value());
            BOOST_TEST(!pool.first_free(type).has_value());
            BOOST_REQUIRE(pool.apply(fn_a, finish_cleaning(type)));
            BOOST_TEST((pool.first_free(type) == fn_a));
        }
    }
}

BOOST_AUTO_TEST_CASE(gpu_needs_scrub_done_and_others_need_clean_done,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto gpu = pool_with(fn_a, FunctionType::gpu_whole, FunctionState::cleaning);
    BOOST_TEST((gpu.apply(fn_a, PoolEvent::clean_done).error() == PoolError::illegal_transition));
    BOOST_TEST((gpu.find(fn_a)->state == FunctionState::cleaning));

    auto nic = pool_with(fn_a, FunctionType::nic_vf, FunctionState::cleaning);
    BOOST_TEST((nic.apply(fn_a, PoolEvent::scrub_done).error() == PoolError::illegal_transition));
    BOOST_TEST((nic.find(fn_a)->state == FunctionState::cleaning));
}

BOOST_AUTO_TEST_CASE(faulted_functions_need_a_power_cycle_and_a_clean,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pool = pool_with(fn_a, FunctionType::gpu_vf, FunctionState::releasing);
    BOOST_REQUIRE(pool.device_released(fn_a));
    BOOST_TEST((*pool.apply(fn_a, PoolEvent::timed_out) == FunctionState::faulted));
    BOOST_TEST(!pool.assign(fn_a, vm_two));
    BOOST_TEST(!pool.apply(fn_a, PoolEvent::scrub_done));

    const auto action = pool.power_cycle_done(fn_a);
    BOOST_REQUIRE(action);
    BOOST_TEST((*action == CleaningAction::scrub_gpu_vf));
    BOOST_TEST((pool.find(fn_a)->state == FunctionState::cleaning));
    BOOST_REQUIRE(pool.apply(fn_a, PoolEvent::scrub_done));
    BOOST_TEST(pool.assign(fn_a, vm_two).has_value());
}

BOOST_AUTO_TEST_CASE(apply_refuses_events_that_need_a_vm,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pool = pool_with(fn_a, FunctionType::nic_vf, FunctionState::free);
    BOOST_TEST((pool.apply(fn_a, PoolEvent::assign).error() == PoolError::illegal_transition));
    BOOST_REQUIRE(pool.assign(fn_a, vm_one));
    BOOST_TEST((pool.apply(fn_a, PoolEvent::release).error() == PoolError::illegal_transition));
    BOOST_TEST((pool.find(fn_a)->state == FunctionState::assigned));
}

BOOST_AUTO_TEST_CASE(release_all_releases_only_that_vms_assigned_functions,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    DevicePool pool;
    for (const auto id : {fn_a, fn_b, fn_c}) {
        BOOST_REQUIRE(pool.add(id, FunctionType::nic_vf));
        BOOST_REQUIRE(pool.apply(id, PoolEvent::clean_done));
    }
    BOOST_REQUIRE(pool.assign(fn_a, vm_one));
    BOOST_REQUIRE(pool.assign(fn_b, vm_two));
    BOOST_REQUIRE(pool.assign(fn_c, vm_one));
    BOOST_REQUIRE(pool.release(fn_c, vm_one));  // already releasing

    const auto released = pool.release_all(vm_one);
    BOOST_TEST((released == std::vector{fn_a}));
    BOOST_TEST((pool.find(fn_a)->state == FunctionState::releasing));
    BOOST_TEST((pool.find(fn_b)->state == FunctionState::assigned));
    BOOST_TEST((pool.held_by(vm_one) == std::vector{fn_a, fn_c}));
    BOOST_TEST(pool.release_all(vm_one).empty());
}

// Random event storm: whatever arrives, in any order, the invariants hold.
BOOST_AUTO_TEST_CASE(invariants_hold_under_random_events,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::mt19937 rng(random_seed);
    std::uniform_int_distribution<std::uint32_t> pick_fn(0, random_functions - 1);
    std::uniform_int_distribution<std::size_t> pick_event(0, ak::helm::all_pool_events.size() - 1);
    std::uniform_int_distribution<VmId> pick_vm(1, random_vms);

    DevicePool pool;
    for (std::uint32_t i = 0; i < random_functions; ++i) {
        const auto type = ak::helm::all_function_types[i % ak::helm::all_function_types.size()];
        BOOST_REQUIRE(pool.add(FunctionId{i}, type));
    }
    // A function that reaches `free` must have passed through `cleaning`
    // since it was last assigned.
    std::set<std::uint32_t> dirty;

    for (int step = 0; step < random_steps; ++step) {
        const auto raw = pick_fn(rng);
        const FunctionId id{raw};
        const auto event = ak::helm::all_pool_events[pick_event(rng)];
        const auto before = *pool.find(id);
        const bool ok = send(pool, id, event, pick_vm(rng));
        const auto after = *pool.find(id);

        if (!ok) {
            BOOST_REQUIRE((after.state == before.state));
            BOOST_REQUIRE((after.owner == before.owner));
            continue;
        }
        BOOST_REQUIRE((ak::helm::next_state(before.type, before.state, event) == after.state));
        if (after.state == FunctionState::assigned) {
            dirty.insert(raw);
        }
        if (after.state == FunctionState::cleaning) {
            dirty.erase(raw);
        }
        if (after.state == FunctionState::free) {
            BOOST_REQUIRE(!dirty.contains(raw));
        }
        const bool held =
            after.state == FunctionState::assigned || after.state == FunctionState::releasing;
        BOOST_REQUIRE(after.owner.has_value() == held);
    }
}
