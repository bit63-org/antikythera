// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ Requirements 6.1 (whole cores, no SMT
// sibling shared between VMs; 1 GiB pages) and 8.1 (refuse without partial
// allocation).

#define BOOST_TEST_MODULE resource_allocator_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <random>
#include <set>
#include <vector>

#include "hull/cpu_topology.hpp"
#include "hull/resource_allocator.hpp"
#include "test_support.hpp"

using ak::hull::AllocError;
using ak::hull::CpuId;
using ak::hull::CpuTopology;
using ak::hull::ResourceAllocator;
using ak::hull::VmId;
using ak::test::unit_timeout_seconds;

namespace {

auto ids(std::initializer_list<CpuId> l) -> std::vector<CpuId> {
    return l;
}

// 4 cores x 2 threads, siblings n and n+4: cores {0,4} {1,5} {2,6} {3,7}.
auto smt_host() -> CpuTopology {
    return *CpuTopology::from_cores({{0, 4}, {1, 5}, {2, 6}, {3, 7}});
}

// Host keeps core {0,4}; the other three cores are isolated for guests.
const std::vector<CpuId> guest_set{1, 2, 3, 5, 6, 7};

constexpr VmId vm_one = 1;
constexpr VmId vm_two = 2;
constexpr VmId vm_three = 3;

}  // namespace

BOOST_AUTO_TEST_SUITE(resource_allocator, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(only_fully_isolated_cores_are_guest_cores) {
    // cpu 6 is not isolated, so core {2,6} stays with the host too.
    const std::vector<CpuId> partial{1, 2, 3, 5, 7};
    ResourceAllocator a{smt_host(), partial, 4};
    BOOST_TEST(a.guest_cores() == 2U);
    BOOST_TEST(a.free_threads() == 4U);
    auto got = a.allocate(vm_one, 4, 1024);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(got->cpus == ids({1, 3, 5, 7}), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(allocates_whole_cores_with_siblings) {
    ResourceAllocator a{smt_host(), guest_set, 8};
    BOOST_TEST(a.guest_cores() == 3U);

    // 3 vCPUs on 2-way SMT: two whole cores, the spare thread stays in the
    // VM's cpuset rather than going to a neighbour.
    auto one = a.allocate(vm_one, 3, 2048);
    BOOST_REQUIRE(one.has_value());
    BOOST_TEST(one->vcpus == 3U);
    BOOST_TEST(one->cpus == ids({1, 2, 5, 6}), boost::test_tools::per_element());
    BOOST_TEST(one->hugepages == 2U);
    BOOST_TEST(one->memory_bytes() == 2ULL << 30U);

    auto two = a.allocate(vm_two, 1, 1024);
    BOOST_REQUIRE(two.has_value());
    BOOST_TEST(two->cpus == ids({3, 7}), boost::test_tools::per_element());

    BOOST_TEST(a.free_cores() == 0U);
    BOOST_TEST(a.free_hugepages() == 5U);
    BOOST_TEST((*a.find(vm_one) == *one));
    BOOST_TEST(a.find(vm_three) == nullptr);
}

BOOST_AUTO_TEST_CASE(rounds_memory_up_to_whole_gib) {
    ResourceAllocator a{smt_host(), guest_set, 8};
    BOOST_TEST(a.allocate(vm_one, 1, 1)->hugepages == 1U);
    BOOST_TEST(a.allocate(vm_two, 1, 1025)->hugepages == 2U);
    BOOST_TEST(a.allocate(vm_three, 1, 3072)->hugepages == 3U);
    BOOST_TEST(a.free_hugepages() == 2U);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_and_duplicate_requests) {
    ResourceAllocator a{smt_host(), guest_set, 8};
    BOOST_TEST((a.allocate(0, 1, 1024).error() == AllocError::invalid_request));
    BOOST_TEST((a.allocate(vm_one, 0, 1024).error() == AllocError::invalid_request));
    BOOST_TEST((a.allocate(vm_one, 1, 0).error() == AllocError::invalid_request));
    BOOST_REQUIRE(a.allocate(vm_one, 1, 1024).has_value());
    BOOST_TEST((a.allocate(vm_one, 1, 1024).error() == AllocError::already_allocated));
    BOOST_TEST(a.free_cores() == 2U);
    BOOST_TEST(a.free_hugepages() == 7U);
}

BOOST_AUTO_TEST_CASE(refuses_without_partial_allocation) {
    ResourceAllocator a{smt_host(), guest_set, 4};
    // Enough cores, too little memory: no core may be taken.
    BOOST_TEST((a.allocate(vm_one, 2, 5 * 1024).error() == AllocError::insufficient_hugepages));
    BOOST_TEST(a.free_cores() == 3U);
    BOOST_TEST(a.free_hugepages() == 4U);
    // Enough memory, too few cores: no page may be taken.
    BOOST_TEST((a.allocate(vm_one, 7, 1024).error() == AllocError::insufficient_cores));
    BOOST_TEST(a.free_cores() == 3U);
    BOOST_TEST(a.free_hugepages() == 4U);
    BOOST_TEST(a.find(vm_one) == nullptr);
    // The exact fit still succeeds afterwards.
    BOOST_TEST(a.allocate(vm_one, 6, 4 * 1024).has_value());
}

BOOST_AUTO_TEST_CASE(release_returns_resources) {
    ResourceAllocator a{smt_host(), guest_set, 4};
    const auto one = *a.allocate(vm_one, 2, 2048);
    const auto two = *a.allocate(vm_two, 4, 2048);
    BOOST_TEST((a.allocate(vm_three, 1, 1024).error() == AllocError::insufficient_cores));

    auto released = a.release(vm_one);
    BOOST_REQUIRE(released.has_value());
    BOOST_TEST((*released == one));
    BOOST_TEST(a.free_cores() == 1U);
    BOOST_TEST(a.free_hugepages() == 2U);
    BOOST_TEST((a.release(vm_one).error() == AllocError::unknown_vm));

    // The freed core is reused; vm_two is untouched.
    auto three = a.allocate(vm_three, 2, 2048);
    BOOST_REQUIRE(three.has_value());
    BOOST_TEST(three->cpus == one.cpus, boost::test_tools::per_element());
    BOOST_TEST((*a.find(vm_two) == two));
}

BOOST_AUTO_TEST_CASE(non_smt_and_mixed_cores) {
    // A hybrid part: two 2-thread cores and two 1-thread cores.
    const auto t = *CpuTopology::from_cores({{0, 1}, {2, 3}, {4}, {5}});
    const std::vector<CpuId> all{0, 1, 2, 3, 4, 5};
    ResourceAllocator a{t, all, 8};
    BOOST_TEST(a.allocate(vm_one, 3, 1024)->cpus == ids({0, 1, 2, 3}),
               boost::test_tools::per_element());
    BOOST_TEST(a.allocate(vm_two, 2, 1024)->cpus == ids({4, 5}), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(random_operations_keep_invariants) {
    constexpr std::uint32_t seed = 20261118;
    constexpr int steps = 20000;
    constexpr VmId vms = 6;
    constexpr std::uint32_t pages = 12;

    std::vector<std::vector<CpuId>> cores;
    std::map<CpuId, std::size_t> core_of;
    for (CpuId c = 0; c < 8; ++c) {
        cores.push_back({c, c + 8});
        core_of[c] = c;
        core_of[c + 8] = c;
    }
    std::vector<CpuId> guest;
    for (CpuId c = 1; c < 16; ++c) {
        if (c != 8) {
            guest.push_back(c);  // core {0,8} is the host's
        }
    }
    ResourceAllocator a{*CpuTopology::from_cores(cores), guest, pages};

    std::mt19937 rng{seed};
    std::map<VmId, ak::hull::Allocation> model;
    for (int i = 0; i < steps; ++i) {
        const VmId vm = 1 + (rng() % vms);
        if (rng() % 2 == 0) {
            const auto vcpus = static_cast<std::uint16_t>(1 + (rng() % 6));
            const auto mib = static_cast<std::uint32_t>(1 + (rng() % (4 * 1024)));
            const auto before_cores = a.free_cores();
            const auto before_pages = a.free_hugepages();
            auto got = a.allocate(vm, vcpus, mib);
            if (got) {
                BOOST_REQUIRE(!model.contains(vm));
                BOOST_REQUIRE_GE(got->cpus.size(), vcpus);
                model[vm] = *got;
            } else {
                BOOST_REQUIRE_EQUAL(a.free_cores(), before_cores);
                BOOST_REQUIRE_EQUAL(a.free_hugepages(), before_pages);
                if (got.error() == AllocError::already_allocated) {
                    BOOST_REQUIRE(model.contains(vm));
                } else if (got.error() == AllocError::insufficient_cores) {
                    BOOST_REQUIRE_LT(a.free_threads(), vcpus);
                }
            }
        } else {
            auto got = a.release(vm);
            BOOST_REQUIRE_EQUAL(got.has_value(), model.contains(vm));
            if (got) {
                BOOST_REQUIRE(*got == model[vm]);
                model.erase(vm);
            }
        }

        // Every guest CPU in at most one VM; no core split between VMs or
        // shared with the host; page and core accounting adds up.
        std::set<CpuId> used;
        std::map<std::size_t, VmId> core_owner;
        std::uint32_t used_pages = 0;
        for (const auto& [id, alloc] : model) {
            used_pages += alloc.hugepages;
            for (const auto c : alloc.cpus) {
                BOOST_REQUIRE(used.insert(c).second);
                BOOST_REQUIRE(c != 0 && c != 8);
                const auto [it, fresh] = core_owner.try_emplace(core_of[c], id);
                BOOST_REQUIRE(fresh || it->second == id);
            }
        }
        BOOST_REQUIRE_EQUAL(used.size() % 2, 0U);
        BOOST_REQUIRE_EQUAL(a.free_hugepages(), pages - used_pages);
        BOOST_REQUIRE_EQUAL(a.free_cores(), a.guest_cores() - core_owner.size());
    }
}

BOOST_AUTO_TEST_SUITE_END()
