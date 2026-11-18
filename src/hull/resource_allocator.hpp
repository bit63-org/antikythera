// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ResourceAllocator: hands each VM whole physical cores and 1 GiB huge
// pages (.kiro/specs/hull-host-agent/ Requirements 6.1 and 8.1).
//
// - Cores are allocated whole: every SMT sibling of a core goes to the same
//   VM, so no two VMs ever share a core's caches and execution units. A VM
//   asking for an odd vCPU count on a 2-way SMT host gets the extra thread
//   in its cpuset; it is idle rather than lent to a neighbour.
// - A core is a guest core only if every one of its siblings is in the
//   guest set (the kernel's isolated CPUs). A core with any host sibling
//   stays with the host.
// - Memory is whole 1 GiB pages: memory_mib rounds up to the next GiB.
// - allocate() checks cores and pages before taking either, so a refused
//   request leaves nothing allocated (Requirement 8.1).
//
// The allocator is pure bookkeeping: it does not touch cgroups or sysfs.
// The VmSupervisor (task 8) writes the returned cpuset and sizes Cloud
// Hypervisor's memory from it. It does not track NUMA nodes yet; every core
// and page is one pool.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "hull/cpu_topology.hpp"

namespace ak::hull {

using VmId = std::uint64_t;

inline constexpr std::uint64_t hugepage_bytes = std::uint64_t{1} << 30U;
inline constexpr std::uint32_t mib_per_hugepage = 1024;

enum class AllocError : std::uint8_t {
    invalid_request,         // vm_id, vcpus or memory_mib is 0
    already_allocated,       // this vm_id already holds resources
    insufficient_cores,      // not enough free whole cores
    insufficient_hugepages,  // not enough free 1 GiB pages
    unknown_vm,              // release() of a vm_id that holds nothing
};

[[nodiscard]] auto to_string(AllocError e) noexcept -> const char*;

struct Allocation {
    VmId vm_id{0};
    std::uint16_t vcpus{0};      // as requested; <= cpus.size()
    std::vector<CpuId> cpus;     // the VM's cpuset, ascending, whole cores
    std::uint32_t hugepages{0};  // 1 GiB pages

    [[nodiscard]] auto memory_bytes() const noexcept -> std::uint64_t {
        return std::uint64_t{hugepages} * hugepage_bytes;
    }
    friend auto operator==(const Allocation&, const Allocation&) -> bool = default;
};

class ResourceAllocator {
public:
    // `guest_cpus`: the logical CPUs guests may use (normally the isolated
    // set). `hugepages`: the free 1 GiB pages at agent start.
    ResourceAllocator(const CpuTopology& topology, std::span<const CpuId> guest_cpus,
                      std::uint32_t hugepages);

    // Takes enough whole free cores to cover `vcpus` threads (lowest
    // numbered first) and ceil(memory_mib / 1024) pages, or nothing.
    [[nodiscard]] auto allocate(VmId vm_id, std::uint16_t vcpus, std::uint32_t memory_mib)
        -> std::expected<Allocation, AllocError>;

    // Returns every core and page `vm_id` held to the pool, and what it held.
    [[nodiscard]] auto release(VmId vm_id) -> std::expected<Allocation, AllocError>;

    [[nodiscard]] auto find(VmId vm_id) const -> const Allocation*;

    [[nodiscard]] auto guest_cores() const noexcept -> std::size_t { return _cores.size(); }
    [[nodiscard]] auto free_cores() const noexcept -> std::size_t;
    [[nodiscard]] auto free_threads() const noexcept -> std::size_t;
    [[nodiscard]] auto total_hugepages() const noexcept -> std::uint32_t { return _hugepages; }
    [[nodiscard]] auto free_hugepages() const noexcept -> std::uint32_t { return _free_hugepages; }

private:
    struct GuestCore {
        std::vector<CpuId> cpus;
        std::optional<VmId> owner;
    };

    std::vector<GuestCore> _cores;
    std::uint32_t _hugepages;
    std::uint32_t _free_hugepages;
    std::map<VmId, Allocation> _allocations;
};

}  // namespace ak::hull
