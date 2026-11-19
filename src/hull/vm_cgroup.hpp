// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The per-VM cgroup v2 node (.kiro/specs/hull-host-agent/ task 7,
// Requirements 6.1 and 9.1): the VMM's cores (cpuset), its 1 GiB huge
// pages (hugetlb), a process cap (pids) and optionally a ceiling on its
// ordinary memory (memory).
//
// Layout: the agent owns one parent cgroup (for example
// /sys/fs/cgroup/hull) with the cpuset, hugetlb, pids and memory
// controllers enabled for its children, and creates one child "vm-<id>"
// per VM. The jail places the VMM in that child atomically at creation
// (clone3 CLONE_INTO_CGROUP with VmCgroup::fd()), so the VMM never runs a
// single instruction outside its limits.
//
// The limits come straight from the ResourceAllocator's Allocation; this
// file does no accounting of its own.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "hull/cpu_topology.hpp"
#include "hull/resource_allocator.hpp"

namespace ak::hull {

struct CgroupLimits {
    std::vector<CpuId> cpus;                  // cpuset.cpus: the VM's cores, strictly ascending
    std::string mems{"0"};                    // cpuset.mems: NUMA nodes (one pool until NUMA lands)
    std::uint32_t hugepages{0};               // hugetlb.1GB.max, in 1 GiB pages
    std::uint32_t pids_max{0};                // pids.max; 0 writes nothing (inherit)
    std::optional<std::uint64_t> memory_max;  // memory.max in bytes (VMM overhead only:
                                              // hugetlb pages are not charged to memory)

    friend auto operator==(const CgroupLimits&, const CgroupLimits&) -> bool = default;
};

// Limits for one allocation: its cpuset and pages, with the given process
// cap and memory ceiling.
[[nodiscard]] auto limits_for(const Allocation& allocation, std::uint32_t pids_max,
                              std::optional<std::uint64_t> memory_max) -> CgroupLimits;

enum class CgroupError : std::uint8_t {
    invalid_limits,  // empty or unordered cpuset, empty mems, zero pages
    open_failed,     // the parent directory or a control file cannot be opened
    already_exists,  // vm-<id> exists: a stale VM must be removed first
    mkdir_failed,    // creating vm-<id> failed for another reason
    write_failed,    // the kernel refused a control-file value
    remove_failed,   // rmdir failed (EBUSY while a process is still inside)
};

[[nodiscard]] auto to_string(CgroupError e) noexcept -> const char*;

struct CgroupFailure {
    CgroupError error{CgroupError::invalid_limits};
    std::string file;  // the control file or directory involved, if any
    int sys_errno{0};
};

// The control-file writes for `limits`, in the order they must happen
// (cpuset.mems before cpuset.cpus is not required by cgroup v2, but the
// order is fixed so tests and logs are stable).
[[nodiscard]] auto cgroup_writes(const CgroupLimits& limits)
    -> std::expected<std::vector<std::pair<std::string, std::string>>, CgroupFailure>;

// Writes `limits` into the cgroup directory `dir_fd`. Control files are
// opened without O_CREAT: on cgroupfs they always exist when the
// controller is enabled, and a missing file means a missing controller.
[[nodiscard]] auto write_cgroup_limits(int dir_fd, const CgroupLimits& limits)
    -> std::expected<void, CgroupFailure>;

// Enables the controllers the VM cgroups need in `parent_fd`'s
// cgroup.subtree_control ("+cpuset +hugetlb +pids +memory").
[[nodiscard]] auto enable_vm_controllers(int parent_fd) -> std::expected<void, CgroupFailure>;

// A created "vm-<id>" cgroup. Move-only; the destructor removes the
// directory best-effort (it fails harmlessly while a process remains).
class VmCgroup {
public:
    // mkdir parent/vm-<id>, then write the limits. On any failure the new
    // directory is removed again, so a refused create leaves nothing.
    [[nodiscard]] static auto create(int parent_fd, VmId vm_id, const CgroupLimits& limits)
        -> std::expected<VmCgroup, CgroupFailure>;

    VmCgroup(const VmCgroup&) = delete;
    auto operator=(const VmCgroup&) -> VmCgroup& = delete;
    VmCgroup(VmCgroup&& other) noexcept;
    auto operator=(VmCgroup&& other) noexcept -> VmCgroup&;
    ~VmCgroup();

    // The cgroup directory, open O_DIRECTORY for CLONE_INTO_CGROUP.
    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }
    [[nodiscard]] auto name() const noexcept -> const std::string& { return _name; }

    // rmdir the cgroup. Fails with remove_failed while the VMM (or any
    // process) is still in it; the handle stays valid then.
    [[nodiscard]] auto remove() -> std::expected<void, CgroupFailure>;

private:
    VmCgroup(int parent_fd, int fd, std::string name) noexcept
        : _parent_fd{parent_fd}, _fd{fd}, _name{std::move(name)} {}
    void reset() noexcept;

    int _parent_fd{-1};  // a dup of the caller's parent fd
    int _fd{-1};
    std::string _name;
};

}  // namespace ak::hull
