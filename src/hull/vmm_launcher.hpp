// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Starting one jailed Cloud Hypervisor per VM (.kiro/specs/hull-host-agent/
// task 8, Requirements 6.1 and 9.1; design.md "VmSupervisor").
//
// VmmLauncher is the supervisor's only way to start a VMM, and VmmHandle its
// only hold on a running one, so the supervisor's logic is tested with
// fakes and the jail is tested on its own. JailedVmmLauncher is the real
// one. For each VM it:
//
//   1. takes a UID/GID pair from the UidPool;
//   2. makes the VM's run directory <run_dir>/vm-<id> (0700, owned by that
//      UID), which holds only the API socket;
//   3. creates the VM's cgroup from its Allocation (cpuset, 1 GiB pages,
//      a process cap, optionally a memory ceiling for the VMM itself);
//   4. starts cloud-hypervisor in a jail (jail.hpp) that may touch only the
//      VMM binary, /dev/kvm, /dev/vfio, /dev/urandom (virtio-rng, see
//      ch_config.hpp), /sys read-only (Cloud Hypervisor reads a passed-
//      through function's sysfs node), the boot payload and the run
//      directory, with RLIMIT_MEMLOCK covering the guest's memory (VFIO
//      pins it all) plus a margin;
//   5. waits until the API socket answers vmm.ping.
//
// Any failure undoes the steps before it. The handle undoes them all when
// it is destroyed: the VMM is killed and reaped, then the cgroup, the run
// directory and the UID are released, in that order.
//
// The /dev/vfio rule covers the whole directory because functions are
// hot-plugged after the VMM has started and Landlock cannot be widened
// afterwards. A VFIO group node is mode 0600 root-owned until the agent
// assigns its function (task 9 hands the node to the VM's UID for exactly
// as long as the VM holds the function), and the VMM has no capabilities,
// so the rule lets it open only its own functions' groups.

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "hull/ch_config.hpp"
#include "hull/jail.hpp"
#include "hull/resource_allocator.hpp"
#include "hull/vmm_api.hpp"

namespace ak::hull {

class VmmHandle {
public:
    VmmHandle() = default;
    VmmHandle(const VmmHandle&) = delete;
    auto operator=(const VmmHandle&) -> VmmHandle& = delete;
    VmmHandle(VmmHandle&&) = delete;
    auto operator=(VmmHandle&&) -> VmmHandle& = delete;
    // Kills and reaps a VMM that is still running, then releases everything
    // the launch took.
    virtual ~VmmHandle() = default;

    // Readable once the VMM has exited (poll(2)); -1 if there is none.
    [[nodiscard]] virtual auto pidfd() const noexcept -> int = 0;
    [[nodiscard]] virtual auto api() -> VmmApi& = 0;
    // Hands the VFIO group node of a function being assigned to the VM's
    // UID (0600), or back to root once the VMM no longer holds it. The jail
    // lets the VMM reach /dev/vfio as a whole; this ownership is what
    // limits it to its own functions.
    [[nodiscard]] virtual auto grant_group(std::uint32_t iommu_group) -> bool = 0;
    virtual auto revoke_group(std::uint32_t iommu_group) -> bool = 0;
    // SIGKILL; harmless if it already exited.
    virtual auto kill() -> void = 0;
    // Blocks until the VMM exits and reaps it: its wait status in
    // waitpid(2) form. Call once.
    [[nodiscard]] virtual auto wait() -> std::expected<int, int> = 0;
};

enum class LaunchError : std::uint8_t {
    no_ids,         // the UidPool is exhausted
    run_dir,        // creating the run directory failed
    cgroup,         // creating or limiting the cgroup failed
    jail,           // spawn_jailed failed
    exited,         // the VMM exited before its API answered
    api_timed_out,  // the API did not answer within start_timeout
};

[[nodiscard]] auto to_string(LaunchError e) noexcept -> const char*;

struct LaunchFailure {
    LaunchError error{LaunchError::jail};
    std::string detail;
    int sys_errno{0};
};

class VmmLauncher {
public:
    VmmLauncher() = default;
    VmmLauncher(const VmmLauncher&) = delete;
    auto operator=(const VmmLauncher&) -> VmmLauncher& = delete;
    VmmLauncher(VmmLauncher&&) = delete;
    auto operator=(VmmLauncher&&) -> VmmLauncher& = delete;
    virtual ~VmmLauncher() = default;

    // A VMM for `allocation`, with its API answering and no VM created yet.
    [[nodiscard]] virtual auto launch(const Allocation& allocation)
        -> std::expected<std::unique_ptr<VmmHandle>, LaunchFailure> = 0;
};

// The paths every production VMM may use besides its binary, payload and
// run directory.
[[nodiscard]] auto default_vmm_paths() -> std::vector<PathRule>;

struct VmmLaunchConfig {
    std::filesystem::path cloud_hypervisor{"/usr/bin/cloud-hypervisor"};
    BootPayload payload;  // its files become read-only rules
    std::filesystem::path run_dir{"/run/hull"};
    // Where VFIO group nodes live; empty: grant_group and revoke_group do
    // nothing (tests without VFIO).
    std::filesystem::path vfio_dir{"/dev/vfio"};
    std::vector<PathRule> paths{default_vmm_paths()};  // tests replace these
    std::vector<PathRule> extra_paths;                 // e.g. shared libraries of a dynamic VMM

    int cgroup_parent_fd{-1};                 // -1: no per-VM cgroup (tests)
    std::uint32_t pids_extra{64};             // pids.max = vcpus + this
    std::optional<std::uint64_t> memory_max;  // memory.max: the VMM's own memory
    std::uint64_t memlock_margin{std::uint64_t{256} << 20U};
    bool set_memlock{true};  // false when unprivileged (tests)

    std::chrono::milliseconds start_timeout{std::chrono::seconds{10}};
    std::chrono::milliseconds api_timeout{std::chrono::seconds{10}};
    int stderr_fd{-1};  // the VMM's stderr; -1: /dev/null
};

class JailedVmmLauncher final : public VmmLauncher {
public:
    JailedVmmLauncher(VmmLaunchConfig config, UidPool& uids)
        : _config{std::move(config)}, _uids{&uids} {}

    [[nodiscard]] auto launch(const Allocation& allocation)
        -> std::expected<std::unique_ptr<VmmHandle>, LaunchFailure> override;

    [[nodiscard]] auto config() const noexcept -> const VmmLaunchConfig& { return _config; }

private:
    VmmLaunchConfig _config;
    UidPool* _uids;
};

}  // namespace ak::hull
