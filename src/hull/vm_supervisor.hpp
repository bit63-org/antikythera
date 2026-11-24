// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VmSupervisor: the VMs on this server (.kiro/specs/hull-host-agent/
// task 8, Requirements 6 and 8.1; design.md "VmSupervisor", "Reset",
// "Error handling").
//
//   CREATE_VM   allocate whole cores and 1 GiB pages (or refuse with
//               insufficient_resources, taking nothing), start a jailed
//               Cloud Hypervisor (VmmLauncher), give it the VM's
//               configuration with vm.create, answer ok. The VM is then
//               `created`: it holds no devices and has not booted; it
//               boots from the volume the controller attaches next (task 9).
//               Any failing step undoes the ones before it.
//   DESTROY_VM  kill the VMM, reap it, answer ok, then reset every function
//               the VM held and send one DEVICE_RELEASED per function, then
//               return its cores, pages, cgroup and UID.
//   VMM exit    a VMM that exits without DESTROY_VM (the guest powered off,
//               the VMM crashed or was killed) produces VM_EXITED, then the
//               same reset and release sequence (Requirement 6.4).
//   LIST_VMS    the VMs by ID (mailbox.hpp, VmList).
//   VM_STATUS   one VM's state, vCPUs, pages and device count.
//
// Events are queued, never sent from inside a command: the mailbox client
// writes the command's response first, and only then does the agent's loop
// send what take_events() returns. helm therefore sees DESTROY_VM's ok
// before the DEVICE_RELEASED events it is waiting for, never the reverse.
//
// Single-threaded: the agent's loop calls the command methods, then
// poll_exits() whenever a VMM's pidfd is readable (or on a timer), then
// sends take_events().

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "helm/mailbox.hpp"
#include "hull/ch_config.hpp"
#include "hull/device_inventory.hpp"
#include "hull/mailbox_client.hpp"
#include "hull/resource_allocator.hpp"
#include "hull/vmm_launcher.hpp"

namespace ak::hull {

struct SupervisorStats {
    std::uint64_t created{0};
    std::uint64_t destroyed{0};
    std::uint64_t exited{0};  // VMM exits hull did not cause
    std::uint64_t launch_failures{0};
    std::uint64_t api_failures{0};
    std::uint64_t reset_failures{0};
};

class VmSupervisor {
public:
    VmSupervisor(ResourceAllocator& allocator, VmmLauncher& launcher, FunctionResetter& resetter,
                 const DeviceInventory& inventory, BootPayload payload)
        : _allocator{&allocator},
          _launcher{&launcher},
          _resetter{&resetter},
          _inventory{&inventory},
          _payload{std::move(payload)} {}

    VmSupervisor(const VmSupervisor&) = delete;
    auto operator=(const VmSupervisor&) -> VmSupervisor& = delete;
    VmSupervisor(VmSupervisor&&) = delete;
    auto operator=(VmSupervisor&&) -> VmSupervisor& = delete;
    // Kills every VMM still running; sends nothing.
    ~VmSupervisor() = default;

    [[nodiscard]] auto create(const helm::mailbox::CreateVm& cmd) -> helm::mailbox::Status;
    [[nodiscard]] auto destroy(const helm::mailbox::DestroyVm& cmd) -> helm::mailbox::Status;
    [[nodiscard]] auto list() const -> CommandOutcome;
    [[nodiscard]] auto status(const helm::mailbox::VmStatus& cmd) const -> CommandOutcome;

    // Handles every VMM that has exited since the last call: VM_EXITED, then
    // resets and releases. Returns how many it found.
    auto poll_exits() -> std::size_t;

    // The VMMs' pidfds, for the agent's poll set.
    [[nodiscard]] auto exit_fds() const -> std::vector<int>;

    // Events queued since the last call, oldest first.
    [[nodiscard]] auto take_events() -> std::vector<helm::mailbox::Body>;

    [[nodiscard]] auto vm_count() const noexcept -> std::size_t { return _vms.size(); }
    [[nodiscard]] auto contains(std::uint64_t vm_id) const noexcept -> bool {
        return _vms.contains(vm_id);
    }
    [[nodiscard]] auto stats() const noexcept -> const SupervisorStats& { return _stats; }

private:
    // What the supervisor keeps per VM. Task 9's attach and detach add and
    // remove functions; the state moves to running at boot.
    struct Vm {
        std::unique_ptr<VmmHandle> vmm;
        Allocation allocation;
        helm::mailbox::VmRunState state{helm::mailbox::VmRunState::created};
        std::vector<helm::mailbox::DeviceRef> devices;  // in attach order
    };

    // Resets and releases every function `vm` held (DEVICE_RELEASED each),
    // then returns its resources. `vm` must already be dead and reaped.
    auto release_vm(std::uint64_t vm_id, Vm& vm) -> void;
    auto queue_event(helm::mailbox::Body event) -> void { _events.push_back(std::move(event)); }

    ResourceAllocator* _allocator;
    VmmLauncher* _launcher;
    FunctionResetter* _resetter;
    const DeviceInventory* _inventory;
    BootPayload _payload;
    std::map<std::uint64_t, Vm> _vms;
    std::deque<helm::mailbox::Body> _events;
    SupervisorStats _stats;
};

// The exit reason and status VM_EXITED reports for a VMM wait status: a
// clean exit (status 0) is the guest powering off; any other exit code or
// a signal is a VMM failure, reported as the exit code or 128 + signal.
[[nodiscard]] auto exit_report(int wait_status) noexcept
    -> std::pair<helm::mailbox::ExitReason, std::uint32_t>;

}  // namespace ak::hull
