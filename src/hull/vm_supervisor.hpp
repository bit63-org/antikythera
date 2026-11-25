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
// Attach and detach (task 9, Requirement 7):
//
//   ATTACH_DEVICE / ATTACH_VOLUME
//               the function must be in the boot inventory with the type
//               the command names (unknown_device) and held by no VM
//               (conflict). The agent hands its VFIO group node to the
//               VM's UID, then vm.add-device: a cold-plug while the VM is
//               `created`, a hot-plug once it runs. The first storage
//               function attached to a created VM is its boot volume: the
//               agent boots the VM right after (Requirement 6.2). ok once
//               the VMM has the function open. A failure undoes the grant
//               (and the add, if the boot failed).
//   DETACH_DEVICE / DETACH_VOLUME
//               vm.remove-device. A created VM drops the function from its
//               configuration at once: reset, DEVICE_RELEASED, ok. A running
//               VM is asked to eject it (ACPI), and the agent answers
//               `accepted` and polls vm.info (poll_detaches). When the
//               function leaves the VM's configuration -- the guest
//               ejected it -- it is reset and released. If timeout_s passes
//               first, the command's policy applies:
//                 destroy_vm  the VM is killed: VM_EXITED (vmm_failure,
//                             128 + SIGKILL), then every function it held is
//                             reset and released;
//                 force       Cloud Hypervisor has no surprise removal, so
//                             the function cannot leave a running VMM
//                             without the guest. The agent resets it in
//                             place, which takes the device's state away
//                             from the guest, and releases it only when the
//                             guest finally ejects it or the VM ends; until
//                             then no other VM can be given it.
//               DETACH_VOLUME under `wait` (block-volume task 13) reaches
//               hull only after the guest released the disk: the timeout
//               and policy do not apply and the agent waits for the eject.
//
// Events are queued, never sent from inside a command: the mailbox client
// writes the command's response first, and only then does the agent's loop
// send what take_events() returns. helm therefore sees DESTROY_VM's ok
// before the DEVICE_RELEASED events it is waiting for, never the reverse.
//
// Single-threaded: the agent's loop calls the command methods, then
// poll_exits() whenever a VMM's pidfd is readable (or on a timer), then
// sends take_events().

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
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
    std::uint64_t attached{0};
    std::uint64_t detached{0};         // functions released after a detach
    std::uint64_t detach_timeouts{0};  // policies applied
    std::uint64_t forced_in_place{0};  // force: reset while the guest still holds it
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
    [[nodiscard]] auto attach(std::uint64_t vm_id, const helm::mailbox::DeviceRef& ref)
        -> helm::mailbox::Status;
    [[nodiscard]] auto detach(std::uint64_t vm_id, const helm::mailbox::DeviceRef& ref,
                              std::uint16_t timeout_s, helm::mailbox::DetachPolicy policy)
        -> helm::mailbox::Status;
    [[nodiscard]] auto list() const -> CommandOutcome;
    [[nodiscard]] auto status(const helm::mailbox::VmStatus& cmd) const -> CommandOutcome;

    // Handles every VMM that has exited since the last call: VM_EXITED, then
    // resets and releases. Returns how many it found.
    auto poll_exits() -> std::size_t;

    // Checks every pending detach once (one vm.info per VM that has one):
    // releases what the guest ejected and applies the policy of each
    // detach whose timeout has passed. Returns how many functions it
    // released. Call it periodically while has_pending_detaches().
    auto poll_detaches() -> std::size_t;
    [[nodiscard]] auto has_pending_detaches() const noexcept -> bool;

    using Clock = std::chrono::steady_clock;
    // For tests: the clock detach deadlines are measured on.
    auto set_clock(std::function<Clock::time_point()> now) -> void { _now = std::move(now); }

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
    // A detach the guest has been asked to complete.
    struct PendingDetach {
        helm::mailbox::DeviceRef ref;
        std::optional<Clock::time_point> deadline;  // none: wait for the eject
        helm::mailbox::DetachPolicy policy{helm::mailbox::DetachPolicy::force};
        bool forced{false};  // reset in place already
    };

    // What the supervisor keeps per VM. Task 9's attach and detach add and
    // remove functions; the state moves to running at boot.
    struct Vm {
        std::unique_ptr<VmmHandle> vmm;
        Allocation allocation;
        helm::mailbox::VmRunState state{helm::mailbox::VmRunState::created};
        std::vector<helm::mailbox::DeviceRef> devices;  // in attach order
        std::vector<PendingDetach> pending;
    };

    // Resets and releases every function `vm` held (DEVICE_RELEASED each),
    // then returns its resources. `vm` must already be dead and reaped.
    auto release_vm(std::uint64_t vm_id, Vm& vm) -> void;
    // Takes one function back from a VM whose VMM no longer has it:
    // revokes its group, resets it, queues DEVICE_RELEASED.
    auto release_function(std::uint64_t vm_id, Vm& vm, const helm::mailbox::DeviceRef& ref) -> void;
    // Kills a VM the agent decided to end (destroy_vm policy): VM_EXITED,
    // then release_vm. Erases it from _vms.
    auto kill_vm(std::map<std::uint64_t, Vm>::iterator it) -> void;
    [[nodiscard]] auto holder_of(const helm::mailbox::DeviceRef& ref) const -> const Vm*;
    auto queue_event(helm::mailbox::Body event) -> void { _events.push_back(std::move(event)); }

    ResourceAllocator* _allocator;
    VmmLauncher* _launcher;
    FunctionResetter* _resetter;
    const DeviceInventory* _inventory;
    BootPayload _payload;
    std::map<std::uint64_t, Vm> _vms;
    std::deque<helm::mailbox::Body> _events;
    SupervisorStats _stats;
    std::function<Clock::time_point()> _now{[] { return Clock::now(); }};
};

// The exit reason and status VM_EXITED reports for a VMM wait status: a
// clean exit (status 0) is the guest powering off; any other exit code or
// a signal is a VMM failure, reported as the exit code or 128 + signal.
[[nodiscard]] auto exit_report(int wait_status) noexcept
    -> std::pair<helm::mailbox::ExitReason, std::uint32_t>;

}  // namespace ak::hull
