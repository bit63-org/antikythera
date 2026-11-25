// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/vm_supervisor.hpp"

#include <poll.h>
#include <sys/wait.h>

#include <algorithm>
#include <csignal>

namespace ak::hull {

namespace mb = helm::mailbox;

auto exit_report(int wait_status) noexcept -> std::pair<mb::ExitReason, std::uint32_t> {
    if (WIFEXITED(wait_status)) {
        const auto code = static_cast<std::uint32_t>(WEXITSTATUS(wait_status));
        return {code == 0 ? mb::ExitReason::guest_shutdown : mb::ExitReason::vmm_failure, code};
    }
    if (WIFSIGNALED(wait_status)) {
        return {mb::ExitReason::vmm_failure,
                128U + static_cast<std::uint32_t>(WTERMSIG(wait_status))};
    }
    return {mb::ExitReason::vmm_failure, 0xFFFF'FFFFU};
}

auto VmSupervisor::create(const mb::CreateVm& cmd) -> mb::Status {
    if (_vms.contains(cmd.vm_id)) {
        return mb::Status::conflict;
    }
    auto allocation = _allocator->allocate(cmd.vm_id, cmd.vcpus, cmd.memory_mib);
    if (!allocation) {
        return allocation.error() == AllocError::already_allocated
                   ? mb::Status::conflict
                   : (allocation.error() == AllocError::invalid_request
                          ? mb::Status::malformed
                          : mb::Status::insufficient_resources);
    }
    auto vmm = _launcher->launch(*allocation);
    if (!vmm) {
        ++_stats.launch_failures;
        (void)_allocator->release(cmd.vm_id);
        return mb::Status::internal_error;
    }
    if (auto r = (*vmm)->api().create(vm_config_json(*allocation, _payload)); !r) {
        ++_stats.api_failures;
        vmm->reset();  // kills and reaps the VMM, frees its cgroup and UID
        (void)_allocator->release(cmd.vm_id);
        return mb::Status::internal_error;
    }
    _vms.emplace(cmd.vm_id, Vm{.vmm = std::move(*vmm),
                               .allocation = std::move(*allocation),
                               .state = mb::VmRunState::created,
                               .devices = {},
                               .pending = {}});
    ++_stats.created;
    return mb::Status::ok;
}

auto VmSupervisor::destroy(const mb::DestroyVm& cmd) -> mb::Status {
    const auto it = _vms.find(cmd.vm_id);
    if (it == _vms.end()) {
        return mb::Status::unknown_vm;
    }
    // persist_volumes is helm's business (whether it destroys the volume
    // keys); for hull every function is reset the same way.
    auto& vm = it->second;
    vm.vmm->kill();
    (void)vm.vmm->wait();
    release_vm(cmd.vm_id, vm);  // also ends any pending detach
    _vms.erase(it);
    ++_stats.destroyed;
    return mb::Status::ok;
}

auto VmSupervisor::release_vm(std::uint64_t vm_id, Vm& vm) -> void {
    while (!vm.devices.empty()) {
        release_function(vm_id, vm, vm.devices.front());
    }
    vm.vmm.reset();  // cgroup, run directory, UID
    (void)_allocator->release(vm_id);
}

auto VmSupervisor::release_function(std::uint64_t vm_id, Vm& vm, const mb::DeviceRef& ref) -> void {
    const auto* entry = _inventory->find(ref);
    if (entry != nullptr && vm.vmm) {
        (void)vm.vmm->revoke_group(entry->iommu_group);
    }
    const bool ok = entry != nullptr && _resetter->reset(*entry);
    if (!ok) {
        ++_stats.reset_failures;
    }
    queue_event(mb::DeviceReleased{.vm_id = vm_id,
                                   .device = ref,
                                   .reset = ok ? mb::ResetResult::ok : mb::ResetResult::failed});
    std::erase(vm.devices, ref);
    std::erase_if(vm.pending, [&](const PendingDetach& p) { return p.ref == ref; });
}

auto VmSupervisor::kill_vm(std::map<std::uint64_t, Vm>::iterator it) -> void {
    auto& vm = it->second;
    vm.vmm->kill();
    (void)vm.vmm->wait();
    // The agent ended the VM, but helm learns of it the way it learns of
    // any VM that died: there is no other event for it.
    const auto [reason, code] = exit_report(SIGKILL);
    queue_event(mb::VmExited{.vm_id = it->first, .exit_status = code, .reason = reason});
    release_vm(it->first, vm);
    _vms.erase(it);
}

auto VmSupervisor::holder_of(const mb::DeviceRef& ref) const -> const Vm* {
    for (const auto& [id, vm] : _vms) {
        if (std::ranges::find(vm.devices, ref) != vm.devices.end()) {
            return &vm;
        }
    }
    return nullptr;
}

namespace {

// After a call that failed in a way that leaves the outcome unknown (a
// timeout, a dropped connection), whether the VMM lists `id`.
auto lists_device(VmmApi& api, const std::string& id) -> std::optional<bool> {
    const auto info = api.info();
    if (!info) {
        return std::nullopt;
    }
    return std::ranges::find(info->device_ids, id) != info->device_ids.end();
}

}  // namespace

auto VmSupervisor::attach(std::uint64_t vm_id, const mb::DeviceRef& ref) -> mb::Status {
    const auto it = _vms.find(vm_id);
    if (it == _vms.end()) {
        return mb::Status::unknown_vm;
    }
    const auto* entry = _inventory->find(ref);
    if (entry == nullptr) {
        return mb::Status::unknown_device;
    }
    if (holder_of(ref) != nullptr) {
        return mb::Status::conflict;
    }
    auto& vm = it->second;
    auto& api = vm.vmm->api();
    const auto id = device_id(ref);
    if (!vm.vmm->grant_group(entry->iommu_group)) {
        (void)vm.vmm->revoke_group(entry->iommu_group);
        return mb::Status::internal_error;
    }
    if (auto added = api.add_device(id, pci_device_path("/sys", entry->bdf)); !added) {
        ++_stats.api_failures;
        // A refusal is a refusal; after a timeout the VMM may have added
        // it anyway, and a function the VMM holds must stay booked to it.
        const bool ambiguous = added.error().error != VmmApiError::refused;
        if (!ambiguous || lists_device(api, id) != std::optional<bool>{true}) {
            (void)vm.vmm->revoke_group(entry->iommu_group);
            return mb::Status::internal_error;
        }
    }
    vm.devices.push_back(ref);
    if (vm.state == mb::VmRunState::created && ref.type == mb::DeviceType::blk_fn) {
        if (auto booted = api.boot(); !booted) {
            ++_stats.api_failures;
            // Not booted, so the VMM only drops it from the configuration.
            if (api.remove_device(id) || lists_device(api, id) == std::optional<bool>{false}) {
                std::erase(vm.devices, ref);
                (void)vm.vmm->revoke_group(entry->iommu_group);
            }
            return mb::Status::internal_error;
        }
        vm.state = mb::VmRunState::running;
    }
    ++_stats.attached;
    return mb::Status::ok;
}

auto VmSupervisor::detach(std::uint64_t vm_id, const mb::DeviceRef& ref, std::uint16_t timeout_s,
                          mb::DetachPolicy policy) -> mb::Status {
    const auto it = _vms.find(vm_id);
    if (it == _vms.end()) {
        return mb::Status::unknown_vm;
    }
    auto& vm = it->second;
    if (std::ranges::find(vm.devices, ref) == vm.devices.end()) {
        return mb::Status::unknown_device;
    }
    if (std::ranges::any_of(vm.pending, [&](const PendingDetach& p) { return p.ref == ref; })) {
        return mb::Status::conflict;  // already being detached
    }
    auto& api = vm.vmm->api();
    const auto id = device_id(ref);
    if (auto removed = api.remove_device(id); !removed) {
        ++_stats.api_failures;
        const auto listed = lists_device(api, id);
        if (listed != std::optional<bool>{false}) {
            return mb::Status::internal_error;
        }
        // Not listed: it is already gone (a guest-initiated eject raced
        // the command); fall through and release it.
    }
    if (vm.state == mb::VmRunState::created) {
        // Never booted: vm.remove-device dropped it from the configuration
        // and the VMM never opened it.
        release_function(vm_id, vm, ref);
        ++_stats.detached;
        return mb::Status::ok;
    }
    PendingDetach pending{.ref = ref, .deadline = std::nullopt, .policy = policy, .forced = false};
    if (policy == mb::DetachPolicy::force || policy == mb::DetachPolicy::destroy_vm) {
        pending.deadline = _now() + std::chrono::seconds{timeout_s};
    }
    vm.pending.push_back(pending);
    return mb::Status::accepted;
}

auto VmSupervisor::has_pending_detaches() const noexcept -> bool {
    return std::ranges::any_of(_vms, [](const auto& e) { return !e.second.pending.empty(); });
}

auto VmSupervisor::poll_detaches() -> std::size_t {
    std::size_t released = 0;
    const auto now = _now();
    for (auto it = _vms.begin(); it != _vms.end();) {
        auto& vm = it->second;
        if (vm.pending.empty()) {
            ++it;
            continue;
        }
        const auto info = vm.vmm->api().info();
        if (!info) {
            // A VMM that stopped answering is either exiting (poll_exits
            // handles it) or wedged; the deadlines below still apply.
            ++_stats.api_failures;
        }
        bool killed = false;
        for (const auto& p : std::vector<PendingDetach>{vm.pending}) {
            const bool gone = info && std::ranges::find(info->device_ids, device_id(p.ref)) ==
                                          info->device_ids.end();
            if (gone) {
                release_function(it->first, vm, p.ref);
                ++_stats.detached;
                ++released;
                continue;
            }
            if (!p.deadline || now < *p.deadline) {
                continue;
            }
            ++_stats.detach_timeouts;
            if (p.policy == mb::DetachPolicy::destroy_vm) {
                released += vm.devices.size();
                kill_vm(it++);
                killed = true;
                break;
            }
            // force: take the device's state away from the guest now; the
            // function itself is released when the VMM lets go of it.
            const auto* entry = _inventory->find(p.ref);
            if (entry == nullptr || !_resetter->reset(*entry)) {
                ++_stats.reset_failures;
            }
            ++_stats.forced_in_place;
            for (auto& q : vm.pending) {
                if (q.ref == p.ref) {
                    q.deadline.reset();
                    q.forced = true;
                }
            }
        }
        if (!killed) {
            ++it;
        }
    }
    return released;
}

auto VmSupervisor::list() const -> CommandOutcome {
    std::vector<std::uint64_t> ids;
    ids.reserve(_vms.size());
    for (const auto& [id, vm] : _vms) {
        ids.push_back(id);  // std::map: ascending
    }
    return {.status = mb::Status::ok, .payload = mb::encode_vm_list_payload(ids)};
}

auto VmSupervisor::status(const mb::VmStatus& cmd) const -> CommandOutcome {
    const auto it = _vms.find(cmd.vm_id);
    if (it == _vms.end()) {
        return {.status = mb::Status::unknown_vm, .payload = {}};
    }
    const auto& vm = it->second;
    return {
        .status = mb::Status::ok,
        .payload = mb::encode_vm_status_payload({
            .vm_id = cmd.vm_id,
            .state = vm.state,
            .devices = static_cast<std::uint8_t>(std::min<std::size_t>(vm.devices.size(), 0xFF)),
            .vcpus = vm.allocation.vcpus,
            .hugepages = vm.allocation.hugepages,
        })};
}

auto VmSupervisor::poll_exits() -> std::size_t {
    std::size_t found = 0;
    for (auto it = _vms.begin(); it != _vms.end();) {
        auto& vm = it->second;
        const int fd = vm.vmm->pidfd();
        pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
        if (fd < 0 || ::poll(&p, 1, 0) <= 0) {
            ++it;
            continue;
        }
        const auto status = vm.vmm->wait();
        const auto [reason, code] = exit_report(status.value_or(SIGKILL));
        queue_event(mb::VmExited{.vm_id = it->first, .exit_status = code, .reason = reason});
        release_vm(it->first, vm);
        it = _vms.erase(it);
        ++_stats.exited;
        ++found;
    }
    return found;
}

auto VmSupervisor::exit_fds() const -> std::vector<int> {
    std::vector<int> fds;
    for (const auto& [id, vm] : _vms) {
        if (vm.vmm->pidfd() >= 0) {
            fds.push_back(vm.vmm->pidfd());
        }
    }
    return fds;
}

auto VmSupervisor::take_events() -> std::vector<mb::Body> {
    std::vector<mb::Body> out{std::make_move_iterator(_events.begin()),
                              std::make_move_iterator(_events.end())};
    _events.clear();
    return out;
}

}  // namespace ak::hull
