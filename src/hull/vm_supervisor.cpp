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
                               .devices = {}});
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
    release_vm(cmd.vm_id, vm);
    _vms.erase(it);
    ++_stats.destroyed;
    return mb::Status::ok;
}

auto VmSupervisor::release_vm(std::uint64_t vm_id, Vm& vm) -> void {
    for (const auto& ref : vm.devices) {
        const auto* entry = _inventory->find(ref);
        const bool ok = entry != nullptr && _resetter->reset(*entry);
        if (!ok) {
            ++_stats.reset_failures;
        }
        queue_event(
            mb::DeviceReleased{.vm_id = vm_id,
                               .device = ref,
                               .reset = ok ? mb::ResetResult::ok : mb::ResetResult::failed});
    }
    vm.devices.clear();
    vm.vmm.reset();  // cgroup, run directory, UID
    (void)_allocator->release(vm_id);
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
