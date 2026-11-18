// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/resource_allocator.hpp"

#include <algorithm>
#include <set>
#include <utility>

namespace ak::hull {

auto to_string(AllocError e) noexcept -> const char* {
    switch (e) {
        case AllocError::invalid_request:
            return "invalid_request";
        case AllocError::already_allocated:
            return "already_allocated";
        case AllocError::insufficient_cores:
            return "insufficient_cores";
        case AllocError::insufficient_hugepages:
            return "insufficient_hugepages";
        case AllocError::unknown_vm:
            return "unknown_vm";
    }
    return "unknown";
}

ResourceAllocator::ResourceAllocator(const CpuTopology& topology, std::span<const CpuId> guest_cpus,
                                     std::uint32_t hugepages)
    : _hugepages{hugepages}, _free_hugepages{hugepages} {
    const std::set<CpuId> guest(guest_cpus.begin(), guest_cpus.end());
    for (const auto& core : topology.cores()) {
        if (std::ranges::all_of(core.cpus, [&](CpuId c) { return guest.contains(c); })) {
            _cores.push_back(GuestCore{.cpus = core.cpus, .owner = std::nullopt});
        }
    }
}

auto ResourceAllocator::allocate(VmId vm_id, std::uint16_t vcpus, std::uint32_t memory_mib)
    -> std::expected<Allocation, AllocError> {
    if (vm_id == 0 || vcpus == 0 || memory_mib == 0) {
        return std::unexpected(AllocError::invalid_request);
    }
    if (_allocations.contains(vm_id)) {
        return std::unexpected(AllocError::already_allocated);
    }

    // Pick cores without taking them, so a refusal changes nothing.
    std::vector<std::size_t> picked;
    std::size_t threads = 0;
    for (std::size_t i = 0; i < _cores.size() && threads < vcpus; ++i) {
        if (!_cores[i].owner) {
            picked.push_back(i);
            threads += _cores[i].cpus.size();
        }
    }
    if (threads < vcpus) {
        return std::unexpected(AllocError::insufficient_cores);
    }
    const auto pages = (memory_mib / mib_per_hugepage) +
                       static_cast<std::uint32_t>(memory_mib % mib_per_hugepage != 0);
    if (pages > _free_hugepages) {
        return std::unexpected(AllocError::insufficient_hugepages);
    }

    Allocation a{.vm_id = vm_id, .vcpus = vcpus, .cpus = {}, .hugepages = pages};
    for (const auto i : picked) {
        _cores[i].owner = vm_id;
        a.cpus.insert(a.cpus.end(), _cores[i].cpus.begin(), _cores[i].cpus.end());
    }
    std::ranges::sort(a.cpus);
    _free_hugepages -= pages;
    _allocations.emplace(vm_id, a);
    return a;
}

auto ResourceAllocator::release(VmId vm_id) -> std::expected<Allocation, AllocError> {
    const auto it = _allocations.find(vm_id);
    if (it == _allocations.end()) {
        return std::unexpected(AllocError::unknown_vm);
    }
    for (auto& core : _cores) {
        if (core.owner == vm_id) {
            core.owner.reset();
        }
    }
    _free_hugepages += it->second.hugepages;
    auto released = std::move(it->second);
    _allocations.erase(it);
    return released;
}

auto ResourceAllocator::find(VmId vm_id) const -> const Allocation* {
    const auto it = _allocations.find(vm_id);
    return it == _allocations.end() ? nullptr : &it->second;
}

auto ResourceAllocator::free_cores() const noexcept -> std::size_t {
    return static_cast<std::size_t>(
        std::ranges::count_if(_cores, [](const GuestCore& c) { return !c.owner; }));
}

auto ResourceAllocator::free_threads() const noexcept -> std::size_t {
    std::size_t n = 0;
    for (const auto& c : _cores) {
        if (!c.owner) {
            n += c.cpus.size();
        }
    }
    return n;
}

}  // namespace ak::hull
