// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What the agent tells Cloud Hypervisor (.kiro/specs/hull-host-agent/
// task 8, Requirement 6.1; design.md "VmSupervisor").
//
// The VMM starts with only an API socket (ch_argv) and gets the VM over it
// (vm_config_json): dedicated vCPUs pinned one-to-one onto the cores the
// ResourceAllocator handed out, guest memory from 1 GiB huge pages, the
// firmware (or, in harbor, a kernel), and no serial port, console, disk,
// network or other emulated device of the agent's choosing. Every PCI
// function reaches the guest by passthrough with vm.add-device, under the
// ID device_id() gives it.
//
// One device the agent cannot leave out: Cloud Hypervisor always creates
// a virtio-rng backed by /dev/urandom (its RngConfig has no "off"). It is
// the only emulated device a guest sees; the jail lets the VMM read
// /dev/urandom for it.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "helm/mailbox.hpp"
#include "hull/cpu_topology.hpp"
#include "hull/resource_allocator.hpp"

namespace ak::hull {

// How the guest starts. Production boots rust-hypervisor-firmware from the
// boot volume (Requirement 6.2); harbor may boot a kernel directly.
struct BootPayload {
    std::filesystem::path firmware;  // set exactly when kernel is not
    std::filesystem::path kernel;
    std::string cmdline;              // kernel only
    std::filesystem::path initramfs;  // kernel only, optional

    friend auto operator==(const BootPayload&, const BootPayload&) -> bool = default;
};

// vm.create's body for `allocation`: vCPU i runs on allocation.cpus[i]
// only (an odd vCPU count on an SMT host leaves the core's last thread idle
// in the VM's cpuset), memory is allocation.memory_bytes() of 1 GiB pages,
// not shared.
[[nodiscard]] auto vm_config_json(const Allocation& allocation, const BootPayload& payload)
    -> std::string;

// The VMM's command line: the API socket, Cloud Hypervisor's own seccomp
// filter, and nothing else (the VM itself comes over the socket).
[[nodiscard]] auto ch_argv(const std::filesystem::path& binary,
                           const std::filesystem::path& api_socket) -> std::vector<std::string>;

// The VMM device ID for a function: "ak-s<slot>-<type>-f<function>" with
// type nic, blk, gpu or gpuvf. Unique per function on a server, so the
// agent can name a device to the VMM without keeping a second table.
[[nodiscard]] auto device_id(const helm::mailbox::DeviceRef& ref) -> std::string;

}  // namespace ak::hull
