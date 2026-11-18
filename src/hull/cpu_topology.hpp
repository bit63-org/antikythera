// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The host's CPU and huge-page inventory, read once from sysfs at agent
// start (.kiro/specs/hull-host-agent/ Requirements 6.1 and 8.1). The
// ResourceAllocator hands guests whole physical cores, so the topology is
// a list of physical cores, each the set of logical CPUs (SMT siblings)
// that share it.
//
// sysfs is the kernel's output, not attacker input, but its cpulist format
// is still parsed strictly and fuzzed (fuzz/fuzz_cpu_list.cpp): a parser
// that tolerates odd input is a parser that can hand one core to two VMs.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string_view>
#include <utility>
#include <vector>

namespace ak::hull {

using CpuId = std::uint32_t;

// Highest logical CPU number accepted (the kernel's CONFIG_NR_CPUS limit is
// 8192). Bounds the memory a cpulist can make the parser allocate.
inline constexpr CpuId max_cpu_id = 8191;

enum class CpuListError : std::uint8_t {
    empty_entry,    // ",," or a leading/trailing comma
    bad_number,     // not a decimal number
    bad_range,      // "N-M" with N > M
    cpu_too_large,  // above max_cpu_id
    not_ascending,  // overlaps or goes backwards; the kernel never writes that
};

[[nodiscard]] auto to_string(CpuListError e) noexcept -> const char*;

// Parses the kernel's cpulist format ("0-3,8,10-11", as in
// /sys/devices/system/cpu/online), with an optional trailing newline. An
// empty list ("" or "\n") is valid: /sys/devices/system/cpu/isolated is
// empty when no CPU is isolated. Returns the CPUs in ascending order.
[[nodiscard]] auto parse_cpu_list(std::string_view text)
    -> std::expected<std::vector<CpuId>, CpuListError>;

// One physical core: its logical CPUs in ascending order (one entry without
// SMT, two with 2-way SMT).
struct PhysicalCore {
    std::vector<CpuId> cpus;
    friend auto operator==(const PhysicalCore&, const PhysicalCore&) -> bool = default;
};

enum class TopologyError : std::uint8_t {
    unreadable,     // a sysfs file is missing or cannot be read
    malformed,      // a sysfs file does not parse
    empty_core,     // a core with no logical CPU
    duplicate_cpu,  // a logical CPU in two cores
    inconsistent,   // a CPU's sibling list does not contain it, or siblings disagree
    no_cpus,        // nothing online
};

[[nodiscard]] auto to_string(TopologyError e) noexcept -> const char*;

class CpuTopology {
public:
    // Validates and normalises a core list: every core non-empty, no CPU in
    // two cores. Cores come out ordered by their lowest CPU.
    [[nodiscard]] static auto from_cores(std::vector<std::vector<CpuId>> cores)
        -> std::expected<CpuTopology, TopologyError>;

    [[nodiscard]] auto cores() const noexcept -> const std::vector<PhysicalCore>& { return _cores; }

private:
    explicit CpuTopology(std::vector<PhysicalCore> cores) : _cores{std::move(cores)} {}
    std::vector<PhysicalCore> _cores;
};

// Reads the online CPUs and their SMT siblings under `sysfs_root`
// (devices/system/cpu/online, then cpuN/topology/core_cpus_list, falling
// back to thread_siblings_list on kernels older than 5.6).
[[nodiscard]] auto load_cpu_topology(const std::filesystem::path& sysfs_root = "/sys")
    -> std::expected<CpuTopology, TopologyError>;

// The CPUs the kernel command line isolated for guests
// (devices/system/cpu/isolated; Requirement 2.4).
[[nodiscard]] auto load_isolated_cpus(const std::filesystem::path& sysfs_root = "/sys")
    -> std::expected<std::vector<CpuId>, TopologyError>;

// The free 1 GiB huge pages reserved on the command line
// (kernel/mm/hugepages/hugepages-1048576kB/free_hugepages). 0 when the
// kernel has no 1 GiB page pool at all.
[[nodiscard]] auto load_free_1g_hugepages(const std::filesystem::path& sysfs_root = "/sys")
    -> std::expected<std::uint32_t, TopologyError>;

}  // namespace ak::hull
