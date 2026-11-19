// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/cpu_topology.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <system_error>

namespace ak::hull {

namespace {

// Huge-page pool counts are bounded well below this; anything larger is
// treated as malformed rather than truncated.
constexpr std::uint64_t max_hugepages = 1U << 24U;

auto parse_decimal(std::string_view s) -> std::optional<std::uint64_t> {
    if (s.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto* first = std::to_address(s.begin());
    const auto* end = std::to_address(s.end());
    const auto [ptr, ec] = std::from_chars(first, end, value);
    if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
    }
    return value;
}

auto strip_newline(std::string_view s) -> std::string_view {
    if (!s.empty() && s.back() == '\n') {
        s.remove_suffix(1);
    }
    return s;
}

auto read_file(const std::filesystem::path& path) -> std::expected<std::string, TopologyError> {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::unexpected(TopologyError::unreadable);
    }
    std::string text{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    if (in.bad()) {
        return std::unexpected(TopologyError::unreadable);
    }
    return text;
}

auto read_cpu_list(const std::filesystem::path& path)
    -> std::expected<std::vector<CpuId>, TopologyError> {
    auto text = read_file(path);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto cpus = parse_cpu_list(*text);
    if (!cpus) {
        return std::unexpected(TopologyError::malformed);
    }
    return std::move(*cpus);
}

}  // namespace

auto to_string(CpuListError e) noexcept -> const char* {
    switch (e) {
        case CpuListError::empty_entry:
            return "empty_entry";
        case CpuListError::bad_number:
            return "bad_number";
        case CpuListError::bad_range:
            return "bad_range";
        case CpuListError::cpu_too_large:
            return "cpu_too_large";
        case CpuListError::not_ascending:
            return "not_ascending";
    }
    return "unknown";
}

auto to_string(TopologyError e) noexcept -> const char* {
    switch (e) {
        case TopologyError::unreadable:
            return "unreadable";
        case TopologyError::malformed:
            return "malformed";
        case TopologyError::empty_core:
            return "empty_core";
        case TopologyError::duplicate_cpu:
            return "duplicate_cpu";
        case TopologyError::inconsistent:
            return "inconsistent";
        case TopologyError::no_cpus:
            return "no_cpus";
    }
    return "unknown";
}

auto format_cpu_list(std::span<const CpuId> cpus) -> std::optional<std::string> {
    std::string out;
    std::size_t i = 0;
    while (i < cpus.size()) {
        if (i > 0 && cpus[i] <= cpus[i - 1]) {
            return std::nullopt;
        }
        std::size_t j = i;
        while (j + 1 < cpus.size() && cpus[j + 1] == cpus[j] + 1) {
            ++j;
        }
        if (!out.empty()) {
            out += ',';
        }
        out += std::to_string(cpus[i]);
        if (j > i) {
            out += '-';
            out += std::to_string(cpus[j]);
        }
        i = j + 1;
    }
    return out;
}

auto parse_cpu_list(std::string_view text) -> std::expected<std::vector<CpuId>, CpuListError> {
    text = strip_newline(text);
    std::vector<CpuId> out;
    if (text.empty()) {
        return out;
    }
    while (true) {
        const auto comma = text.find(',');
        const auto entry = text.substr(0, comma);
        if (entry.empty()) {
            return std::unexpected(CpuListError::empty_entry);
        }
        const auto dash = entry.find('-');
        const auto lo = parse_decimal(entry.substr(0, dash));
        const auto hi = dash == std::string_view::npos ? lo : parse_decimal(entry.substr(dash + 1));
        if (!lo || !hi) {
            return std::unexpected(CpuListError::bad_number);
        }
        if (*lo > *hi) {
            return std::unexpected(CpuListError::bad_range);
        }
        if (*hi > max_cpu_id) {
            return std::unexpected(CpuListError::cpu_too_large);
        }
        if (!out.empty() && *lo <= out.back()) {
            return std::unexpected(CpuListError::not_ascending);
        }
        for (auto cpu = *lo; cpu <= *hi; ++cpu) {
            out.push_back(static_cast<CpuId>(cpu));
        }
        if (comma == std::string_view::npos) {
            return out;
        }
        text.remove_prefix(comma + 1);
        if (text.empty()) {
            return std::unexpected(CpuListError::empty_entry);
        }
    }
}

auto CpuTopology::from_cores(std::vector<std::vector<CpuId>> cores)
    -> std::expected<CpuTopology, TopologyError> {
    if (cores.empty()) {
        return std::unexpected(TopologyError::no_cpus);
    }
    std::set<CpuId> seen;
    std::vector<PhysicalCore> out;
    out.reserve(cores.size());
    for (auto& cpus : cores) {
        if (cpus.empty()) {
            return std::unexpected(TopologyError::empty_core);
        }
        std::ranges::sort(cpus);
        for (const auto cpu : cpus) {
            if (!seen.insert(cpu).second) {
                return std::unexpected(TopologyError::duplicate_cpu);
            }
        }
        out.push_back(PhysicalCore{.cpus = std::move(cpus)});
    }
    std::ranges::sort(out, {}, [](const PhysicalCore& c) { return c.cpus.front(); });
    return CpuTopology{std::move(out)};
}

auto load_cpu_topology(const std::filesystem::path& sysfs_root)
    -> std::expected<CpuTopology, TopologyError> {
    const auto cpu_dir = sysfs_root / "devices/system/cpu";
    auto online = read_cpu_list(cpu_dir / "online");
    if (!online) {
        return std::unexpected(online.error());
    }
    if (online->empty()) {
        return std::unexpected(TopologyError::no_cpus);
    }
    const std::set<CpuId> online_set(online->begin(), online->end());

    // Keyed by the lowest sibling, so each core is recorded once and every
    // sibling must report the identical list.
    std::map<CpuId, std::vector<CpuId>> cores;
    for (const auto cpu : *online) {
        const auto topo = cpu_dir / ("cpu" + std::to_string(cpu)) / "topology";
        auto siblings = read_cpu_list(topo / "core_cpus_list");
        if (!siblings && siblings.error() == TopologyError::unreadable) {
            siblings = read_cpu_list(topo / "thread_siblings_list");
        }
        if (!siblings) {
            return std::unexpected(siblings.error());
        }
        if (!std::ranges::binary_search(*siblings, cpu)) {
            return std::unexpected(TopologyError::inconsistent);
        }
        // An offline sibling cannot run a guest, but its core is still
        // shared with it if it comes back: keep only online siblings and
        // let the allocator see the core as smaller.
        std::erase_if(*siblings, [&](CpuId c) { return !online_set.contains(c); });
        const auto [it, inserted] = cores.try_emplace(siblings->front(), *siblings);
        if (!inserted && it->second != *siblings) {
            return std::unexpected(TopologyError::inconsistent);
        }
    }
    std::vector<std::vector<CpuId>> list;
    list.reserve(cores.size());
    for (auto& [first, cpus] : cores) {
        list.push_back(std::move(cpus));
    }
    auto topology = CpuTopology::from_cores(std::move(list));
    if (!topology && topology.error() == TopologyError::duplicate_cpu) {
        // Two different sibling lists that overlap: sysfs disagrees with itself.
        return std::unexpected(TopologyError::inconsistent);
    }
    return topology;
}

auto load_isolated_cpus(const std::filesystem::path& sysfs_root)
    -> std::expected<std::vector<CpuId>, TopologyError> {
    return read_cpu_list(sysfs_root / "devices/system/cpu/isolated");
}

auto load_free_1g_hugepages(const std::filesystem::path& sysfs_root)
    -> std::expected<std::uint32_t, TopologyError> {
    const auto pool = sysfs_root / "kernel/mm/hugepages/hugepages-1048576kB";
    std::error_code ec;
    if (!std::filesystem::is_directory(pool, ec)) {
        return 0U;
    }
    auto text = read_file(pool / "free_hugepages");
    if (!text) {
        return std::unexpected(text.error());
    }
    const auto value = parse_decimal(strip_newline(*text));
    if (!value || *value > max_hugepages) {
        return std::unexpected(TopologyError::malformed);
    }
    return static_cast<std::uint32_t>(*value);
}

}  // namespace ak::hull
