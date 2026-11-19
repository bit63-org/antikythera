// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/vm_cgroup.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <string_view>

namespace ak::hull {

namespace {

auto vm_cgroup_name(VmId vm_id) -> std::string {
    return "vm-" + std::to_string(vm_id);
}

auto write_file(int dir_fd, const std::string& file, std::string_view value)
    -> std::expected<void, CgroupFailure> {
    const int fd = ::openat(dir_fd, file.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return std::unexpected(CgroupFailure{CgroupError::open_failed, file, errno});
    }
    // cgroupfs takes one value per write(2); a short write is a refusal.
    const auto written = ::write(fd, value.data(), value.size());
    const int write_errno = errno;
    (void)::close(fd);
    if (written < 0 || static_cast<std::size_t>(written) != value.size()) {
        return std::unexpected(
            CgroupFailure{CgroupError::write_failed, file, written < 0 ? write_errno : EIO});
    }
    return {};
}

}  // namespace

auto to_string(CgroupError e) noexcept -> const char* {
    switch (e) {
        case CgroupError::invalid_limits:
            return "invalid_limits";
        case CgroupError::open_failed:
            return "open_failed";
        case CgroupError::already_exists:
            return "already_exists";
        case CgroupError::mkdir_failed:
            return "mkdir_failed";
        case CgroupError::write_failed:
            return "write_failed";
        case CgroupError::remove_failed:
            return "remove_failed";
    }
    return "unknown";
}

auto limits_for(const Allocation& allocation, std::uint32_t pids_max,
                std::optional<std::uint64_t> memory_max) -> CgroupLimits {
    CgroupLimits limits;
    limits.cpus = allocation.cpus;
    limits.hugepages = allocation.hugepages;
    limits.pids_max = pids_max;
    limits.memory_max = memory_max;
    return limits;
}

auto cgroup_writes(const CgroupLimits& limits)
    -> std::expected<std::vector<std::pair<std::string, std::string>>, CgroupFailure> {
    const auto cpus = format_cpu_list(limits.cpus);
    if (!cpus || cpus->empty() || limits.mems.empty() || limits.hugepages == 0) {
        return std::unexpected(CgroupFailure{CgroupError::invalid_limits, {}, 0});
    }
    std::vector<std::pair<std::string, std::string>> out;
    out.emplace_back("cpuset.cpus", *cpus);
    out.emplace_back("cpuset.mems", limits.mems);
    out.emplace_back("hugetlb.1GB.max",
                     std::to_string(std::uint64_t{limits.hugepages} * hugepage_bytes));
    if (limits.pids_max != 0) {
        out.emplace_back("pids.max", std::to_string(limits.pids_max));
    }
    if (limits.memory_max) {
        out.emplace_back("memory.max", std::to_string(*limits.memory_max));
    }
    return out;
}

auto write_cgroup_limits(int dir_fd, const CgroupLimits& limits)
    -> std::expected<void, CgroupFailure> {
    const auto writes = cgroup_writes(limits);
    if (!writes) {
        return std::unexpected(writes.error());
    }
    for (const auto& [file, value] : *writes) {
        if (auto r = write_file(dir_fd, file, value); !r) {
            return r;
        }
    }
    return {};
}

auto enable_vm_controllers(int parent_fd) -> std::expected<void, CgroupFailure> {
    return write_file(parent_fd, "cgroup.subtree_control", "+cpuset +hugetlb +pids +memory");
}

auto VmCgroup::create(int parent_fd, VmId vm_id, const CgroupLimits& limits)
    -> std::expected<VmCgroup, CgroupFailure> {
    // Validate before touching the filesystem.
    if (auto writes = cgroup_writes(limits); !writes) {
        return std::unexpected(writes.error());
    }
    auto name = vm_cgroup_name(vm_id);
    const int parent = ::fcntl(parent_fd, F_DUPFD_CLOEXEC, 0);
    if (parent < 0) {
        return std::unexpected(CgroupFailure{CgroupError::open_failed, {}, errno});
    }
    if (::mkdirat(parent, name.c_str(), 0755) != 0) {
        const int e = errno;
        (void)::close(parent);
        return std::unexpected(CgroupFailure{
            e == EEXIST ? CgroupError::already_exists : CgroupError::mkdir_failed, name, e});
    }
    const int fd = ::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        const int e = errno;
        (void)::unlinkat(parent, name.c_str(), AT_REMOVEDIR);
        (void)::close(parent);
        return std::unexpected(CgroupFailure{CgroupError::open_failed, name, e});
    }
    VmCgroup cgroup{parent, fd, std::move(name)};
    if (auto r = write_cgroup_limits(cgroup._fd, limits); !r) {
        (void)cgroup.remove();
        return std::unexpected(r.error());
    }
    return cgroup;
}

VmCgroup::VmCgroup(VmCgroup&& other) noexcept
    : _parent_fd{std::exchange(other._parent_fd, -1)},
      _fd{std::exchange(other._fd, -1)},
      _name{std::move(other._name)} {}

auto VmCgroup::operator=(VmCgroup&& other) noexcept -> VmCgroup& {
    if (this != &other) {
        reset();
        _parent_fd = std::exchange(other._parent_fd, -1);
        _fd = std::exchange(other._fd, -1);
        _name = std::move(other._name);
    }
    return *this;
}

VmCgroup::~VmCgroup() {
    reset();
}

void VmCgroup::reset() noexcept {
    if (_parent_fd >= 0) {
        (void)remove();
    }
    if (_fd >= 0) {
        (void)::close(_fd);
        _fd = -1;
    }
    if (_parent_fd >= 0) {
        (void)::close(_parent_fd);
        _parent_fd = -1;
    }
}

auto VmCgroup::remove() -> std::expected<void, CgroupFailure> {
    if (_parent_fd < 0 || _name.empty()) {
        return {};
    }
    if (::unlinkat(_parent_fd, _name.c_str(), AT_REMOVEDIR) != 0) {
        return std::unexpected(CgroupFailure{CgroupError::remove_failed, _name, errno});
    }
    // Removed: forget the name so neither a second remove() nor the
    // destructor touches a directory a later VM may have reused.
    _name.clear();
    return {};
}

}  // namespace ak::hull
