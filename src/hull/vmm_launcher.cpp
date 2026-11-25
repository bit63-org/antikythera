// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/vmm_launcher.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <set>
#include <system_error>
#include <thread>
#include <utility>

#include "hull/vm_cgroup.hpp"

namespace ak::hull {

namespace {

using Clock = std::chrono::steady_clock;

// Everything one launch took, released in reverse order on destruction.
class JailedVmm final : public VmmHandle {
public:
    JailedVmm(UidPool& uids, VmId vm, JailIds ids, std::filesystem::path dir,
              std::filesystem::path vfio_dir, std::chrono::milliseconds timeout)
        : _uids{&uids},
          _vm{vm},
          _ids{ids},
          _dir{std::move(dir)},
          _vfio_dir{std::move(vfio_dir)},
          _api{_dir / "api.sock", timeout} {}

    JailedVmm(const JailedVmm&) = delete;
    auto operator=(const JailedVmm&) -> JailedVmm& = delete;
    JailedVmm(JailedVmm&&) = delete;
    auto operator=(JailedVmm&&) -> JailedVmm& = delete;

    ~JailedVmm() override {
        _process.reset();  // SIGKILL and reap before the cgroup can go
        for (const auto group : std::vector<std::uint32_t>{_granted.begin(), _granted.end()}) {
            (void)revoke_group(group);
        }
        if (_cgroup) {
            (void)_cgroup->remove();
            _cgroup.reset();
        }
        std::error_code ec;
        std::filesystem::remove_all(_dir, ec);
        _uids->release(_vm);
    }

    [[nodiscard]] auto pidfd() const noexcept -> int override {
        return _process ? _process->pidfd() : -1;
    }
    [[nodiscard]] auto api() -> VmmApi& override { return _api; }
    [[nodiscard]] auto grant_group(std::uint32_t group) -> bool override {
        if (!_vfio_dir.empty() && !own(group, _ids.uid, _ids.gid)) {
            return false;
        }
        _granted.insert(group);
        return true;
    }
    auto revoke_group(std::uint32_t group) -> bool override {
        _granted.erase(group);
        return _vfio_dir.empty() || own(group, 0, 0);
    }
    auto kill() -> void override {
        if (_process) {
            (void)_process->signal(SIGKILL);
        }
    }
    [[nodiscard]] auto wait() -> std::expected<int, int> override {
        if (!_process) {
            return std::unexpected(ECHILD);
        }
        return _process->wait();
    }

    auto client() -> ChApiClient& { return _api; }

    std::optional<VmCgroup> _cgroup;
    std::optional<JailedProcess> _process;

private:
    // chown and chmod 0600 the group's node, without following a link.
    [[nodiscard]] auto own(std::uint32_t group, uid_t uid, gid_t gid) const -> bool {
        const auto node = _vfio_dir / std::to_string(group);
        const int fd = ::open(node.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            return false;
        }
        struct stat st{};
        const bool ok = ::fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) &&
                        ::fchownat(fd, "", uid, gid, AT_EMPTY_PATH) == 0 &&
                        ::chmod(("/proc/self/fd/" + std::to_string(fd)).c_str(), 0600) == 0;
        ::close(fd);
        return ok;
    }

    UidPool* _uids;
    VmId _vm;
    JailIds _ids;
    std::filesystem::path _dir;
    std::filesystem::path _vfio_dir;
    ChApiClient _api;
    std::set<std::uint32_t> _granted;
};

auto exited(int pidfd) -> bool {
    pollfd p{.fd = pidfd, .events = POLLIN, .revents = 0};
    return ::poll(&p, 1, 0) > 0;
}

}  // namespace

auto to_string(LaunchError e) noexcept -> const char* {
    switch (e) {
        case LaunchError::no_ids:
            return "no_ids";
        case LaunchError::run_dir:
            return "run_dir";
        case LaunchError::cgroup:
            return "cgroup";
        case LaunchError::jail:
            return "jail";
        case LaunchError::exited:
            return "exited";
        case LaunchError::api_timed_out:
            return "api_timed_out";
    }
    return "unknown";
}

auto default_vmm_paths() -> std::vector<PathRule> {
    return {
        {.path = "/dev/kvm", .access = PathAccess::device_rw},
        {.path = "/dev/vfio", .access = PathAccess::device_rw},
        {.path = "/dev/urandom", .access = PathAccess::read_only},
        {.path = "/sys", .access = PathAccess::read_only},
    };
}

auto JailedVmmLauncher::launch(const Allocation& allocation)
    -> std::expected<std::unique_ptr<VmmHandle>, LaunchFailure> {
    const auto ids = _uids->acquire(allocation.vm_id);
    if (!ids) {
        return std::unexpected(LaunchFailure{.error = LaunchError::no_ids, .detail = {}});
    }
    const auto dir = _config.run_dir / ("vm-" + std::to_string(allocation.vm_id));
    // From here the handle owns the UID and the directory.
    auto vmm = std::make_unique<JailedVmm>(*_uids, allocation.vm_id, *ids, dir, _config.vfio_dir,
                                           _config.api_timeout);

    // A directory left by a VM of the same ID from before an agent restart
    // holds nothing anyone needs.
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    if (::mkdir(dir.c_str(), 0700) != 0 || ::chown(dir.c_str(), ids->uid, ids->gid) != 0) {
        return std::unexpected(LaunchFailure{
            .error = LaunchError::run_dir, .detail = dir.native(), .sys_errno = errno});
    }

    if (_config.cgroup_parent_fd >= 0) {
        const auto limits =
            limits_for(allocation, allocation.vcpus + _config.pids_extra, _config.memory_max);
        auto cg = VmCgroup::create(_config.cgroup_parent_fd, allocation.vm_id, limits);
        if (!cg) {
            return std::unexpected(LaunchFailure{.error = LaunchError::cgroup,
                                                 .detail = cg.error().file,
                                                 .sys_errno = cg.error().sys_errno});
        }
        vmm->_cgroup.emplace(std::move(*cg));
    }

    JailSpec spec;
    spec.ids = *ids;
    spec.executable = _config.cloud_hypervisor;
    spec.argv = ch_argv(_config.cloud_hypervisor, dir / "api.sock");
    spec.working_dir = dir;
    spec.paths = _config.paths;
    spec.paths.push_back({.path = _config.cloud_hypervisor, .access = PathAccess::read_exec});
    spec.paths.push_back({.path = dir, .access = PathAccess::socket_dir});
    for (const auto* p :
         {&_config.payload.firmware, &_config.payload.kernel, &_config.payload.initramfs}) {
        if (!p->empty()) {
            spec.paths.push_back({.path = *p, .access = PathAccess::read_only});
        }
    }
    spec.paths.insert(spec.paths.end(), _config.extra_paths.begin(), _config.extra_paths.end());
    spec.cgroup_fd = vmm->_cgroup ? vmm->_cgroup->fd() : -1;
    spec.stderr_fd = _config.stderr_fd;
    if (_config.set_memlock) {
        spec.memlock_bytes = allocation.memory_bytes() + _config.memlock_margin;
    }

    auto process = spawn_jailed(spec);
    if (!process) {
        return std::unexpected(
            LaunchFailure{.error = LaunchError::jail,
                          .detail = std::string{to_string(process.error().error)} + " " +
                                    to_string(process.error().step) + " " + process.error().detail,
                          .sys_errno = process.error().sys_errno});
    }
    vmm->_process.emplace(std::move(*process));

    // Wait for the API. Cloud Hypervisor binds the socket early in its
    // start-up, so this is normally a few milliseconds.
    const auto deadline = Clock::now() + _config.start_timeout;
    for (;;) {
        if (exited(vmm->pidfd())) {
            return std::unexpected(LaunchFailure{.error = LaunchError::exited, .detail = {}});
        }
        if (vmm->client().ping()) {
            break;
        }
        if (Clock::now() >= deadline) {
            return std::unexpected(
                LaunchFailure{.error = LaunchError::api_timed_out, .detail = {}});
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return vmm;
}

}  // namespace ak::hull
