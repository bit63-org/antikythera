// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/jail.hpp"

#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <string_view>
#include <utility>

namespace ak::hull {

namespace {

// --- Kernel ABI, spelled out ------------------------------------------------
//
// Landlock and clone3 grew fields after Ubuntu 24.04's uapi headers were
// cut (Landlock scopes are ABI 6), so the structures and constants are
// defined here from the stable kernel ABI rather than taken from headers
// whose contents depend on the build host.

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2U)
#endif

constexpr std::uint32_t landlock_create_ruleset_version = 1U << 0U;
constexpr int landlock_rule_path_beneath = 1;

namespace fs_access {
constexpr std::uint64_t execute = 1ULL << 0U;
constexpr std::uint64_t write_file = 1ULL << 1U;
constexpr std::uint64_t read_file = 1ULL << 2U;
constexpr std::uint64_t read_dir = 1ULL << 3U;
constexpr std::uint64_t remove_dir = 1ULL << 4U;
constexpr std::uint64_t remove_file = 1ULL << 5U;
constexpr std::uint64_t make_dir = 1ULL << 7U;
constexpr std::uint64_t make_reg = 1ULL << 8U;
constexpr std::uint64_t make_sock = 1ULL << 9U;
constexpr std::uint64_t truncate = 1ULL << 14U;   // ABI 3
constexpr std::uint64_t ioctl_dev = 1ULL << 15U;  // ABI 5
// The only rights a rule on a non-directory may carry.
constexpr std::uint64_t file_only = execute | write_file | read_file | truncate | ioctl_dev;
}  // namespace fs_access

constexpr std::uint64_t net_bind_tcp = 1ULL << 0U;                // ABI 4
constexpr std::uint64_t net_connect_tcp = 1ULL << 1U;             // ABI 4
constexpr std::uint64_t scope_abstract_unix_socket = 1ULL << 0U;  // ABI 6
constexpr std::uint64_t scope_signal = 1ULL << 1U;                // ABI 6

struct LandlockRulesetAttr {
    std::uint64_t handled_access_fs;
    std::uint64_t handled_access_net;  // ABI 4
    std::uint64_t scoped;              // ABI 6
};

struct __attribute__((packed)) LandlockPathBeneathAttr {
    std::uint64_t allowed_access;
    std::int32_t parent_fd;
};

// Every filesystem right the kernel's ABI knows: all of them are "handled",
// so anything a rule does not grant is denied.
auto handled_fs(int abi) noexcept -> std::uint64_t {
    if (abi >= 5) {
        return (1ULL << 16U) - 1;
    }
    if (abi >= 3) {
        return (1ULL << 15U) - 1;
    }
    if (abi == 2) {
        return (1ULL << 14U) - 1;
    }
    return (1ULL << 13U) - 1;
}

auto rights_for(PathAccess access) noexcept -> std::uint64_t {
    using namespace fs_access;
    constexpr std::uint64_t read = read_file | read_dir;
    switch (access) {
        case PathAccess::read_only:
            return read;
        case PathAccess::read_exec:
            return read | execute;
        case PathAccess::device_rw:
            return read | write_file | ioctl_dev;
        case PathAccess::socket_dir:
            return read | make_sock | remove_file;
        case PathAccess::read_write:
            return read | write_file | truncate | make_reg | make_dir | remove_file | remove_dir;
    }
    return 0;
}

constexpr std::uint32_t clone_into_cgroup_flag_bit = 33;  // CLONE_INTO_CGROUP, 5.7
constexpr std::uint64_t clone_pidfd = 0x00001000ULL;

struct CloneArgs {
    std::uint64_t flags;
    std::uint64_t pidfd;
    std::uint64_t child_tid;
    std::uint64_t parent_tid;
    std::uint64_t exit_signal;
    std::uint64_t stack;
    std::uint64_t stack_size;
    std::uint64_t tls;
    std::uint64_t set_tid;
    std::uint64_t set_tid_size;
    std::uint64_t cgroup;
};

// --- Small RAII and helpers -------------------------------------------------

class Fd {
public:
    Fd() noexcept = default;
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&& other) noexcept : _fd{std::exchange(other._fd, -1)} {}
    auto operator=(Fd&& other) noexcept -> Fd& {
        if (this != &other) {
            close();
            _fd = std::exchange(other._fd, -1);
        }
        return *this;
    }
    ~Fd() { close(); }
    [[nodiscard]] auto get() const noexcept -> int { return _fd; }
    [[nodiscard]] auto valid() const noexcept -> bool { return _fd >= 0; }
    void close() noexcept {
        if (_fd >= 0) {
            (void)::close(_fd);
            _fd = -1;
        }
    }

private:
    int _fd{-1};
};

// A close-on-exec duplicate of `fd` numbered 3 or above, so the child's
// dup2 onto 0-2 never collides with a descriptor it still needs.
auto high_dup(int fd) -> Fd {
    return Fd{::fcntl(fd, F_DUPFD_CLOEXEC, 3)};
}

auto failure(JailError e, int err = 0, std::string detail = {}) -> std::unexpected<JailFailure> {
    return std::unexpected(JailFailure{e, JailStep::none, err, std::move(detail)});
}

auto has_nul(std::string_view s) noexcept -> bool {
    return s.find('\0') != std::string_view::npos;
}

// Absolute, no "." or ".." component, no empty component, no trailing
// slash (except "/" itself). Landlock and the jail compare paths
// component-wise, so anything looser could cover more than it says.
auto is_clean_absolute(const std::filesystem::path& p) -> bool {
    const auto& s = p.native();
    if (s.empty() || s.front() != '/' || has_nul(s)) {
        return false;
    }
    if (s == "/") {
        return true;
    }
    if (s.back() == '/') {
        return false;
    }
    std::string_view rest{s};
    rest.remove_prefix(1);
    while (true) {
        const auto slash = rest.find('/');
        const auto part = rest.substr(0, slash);
        if (part.empty() || part == "." || part == "..") {
            return false;
        }
        if (slash == std::string_view::npos) {
            return true;
        }
        rest.remove_prefix(slash + 1);
    }
}

// True when `inner` is `outer` or lies beneath it, component-wise.
auto is_within(const std::filesystem::path& inner, const std::filesystem::path& outer) -> bool {
    const auto& i = inner.native();
    const auto& o = outer.native();
    if (o == "/") {
        return true;
    }
    return i == o || (i.size() > o.size() && i.starts_with(o) && i[o.size()] == '/');
}

auto build_ruleset(int abi, const std::vector<PathRule>& rules) -> std::expected<Fd, JailFailure> {
    LandlockRulesetAttr attr{};
    attr.handled_access_fs = handled_fs(abi);
    std::size_t attr_size = sizeof(std::uint64_t);
    if (abi >= 4) {
        attr.handled_access_net = net_bind_tcp | net_connect_tcp;
        attr_size = 2 * sizeof(std::uint64_t);
    }
    if (abi >= 6) {
        attr.scoped = scope_abstract_unix_socket | scope_signal;
        attr_size = sizeof attr;
    }
    Fd ruleset{static_cast<int>(::syscall(SYS_landlock_create_ruleset, &attr, attr_size, 0U))};
    if (!ruleset.valid()) {
        return failure(JailError::landlock_failed, errno, "landlock_create_ruleset");
    }
    for (const auto& rule : rules) {
        const Fd target{::open(rule.path.c_str(), O_PATH | O_CLOEXEC)};
        if (!target.valid()) {
            return failure(JailError::landlock_failed, errno, rule.path.string());
        }
        struct stat st{};
        if (::fstat(target.get(), &st) != 0) {
            return failure(JailError::landlock_failed, errno, rule.path.string());
        }
        auto allowed = rights_for(rule.access) & attr.handled_access_fs;
        if (!S_ISDIR(st.st_mode)) {
            allowed &= fs_access::file_only;
        }
        const LandlockPathBeneathAttr beneath{allowed, target.get()};
        if (::syscall(SYS_landlock_add_rule, ruleset.get(), landlock_rule_path_beneath, &beneath,
                      0U) != 0) {
            return failure(JailError::landlock_failed, errno, rule.path.string());
        }
    }
    return ruleset;
}

auto write_proc_file(pid_t pid, const char* name, std::string_view text) -> int {
    const auto path = "/proc/" + std::to_string(pid) + "/" + name;
    const Fd fd{::open(path.c_str(), O_WRONLY | O_CLOEXEC)};
    if (!fd.valid()) {
        return errno;
    }
    const auto n = ::write(fd.get(), text.data(), text.size());
    if (n < 0) {
        return errno;
    }
    return static_cast<std::size_t>(n) == text.size() ? 0 : EIO;
}

// --- The child --------------------------------------------------------------

struct ChildReport {
    std::uint32_t step;
    std::int32_t err;
};

// Everything the child reads, prepared by the parent. Plain data only.
struct ChildPlan {
    int sync_read;
    int sync_write;
    int report_read;
    int report_write;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    int ruleset_fd;
    uid_t uid;
    gid_t gid;
    bool clear_groups;
    bool mount_proc;
    bool die_with_parent;
    const char* executable;
    const char* working_dir;
    char* const* argv;
    char* const* envp;
};

[[noreturn]] void child_fail(const ChildPlan& plan, JailStep step, int err) noexcept {
    const ChildReport report{static_cast<std::uint32_t>(step), err};
    // Best effort: if the parent is gone there is nobody to tell.
    [[maybe_unused]] const auto written = ::write(plan.report_write, &report, sizeof report);
    ::_exit(127);
}

// Runs in the clone3 child. Raw system calls only: no allocation, and no
// glibc set*id wrappers (they signal every thread the parent had).
[[noreturn]] void child_main(const ChildPlan& plan) noexcept {
    (void)::close(plan.sync_write);
    (void)::close(plan.report_read);

    char go = 0;
    ssize_t n = 0;
    do {
        n = ::read(plan.sync_read, &go, 1);
    } while (n < 0 && errno == EINTR);
    if (n != 1) {
        child_fail(plan, JailStep::sync, n < 0 ? errno : EPIPE);
    }

    if (plan.clear_groups && ::syscall(SYS_setgroups, 0, nullptr) != 0) {
        child_fail(plan, JailStep::groups, errno);
    }
    if (::syscall(SYS_setresgid, plan.gid, plan.gid, plan.gid) != 0 ||
        ::syscall(SYS_setresuid, plan.uid, plan.uid, plan.uid) != 0) {
        child_fail(plan, JailStep::ids, errno);
    }

    // The mount namespace is a copy of the agent's: stop propagation both
    // ways, and give the new PID namespace a /proc that shows only it.
    if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        child_fail(plan, JailStep::mounts, errno);
    }
    if (plan.mount_proc &&
        ::mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
        child_fail(plan, JailStep::mounts, errno);
    }

    if (::dup2(plan.stdin_fd, STDIN_FILENO) < 0 || ::dup2(plan.stdout_fd, STDOUT_FILENO) < 0 ||
        ::dup2(plan.stderr_fd, STDERR_FILENO) < 0) {
        child_fail(plan, JailStep::stdio, errno);
    }
    // Everything above 2 closes at exec, including the report pipe, whose
    // closing tells the parent the exec succeeded.
    if (::syscall(SYS_close_range, 3U, ~0U, CLOSE_RANGE_CLOEXEC) != 0) {
        child_fail(plan, JailStep::fds, errno);
    }

    if (::chdir(plan.working_dir) != 0) {
        child_fail(plan, JailStep::chdir, errno);
    }

    // PDEATHSIG is cleared by a credential change, so it is set after
    // setresuid; it survives the exec of a non-set-ID binary.
    if (plan.die_with_parent && ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
        child_fail(plan, JailStep::prctl, errno);
    }
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        child_fail(plan, JailStep::prctl, errno);
    }

    if (::syscall(SYS_landlock_restrict_self, plan.ruleset_fd, 0U) != 0) {
        child_fail(plan, JailStep::landlock, errno);
    }

    // The child holds a full capability set in its user namespace. Empty
    // every set: ambient, bounding (until the kernel says the number is
    // past its last capability), then effective/permitted/inheritable.
    if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
        child_fail(plan, JailStep::capabilities, errno);
    }
    for (unsigned long cap = 0; cap < 64; ++cap) {
        if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
            if (errno == EINVAL) {
                break;
            }
            child_fail(plan, JailStep::capabilities, errno);
        }
    }
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, 2> data{};
    if (::syscall(SYS_capset, &header, data.data()) != 0) {
        child_fail(plan, JailStep::capabilities, errno);
    }

    ::execve(plan.executable, plan.argv, plan.envp);
    child_fail(plan, JailStep::exec, errno);
}

}  // namespace

// --- UidPool -----------------------------------------------------------------

auto UidPool::acquire(VmId vm_id) -> std::optional<JailIds> {
    if (_by_vm.contains(vm_id) || _by_vm.size() >= _count) {
        return std::nullopt;
    }
    std::vector<bool> used(_count, false);
    for (const auto& [vm, slot] : _by_vm) {
        used[slot] = true;
    }
    const auto it = std::ranges::find(used, false);
    const auto slot = static_cast<std::uint32_t>(it - used.begin());
    _by_vm.emplace(vm_id, slot);
    return JailIds{_base + slot, _base + slot};
}

auto UidPool::release(VmId vm_id) -> bool {
    return _by_vm.erase(vm_id) == 1;
}

auto UidPool::find(VmId vm_id) const -> std::optional<JailIds> {
    const auto it = _by_vm.find(vm_id);
    if (it == _by_vm.end()) {
        return std::nullopt;
    }
    return JailIds{_base + it->second, _base + it->second};
}

// --- Strings -------------------------------------------------------------------

auto to_string(JailError e) noexcept -> const char* {
    switch (e) {
        case JailError::invalid_spec:
            return "invalid_spec";
        case JailError::landlock_unavailable:
            return "landlock_unavailable";
        case JailError::landlock_failed:
            return "landlock_failed";
        case JailError::io_failed:
            return "io_failed";
        case JailError::clone_failed:
            return "clone_failed";
        case JailError::id_map_failed:
            return "id_map_failed";
        case JailError::rlimit_failed:
            return "rlimit_failed";
        case JailError::child_setup_failed:
            return "child_setup_failed";
        case JailError::exec_failed:
            return "exec_failed";
    }
    return "unknown";
}

auto to_string(JailStep s) noexcept -> const char* {
    switch (s) {
        case JailStep::none:
            return "none";
        case JailStep::sync:
            return "sync";
        case JailStep::groups:
            return "groups";
        case JailStep::ids:
            return "ids";
        case JailStep::mounts:
            return "mounts";
        case JailStep::stdio:
            return "stdio";
        case JailStep::fds:
            return "fds";
        case JailStep::chdir:
            return "chdir";
        case JailStep::prctl:
            return "prctl";
        case JailStep::landlock:
            return "landlock";
        case JailStep::capabilities:
            return "capabilities";
        case JailStep::exec:
            return "exec";
    }
    return "unknown";
}

// --- Landlock ------------------------------------------------------------------

auto landlock_abi() noexcept -> int {
    const auto abi =
        ::syscall(SYS_landlock_create_ruleset, nullptr, 0, landlock_create_ruleset_version);
    return abi < 0 ? 0 : static_cast<int>(abi);
}

// --- Validation ----------------------------------------------------------------

auto validate(const JailSpec& spec) -> std::expected<void, JailFailure> {
    if (spec.ids.uid == 0 || spec.ids.gid == 0) {
        return failure(JailError::invalid_spec, 0, "ids");
    }
    if (spec.argv.empty()) {
        return failure(JailError::invalid_spec, 0, "argv");
    }
    for (const auto& a : spec.argv) {
        if (has_nul(a)) {
            return failure(JailError::invalid_spec, 0, "argv");
        }
    }
    for (const auto& e : spec.env) {
        const auto eq = e.find('=');
        if (has_nul(e) || eq == std::string::npos || eq == 0) {
            return failure(JailError::invalid_spec, 0, "env");
        }
    }
    for (const auto& rule : spec.paths) {
        if (!is_clean_absolute(rule.path)) {
            return failure(JailError::invalid_spec, 0, rule.path.string());
        }
    }
    if (!is_clean_absolute(spec.executable)) {
        return failure(JailError::invalid_spec, 0, spec.executable.string());
    }
    const bool exec_covered = std::ranges::any_of(spec.paths, [&](const PathRule& r) {
        return r.access == PathAccess::read_exec && is_within(spec.executable, r.path);
    });
    if (!exec_covered) {
        return failure(JailError::invalid_spec, 0, spec.executable.string());
    }
    if (!is_clean_absolute(spec.working_dir)) {
        return failure(JailError::invalid_spec, 0, spec.working_dir.string());
    }
    const bool cwd_covered = std::ranges::any_of(
        spec.paths, [&](const PathRule& r) { return is_within(spec.working_dir, r.path); });
    if (!cwd_covered) {
        return failure(JailError::invalid_spec, 0, spec.working_dir.string());
    }
    return {};
}

// --- JailedProcess -------------------------------------------------------------

JailedProcess::JailedProcess(JailedProcess&& other) noexcept
    : _pid{std::exchange(other._pid, -1)}, _pidfd{std::exchange(other._pidfd, -1)} {}

auto JailedProcess::operator=(JailedProcess&& other) noexcept -> JailedProcess& {
    if (this != &other) {
        reset();
        _pid = std::exchange(other._pid, -1);
        _pidfd = std::exchange(other._pidfd, -1);
    }
    return *this;
}

JailedProcess::~JailedProcess() {
    reset();
}

void JailedProcess::reset() noexcept {
    if (_pid > 0) {
        (void)signal(SIGKILL);
        int status = 0;
        while (::waitpid(_pid, &status, 0) < 0 && errno == EINTR) {
        }
        _pid = -1;
    }
    if (_pidfd >= 0) {
        (void)::close(_pidfd);
        _pidfd = -1;
    }
}

auto JailedProcess::signal(int sig) const -> std::expected<void, int> {
    if (_pidfd < 0) {
        return std::unexpected(EBADF);
    }
    if (::syscall(SYS_pidfd_send_signal, _pidfd, sig, nullptr, 0U) != 0) {
        return std::unexpected(errno);
    }
    return {};
}

auto JailedProcess::wait() -> std::expected<int, int> {
    if (_pid <= 0) {
        return std::unexpected(ECHILD);
    }
    int status = 0;
    pid_t r = 0;
    do {
        r = ::waitpid(_pid, &status, 0);
    } while (r < 0 && errno == EINTR);
    if (r < 0) {
        return std::unexpected(errno);
    }
    _pid = -1;  // reaped: the destructor must not signal a reused PID
    return status;
}

// --- spawn_jailed ----------------------------------------------------------------

auto spawn_jailed(const JailSpec& spec) -> std::expected<JailedProcess, JailFailure> {
    if (auto v = validate(spec); !v) {
        return std::unexpected(v.error());
    }
    const int abi = landlock_abi();
    if (abi < 1) {
        return failure(JailError::landlock_unavailable);
    }
    auto ruleset = build_ruleset(abi, spec.paths);
    if (!ruleset) {
        return std::unexpected(ruleset.error());
    }
    Fd ruleset_fd = high_dup(ruleset->get());

    // argv and envp as the char* arrays execve wants, owned here.
    std::vector<std::string> strings;
    strings.reserve(spec.argv.size() + spec.env.size());
    strings.insert(strings.end(), spec.argv.begin(), spec.argv.end());
    strings.insert(strings.end(), spec.env.begin(), spec.env.end());
    std::vector<char*> argv;
    std::vector<char*> envp;
    for (std::size_t i = 0; i < strings.size(); ++i) {
        (i < spec.argv.size() ? argv : envp).push_back(strings[i].data());
    }
    argv.push_back(nullptr);
    envp.push_back(nullptr);
    const std::string executable = spec.executable.string();
    const std::string working_dir = spec.working_dir.string();

    const Fd devnull_raw{::open("/dev/null", O_RDWR | O_CLOEXEC)};
    if (!devnull_raw.valid()) {
        return failure(JailError::io_failed, errno, "/dev/null");
    }
    const Fd devnull = high_dup(devnull_raw.get());
    const Fd out = high_dup(spec.stdout_fd >= 0 ? spec.stdout_fd : devnull.get());
    const Fd err = high_dup(spec.stderr_fd >= 0 ? spec.stderr_fd : devnull.get());

    std::array<int, 2> sync_raw{-1, -1};
    std::array<int, 2> report_raw{-1, -1};
    if (::pipe2(sync_raw.data(), O_CLOEXEC) != 0) {
        return failure(JailError::io_failed, errno, "pipe");
    }
    Fd sync_read_raw{sync_raw[0]};
    Fd sync_write_raw{sync_raw[1]};
    if (::pipe2(report_raw.data(), O_CLOEXEC) != 0) {
        return failure(JailError::io_failed, errno, "pipe");
    }
    Fd report_read_raw{report_raw[0]};
    Fd report_write_raw{report_raw[1]};
    Fd sync_read = high_dup(sync_read_raw.get());
    Fd sync_write = high_dup(sync_write_raw.get());
    Fd report_read = high_dup(report_read_raw.get());
    Fd report_write = high_dup(report_write_raw.get());
    sync_read_raw.close();
    sync_write_raw.close();
    report_read_raw.close();
    report_write_raw.close();
    if (!ruleset_fd.valid() || !devnull.valid() || !out.valid() || !err.valid() ||
        !sync_read.valid() || !sync_write.valid() || !report_read.valid() ||
        !report_write.valid()) {
        return failure(JailError::io_failed, EBADF, "fd");
    }

    const bool privileged = ::geteuid() == 0;
    const ChildPlan plan{
        .sync_read = sync_read.get(),
        .sync_write = sync_write.get(),
        .report_read = report_read.get(),
        .report_write = report_write.get(),
        .stdin_fd = devnull.get(),
        .stdout_fd = out.get(),
        .stderr_fd = err.get(),
        .ruleset_fd = ruleset_fd.get(),
        .uid = spec.ids.uid,
        .gid = spec.ids.gid,
        .clear_groups = privileged,
        .mount_proc = spec.mount_proc,
        .die_with_parent = spec.die_with_parent,
        .executable = executable.c_str(),
        .working_dir = working_dir.c_str(),
        .argv = argv.data(),
        .envp = envp.data(),
    };

    int pidfd = -1;
    CloneArgs args{};
    args.flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWNET |
                 CLONE_NEWUTS | CLONE_NEWCGROUP | clone_pidfd;
    args.pidfd = reinterpret_cast<std::uint64_t>(&pidfd);
    args.exit_signal = SIGCHLD;
    if (spec.cgroup_fd >= 0) {
        args.flags |= 1ULL << clone_into_cgroup_flag_bit;
        args.cgroup = static_cast<std::uint64_t>(spec.cgroup_fd);
    }
    const auto pid = static_cast<pid_t>(::syscall(SYS_clone3, &args, sizeof args));
    if (pid < 0) {
        return failure(JailError::clone_failed, errno);
    }
    if (pid == 0) {
        child_main(plan);
    }

    // Parent. From here on a failure must kill and reap the child: the
    // JailedProcess handle does that in its destructor.
    JailedProcess child{pid, pidfd};
    sync_read.close();
    report_write.close();

    const auto abort_child = [&](JailError e, int error, std::string detail) {
        sync_write.close();  // the child reads EOF and exits if still waiting
        (void)child.signal(SIGKILL);
        (void)child.wait();
        return failure(e, error, std::move(detail));
    };

    // An unprivileged writer must deny setgroups before writing gid_map
    // (user_namespaces(7)); a privileged agent leaves it allowed so the
    // child can drop its supplementary groups.
    if (!privileged) {
        if (const int e = write_proc_file(pid, "setgroups", "deny"); e != 0) {
            return abort_child(JailError::id_map_failed, e, "setgroups");
        }
    }
    const auto uid_line =
        std::to_string(spec.ids.uid) + " " + std::to_string(spec.ids.uid) + " 1\n";
    const auto gid_line =
        std::to_string(spec.ids.gid) + " " + std::to_string(spec.ids.gid) + " 1\n";
    if (const int e = write_proc_file(pid, "uid_map", uid_line); e != 0) {
        return abort_child(JailError::id_map_failed, e, "uid_map");
    }
    if (const int e = write_proc_file(pid, "gid_map", gid_line); e != 0) {
        return abort_child(JailError::id_map_failed, e, "gid_map");
    }

    // Resource limits are set from outside: raising RLIMIT_MEMLOCK needs
    // CAP_SYS_RESOURCE in the initial namespace, which the child never has.
    const rlimit no_core{0, 0};
    if (::prlimit(pid, RLIMIT_CORE, &no_core, nullptr) != 0) {
        return abort_child(JailError::rlimit_failed, errno, "RLIMIT_CORE");
    }
    if (spec.memlock_bytes) {
        const rlimit memlock{*spec.memlock_bytes, *spec.memlock_bytes};
        if (::prlimit(pid, RLIMIT_MEMLOCK, &memlock, nullptr) != 0) {
            return abort_child(JailError::rlimit_failed, errno, "RLIMIT_MEMLOCK");
        }
    }

    const char go = 1;
    if (::write(sync_write.get(), &go, 1) != 1) {
        return abort_child(JailError::io_failed, errno, "sync");
    }
    sync_write.close();

    ChildReport report{};
    ssize_t n = 0;
    do {
        n = ::read(report_read.get(), &report, sizeof report);
    } while (n < 0 && errno == EINTR);
    if (n == 0) {
        return child;  // the report pipe closed at exec: the jail is running
    }
    (void)child.wait();
    if (n != static_cast<ssize_t>(sizeof report)) {
        return failure(JailError::io_failed, n < 0 ? errno : EIO, "report");
    }
    const auto step = static_cast<JailStep>(report.step);
    return std::unexpected(
        JailFailure{step == JailStep::exec ? JailError::exec_failed : JailError::child_setup_failed,
                    step, report.err, step == JailStep::exec ? executable : std::string{}});
}

}  // namespace ak::hull
