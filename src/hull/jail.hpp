// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The per-VMM jail (.kiro/specs/hull-host-agent/ task 7, Requirements 6.1
// and 9.1; design.md "VmSupervisor"). Each Cloud Hypervisor process starts
// confined by:
//
// - its own UID and GID, unique to the VM (UidPool), mapped 1:1 into
// - fresh user, PID, mount, IPC, network, UTS and cgroup namespaces
//   (clone3), so it sees only its own processes, no network interfaces, no
//   SysV IPC and none of the host's cgroup tree;
// - its cgroup (VmCgroup), entered atomically through CLONE_INTO_CGROUP;
// - a Landlock ruleset that allows only the paths the spec lists (in hull:
//   /dev/kvm, the VM's /dev/vfio nodes, the firmware, the VMM binary and
//   the directory holding its API socket) and, where the kernel supports
//   it, denies TCP and scopes abstract UNIX sockets and signals;
// - no capabilities (bounding, ambient, effective, permitted, inheritable
//   all empty), no_new_privs, no core dumps, a clean environment, and only
//   stdin/stdout/stderr open across exec.
//
// Seccomp is Cloud Hypervisor's own (--seccomp true), installed after it
// has opened its devices; the jail does not add a second filter.
//
// Everything the child needs is prepared in the parent before clone3: the
// Landlock ruleset is built there, argv and envp are flattened there. After
// clone3 the child makes raw system calls only (no allocation, no glibc
// setxid broadcast), because the agent is multithreaded and the child
// inherits a copy of locks other threads may hold.

#include <sys/types.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "hull/resource_allocator.hpp"

namespace ak::hull {

// --- Per-VM identities -----------------------------------------------------

struct JailIds {
    uid_t uid{0};
    gid_t gid{0};
    friend auto operator==(const JailIds&, const JailIds&) -> bool = default;
};

// Hands each VM a UID/GID pair from a reserved range (uid = gid = base + n),
// never two live VMs the same pair. The range must not overlap any account
// on the host; hull has none besides root.
class UidPool {
public:
    UidPool(uid_t base, std::uint32_t count) noexcept : _base{base}, _count{count} {}

    // The pair for `vm_id`: the lowest free slot. std::nullopt when the
    // range is exhausted or vm_id already holds one.
    [[nodiscard]] auto acquire(VmId vm_id) -> std::optional<JailIds>;
    // Returns vm_id's pair to the pool; false if it held none.
    auto release(VmId vm_id) -> bool;
    [[nodiscard]] auto find(VmId vm_id) const -> std::optional<JailIds>;
    [[nodiscard]] auto in_use() const noexcept -> std::size_t { return _by_vm.size(); }

private:
    uid_t _base;
    std::uint32_t _count;
    std::map<VmId, std::uint32_t> _by_vm;  // vm -> slot
};

// --- Landlock ---------------------------------------------------------------

enum class PathAccess : std::uint8_t {
    read_only,   // read files, list directories
    read_exec,   // read_only plus execute (the VMM binary, its libraries)
    device_rw,   // read, write and ioctl a device node (/dev/kvm, /dev/vfio/*)
    socket_dir,  // read_only plus create and remove sockets (the API socket)
    read_write,  // read_only plus create, write, truncate and remove regular files
};

struct PathRule {
    std::filesystem::path path;  // absolute, lexically normal
    PathAccess access{PathAccess::read_only};
};

// The Landlock ABI version the running kernel supports, or 0 when Landlock
// is compiled out or disabled at boot.
[[nodiscard]] auto landlock_abi() noexcept -> int;

// --- The jail ---------------------------------------------------------------

struct JailSpec {
    JailIds ids;
    std::filesystem::path executable;  // absolute; must be covered by a read_exec rule
    std::vector<std::string> argv;     // argv[0] included; non-empty
    std::vector<std::string> env;      // NAME=value; nothing else is inherited
    std::filesystem::path working_dir{"/"};
    std::vector<PathRule> paths;  // the only paths the VMM may touch

    int cgroup_fd{-1};  // VmCgroup::fd(), or -1 to stay in the agent's cgroup
    int stdout_fd{-1};  // -1: /dev/null
    int stderr_fd{-1};  // -1: /dev/null

    // RLIMIT_MEMLOCK for the VMM: VFIO pins all guest memory for DMA and
    // charges it here, so the supervisor sets it to the guest's memory plus
    // a margin. std::nullopt leaves the inherited limit.
    std::optional<std::uint64_t> memlock_bytes;

    bool mount_proc{true};       // a fresh /proc for the new PID namespace
    bool die_with_parent{true};  // SIGKILL the VMM if the agent dies
};

enum class JailError : std::uint8_t {
    invalid_spec,          // see validate()
    landlock_unavailable,  // the kernel has no Landlock: fail closed
    landlock_failed,       // building the ruleset failed (a path is missing, ...)
    io_failed,             // pipe, /dev/null or a similar parent-side setup step
    clone_failed,          // clone3 refused (no user namespaces, no permission, ...)
    id_map_failed,         // writing uid_map / gid_map / setgroups
    rlimit_failed,         // prlimit on the child
    child_setup_failed,    // a step in the child failed; see JailFailure::step
    exec_failed,           // execve failed
};

[[nodiscard]] auto to_string(JailError e) noexcept -> const char*;

// The child's setup steps, in order, for failure reports.
enum class JailStep : std::uint8_t {
    none,
    sync,    // waiting for the parent to write the ID maps
    groups,  // setgroups(0)
    ids,     // setresgid / setresuid
    mounts,  // private propagation, fresh /proc
    stdio,   // dup2 stdin/stdout/stderr
    fds,     // close_range
    chdir,
    prctl,         // pdeathsig, no_new_privs
    landlock,      // landlock_restrict_self
    capabilities,  // ambient, bounding, capset
    exec,
};

[[nodiscard]] auto to_string(JailStep s) noexcept -> const char*;

struct JailFailure {
    JailError error{JailError::invalid_spec};
    JailStep step{JailStep::none};
    int sys_errno{0};
    std::string detail;  // the offending path or field, when there is one
};

// Static checks, before any system call: non-root IDs, non-empty argv,
// absolute normal paths, the executable covered by a read_exec rule, the
// working directory covered by some rule, NAME=value environment entries,
// no NUL bytes anywhere.
[[nodiscard]] auto validate(const JailSpec& spec) -> std::expected<void, JailFailure>;

// A running jailed process. Move-only. The destructor SIGKILLs and reaps a
// process that has not been waited for, so a jail never outlives its handle.
class JailedProcess {
public:
    JailedProcess(const JailedProcess&) = delete;
    auto operator=(const JailedProcess&) -> JailedProcess& = delete;
    JailedProcess(JailedProcess&& other) noexcept;
    auto operator=(JailedProcess&& other) noexcept -> JailedProcess&;
    ~JailedProcess();

    [[nodiscard]] auto pid() const noexcept -> pid_t { return _pid; }
    // A pidfd for poll(2): readable once the process exits.
    [[nodiscard]] auto pidfd() const noexcept -> int { return _pidfd; }

    // Sends `sig` through the pidfd (no PID reuse race).
    [[nodiscard]] auto signal(int sig) const -> std::expected<void, int>;
    // Blocks until the process exits and reaps it. Returns the wait status
    // in waitpid(2) form (WIFEXITED / WEXITSTATUS / WIFSIGNALED work on it).
    [[nodiscard]] auto wait() -> std::expected<int, int>;

private:
    friend auto spawn_jailed(const JailSpec& spec) -> std::expected<JailedProcess, JailFailure>;
    JailedProcess(pid_t pid, int pidfd) noexcept : _pid{pid}, _pidfd{pidfd} {}
    void reset() noexcept;

    pid_t _pid{-1};
    int _pidfd{-1};
};

// Validates `spec`, builds its Landlock ruleset and starts the jailed
// process. Returns once the child has exec'd (or failed: the failure names
// the step and errno, and the child has been reaped).
//
// Run as root this is the production path: any non-root IDs may be mapped.
// Run unprivileged (the test suite in CI) the kernel allows mapping only
// the caller's own IDs, setgroups is denied, and RLIMIT_MEMLOCK can only be
// lowered.
[[nodiscard]] auto spawn_jailed(const JailSpec& spec) -> std::expected<JailedProcess, JailFailure>;

}  // namespace ak::hull
