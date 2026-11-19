// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Runs inside the jail for jail_test and reports what it can see and do,
// one "key=value" line per command on stdout:
//
//   jail_probe report             ids, pid, groups, capabilities, no_new_privs,
//                                 RLIMIT_CORE, RLIMIT_MEMLOCK, cwd, environment size
//   jail_probe read <path>        open(O_RDONLY)
//   jail_probe write <path>       open(O_WRONLY)
//   jail_probe exec <path>        execv; prints only on failure
//   jail_probe cgroup             the first line of /proc/self/cgroup
//   jail_probe sleep              pause until killed

#include <fcntl.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

namespace {

auto report() -> int {
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, 2> caps{};
    if (::syscall(SYS_capget, &header, caps.data()) != 0) {
        std::cout << "capget_errno=" << errno << "\n";
        return 1;
    }
    std::uint64_t bounding = 0;
    for (unsigned long cap = 0; cap < 64; ++cap) {
        const int r = ::prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (r < 0) {
            break;
        }
        if (r == 1) {
            bounding |= 1ULL << cap;
        }
    }
    rlimit core{};
    rlimit memlock{};
    (void)::getrlimit(RLIMIT_CORE, &core);
    (void)::getrlimit(RLIMIT_MEMLOCK, &memlock);
    std::array<char, 4096> cwd{};
    if (::getcwd(cwd.data(), cwd.size()) == nullptr) {
        cwd[0] = '\0';
    }
    std::size_t env_count = 0;
    for (char** e = environ; *e != nullptr; ++e) {
        ++env_count;
    }
    std::cout << "uid=" << ::getuid() << " euid=" << ::geteuid() << " gid=" << ::getgid()
              << " egid=" << ::getegid() << " pid=" << ::getpid()
              << " groups=" << ::getgroups(0, nullptr)
              << " cap_eff=" << (caps[0].effective | caps[1].effective)
              << " cap_prm=" << (caps[0].permitted | caps[1].permitted) << " cap_bnd=" << bounding
              << " nnp=" << ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) << " core=" << core.rlim_cur
              << " memlock=" << memlock.rlim_cur << " cwd=" << cwd.data() << " env=" << env_count
              << "\n";
    return 0;
}

auto try_open(const char* path, int flags) -> int {
    const int fd = ::open(path, flags | O_CLOEXEC);
    if (fd < 0) {
        std::cout << "errno=" << errno << "\n";
        return 0;
    }
    (void)::close(fd);
    std::cout << "ok\n";
    return 0;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::span args{argv, static_cast<std::size_t>(argc)};
    if (args.size() < 2) {
        return 2;
    }
    const std::string_view cmd{args[1]};
    if (cmd == "report") {
        return report();
    }
    if (cmd == "read" && args.size() == 3) {
        return try_open(args[2], O_RDONLY);
    }
    if (cmd == "write" && args.size() == 3) {
        return try_open(args[2], O_WRONLY);
    }
    if (cmd == "exec" && args.size() == 3) {
        std::cout.flush();
        std::array<char*, 2> exec_argv{args[2], nullptr};
        ::execv(args[2], exec_argv.data());
        std::cout << "errno=" << errno << "\n";
        return 0;
    }
    if (cmd == "cgroup") {
        std::ifstream in{"/proc/self/cgroup"};
        std::string line;
        std::getline(in, line);
        std::cout << "cgroup=" << line << "\n";
        return 0;
    }
    if (cmd == "sleep") {
        ::pause();
        return 0;
    }
    return 2;
}
