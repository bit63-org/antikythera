// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hull-init: /init in hull's initramfs (.kiro/specs/hull-host-agent/
// task 3, Requirements 3.1, 4.4, 5.1, 5.2, 5.3; design.md "Init"). A C++
// program, because the image has no shell.
//
//   1. mount /proc, /sys, /dev, /run, /dev/hugepages (1 GiB pages) and the
//      cgroup v2 hierarchy, and enable the controllers the per-VM cgroups
//      use at its root;
//   2. read the allow-list (/etc/hull/hull.conf, host_setup.hpp), and for
//      each SR-IOV board bind its PF to vfio-pci and set its VF count
//      (Requirement 5.3), so the VFs exist before step 3 looks for them;
//   3. find the mailbox and every slot's functions, bind each to vfio-pci
//      and check the binding took;
//   4. check every one is alone in its IOMMU group;
//   5. read the server ID from where the allow-list says;
//   6. write /run/hull/inventory and exec the agent with the mailbox
//      address, the inventory and the server ID.
//
// Any failure is fatal: init prints why and exits, which as PID 1 panics
// the kernel, so a host that cannot be set up safely does not run guests.
//
// For harbor and tests, --no-mount skips step 1 and the paths can be moved
// with --sysfs, --config, --cmdline, --dev (where the provisioning
// partition's device node is), --tpm (the TPM, default /dev/tpmrm0),
// --run-dir and --agent; arguments after "--" go to the agent unchanged.

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "hull/host_setup.hpp"
#include "hull/measured_boot.hpp"

namespace fs = std::filesystem;
using namespace ak::hull;

namespace {

struct Options {
    bool mount{true};
    fs::path sysfs{"/sys"};
    fs::path config{"/etc/hull/hull.conf"};
    fs::path cmdline{"/proc/cmdline"};
    fs::path dev{"/dev"};
    fs::path tpm{"/dev/tpmrm0"};
    fs::path run_dir{"/run/hull"};
    fs::path agent{"/usr/bin/hull-agent"};
    std::vector<std::string> agent_args;
};

[[noreturn]] auto die(const std::string& what) -> void {
    std::fprintf(stderr, "hull-init: %s\n", what.c_str());
    std::fflush(stderr);
    std::_Exit(1);
}

auto slurp(const fs::path& p) -> std::string {
    std::ifstream in{p, std::ios::binary};
    if (!in) {
        die("cannot read " + p.string());
    }
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

auto mount_or_die(const char* source, const char* target, const char* type, unsigned long flags,
                  const char* data) -> void {
    ::mkdir(target, 0755);
    if (::mount(source, target, type, flags, data) != 0 && errno != EBUSY) {
        die(std::string{"mount "} + target + ": " + std::strerror(errno));
    }
}

auto mount_all() -> void {
    constexpr unsigned long secure = MS_NOSUID | MS_NOEXEC | MS_NODEV;
    mount_or_die("proc", "/proc", "proc", secure, "hidepid=2");
    mount_or_die("sysfs", "/sys", "sysfs", secure, nullptr);
    mount_or_die("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
    mount_or_die("tmpfs", "/run", "tmpfs", secure, "mode=0755");
    mount_or_die("hugetlbfs", "/dev/hugepages", "hugetlbfs", secure, "pagesize=1G,mode=0700");
    mount_or_die("cgroup2", "/sys/fs/cgroup", "cgroup2", secure, nullptr);
    std::ofstream ctl{"/sys/fs/cgroup/cgroup.subtree_control"};
    ctl << "+cpuset +hugetlb +pids +memory";
    ctl.flush();
    if (!ctl) {
        die("cannot enable cgroup controllers at the root");
    }
}

auto parse_args(int argc, char** argv) -> Options {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a{argv[i]};
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                die(std::string{"missing value for "} + std::string{a});
            }
            return argv[++i];
        };
        if (a == "--no-mount") {
            o.mount = false;
        } else if (a == "--sysfs") {
            o.sysfs = value();
        } else if (a == "--config") {
            o.config = value();
        } else if (a == "--cmdline") {
            o.cmdline = value();
        } else if (a == "--dev") {
            o.dev = value();
        } else if (a == "--tpm") {
            o.tpm = value();
        } else if (a == "--run-dir") {
            o.run_dir = value();
        } else if (a == "--agent") {
            o.agent = value();
        } else if (a == "--") {
            for (++i; i < argc; ++i) {
                o.agent_args.emplace_back(argv[i]);
            }
        } else {
            die("unknown argument " + std::string{a});
        }
    }
    return o;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opt = parse_args(argc, argv);
    if (opt.mount) {
        mount_all();
    }

    const auto config = parse_host_config(slurp(opt.config));
    if (!config) {
        die(opt.config.string() + ":" + std::to_string(config.error().line) + ": " +
            config.error().reason);
    }

    for (const auto& rule : config->sriov) {
        const auto pf = find_sriov_pf(rule, opt.sysfs);
        if (!pf) {
            die(pf.error().step + ": " + pf.error().detail);
        }
        if (auto b = bind_to_vfio(*pf, opt.sysfs); !b) {
            die(b.error().step + " " + b.error().detail + ": " +
                std::strerror(b.error().sys_errno));
        }
        if (!bound_to_vfio(*pf, opt.sysfs)) {
            die("bind " + *pf + ": vfio-pci did not take it");
        }
        if (auto v = create_vfs(*pf, rule.vfs, opt.sysfs); !v) {
            die(v.error().step + ": " + v.error().detail +
                (v.error().sys_errno != 0 ? std::string{": "} + std::strerror(v.error().sys_errno)
                                          : std::string{}));
        }
        std::printf("hull-init: PF %s has %u VF(s)\n", pf->c_str(), unsigned{rule.vfs});
    }

    auto found = discover(*config, opt.sysfs);
    if (!found) {
        die(found.error().step + ": " + found.error().detail);
    }

    std::vector<std::string> all{found->mailbox_bdf};
    for (const auto& f : found->functions) {
        all.push_back(f.bdf);
    }
    for (const auto& bdf : all) {
        if (auto b = bind_to_vfio(bdf, opt.sysfs); !b) {
            die(b.error().step + " " + b.error().detail + ": " +
                std::strerror(b.error().sys_errno));
        }
        if (!bound_to_vfio(bdf, opt.sysfs)) {
            die("bind " + bdf + ": vfio-pci did not take it");
        }
    }
    for (auto& f : found->functions) {
        auto g = isolated_group(f.bdf, opt.sysfs);
        if (!g) {
            die(g.error().detail);
        }
        f.iommu_group = *g;
    }
    if (auto g = isolated_group(found->mailbox_bdf, opt.sysfs); !g) {
        die(g.error().detail);
    }

    // The server ID, and with helm's provisioning frame the boot epoch and
    // the sequence floor (.kiro/specs/cold-start/ Requirement 6). A server
    // ID from the command line comes with neither.
    std::optional<ak::proto::Provisioning> provisioning;
    if (config->server_id_source == ServerIdSource::cmdline) {
        if (const auto id = server_id_from_cmdline(slurp(opt.cmdline))) {
            provisioning = ak::proto::Provisioning{.server_id = *id};
        }
    } else if (config->server_id_source == ServerIdSource::partition) {
        // Measured into the TPM before it is read (server-provisioning
        // Requirement 4); a frame that cannot be measured stops the boot.
        auto p = read_measured_provisioning(opt.sysfs, opt.dev, opt.tpm);
        if (!p) {
            die(p.error().step + ": " + p.error().detail +
                (p.error().sys_errno != 0 ? std::string{": "} + std::strerror(p.error().sys_errno)
                                          : std::string{}));
        }
        provisioning = *p;
    } else {
        const auto text = slurp(config->server_id_file);
        provisioning = provisioning_from_file(std::as_bytes(std::span{text}));
    }
    if (!provisioning) {
        die("no valid server ID");
    }
    const auto server_id = provisioning->server_id;

    std::error_code ec;
    fs::create_directories(opt.run_dir, ec);
    const auto inventory = opt.run_dir / "inventory";
    {
        std::ofstream out{inventory, std::ios::trunc};
        out << format_inventory(found->functions);
        out.flush();
        if (!out) {
            die("cannot write " + inventory.string());
        }
    }
    std::printf(
        "hull-init: mailbox %s, %zu function(s), server %llu, boot epoch %llu, "
        "sequence floor %llu\n",
        found->mailbox_bdf.c_str(), found->functions.size(),
        static_cast<unsigned long long>(server_id),
        static_cast<unsigned long long>(provisioning->boot_epoch),
        static_cast<unsigned long long>(provisioning->sequence_floor));
    std::fflush(stdout);

    std::vector<std::string> args{opt.agent.string(),
                                  "--mailbox",
                                  found->mailbox_bdf,
                                  "--inventory",
                                  inventory.string(),
                                  "--server-id",
                                  std::to_string(server_id),
                                  "--boot-epoch",
                                  std::to_string(provisioning->boot_epoch),
                                  "--sequence-floor",
                                  std::to_string(provisioning->sequence_floor)};
    args.insert(args.end(), opt.agent_args.begin(), opt.agent_args.end());
    std::vector<char*> cargs;
    for (auto& a : args) {
        cargs.push_back(a.data());
    }
    cargs.push_back(nullptr);
    char* const envp[] = {nullptr};
    ::execve(opt.agent.c_str(), cargs.data(), envp);
    die("exec " + opt.agent.string() + ": " + std::strerror(errno));
}
