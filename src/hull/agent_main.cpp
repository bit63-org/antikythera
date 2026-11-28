// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hull-agent: the host's one privileged process (.kiro/specs/hull-host-agent/
// tasks 3, 4, 8, 9; design.md "Overview"). hull-init execs it with the
// mailbox's address, the inventory it recorded and the server ID.
//
// Setup, while it still has every capability:
//   - the compiled-in controller keys (controller_keys.hpp, Requirement 4.1);
//   - the inventory file; the CPU topology, isolated CPUs and free 1 GiB
//     pages from sysfs;
//   - the parent cgroup for VMs (<cgroup>/hull, controllers enabled);
//   - the mailbox through VFIO (BAR0 mapped, MSI-X on an eventfd, no DMA).
// Then it drops every capability it does not need (capabilities.hpp,
// Requirement 9.1), tells helm it (re)started with HOST_FAULT
// agent_restarted, and runs one loop:
//   - poll the MSI-X eventfd and every VMM's pidfd;
//   - on an interrupt, take commands until the doorbell is quiet;
//   - handle VMM exits and pending detaches;
//   - send the events those produced, after the responses they follow.
//
// Usage:
//   hull-agent --mailbox <bdf> --inventory <file> --server-id <n>
//              [--cloud-hypervisor <path>] (--firmware <path> |
//              --kernel <path> [--cmdline <text>] [--initramfs <path>])
//              [--run-dir <dir>] [--cgroup <dir>] [--uid-base <n>]
//              [--uid-count <n>] [--sysfs <dir>] [--vmm-stderr]

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "hull/agent_handler.hpp"
#include "hull/capabilities.hpp"
#include "hull/controller_keys.hpp"
#include "hull/cpu_topology.hpp"
#include "hull/host_setup.hpp"
#include "hull/jail.hpp"
#include "hull/mailbox_client.hpp"
#include "hull/resource_allocator.hpp"
#include "hull/sequence_tracker.hpp"
#include "hull/standing_starts.hpp"
#include "hull/signature_verifier.hpp"
#include "hull/vfio_mailbox.hpp"
#include "hull/vm_cgroup.hpp"
#include "hull/vm_supervisor.hpp"
#include "hull/vmm_launcher.hpp"

namespace fs = std::filesystem;
namespace mb = ak::helm::mailbox;
using namespace ak::hull;

namespace {

struct Options {
    std::string mailbox;
    fs::path inventory;
    mb::ServerId server_id{mb::no_server_id};
    // From helm's provisioning file (.kiro/specs/cold-start/ Requirement 6):
    // this boot's number and the last sequence number helm relayed before
    // it, below which every command is a replay.
    std::uint64_t boot_epoch{0};
    std::uint64_t sequence_floor{0};
    fs::path cloud_hypervisor{"/usr/bin/cloud-hypervisor"};
    BootPayload payload;
    fs::path run_dir{"/run/hull"};
    fs::path cgroup{"/sys/fs/cgroup"};
    uid_t uid_base{100'000};
    std::uint32_t uid_count{4096};
    fs::path sysfs{"/sys"};
    bool vmm_stderr{false};
};

[[noreturn]] auto die(const std::string& what) -> void {
    std::fprintf(stderr, "hull-agent: %s\n", what.c_str());
    std::fflush(stderr);
    std::_Exit(1);
}

template<typename T> auto number(std::string_view s, const char* what) -> T {
    T v{};
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size()) {
        die(std::string{"bad "} + what);
    }
    return v;
}

auto parse_args(int argc, char** argv) -> Options {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a{argv[i]};
        auto value = [&]() -> std::string_view {
            if (i + 1 >= argc) {
                die("missing value for " + std::string{a});
            }
            return argv[++i];
        };
        if (a == "--mailbox") {
            o.mailbox = value();
        } else if (a == "--inventory") {
            o.inventory = value();
        } else if (a == "--server-id") {
            o.server_id = number<mb::ServerId>(value(), "--server-id");
        } else if (a == "--boot-epoch") {
            o.boot_epoch = number<std::uint64_t>(value(), "--boot-epoch");
        } else if (a == "--sequence-floor") {
            o.sequence_floor = number<std::uint64_t>(value(), "--sequence-floor");
        } else if (a == "--cloud-hypervisor") {
            o.cloud_hypervisor = value();
        } else if (a == "--firmware") {
            o.payload.firmware = value();
        } else if (a == "--kernel") {
            o.payload.kernel = value();
        } else if (a == "--cmdline") {
            o.payload.cmdline = value();
        } else if (a == "--initramfs") {
            o.payload.initramfs = value();
        } else if (a == "--run-dir") {
            o.run_dir = value();
        } else if (a == "--cgroup") {
            o.cgroup = value();
        } else if (a == "--uid-base") {
            o.uid_base = number<uid_t>(value(), "--uid-base");
        } else if (a == "--uid-count") {
            o.uid_count = number<std::uint32_t>(value(), "--uid-count");
        } else if (a == "--sysfs") {
            o.sysfs = value();
        } else if (a == "--vmm-stderr") {
            o.vmm_stderr = true;
        } else {
            die("unknown argument " + std::string{a});
        }
    }
    if (!valid_bdf(o.mailbox) || o.inventory.empty() || o.server_id == mb::no_server_id) {
        die("--mailbox, --inventory and --server-id are required");
    }
    if (o.payload.firmware.empty() == o.payload.kernel.empty()) {
        die("exactly one of --firmware and --kernel");
    }
    if (o.uid_base == 0 || o.uid_count == 0) {
        die("the VM UID range must be non-root and non-empty");
    }
    return o;
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

// The agent's own cgroup for VMs: <root>/hull with the VM controllers on.
auto vm_cgroup_parent(const fs::path& root) -> int {
    const auto dir = root / "hull";
    if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
        die("mkdir " + dir.string() + ": " + std::strerror(errno));
    }
    const int fd = ::open(dir.c_str(), O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        die("open " + dir.string() + ": " + std::strerror(errno));
    }
    if (auto r = enable_vm_controllers(fd); !r) {
        die("enable controllers in " + dir.string() + ": " + to_string(r.error().error));
    }
    return fd;
}

// Sends every queued event (after the responses they follow).
auto flush(VmSupervisor& sup, MailboxClient& client) -> void {
    for (const auto& e : sup.take_events()) {
        (void)client.send_event(e);
    }
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const auto opt = parse_args(argc, argv);

    const auto keys = parse_controller_keys(compiled_controller_keys());
    if (!keys || keys->empty()) {
        die("no valid controller keys compiled in (AK_HULL_CONTROLLER_KEYS)");
    }
    auto verifier = SignatureVerifier::create(*keys);
    if (!verifier) {
        die(std::string{"controller keys: "} + to_string(verifier.error()));
    }

    const auto inventory_entries = parse_inventory(slurp(opt.inventory));
    if (!inventory_entries) {
        die(opt.inventory.string() + ":" + std::to_string(inventory_entries.error().line) + ": " +
            inventory_entries.error().reason);
    }
    const DeviceInventory inventory{*inventory_entries};

    const auto topology = load_cpu_topology(opt.sysfs);
    const auto isolated = load_isolated_cpus(opt.sysfs);
    const auto pages = load_free_1g_hugepages(opt.sysfs);
    if (!topology || !isolated || !pages) {
        die("cannot read the CPU topology, isolated CPUs or 1 GiB pages from sysfs");
    }
    ResourceAllocator allocator{*topology, *isolated, *pages};

    const int cgroup_parent = vm_cgroup_parent(opt.cgroup);
    std::error_code ec;
    fs::create_directories(opt.run_dir, ec);

    auto mailbox = VfioMailbox::open(opt.mailbox, opt.sysfs.string());
    if (!mailbox) {
        die("mailbox " + opt.mailbox + ": " + to_string(mailbox.error()));
    }

    UidPool uids{opt.uid_base, opt.uid_count};
    VmmLaunchConfig launch;
    launch.cloud_hypervisor = opt.cloud_hypervisor;
    launch.payload = opt.payload;
    launch.run_dir = opt.run_dir;
    launch.cgroup_parent_fd = cgroup_parent;
    launch.stderr_fd = opt.vmm_stderr ? STDERR_FILENO : -1;
    JailedVmmLauncher launcher{launch, uids};
    SysfsFunctionResetter resetter{opt.sysfs};
    VmSupervisor supervisor{allocator, launcher, resetter, inventory, opt.payload};
    AgentHandler handler{supervisor};
    // A command at or below the floor was relayed before this boot (or is
    // a replay of one), so it is refused (cold-start Requirement 6.2).
    SequenceTracker sequence{opt.sequence_floor};
    MailboxClient client{**mailbox, opt.server_id, *verifier, sequence, handler};
    // Standing starts (cold-start Requirement 4.5) are for the first run
    // of the agent in a boot only. The run directory is a tmpfs that a
    // boot clears, so a marker left there says this run is a restart and
    // the controller may already be talking to the server.
    StandingStarts standing{opt.server_id, *verifier};
    // "x" creates the marker only if it is absent: an existing marker, or
    // one that cannot be made (so a restart cannot be told from a first
    // run), closes standing starts.
    if (FILE* f = std::fopen((opt.run_dir / "agent-started").c_str(), "wx"); f != nullptr) {
        std::fclose(f);
    } else {
        standing.close();
    }
    client.set_standing_starts(&standing);
    if (auto a = client.attach(); !a) {
        die(std::string{"mailbox attach: "} + to_string(a.error()));
    }

    if (auto d = drop_capabilities_except(agent_capabilities()); !d) {
        die(std::string{"dropping capabilities: "} + std::strerror(d.error()));
    }

    std::printf(
        "hull-agent: server %llu, boot epoch %llu, sequence floor %llu, %zu function(s), "
        "%zu guest core(s), %u page(s)\n",
        static_cast<unsigned long long>(opt.server_id),
        static_cast<unsigned long long>(opt.boot_epoch),
        static_cast<unsigned long long>(opt.sequence_floor), inventory.entries().size(),
        allocator.guest_cores(), allocator.total_hugepages());
    std::fflush(stdout);
    // helm cannot know what a previous run of the agent left behind.
    (void)client.send_event(
        mb::HostFault{.code = mb::FaultCode::agent_restarted, .slot = mb::no_slot, .detail = 0});

    for (;;) {
        std::vector<pollfd> fds{{.fd = (*mailbox)->irq_fd(), .events = POLLIN, .revents = 0}};
        for (const int fd : supervisor.exit_fds()) {
            fds.push_back({.fd = fd, .events = POLLIN, .revents = 0});
        }
        const int timeout_ms = supervisor.has_pending_detaches() ? 250 : 1000;
        const int r = ::poll(fds.data(), fds.size(), timeout_ms);
        if (r < 0 && errno != EINTR) {
            die(std::string{"poll: "} + std::strerror(errno));
        }
        if ((fds[0].revents & POLLIN) != 0) {
            std::uint64_t count = 0;
            static_cast<void>(::eventfd_read(fds[0].fd, &count));
        }
        // The doorbell is the truth; a lost or merged interrupt only delays.
        while (client.service()) {
            flush(supervisor, client);
        }
        supervisor.poll_exits();
        supervisor.poll_detaches();
        flush(supervisor, client);
    }
}
