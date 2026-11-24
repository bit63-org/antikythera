// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 8 (Requirements 6.1, 6.4, 9.1): the
// real JailedVmmLauncher starting tests/fake_vmm -- a stand-in that takes
// cloud-hypervisor's command line and answers its API -- inside real jails,
// and the VmSupervisor driving it end to end: vm.create over the API
// socket, a guest power-off seen as VM_EXITED, a crash, a destroy, and
// cleanup of the run directory and UID.
//
// Like jail_test it needs user namespaces and Landlock and logs "skipped"
// where the kernel or sandbox refuses either. As root it maps a reserved
// UID; as an ordinary user, the caller's own.
//
// Usage: vmm_launcher_test [boost.test options] -- <path to fake_vmm>

#define BOOST_TEST_MODULE vmm_launcher_test
#include <boost/test/unit_test.hpp>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>

#include "helm/mailbox.hpp"
#include "hull/jail.hpp"
#include "hull/resource_allocator.hpp"
#include "hull/vm_supervisor.hpp"
#include "hull/vmm_launcher.hpp"
#include "hull/json.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
namespace mb = ak::helm::mailbox;
using ak::hull::Allocation;
using ak::hull::JailedVmmLauncher;
using ak::hull::LaunchError;
using ak::hull::PathAccess;
using ak::hull::UidPool;
using ak::hull::VmmLaunchConfig;
using ak::hull::VmmState;
using ak::test::unit_timeout_seconds;

BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<std::uint64_t>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<bool>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<ak::hull::json::JsonError>)

namespace {

constexpr uid_t test_uid_base = 4'100'100;

auto fake_vmm_path() -> fs::path {
    const auto& suite = boost::unit_test::framework::master_test_suite();
    BOOST_TEST_REQUIRE(suite.argc >= 2, "usage: vmm_launcher_test -- <fake_vmm>");
    return fs::absolute(fs::path{suite.argv[suite.argc - 1]});
}

auto make_pool() -> UidPool {
    if (::geteuid() == 0) {
        return UidPool{test_uid_base, 8};
    }
    return UidPool{::geteuid(), 1};  // unprivileged: only our own ID maps
}

// A run directory the jailed UID can traverse.
class RunDir {
public:
    RunDir() {
        const auto* tc = boost::unit_test::framework::current_test_case().p_name->c_str();
        _root = fs::temp_directory_path() / ("ak_vmm_" + std::to_string(::getpid()) + "_" + tc);
        fs::remove_all(_root);
        fs::create_directories(_root);
        fs::permissions(_root,
                        fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
    }
    RunDir(const RunDir&) = delete;
    auto operator=(const RunDir&) -> RunDir& = delete;
    RunDir(RunDir&&) = delete;
    auto operator=(RunDir&&) -> RunDir& = delete;
    ~RunDir() {
        std::error_code ec;
        fs::remove_all(_root, ec);
    }
    [[nodiscard]] auto path() const -> const fs::path& { return _root; }

private:
    fs::path _root;
};

auto test_config(const fs::path& run_dir) -> VmmLaunchConfig {
    VmmLaunchConfig c;
    c.cloud_hypervisor = fake_vmm_path();
    c.run_dir = run_dir;
    // A dynamically linked stand-in needs the loader and libraries; it uses
    // no device nodes.
    c.paths = {{.path = "/usr/lib", .access = PathAccess::read_exec}};
    if (fs::exists("/etc/ld.so.cache")) {
        c.paths.push_back({.path = "/etc/ld.so.cache", .access = PathAccess::read_only});
    }
    // Raising RLIMIT_MEMLOCK needs CAP_SYS_RESOURCE, which a container's
    // root may lack; jail_test covers the limit itself.
    c.set_memlock = false;
    c.start_timeout = std::chrono::seconds{10};
    c.api_timeout = std::chrono::seconds{5};
    return c;
}

// Why jails cannot run here, from a failed launch, or nullopt for a real failure.
auto jail_refused(const ak::hull::LaunchFailure& f) -> std::optional<std::string> {
    if (f.error != LaunchError::jail) {
        return std::nullopt;
    }
    for (const char* why : {"landlock_unavailable", "clone_failed", "id_map_failed",
                            "child_setup_failed mounts", "child_setup_failed groups"}) {
        if (f.detail.starts_with(why)) {
            return f.detail;
        }
    }
    return std::nullopt;
}

const Allocation one_core{.vm_id = 1, .vcpus = 1, .cpus = {0}, .hugepages = 1};

}  // namespace

BOOST_AUTO_TEST_CASE(launch_talk_and_shut_down, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const RunDir run;
    auto pool = make_pool();
    JailedVmmLauncher launcher{test_config(run.path()), pool};
    auto vmm = launcher.launch(one_core);
    if (!vmm) {
        const auto why = jail_refused(vmm.error());
        BOOST_TEST_REQUIRE(why.has_value(), to_string(vmm.error().error)
                                                << " " << vmm.error().detail);
        BOOST_TEST_MESSAGE("skipped: " << *why);
        return;
    }
    const auto dir = run.path() / "vm-1";
    BOOST_TEST(fs::exists(dir / "api.sock"));
    struct stat st{};
    BOOST_TEST_REQUIRE(::stat(dir.c_str(), &st) == 0);
    BOOST_TEST((st.st_mode & 07777) == 0700U);
    BOOST_TEST(st.st_uid == pool.find(1)->uid);

    auto& api = (*vmm)->api();
    BOOST_TEST(api.create(R"({"payload":{"firmware":"/fw"}})").has_value());
    BOOST_TEST(api.add_device("ak-s1-nic-f0", "/sys/bus/pci/devices/0000:01:00.0").has_value());
    auto info = api.info();
    BOOST_TEST_REQUIRE(info.has_value());
    BOOST_TEST((info->state == VmmState::created));
    BOOST_TEST((info->device_ids == std::vector<std::string>{"ak-s1-nic-f0"}));
    BOOST_TEST(api.boot().has_value());
    BOOST_TEST(api.remove_device("ak-s1-nic-f0").has_value());
    info = api.info();
    BOOST_TEST_REQUIRE(info.has_value());
    BOOST_TEST((info->state == VmmState::running));
    BOOST_TEST(info->device_ids.empty());

    BOOST_TEST(api.shutdown_vmm().has_value());
    const auto status = (*vmm)->wait();
    BOOST_TEST_REQUIRE(status.has_value());
    BOOST_TEST(WIFEXITED(*status));
    BOOST_TEST(WEXITSTATUS(*status) == 0);

    vmm->reset();
    BOOST_TEST(!fs::exists(dir));
    BOOST_TEST(pool.in_use() == 0U);
}

BOOST_AUTO_TEST_CASE(a_vmm_that_dies_at_start_is_reported,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const RunDir run;
    auto pool = make_pool();
    auto config = test_config(run.path());
    config.cloud_hypervisor = "/usr/bin/false";
    config.paths.push_back({.path = "/usr/bin/false", .access = PathAccess::read_exec});
    JailedVmmLauncher launcher{config, pool};
    const auto vmm = launcher.launch(one_core);
    BOOST_TEST_REQUIRE(!vmm.has_value());
    if (const auto why = jail_refused(vmm.error())) {
        BOOST_TEST_MESSAGE("skipped: " << *why);
        return;
    }
    BOOST_TEST((vmm.error().error == LaunchError::exited));
    BOOST_TEST(!fs::exists(run.path() / "vm-1"));
    BOOST_TEST(pool.in_use() == 0U);
}

BOOST_AUTO_TEST_CASE(the_pool_bounds_concurrent_vmms,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const RunDir run;
    UidPool pool{::geteuid() == 0 ? test_uid_base : ::geteuid(), 1};
    JailedVmmLauncher launcher{test_config(run.path()), pool};
    auto first = launcher.launch(one_core);
    if (!first) {
        const auto why = jail_refused(first.error());
        BOOST_TEST_REQUIRE(why.has_value(), to_string(first.error().error));
        BOOST_TEST_MESSAGE("skipped: " << *why);
        return;
    }
    auto second = launcher.launch({.vm_id = 2, .vcpus = 1, .cpus = {1}, .hugepages = 1});
    BOOST_TEST_REQUIRE(!second.has_value());
    BOOST_TEST((second.error().error == LaunchError::no_ids));
}

BOOST_AUTO_TEST_CASE(supervisor_end_to_end, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const RunDir run;
    auto pool = make_pool();
    JailedVmmLauncher launcher{test_config(run.path()), pool};
    // Probe once so a sandbox without jails skips rather than fails.
    if (auto probe = launcher.launch({.vm_id = 99, .vcpus = 1, .cpus = {0}, .hugepages = 1});
        !probe) {
        const auto why = jail_refused(probe.error());
        BOOST_TEST_REQUIRE(why.has_value(), to_string(probe.error().error));
        BOOST_TEST_MESSAGE("skipped: " << *why);
        return;
    }

    const auto topo = ak::hull::CpuTopology::from_cores({{0}, {1}, {2}}).value();
    ak::hull::ResourceAllocator allocator{topo, std::vector<ak::hull::CpuId>{0, 1, 2}, 3};
    const ak::hull::DeviceInventory inventory;
    struct NoReset final : ak::hull::FunctionResetter {
        auto reset(const ak::hull::InventoryEntry&) -> bool override { return true; }
    } resetter;
    ak::hull::VmSupervisor sup{allocator,
                               launcher,
                               resetter,
                               inventory,
                               {.firmware = "/fw", .kernel = {}, .cmdline = {}, .initramfs = {}}};

    // One VM at a time: an unprivileged run has a single UID to hand out.
    auto wait_for_exit = [&]() -> std::optional<mb::VmExited> {
        for (int i = 0; i < 500; ++i) {
            sup.poll_exits();
            auto events = sup.take_events();
            if (!events.empty()) {
                BOOST_TEST(events.size() == 1U);
                return std::get<mb::VmExited>(events[0]);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        return std::nullopt;
    };

    // VM 1's guest powers off.
    BOOST_TEST_REQUIRE(
        (sup.create({.vm_id = 1, .vcpus = 1, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST(sup.exit_fds().size() == 1U);
    {
        ak::hull::ChApiClient c{run.path() / "vm-1" / "api.sock", std::chrono::seconds{5}};
        BOOST_TEST(c.call("PUT", "vm.power-button", {}).has_value());
    }
    auto exit1 = wait_for_exit();
    BOOST_TEST_REQUIRE(exit1.has_value());
    BOOST_TEST(
        (*exit1 ==
         mb::VmExited{.vm_id = 1, .exit_status = 0, .reason = mb::ExitReason::guest_shutdown}));
    BOOST_TEST(!fs::exists(run.path() / "vm-1"));

    // VM 2's VMM crashes.
    BOOST_TEST_REQUIRE(
        (sup.create({.vm_id = 2, .vcpus = 1, .memory_mib = 1024}) == mb::Status::ok));
    {
        ak::hull::ChApiClient c{run.path() / "vm-2" / "api.sock", std::chrono::seconds{5}};
        BOOST_TEST(!c.call("PUT", "fake.crash", {}).has_value());
    }
    auto exit2 = wait_for_exit();
    BOOST_TEST_REQUIRE(exit2.has_value());
    BOOST_TEST((*exit2 ==
                mb::VmExited{.vm_id = 2, .exit_status = 3, .reason = mb::ExitReason::vmm_failure}));
    BOOST_TEST(!fs::exists(run.path() / "vm-2"));

    BOOST_TEST_REQUIRE(
        (sup.create({.vm_id = 3, .vcpus = 1, .memory_mib = 1024}) == mb::Status::ok));
    // Destroy the last one: killed, no VM_EXITED, everything released.
    BOOST_TEST((sup.destroy({.vm_id = 3}) == mb::Status::ok));
    BOOST_TEST(sup.take_events().empty());
    BOOST_TEST(!fs::exists(run.path() / "vm-3"));
    BOOST_TEST(pool.in_use() == 0U);
    BOOST_TEST(allocator.free_cores() == 3U);
}
