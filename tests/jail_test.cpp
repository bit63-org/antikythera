// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 7 (Requirements 6.1 and 9.1): the
// per-VMM jail and cgroup.
//
// The pure parts (UID pool, spec validation, cpulist formatting, cgroup
// control-file values) always run. The spawn tests start tests/jail_probe
// inside a real jail and check what it can see and do; they need user
// namespaces and Landlock, and are skipped with a message where the kernel
// or the sandbox refuses either. As root they map a reserved UID; as an
// ordinary user they map the caller's own IDs. The cgroup placement test
// also needs root and a pure cgroup v2 hierarchy at /sys/fs/cgroup, and CI
// runs this binary under sudo for that reason.
//
// Usage: jail_test [boost.test options] -- <path to jail_probe>

#define BOOST_TEST_MODULE jail_test
#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "hull/cpu_topology.hpp"
#include "hull/jail.hpp"
#include "hull/vm_cgroup.hpp"
#include "test_support.hpp"

using ak::hull::CgroupError;
using ak::hull::CgroupLimits;
using ak::hull::CpuId;
using ak::hull::format_cpu_list;
using ak::hull::JailedProcess;
using ak::hull::JailError;
using ak::hull::JailFailure;
using ak::hull::JailIds;
using ak::hull::JailSpec;
using ak::hull::JailStep;
using ak::hull::PathAccess;
using ak::hull::PathRule;
using ak::hull::UidPool;
using ak::hull::VmCgroup;
using ak::test::unit_timeout_seconds;

namespace fs = std::filesystem;

// Boost.Test prints values on failure; teach it these types.
namespace ak::hull {
auto boost_test_print_type(std::ostream& os, JailError e) -> std::ostream& {
    return os << to_string(e);
}
auto boost_test_print_type(std::ostream& os, JailStep s) -> std::ostream& {
    return os << to_string(s);
}
auto boost_test_print_type(std::ostream& os, CgroupError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::hull

namespace {

// A UID/GID no account uses, for the privileged runs.
constexpr uid_t test_uid = 4'100'007;

auto probe_path() -> fs::path {
    const auto& suite = boost::unit_test::framework::master_test_suite();
    BOOST_TEST_REQUIRE(suite.argc >= 2, "usage: jail_test -- <jail_probe>");
    return fs::absolute(fs::path{suite.argv[suite.argc - 1]});
}

// A throwaway directory, world-readable so the jailed UID can enter it.
class TempDir {
public:
    TempDir() {
        const auto* tc = boost::unit_test::framework::current_test_case().p_name->c_str();
        _root =
            fs::temp_directory_path() / ("ak_jail_test_" + std::to_string(::getpid()) + "_" + tc);
        fs::remove_all(_root);
        fs::create_directories(_root);
        fs::permissions(_root, fs::perms::owner_all | fs::perms::group_read |
                                   fs::perms::group_exec | fs::perms::others_read |
                                   fs::perms::others_exec);
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(_root, ec);
    }
    [[nodiscard]] auto path() const -> const fs::path& { return _root; }

    // A file readable (and, with `world_writable`, writable) by anyone.
    [[nodiscard]] auto file(const std::string& name, bool world_writable = false) const
        -> fs::path {
        const auto p = _root / name;
        std::ofstream{p} << "data\n";
        auto perms = fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                     fs::perms::others_read;
        if (world_writable) {
            perms |= fs::perms::group_write | fs::perms::others_write;
        }
        fs::permissions(p, perms);
        return p;
    }
    [[nodiscard]] auto dir(const std::string& name) const -> fs::path {
        const auto p = _root / name;
        fs::create_directories(p);
        fs::permissions(p, fs::perms::all);
        return p;
    }

private:
    fs::path _root;
};

auto own_ids() -> JailIds {
    if (::geteuid() == 0) {
        return {test_uid, test_uid};
    }
    return {::geteuid(), ::getegid()};
}

// The rules any dynamically linked probe needs: the loader and libraries
// (read + execute under /usr/lib) and the loader cache. /usr/bin is
// deliberately not covered, so exec of /usr/bin/true is a Landlock denial.
auto base_spec(const fs::path& working_dir) -> JailSpec {
    JailSpec spec;
    spec.ids = own_ids();
    spec.executable = probe_path();
    spec.argv = {"jail_probe", "report"};
    spec.env = {"AK_JAIL_TEST=1"};
    spec.working_dir = working_dir;
    spec.paths = {
        {"/usr/lib", PathAccess::read_exec},
        {spec.executable, PathAccess::read_exec},
        {working_dir, PathAccess::read_only},
    };
    if (fs::exists("/etc/ld.so.cache")) {
        spec.paths.push_back({"/etc/ld.so.cache", PathAccess::read_only});
    }
    return spec;
}

struct ProbeRun {
    std::expected<int, JailFailure> status;  // the wait status, or why the spawn failed
    std::string output;
};

auto run(JailSpec spec) -> ProbeRun {
    std::array<int, 2> p{-1, -1};
    BOOST_TEST_REQUIRE(::pipe2(p.data(), O_CLOEXEC) == 0);
    spec.stdout_fd = p[1];
    auto child = ak::hull::spawn_jailed(spec);
    (void)::close(p[1]);
    std::string out;
    std::array<char, 512> buf{};
    ssize_t n = 0;
    while ((n = ::read(p[0], buf.data(), buf.size())) > 0) {
        out.append(buf.data(), static_cast<std::size_t>(n));
    }
    (void)::close(p[0]);
    if (!child) {
        return {std::unexpected(child.error()), out};
    }
    auto status = child->wait();
    BOOST_TEST_REQUIRE(status.has_value());
    return {*status, out};
}

// "k=v k=v\n" -> map.
auto fields(const std::string& line) -> std::map<std::string, std::string> {
    std::map<std::string, std::string> out;
    std::istringstream in{line};
    std::string token;
    while (in >> token) {
        const auto eq = token.find('=');
        if (eq != std::string::npos) {
            out[token.substr(0, eq)] = token.substr(eq + 1);
        }
    }
    return out;
}

auto describe(const JailFailure& f) -> std::string {
    return std::string{ak::hull::to_string(f.error)} + " step=" + ak::hull::to_string(f.step) +
           " errno=" + std::to_string(f.sys_errno) + " detail=" + f.detail;
}

// Whether this kernel and sandbox can build a jail at all; the reason if not.
auto jail_unavailable() -> std::optional<std::string> {
    static const std::optional<std::string> reason = []() -> std::optional<std::string> {
        if (ak::hull::landlock_abi() < 1) {
            return "Landlock is not available";
        }
        const TempDir dir;
        const auto r = run(base_spec(dir.path()));
        if (r.status) {
            return std::nullopt;
        }
        const auto& f = r.status.error();
        if (f.error == JailError::clone_failed || f.error == JailError::id_map_failed ||
            (f.error == JailError::child_setup_failed &&
             (f.step == JailStep::mounts || f.step == JailStep::groups))) {
            return "user namespaces refused here (" + describe(f) + ")";
        }
        return std::nullopt;  // a real failure: let the tests report it
    }();
    return reason;
}

// The first cgroup v2 mount point: /sys/fs/cgroup on a unified host,
// /sys/fs/cgroup/unified (controllers usually bound to v1) on a hybrid one.
auto cgroup2_mount() -> std::optional<fs::path> {
    std::ifstream mounts{"/proc/self/mounts"};
    std::string device;
    std::string mount_point;
    std::string type;
    std::string rest;
    while (mounts >> device >> mount_point >> type && std::getline(mounts, rest)) {
        if (type == "cgroup2") {
            return fs::path{mount_point};
        }
    }
    return std::nullopt;
}

#define AK_REQUIRE_JAIL()                            \
    do {                                             \
        if (const auto why = jail_unavailable()) {   \
            BOOST_TEST_MESSAGE("skipped: " << *why); \
            return;                                  \
        }                                            \
    } while (false)

}  // namespace

// --- UidPool -----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(uid_pool_hands_out_distinct_pairs,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    UidPool pool{100'000, 2};
    const auto a = pool.acquire(1);
    const auto b = pool.acquire(2);
    BOOST_TEST_REQUIRE(a.has_value());
    BOOST_TEST_REQUIRE(b.has_value());
    BOOST_TEST(a->uid == 100'000U);
    BOOST_TEST(a->gid == 100'000U);
    BOOST_TEST(b->uid == 100'001U);
    BOOST_TEST(!pool.acquire(3).has_value());  // exhausted
    BOOST_TEST(!pool.acquire(1).has_value());  // already holds one
    BOOST_TEST((pool.find(2) == b));
}

BOOST_AUTO_TEST_CASE(uid_pool_reuses_the_lowest_released_slot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    UidPool pool{500, 3};
    (void)pool.acquire(10);
    (void)pool.acquire(11);
    (void)pool.acquire(12);
    BOOST_TEST(pool.release(11));
    BOOST_TEST(!pool.release(11));
    BOOST_TEST(!pool.find(11).has_value());
    const auto again = pool.acquire(13);
    BOOST_TEST_REQUIRE(again.has_value());
    BOOST_TEST(again->uid == 501U);
    BOOST_TEST(pool.in_use() == 3U);
}

// --- validate ------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(validate_accepts_a_minimal_spec,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    JailSpec spec;
    spec.ids = {1000, 1000};
    spec.executable = "/opt/vmm/cloud-hypervisor";
    spec.argv = {"cloud-hypervisor"};
    spec.working_dir = "/run/hull/vm-1";
    spec.paths = {{"/opt/vmm", PathAccess::read_exec}, {"/run/hull/vm-1", PathAccess::socket_dir}};
    BOOST_TEST(ak::hull::validate(spec).has_value());
}

BOOST_AUTO_TEST_CASE(validate_rejects_unsafe_specs,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    JailSpec good;
    good.ids = {1000, 1000};
    good.executable = "/opt/vmm/cloud-hypervisor";
    good.argv = {"cloud-hypervisor"};
    good.working_dir = "/run/hull/vm-1";
    good.paths = {{"/opt/vmm", PathAccess::read_exec}, {"/run/hull/vm-1", PathAccess::socket_dir}};

    const std::vector<std::pair<std::string, std::function<void(JailSpec&)>>> cases = {
        {"root uid", [](JailSpec& s) { s.ids.uid = 0; }},
        {"root gid", [](JailSpec& s) { s.ids.gid = 0; }},
        {"empty argv", [](JailSpec& s) { s.argv.clear(); }},
        {"NUL in argv", [](JailSpec& s) { s.argv.emplace_back(std::string{"a\0b", 3}); }},
        {"env without =", [](JailSpec& s) { s.env = {"PATH"}; }},
        {"env with empty name", [](JailSpec& s) { s.env = {"=x"}; }},
        {"relative executable", [](JailSpec& s) { s.executable = "cloud-hypervisor"; }},
        {"dot-dot executable", [](JailSpec& s) { s.executable = "/opt/vmm/../bin/sh"; }},
        {"executable not executable",
         [](JailSpec& s) { s.paths[0].access = PathAccess::read_only; }},
        {"executable outside its rule",
         [](JailSpec& s) { s.executable = "/opt/vmm2/cloud-hypervisor"; }},
        {"relative rule",
         [](JailSpec& s) { s.paths.push_back({"dev/kvm", PathAccess::device_rw}); }},
        {"rule with trailing slash",
         [](JailSpec& s) { s.paths.push_back({"/dev/", PathAccess::read_only}); }},
        {"rule with empty component",
         [](JailSpec& s) { s.paths.push_back({"/dev//kvm", PathAccess::device_rw}); }},
        {"rule with dot",
         [](JailSpec& s) { s.paths.push_back({"/dev/./kvm", PathAccess::device_rw}); }},
        {"working dir uncovered", [](JailSpec& s) { s.working_dir = "/tmp"; }},
        {"working dir relative", [](JailSpec& s) { s.working_dir = "run"; }},
    };
    for (const auto& [name, mutate] : cases) {
        BOOST_TEST_CONTEXT(name) {
            auto spec = good;
            mutate(spec);
            const auto r = ak::hull::validate(spec);
            BOOST_TEST_REQUIRE(!r.has_value());
            BOOST_TEST(r.error().error == JailError::invalid_spec);
            BOOST_TEST(!ak::hull::spawn_jailed(spec).has_value());
        }
    }
}

// --- Cgroup values ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(format_cpu_list_compacts_runs,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((format_cpu_list(std::vector<CpuId>{}) == std::optional<std::string>{""}));
    BOOST_TEST((format_cpu_list(std::vector<CpuId>{5}) == std::optional<std::string>{"5"}));
    BOOST_TEST((format_cpu_list(std::vector<CpuId>{0, 1, 2, 3, 8, 10, 11}) ==
                std::optional<std::string>{"0-3,8,10-11"}));
    BOOST_TEST(!format_cpu_list(std::vector<CpuId>{2, 1}).has_value());
    BOOST_TEST(!format_cpu_list(std::vector<CpuId>{1, 1}).has_value());
    const std::vector<CpuId> cpus{0, 2, 3, 4, 7, 8191};
    BOOST_TEST(ak::hull::parse_cpu_list(*format_cpu_list(cpus)).value() == cpus);
}

BOOST_AUTO_TEST_CASE(cgroup_writes_follow_the_allocation,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    ak::hull::Allocation alloc;
    alloc.vm_id = 7;
    alloc.vcpus = 3;
    alloc.cpus = {4, 5, 6, 7};
    alloc.hugepages = 2;
    const auto limits = ak::hull::limits_for(alloc, 256, std::uint64_t{512} << 20U);
    const auto writes = ak::hull::cgroup_writes(limits);
    BOOST_TEST_REQUIRE(writes.has_value());
    const std::vector<std::pair<std::string, std::string>> expected = {
        {"cpuset.cpus", "4-7"}, {"cpuset.mems", "0"},        {"hugetlb.1GB.max", "2147483648"},
        {"pids.max", "256"},    {"memory.max", "536870912"},
    };
    BOOST_TEST((*writes == expected));

    auto minimal = limits;
    minimal.pids_max = 0;
    minimal.memory_max.reset();
    BOOST_TEST(ak::hull::cgroup_writes(minimal)->size() == 3U);
}

BOOST_AUTO_TEST_CASE(cgroup_writes_reject_bad_limits,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    CgroupLimits good;
    good.cpus = {1};
    good.hugepages = 1;
    BOOST_TEST(ak::hull::cgroup_writes(good).has_value());
    auto no_cpus = good;
    no_cpus.cpus.clear();
    auto unordered = good;
    unordered.cpus = {3, 2};
    auto no_mems = good;
    no_mems.mems.clear();
    auto no_pages = good;
    no_pages.hugepages = 0;
    for (const auto& bad : {no_cpus, unordered, no_mems, no_pages}) {
        const auto r = ak::hull::cgroup_writes(bad);
        BOOST_TEST_REQUIRE(!r.has_value());
        BOOST_TEST(r.error().error == CgroupError::invalid_limits);
    }
}

BOOST_AUTO_TEST_CASE(write_cgroup_limits_writes_each_file,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const TempDir dir;
    for (const char* f : {"cpuset.cpus", "cpuset.mems", "hugetlb.1GB.max", "pids.max"}) {
        std::ofstream{dir.path() / f} << "stale-and-longer-than-the-value\n";
    }
    CgroupLimits limits;
    limits.cpus = {2, 3};
    limits.hugepages = 1;
    limits.pids_max = 64;
    const int fd = ::open(dir.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    BOOST_TEST_REQUIRE(fd >= 0);
    BOOST_TEST(ak::hull::write_cgroup_limits(fd, limits).has_value());

    const auto slurp = [&](const char* f) {
        std::ifstream in{dir.path() / f};
        return std::string{std::istreambuf_iterator<char>{in}, {}};
    };
    BOOST_TEST(slurp("cpuset.cpus") == "2-3");
    BOOST_TEST(slurp("cpuset.mems") == "0");
    BOOST_TEST(slurp("hugetlb.1GB.max") == "1073741824");
    BOOST_TEST(slurp("pids.max") == "64");

    // memory.max does not exist here: a missing controller file is an
    // open failure naming the file, never a file created by the agent.
    limits.memory_max = 1U << 28U;
    const auto r = ak::hull::write_cgroup_limits(fd, limits);
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().error == CgroupError::open_failed);
    BOOST_TEST(r.error().file == "memory.max");
    BOOST_TEST(!fs::exists(dir.path() / "memory.max"));
    (void)::close(fd);
}

BOOST_AUTO_TEST_CASE(vm_cgroup_create_cleans_up_on_failure,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A plain directory has no controller files, so create() makes vm-9,
    // fails on the first write and must remove vm-9 again.
    const TempDir dir;
    const int parent = ::open(dir.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    BOOST_TEST_REQUIRE(parent >= 0);
    CgroupLimits limits;
    limits.cpus = {0};
    limits.hugepages = 1;
    const auto r = VmCgroup::create(parent, 9, limits);
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().error == CgroupError::open_failed);
    BOOST_TEST(r.error().file == "cpuset.cpus");
    BOOST_TEST(!fs::exists(dir.path() / "vm-9"));

    // A leftover vm-9 is a stale VM: refused, and left alone.
    fs::create_directory(dir.path() / "vm-9");
    const auto again = VmCgroup::create(parent, 9, limits);
    BOOST_TEST_REQUIRE(!again.has_value());
    BOOST_TEST(again.error().error == CgroupError::already_exists);
    BOOST_TEST(fs::exists(dir.path() / "vm-9"));

    // Invalid limits never touch the filesystem.
    limits.cpus.clear();
    BOOST_TEST(VmCgroup::create(parent, 10, limits).error().error == CgroupError::invalid_limits);
    BOOST_TEST(!fs::exists(dir.path() / "vm-10"));
    (void)::close(parent);
}

// --- The jail, for real --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(jail_drops_identity_capabilities_and_environment,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    AK_REQUIRE_JAIL();
    const TempDir dir;
    auto spec = base_spec(dir.path());
    spec.env = {"AK_JAIL_TEST=1", "SECOND=2"};
    const auto r = run(spec);
    BOOST_TEST_REQUIRE(r.status.has_value(), (r.status ? "" : describe(r.status.error())));
    BOOST_TEST(WIFEXITED(*r.status));
    BOOST_TEST(WEXITSTATUS(*r.status) == 0);
    BOOST_TEST_MESSAGE("probe: " << r.output);
    auto f = fields(r.output);
    const auto ids = own_ids();
    BOOST_TEST(f["uid"] == std::to_string(ids.uid));
    BOOST_TEST(f["euid"] == std::to_string(ids.uid));
    BOOST_TEST(f["gid"] == std::to_string(ids.gid));
    BOOST_TEST(f["egid"] == std::to_string(ids.gid));
    BOOST_TEST(f["pid"] == "1");  // alone in a new PID namespace
    if (::geteuid() == 0) {
        BOOST_TEST(f["groups"] == "0");  // supplementary groups dropped
    }
    BOOST_TEST(f["cap_eff"] == "0");
    BOOST_TEST(f["cap_prm"] == "0");
    BOOST_TEST(f["cap_bnd"] == "0");
    BOOST_TEST(f["nnp"] == "1");
    BOOST_TEST(f["core"] == "0");
    BOOST_TEST(f["cwd"] == dir.path().string());
    BOOST_TEST(f["env"] == "2");
}

BOOST_AUTO_TEST_CASE(jail_enforces_landlock_rules,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    AK_REQUIRE_JAIL();
    const TempDir dir;
    const auto allowed = dir.file("allowed", true);
    const auto ro_dir = dir.dir("ro");
    const auto ro_file = ro_dir / "file";
    std::ofstream{ro_file} << "x\n";
    fs::permissions(ro_file, fs::perms::all);
    const auto denied = dir.file("denied", true);
    const auto rw_dir = dir.dir("rw");
    const auto rw_file = dir.file("rw/existing", true);

    auto probe = [&](std::vector<std::string> argv) {
        auto spec = base_spec(rw_dir);
        spec.paths = {
            {"/usr/lib", PathAccess::read_exec}, {spec.executable, PathAccess::read_exec},
            {allowed, PathAccess::device_rw},    {ro_dir, PathAccess::read_only},
            {rw_dir, PathAccess::read_write},
        };
        if (fs::exists("/etc/ld.so.cache")) {
            spec.paths.push_back({"/etc/ld.so.cache", PathAccess::read_only});
        }
        spec.argv = std::move(argv);
        const auto r = run(spec);
        BOOST_TEST_REQUIRE(r.status.has_value(), (r.status ? "" : describe(r.status.error())));
        return r.output;
    };
    const std::string eacces = "errno=" + std::to_string(EACCES) + "\n";

    BOOST_TEST(probe({"p", "read", allowed.string()}) == "ok\n");
    BOOST_TEST(probe({"p", "write", allowed.string()}) == "ok\n");
    BOOST_TEST(probe({"p", "read", ro_file.string()}) == "ok\n");
    BOOST_TEST(probe({"p", "write", ro_file.string()}) == eacces);  // DAC allows; Landlock refuses
    BOOST_TEST(probe({"p", "read", denied.string()}) == eacces);    // not listed at all
    BOOST_TEST(probe({"p", "read", "/etc/passwd"}) == eacces);
    BOOST_TEST(probe({"p", "write", rw_file.string()}) == "ok\n");
    BOOST_TEST(probe({"p", "exec", "/usr/bin/true"}) ==
               eacces);  // no execute right outside /usr/lib
}

BOOST_AUTO_TEST_CASE(jail_sets_memlock_from_outside,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    AK_REQUIRE_JAIL();
    const TempDir dir;
    auto spec = base_spec(dir.path());
    spec.memlock_bytes = 65536;  // lowering works unprivileged too
    const auto r = run(spec);
    BOOST_TEST_REQUIRE(r.status.has_value(), (r.status ? "" : describe(r.status.error())));
    BOOST_TEST(fields(r.output)["memlock"] == "65536");
}

BOOST_AUTO_TEST_CASE(jail_reports_the_failing_step,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    AK_REQUIRE_JAIL();
    const TempDir dir;

    // The working directory is covered by a rule but does not exist.
    auto spec = base_spec(dir.path());
    spec.working_dir = dir.path() / "missing";
    auto r = run(spec);
    BOOST_TEST_REQUIRE(!r.status.has_value());
    BOOST_TEST(r.status.error().error == JailError::child_setup_failed);
    BOOST_TEST(r.status.error().step == JailStep::chdir);
    BOOST_TEST(r.status.error().sys_errno == ENOENT);

    // The executable's directory is allowed, the file is not there.
    spec = base_spec(dir.path());
    spec.paths.push_back({dir.path(), PathAccess::read_exec});
    spec.executable = dir.path() / "no-such-vmm";
    r = run(spec);
    BOOST_TEST_REQUIRE(!r.status.has_value());
    BOOST_TEST(r.status.error().error == JailError::exec_failed);
    BOOST_TEST(r.status.error().step == JailStep::exec);
    BOOST_TEST(r.status.error().sys_errno == ENOENT);

    // A rule naming a path that does not exist fails in the parent.
    spec = base_spec(dir.path());
    spec.paths.push_back({"/dev/vfio/ak-no-such-group", PathAccess::device_rw});
    r = run(spec);
    BOOST_TEST_REQUIRE(!r.status.has_value());
    BOOST_TEST(r.status.error().error == JailError::landlock_failed);
    BOOST_TEST(r.status.error().detail == "/dev/vfio/ak-no-such-group");
}

BOOST_AUTO_TEST_CASE(jailed_process_handle_kills_and_reaps,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    AK_REQUIRE_JAIL();
    const TempDir dir;
    auto spec = base_spec(dir.path());
    spec.argv = {"jail_probe", "sleep"};

    auto child = ak::hull::spawn_jailed(spec);
    BOOST_TEST_REQUIRE(child.has_value(), (child ? "" : describe(child.error())));
    BOOST_TEST(child->pidfd() >= 0);
    BOOST_TEST(child->signal(SIGKILL).has_value());
    const auto status = child->wait();
    BOOST_TEST_REQUIRE(status.has_value());
    BOOST_TEST(WIFSIGNALED(*status));
    BOOST_TEST(WTERMSIG(*status) == SIGKILL);
    BOOST_TEST(!child->wait().has_value());  // already reaped

    // Dropping a live handle kills and reaps the process.
    pid_t pid = -1;
    {
        auto other = ak::hull::spawn_jailed(spec);
        BOOST_TEST_REQUIRE(other.has_value());
        pid = other->pid();
        BOOST_TEST(::kill(pid, 0) == 0);
    }
    BOOST_TEST(::waitpid(pid, nullptr, WNOHANG) == -1);
    BOOST_TEST(errno == ECHILD);
}

BOOST_AUTO_TEST_CASE(jail_enters_its_cgroup_atomically,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    AK_REQUIRE_JAIL();
    const auto cgroup_root = cgroup2_mount();
    if (::geteuid() != 0 || !cgroup_root) {
        BOOST_TEST_MESSAGE("skipped: needs root and a cgroup v2 mount");
        return;
    }
    BOOST_TEST_MESSAGE("cgroup v2 at " << *cgroup_root);
    // A controller can only be enabled for a child if the root enables it
    // too, and systemd does not enable every one (cpuset, hugetlb) at the
    // root. hull's init enables them there; this test does the same, but
    // only when asked (CI's throwaway runner), never on a developer host.
    if (const char* opt_in = std::getenv("AK_JAIL_TEST_CGROUP");
        opt_in != nullptr && *opt_in == '1') {
        const int root = ::open(cgroup_root->c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        BOOST_TEST_REQUIRE(root >= 0);
        const auto enabled = ak::hull::enable_vm_controllers(root);
        (void)::close(root);
        if (!enabled) {
            BOOST_TEST_MESSAGE("root controllers: " << ak::hull::to_string(enabled.error().error)
                                                    << " errno " << enabled.error().sys_errno);
        }
    }
    const auto parent_dir = *cgroup_root / ("ak-jail-test-" + std::to_string(::getpid()));
    std::error_code ec;
    fs::create_directory(parent_dir, ec);
    if (ec) {
        BOOST_TEST_MESSAGE("skipped: cannot create " << parent_dir << ": " << ec.message());
        return;
    }
    const int parent = ::open(parent_dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    BOOST_TEST_REQUIRE(parent >= 0);
    const auto cleanup = [&] {
        (void)::close(parent);
        fs::remove(parent_dir, ec);
    };
    if (auto r = ak::hull::enable_vm_controllers(parent); !r) {
        std::string controllers;
        std::getline(std::ifstream{*cgroup_root / "cgroup.subtree_control"}, controllers);
        BOOST_TEST_MESSAGE("skipped: controllers unavailable ("
                           << ak::hull::to_string(r.error().error) << " " << r.error().file
                           << " errno " << r.error().sys_errno << "; root subtree_control: '"
                           << controllers << "')");
        cleanup();
        return;
    }
    CgroupLimits limits;
    limits.cpus = {0};
    limits.hugepages = 1;
    limits.pids_max = 16;
    auto cgroup = VmCgroup::create(parent, 7, limits);
    if (!cgroup && cgroup.error().file == "hugetlb.1GB.max") {
        BOOST_TEST_MESSAGE("skipped: no 1 GiB huge-page support");
        cleanup();
        return;
    }
    BOOST_TEST_REQUIRE(cgroup.has_value(), (cgroup ? "" : cgroup.error().file));

    {
        const TempDir dir;
        auto spec = base_spec(dir.path());
        spec.argv = {"jail_probe", "sleep"};
        spec.cgroup_fd = cgroup->fd();
        auto child = ak::hull::spawn_jailed(spec);
        BOOST_TEST_REQUIRE(child.has_value(), (child ? "" : describe(child.error())));
        std::ifstream procs{parent_dir / "vm-7" / "cgroup.procs"};
        std::string first;
        procs >> first;
        BOOST_TEST(first == std::to_string(child->pid()));
        std::ifstream pids_max{parent_dir / "vm-7" / "pids.max"};
        std::string value;
        pids_max >> value;
        BOOST_TEST(value == "16");

        // Busy while the VMM lives; removable once it is gone.
        BOOST_TEST(cgroup->remove().error().error == CgroupError::remove_failed);
        (void)child->signal(SIGKILL);
        (void)child->wait();
    }
    // The kernel finishes taking an exited task out of its cgroup
    // asynchronously; give rmdir a moment.
    bool removed = false;
    for (int i = 0; i < 50 && !removed; ++i) {
        removed = cgroup->remove().has_value();
        if (!removed) {
            ::usleep(20'000);
        }
    }
    BOOST_TEST(removed);
    BOOST_TEST(!fs::exists(parent_dir / "vm-7"));
    cleanup();
}
