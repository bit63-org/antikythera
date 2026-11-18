// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ Requirements 6.1 and 8.1: the cpulist
// parser and the sysfs topology and huge-page readers, against a fake
// sysfs tree in a temporary directory.

#define BOOST_TEST_MODULE cpu_topology_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "hull/cpu_topology.hpp"
#include "test_support.hpp"

using ak::hull::CpuId;
using ak::hull::CpuListError;
using ak::hull::CpuTopology;
using ak::hull::load_cpu_topology;
using ak::hull::load_free_1g_hugepages;
using ak::hull::load_isolated_cpus;
using ak::hull::parse_cpu_list;
using ak::hull::TopologyError;
using ak::test::unit_timeout_seconds;

namespace fs = std::filesystem;

namespace {

auto ids(std::initializer_list<CpuId> l) -> std::vector<CpuId> {
    return l;
}

// A throwaway sysfs root, removed when the test case ends.
class FakeSysfs {
public:
    FakeSysfs() {
        const auto* tc = boost::unit_test::framework::current_test_case().p_name->c_str();
        _root = fs::temp_directory_path() / ("ak_cpu_topology_test_" + std::string{tc});
        fs::remove_all(_root);
        fs::create_directories(_root);
    }
    FakeSysfs(const FakeSysfs&) = delete;
    auto operator=(const FakeSysfs&) -> FakeSysfs& = delete;
    FakeSysfs(FakeSysfs&&) = delete;
    auto operator=(FakeSysfs&&) -> FakeSysfs& = delete;
    ~FakeSysfs() {
        std::error_code ec;
        fs::remove_all(_root, ec);
    }

    void write(const fs::path& rel, std::string_view text) const {
        const auto path = _root / rel;
        fs::create_directories(path.parent_path());
        std::ofstream{path} << text;
    }

    void cpu(CpuId n, std::string_view siblings, const char* file = "core_cpus_list") const {
        write(fs::path{"devices/system/cpu"} / ("cpu" + std::to_string(n)) / "topology" / file,
              std::string{siblings} + "\n");
    }

    [[nodiscard]] auto root() const -> const fs::path& { return _root; }

private:
    fs::path _root;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(cpu_list, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(parses_kernel_formats) {
    BOOST_TEST(*parse_cpu_list("0") == ids({0}), boost::test_tools::per_element());
    BOOST_TEST(*parse_cpu_list("0-3\n") == ids({0, 1, 2, 3}), boost::test_tools::per_element());
    BOOST_TEST(*parse_cpu_list("0-1,4,6-7") == ids({0, 1, 4, 6, 7}),
               boost::test_tools::per_element());
    BOOST_TEST(*parse_cpu_list("8191") == ids({8191}), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(empty_list_is_valid) {
    BOOST_TEST(parse_cpu_list("")->empty());
    BOOST_TEST(parse_cpu_list("\n")->empty());
}

BOOST_AUTO_TEST_CASE(rejects_malformed_lists) {
    const auto err = [](std::string_view s) { return parse_cpu_list(s).error(); };
    BOOST_TEST((err(",") == CpuListError::empty_entry));
    BOOST_TEST((err("0,") == CpuListError::empty_entry));
    BOOST_TEST((err(",0") == CpuListError::empty_entry));
    BOOST_TEST((err("0,,1") == CpuListError::empty_entry));
    BOOST_TEST((err("a") == CpuListError::bad_number));
    BOOST_TEST((err(" 0") == CpuListError::bad_number));
    BOOST_TEST((err("0 ") == CpuListError::bad_number));
    BOOST_TEST((err("+1") == CpuListError::bad_number));
    BOOST_TEST((err("-1") == CpuListError::bad_number));
    BOOST_TEST((err("1-") == CpuListError::bad_number));
    BOOST_TEST((err("1-2-3") == CpuListError::bad_number));
    BOOST_TEST((err("0\n\n") == CpuListError::bad_number));
    BOOST_TEST((err("99999999999999999999") == CpuListError::bad_number));
    BOOST_TEST((err("3-1") == CpuListError::bad_range));
    BOOST_TEST((err("8192") == CpuListError::cpu_too_large));
    BOOST_TEST((err("0-4294967295") == CpuListError::cpu_too_large));
    BOOST_TEST((err("2,1") == CpuListError::not_ascending));
    BOOST_TEST((err("0-3,3") == CpuListError::not_ascending));
    BOOST_TEST((err("1,1") == CpuListError::not_ascending));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(topology, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(from_cores_sorts_and_validates) {
    auto t = CpuTopology::from_cores({{5, 1}, {0, 4}});
    BOOST_REQUIRE(t.has_value());
    BOOST_REQUIRE_EQUAL(t->cores().size(), 2U);
    BOOST_TEST(t->cores()[0].cpus == ids({0, 4}), boost::test_tools::per_element());
    BOOST_TEST(t->cores()[1].cpus == ids({1, 5}), boost::test_tools::per_element());

    BOOST_TEST((CpuTopology::from_cores({}).error() == TopologyError::no_cpus));
    BOOST_TEST((CpuTopology::from_cores({{0}, {}}).error() == TopologyError::empty_core));
    BOOST_TEST((CpuTopology::from_cores({{0, 1}, {1}}).error() == TopologyError::duplicate_cpu));
}

BOOST_AUTO_TEST_CASE(loads_smt_topology) {
    // 2 cores x 2 threads, Intel-style numbering (siblings are n and n+2).
    FakeSysfs sys;
    sys.write("devices/system/cpu/online", "0-3\n");
    sys.cpu(0, "0,2");
    sys.cpu(1, "1,3");
    sys.cpu(2, "0,2");
    sys.cpu(3, "1,3");
    auto t = load_cpu_topology(sys.root());
    BOOST_REQUIRE(t.has_value());
    BOOST_REQUIRE_EQUAL(t->cores().size(), 2U);
    BOOST_TEST(t->cores()[0].cpus == ids({0, 2}), boost::test_tools::per_element());
    BOOST_TEST(t->cores()[1].cpus == ids({1, 3}), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(falls_back_to_thread_siblings_list) {
    FakeSysfs sys;
    sys.write("devices/system/cpu/online", "0-1\n");
    sys.cpu(0, "0-1", "thread_siblings_list");
    sys.cpu(1, "0-1", "thread_siblings_list");
    auto t = load_cpu_topology(sys.root());
    BOOST_REQUIRE(t.has_value());
    BOOST_REQUIRE_EQUAL(t->cores().size(), 1U);
    BOOST_TEST(t->cores()[0].cpus == ids({0, 1}), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(drops_offline_siblings) {
    // cpu3 (cpu1's sibling) is offline: core {1,3} is seen as {1}.
    FakeSysfs sys;
    sys.write("devices/system/cpu/online", "0-2\n");
    sys.cpu(0, "0,2");
    sys.cpu(1, "1,3");
    sys.cpu(2, "0,2");
    auto t = load_cpu_topology(sys.root());
    BOOST_REQUIRE(t.has_value());
    BOOST_REQUIRE_EQUAL(t->cores().size(), 2U);
    BOOST_TEST(t->cores()[1].cpus == ids({1}), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(rejects_inconsistent_siblings) {
    {
        FakeSysfs sys;  // cpu1 does not list itself
        sys.write("devices/system/cpu/online", "0-1\n");
        sys.cpu(0, "0");
        sys.cpu(1, "0");
        BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::inconsistent));
    }
    {
        FakeSysfs sys;  // cpu0 and cpu1 disagree about their core
        sys.write("devices/system/cpu/online", "0-1\n");
        sys.cpu(0, "0-1");
        sys.cpu(1, "1");
        BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::inconsistent));
    }
    {
        FakeSysfs sys;  // overlapping cores {0,1} and {1,2}
        sys.write("devices/system/cpu/online", "0-2\n");
        sys.cpu(0, "0-1");
        sys.cpu(1, "1-2");
        sys.cpu(2, "1-2");
        BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::inconsistent));
    }
}

BOOST_AUTO_TEST_CASE(reports_unreadable_and_malformed) {
    FakeSysfs sys;
    BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::unreadable));
    sys.write("devices/system/cpu/online", "\n");
    BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::no_cpus));
    sys.write("devices/system/cpu/online", "0-1\n");
    sys.cpu(0, "0");
    BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::unreadable));
    sys.cpu(1, "x");
    BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::malformed));
    sys.write("devices/system/cpu/online", "1-0\n");
    BOOST_TEST((load_cpu_topology(sys.root()).error() == TopologyError::malformed));
}

BOOST_AUTO_TEST_CASE(loads_isolated_cpus) {
    FakeSysfs sys;
    BOOST_TEST((load_isolated_cpus(sys.root()).error() == TopologyError::unreadable));
    sys.write("devices/system/cpu/isolated", "\n");
    BOOST_TEST(load_isolated_cpus(sys.root())->empty());
    sys.write("devices/system/cpu/isolated", "2-7\n");
    BOOST_TEST(*load_isolated_cpus(sys.root()) == ids({2, 3, 4, 5, 6, 7}),
               boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(loads_free_1g_hugepages) {
    FakeSysfs sys;
    BOOST_TEST(*load_free_1g_hugepages(sys.root()) == 0U);  // no 1 GiB pool
    const fs::path pool = "kernel/mm/hugepages/hugepages-1048576kB";
    fs::create_directories(sys.root() / pool);
    BOOST_TEST((load_free_1g_hugepages(sys.root()).error() == TopologyError::unreadable));
    sys.write(pool / "free_hugepages", "48\n");
    BOOST_TEST(*load_free_1g_hugepages(sys.root()) == 48U);
    sys.write(pool / "free_hugepages", "-1\n");
    BOOST_TEST((load_free_1g_hugepages(sys.root()).error() == TopologyError::malformed));
    sys.write(pool / "free_hugepages", "99999999999\n");
    BOOST_TEST((load_free_1g_hugepages(sys.root()).error() == TopologyError::malformed));
}

BOOST_AUTO_TEST_SUITE_END()
