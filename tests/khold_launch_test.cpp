// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kythira .kiro/specs/khold-block-service/ task 17: how ak-khold launches
// and feeds the khold node (NodeProcess: start, restart with backoff,
// layouts and reports through files, stop), and the storage self-test that
// fills the role's capacity reports (Requirement 12.1).

#define BOOST_TEST_MODULE khold_launch_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include <csignal>
#include <unistd.h>

#include "khold/node_process.hpp"
#include "khold/self_test.hpp"
#include "proto/report.hpp"

namespace {

namespace proto = ak::proto;
using namespace ak::khold;
using namespace std::chrono_literals;
using Bytes = std::vector<std::byte>;

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-khold-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

auto read_bytes(const std::filesystem::path& p) -> Bytes {
    std::ifstream in{p, std::ios::binary};
    const std::vector<char> chars{std::istreambuf_iterator<char>{in},
                                  std::istreambuf_iterator<char>{}};
    Bytes out;
    for (const char c : chars) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto write_bytes(const std::filesystem::path& p, const Bytes& b) -> void {
    std::ofstream out{p, std::ios::binary};
    out.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}

auto write_text(const std::filesystem::path& p, const std::string& s) -> void {
    std::ofstream out{p};
    out << s;
}

auto report_bytes(proto::ReportBody body) -> Bytes {
    auto b = proto::encode_report({.server_id = 9, .report_seq = 1, .body = std::move(body)});
    BOOST_REQUIRE(b.has_value());
    return *b;
}

// Polls until `done` or about two seconds pass.
template<typename F> auto eventually(NodeProcess& node, F done) -> bool {
    for (int i = 0; i < 400; ++i) {
        node.poll(Clock::now());
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(5ms);
    }
    return false;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(node_process)

BOOST_AUTO_TEST_CASE(starts_the_node_and_stops_it) {
    TempDir dir;
    NodeProcess node{{.argv = {"sleep", "30"},
                      .layout_dir = dir.path / "layouts",
                      .report_dir = dir.path / "reports"}};
    BOOST_TEST(std::filesystem::is_directory(dir.path / "layouts"));
    BOOST_TEST(std::filesystem::is_directory(dir.path / "reports"));
    BOOST_TEST(!node.running());
    BOOST_TEST(node.generation() == 0U);
    node.poll(Clock::now());
    BOOST_REQUIRE(node.running());
    BOOST_TEST(node.generation() == 1U);
    const auto pid = node.pid();
    BOOST_TEST(::kill(pid, 0) == 0);
    node.stop();
    BOOST_TEST(!node.running());
    node.poll(Clock::now() + 1h);
    BOOST_TEST(!node.running());  // stopped for good
    BOOST_TEST(node.stats().starts == 1U);
}

BOOST_AUTO_TEST_CASE(an_exited_node_is_restarted_with_backoff) {
    TempDir dir;
    NodeProcess node{{.argv = {"sh", "-c", "exit 3"},
                      .layout_dir = dir.path / "layouts",
                      .report_dir = dir.path / "reports",
                      .restart_min = 10ms,
                      .restart_max = 10s}};
    node.poll(Clock::now());
    BOOST_TEST(node.generation() == 1U);
    BOOST_REQUIRE(eventually(node, [&] { return node.generation() >= 3U; }));
    BOOST_TEST(node.stats().exits >= 2U);
    node.stop();
}

BOOST_AUTO_TEST_CASE(a_node_that_cannot_be_run_is_not_running) {
    TempDir dir;
    NodeProcess node{{.argv = {(dir.path / "missing").string()},
                      .layout_dir = dir.path / "layouts",
                      .report_dir = dir.path / "reports",
                      .restart_min = 10ms}};
    node.poll(Clock::now());
    // exec fails in the child, which exits 127: reaped like any exit.
    BOOST_REQUIRE(eventually(node, [&] { return node.stats().exits >= 1U; }));
    node.stop();
}

BOOST_AUTO_TEST_CASE(layouts_are_written_whole_by_volume) {
    TempDir dir;
    NodeProcess node{{.argv = {}, .layout_dir = dir.path / "l", .report_dir = dir.path / "r"}};
    BOOST_TEST(layout_file_name(0x2A) == "000000000000002a.vlay");
    const Bytes first{std::byte{1}, std::byte{2}, std::byte{3}};
    const Bytes second{std::byte{4}, std::byte{5}};
    BOOST_TEST(node.apply_layout(0x2A, 1, first));
    BOOST_TEST(node.apply_layout(0x2A, 2, second));
    const auto path = dir.path / "l" / layout_file_name(0x2A);
    BOOST_TEST((read_bytes(path) == second));  // replaced, never appended
    std::size_t files = 0;
    for ([[maybe_unused]] const auto& e : std::filesystem::directory_iterator{dir.path / "l"}) {
        ++files;
    }
    BOOST_TEST(files == 1U);  // no temporary left behind
    BOOST_TEST(node.stats().layouts_written == 2U);

    std::filesystem::remove_all(dir.path / "l");
    BOOST_TEST(!node.apply_layout(0x2B, 1, first));
    BOOST_TEST(node.stats().layout_write_failures == 1U);
}

BOOST_AUTO_TEST_CASE(reports_are_taken_in_name_order_and_deleted) {
    TempDir dir;
    NodeProcess node{
        {.argv = {}, .layout_dir = dir.path / "l", .report_dir = dir.path / "r", .max_reports = 2}};
    const proto::GroupFault fault{.volume_id = 1,
                                  .group_id = 2,
                                  .epoch = 3,
                                  .term = 4,
                                  .suspect = 5,
                                  .kind = proto::GroupFaultKind::lagging,
                                  .slot = 0,
                                  .drive = 0};
    const proto::GroupStatus status{.slot = 0, .entries = {}};
    write_bytes(dir.path / "r" / "0002.rpt", report_bytes(status));
    write_bytes(dir.path / "r" / "0001.rpt", report_bytes(fault));
    write_bytes(dir.path / "r" / "0003.rpt", Bytes(10, std::byte{7}));  // not a report
    write_bytes(dir.path / "r" / "0004.tmp", report_bytes(status));     // still being written
    auto got = node.take_reports();
    BOOST_REQUIRE(got.size() == 2U);  // max_reports
    BOOST_TEST((std::get<proto::GroupFault>(got[0]) == fault));
    BOOST_TEST((std::get<proto::GroupStatus>(got[1]) == status));
    got = node.take_reports();
    BOOST_TEST(got.empty());
    BOOST_TEST(node.stats().reports_read == 2U);
    BOOST_TEST(node.stats().reports_bad == 1U);
    BOOST_TEST(!std::filesystem::exists(dir.path / "r" / "0001.rpt"));
    BOOST_TEST(!std::filesystem::exists(dir.path / "r" / "0003.rpt"));
    BOOST_TEST(std::filesystem::exists(dir.path / "r" / "0004.tmp"));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(self_test)

BOOST_AUTO_TEST_CASE(measures_a_drive_and_leaves_nothing_behind) {
    TempDir dir;
    const auto d = measure_drive({.drive = 3, .dir = dir.path}, std::uint64_t{2} << 20U, 20ms);
    BOOST_TEST(d.drive == 3U);
    BOOST_TEST((d.state == proto::DriveState::ok));
    BOOST_TEST(d.capacity_bytes > 0U);
    BOOST_TEST(d.read_iops > 0U);
    BOOST_TEST(d.write_iops > 0U);
    BOOST_TEST(d.read_mib_per_s > 0U);
    BOOST_TEST(d.write_mib_per_s > 0U);
    BOOST_TEST(d.allocated_bytes == 0U);  // the node's figure, not the test's
    BOOST_TEST(std::filesystem::is_empty(dir.path));
}

BOOST_AUTO_TEST_CASE(an_unusable_drive_is_failed) {
    TempDir dir;
    const auto d = measure_drive({.drive = 1, .dir = dir.path / "absent"}, 1U << 20U, 10ms);
    BOOST_TEST((d.state == proto::DriveState::failed));
    BOOST_TEST(d.read_iops == 0U);
    BOOST_TEST(d.capacity_bytes == 0U);
}

BOOST_AUTO_TEST_CASE(link_speed_comes_from_sysfs) {
    TempDir dir;
    std::filesystem::create_directories(dir.path / "eth0");
    std::filesystem::create_directories(dir.path / "down0");
    std::filesystem::create_directories(dir.path / "junk0");
    write_text(dir.path / "eth0" / "speed", "25000\n");
    write_text(dir.path / "down0" / "speed", "-1\n");
    write_text(dir.path / "junk0" / "speed", "fast\n");
    BOOST_TEST(read_link_mbps(dir.path, "eth0") == 25000U);
    BOOST_TEST(read_link_mbps(dir.path, "down0") == 0U);
    BOOST_TEST(read_link_mbps(dir.path, "junk0") == 0U);
    BOOST_TEST(read_link_mbps(dir.path, "missing0") == 0U);
    BOOST_TEST(read_link_mbps(dir.path, "") == 0U);
    BOOST_TEST(read_link_mbps(dir.path, "../eth0") == 0U);
    BOOST_TEST(read_link_mbps(dir.path, "..") == 0U);
}

BOOST_AUTO_TEST_CASE(the_whole_test_reports_every_drive_and_the_link) {
    TempDir dir;
    std::filesystem::create_directories(dir.path / "net" / "stor0");
    write_text(dir.path / "net" / "stor0" / "speed", "1000");
    std::filesystem::create_directories(dir.path / "d0");
    std::filesystem::create_directories(dir.path / "d1");
    SelfTestConfig config{.drives = {{.drive = 0, .dir = dir.path / "d0"},
                                     {.drive = 1, .dir = dir.path / "d1"},
                                     {.drive = 1, .dir = dir.path / "d0"},  // out of order: skipped
                                     {.drive = 4, .dir = dir.path / "absent"}},
                          .link_interface = "stor0",
                          .link_mbps = 0,
                          .sys_class_net = dir.path / "net",
                          .file_bytes = 1U << 20U,
                          .phase_budget = 10ms};
    auto c = run_self_test(config);
    BOOST_TEST(c.slot == 0U);
    BOOST_TEST(c.link_mbps == 1000U);
    BOOST_REQUIRE(c.drives.size() == 3U);
    BOOST_TEST(c.drives[0].drive == 0U);
    BOOST_TEST(c.drives[1].drive == 1U);
    BOOST_TEST((c.drives[2].state == proto::DriveState::failed));
    BOOST_TEST(proto::detail::check_body(c).has_value());  // a report the controller takes

    config.link_mbps = 200000;  // stated, not read
    config.drives.clear();
    BOOST_TEST(run_self_test(config).link_mbps == 200000U);
}

BOOST_AUTO_TEST_SUITE_END()
