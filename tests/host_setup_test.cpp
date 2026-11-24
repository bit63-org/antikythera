// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 3 (Requirements 3.1, 4.1, 4.4, 5.1,
// 5.2): the allow-list parser, discovery, vfio-pci binding and the IOMMU
// group check against a fake sysfs tree, the inventory file, the server ID
// sources and the compiled-in controller keys; and hull-init end to end,
// exec'ing a stand-in agent that records its arguments.

#define BOOST_TEST_MODULE host_setup_test
#include <boost/test/unit_test.hpp>

#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "hull/host_setup.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
namespace mb = ak::helm::mailbox;
using namespace ak::hull;
using ak::test::unit_timeout_seconds;

BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<mb::ServerId>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(ServerIdSource)
BOOST_TEST_DONT_PRINT_LOG_VALUE(ResetMethod)
BOOST_TEST_DONT_PRINT_LOG_VALUE(mb::DeviceType)

namespace {

constexpr std::string_view good_config = R"(# hull.conf
mailbox 1af4:10ff
slot 0 port 0000:00:01.0 type nic_vf id 8086:1889   # E810 VFs
slot 1 port 0000:00:02.0 type blk_fn id 1b36:0010
server-id cmdline
)";

auto reason(std::string_view text) -> std::string {
    const auto r = parse_host_config(text);
    return r ? std::string{"accepted"} : r.error().reason;
}

auto slurp(const fs::path& p) -> std::string {
    std::ifstream in{p};
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

// A sysfs tree with PCI devices under root ports, the way the kernel lays
// it out: the real directories under devices/pci0000:00/, links to them in
// bus/pci/devices/, IOMMU groups under kernel/iommu_groups/.
class FakeSysfs {
public:
    FakeSysfs() {
        const auto* tc = boost::unit_test::framework::current_test_case().p_name->c_str();
        _root = fs::temp_directory_path() /
                ("ak_host_setup_test_" + std::to_string(::getpid()) + "_" + tc);
        fs::remove_all(_root);
        fs::create_directories(_root / "bus/pci/devices");
        fs::create_directories(_root / "bus/pci/drivers/vfio-pci");
        fs::create_directories(_root / "bus/pci/drivers/ixgbevf");
        touch("bus/pci/drivers_probe");
        touch("bus/pci/drivers/ixgbevf/unbind");
    }
    FakeSysfs(const FakeSysfs&) = delete;
    auto operator=(const FakeSysfs&) -> FakeSysfs& = delete;
    FakeSysfs(FakeSysfs&&) = delete;
    auto operator=(FakeSysfs&&) -> FakeSysfs& = delete;
    ~FakeSysfs() {
        std::error_code ec;
        fs::remove_all(_root, ec);
    }

    void touch(const fs::path& rel) const {
        fs::create_directories((_root / rel).parent_path());
        std::ofstream{_root / rel};
    }

    // `parent` is the real path below devices/ of the port (empty for a
    // device on the root complex).
    void device(const std::string& bdf, const fs::path& parent, std::string_view id,
                std::uint32_t group, bool vf = false, std::string_view driver = {}) const {
        const auto rel = fs::path{"devices/pci0000:00"} / parent / bdf;
        const auto dir = _root / rel;
        fs::create_directories(dir);
        std::ofstream{dir / "vendor"} << "0x" << id.substr(0, 4) << "\n";
        std::ofstream{dir / "device"} << "0x" << id.substr(5) << "\n";
        std::ofstream{dir / "driver_override"} << "";
        fs::create_symlink(fs::path{"../../.."} / rel, _root / "bus/pci/devices" / bdf);
        const auto gdir = _root / "kernel/iommu_groups" / std::to_string(group) / "devices";
        fs::create_directories(gdir);
        fs::create_symlink(dir, gdir / bdf);
        fs::create_symlink(_root / "kernel/iommu_groups" / std::to_string(group),
                           dir / "iommu_group");
        if (vf) {
            fs::create_symlink(dir.parent_path(), dir / "physfn");
        }
        if (!driver.empty()) {
            fs::create_symlink(_root / "bus/pci/drivers" / driver, dir / "driver");
        }
    }

    // The standard host: a mailbox, two VFs and a PF below port 01.0 (only
    // the VFs match slot 0), one block function below port 02.0, and a
    // matching VF below an unlisted port 03.0.
    void standard_host() const {
        device("0000:00:1f.0", {}, "1af4:10ff", 1, false, "vfio-pci");
        device("0000:00:01.0", {}, "8086:7a38", 2);
        device("0000:01:00.0", "0000:00:01.0", "8086:1592", 3);
        device("0000:01:01.1", "0000:00:01.0", "8086:1889", 5, true, "vfio-pci");
        device("0000:01:01.0", "0000:00:01.0", "8086:1889", 4, true, "vfio-pci");
        device("0000:00:02.0", {}, "8086:7a39", 6);
        device("0000:02:00.0", "0000:00:02.0", "1b36:0010", 7, false, "vfio-pci");
        device("0000:00:03.0", {}, "8086:7a3a", 8);
        device("0000:03:00.1", "0000:00:03.0", "8086:1889", 9, true);
    }

    [[nodiscard]] auto root() const -> const fs::path& { return _root; }

private:
    fs::path _root;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(host_config, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(parses_the_allow_list) {
    const auto c = parse_host_config(good_config);
    BOOST_TEST_REQUIRE(c.has_value());
    BOOST_TEST((c->mailbox == PciId{.vendor = 0x1af4, .device = 0x10ff}));
    BOOST_TEST_REQUIRE(c->slots.size() == 2U);
    BOOST_TEST(c->slots[0].slot == 0U);
    BOOST_TEST(c->slots[0].port == "0000:00:01.0");
    BOOST_TEST(c->slots[0].type == mb::DeviceType::nic_vf);
    BOOST_TEST((c->slots[0].id == PciId{.vendor = 0x8086, .device = 0x1889}));
    BOOST_TEST(c->slots[1].type == mb::DeviceType::blk_fn);
    BOOST_TEST(c->server_id_source == ServerIdSource::cmdline);

    const auto f = parse_host_config("mailbox 1af4:10ff\nserver-id file /etc/hull/server-id\n");
    BOOST_TEST_REQUIRE(f.has_value());
    BOOST_TEST(f->slots.empty());
    BOOST_TEST(f->server_id_source == ServerIdSource::file);
    BOOST_TEST(f->server_id_file == fs::path{"/etc/hull/server-id"});
    BOOST_TEST(parse_host_config("\tmailbox\t1af4:10ff  \n\n# x\nserver-id cmdline").has_value());
}

BOOST_AUTO_TEST_CASE(rejects_a_bad_allow_list) {
    BOOST_TEST(reason("") == "no mailbox line");
    BOOST_TEST(reason("mailbox 1af4:10ff\n") == "no server-id line");
    BOOST_TEST(reason("server-id cmdline\n") == "no mailbox line");
    const std::string head = "mailbox 1af4:10ff\nserver-id cmdline\n";
    BOOST_TEST(reason(head + "mailbox 1af4:10fe\n") == "second mailbox line");
    BOOST_TEST(reason(head + "server-id cmdline\n") == "second server-id line");
    BOOST_TEST(reason("mailbox 1AF4:10ff\nserver-id cmdline\n") == "bad PCI ID");
    BOOST_TEST(reason("mailbox 1af4:10f\nserver-id cmdline\n") == "bad PCI ID");
    BOOST_TEST(reason("mailbox 1af4\nserver-id cmdline\n") == "bad PCI ID");
    BOOST_TEST(reason("mailbox 1af4:10ff x\nserver-id cmdline\n") ==
               "mailbox takes one <vendor>:<device>");
    BOOST_TEST(reason(head + "slot 255 port 0000:00:01.0 type nic_vf id 8086:1889\n") ==
               "bad slot number");
    BOOST_TEST(reason(head + "slot 01 port 0000:00:01.0 type nic_vf id 8086:1889\n") ==
               "bad slot number");
    BOOST_TEST(reason(head + "slot 1 port 00:01.0 type nic_vf id 8086:1889\n") ==
               "bad port address");
    BOOST_TEST(reason(head + "slot 1 port 0000:00:01.0 type nic id 8086:1889\n") ==
               "unknown function type");
    BOOST_TEST(reason(head + "slot 1 port 0000:00:01.0 type nic_vf 8086:1889\n") ==
               "slot <n> port <bdf> type <type> id <vendor>:<device>");
    BOOST_TEST(reason(head + "slot 1 port 0000:00:01.0 type nic_vf id 8086:1889\n" +
                      "slot 1 port 0000:00:02.0 type nic_vf id 8086:1889\n") ==
               "slot listed twice");
    BOOST_TEST(reason(head + "slot 1 port 0000:00:01.0 type nic_vf id 8086:1889\n" +
                      "slot 2 port 0000:00:01.0 type blk_fn id 1b36:0010\n") ==
               "port listed twice");
    BOOST_TEST(reason("mailbox 1af4:10ff\nserver-id file relative\n") ==
               "server-id cmdline | server-id file <absolute path>");
    BOOST_TEST(reason("mailbox 1af4:10ff\nserver-id file /etc/../x\n") ==
               "server-id file path is not normal");
    BOOST_TEST(reason(head + "kernel /boot/vmlinuz\n") == "unknown keyword");
    BOOST_TEST(reason(head + "\r\n") == "control or non-ASCII byte");
    BOOST_TEST(reason(std::string{"mailbox 1af4:10ff\0", 18} + "\nserver-id cmdline\n") ==
               "control or non-ASCII byte");
    BOOST_TEST(reason(head + "# caf\xc3\xa9\n") == "control or non-ASCII byte");
    BOOST_TEST(reason(head + std::string(max_config_bytes, '#')) == "file too large");

    const auto r = parse_host_config(head + "\nbogus\n");
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().line == 4U);
}

BOOST_AUTO_TEST_CASE(pci_addresses_are_canonical) {
    BOOST_TEST(valid_bdf("0000:00:1f.7"));
    BOOST_TEST(valid_bdf("ffff:ff:1f.0"));
    BOOST_TEST(!valid_bdf("0000:00:20.0"));  // device numbers stop at 1f
    BOOST_TEST(!valid_bdf("0000:00:1f.8"));  // function numbers stop at 7
    BOOST_TEST(!valid_bdf("0000:00:1F.0"));
    BOOST_TEST(!valid_bdf("00:1f.0"));
    BOOST_TEST(!valid_bdf("0000:00:1f.0 "));
    BOOST_TEST(!valid_bdf("../00:1f.0aa"));
    BOOST_TEST(!valid_bdf(""));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(server_id, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(from_the_kernel_command_line) {
    BOOST_TEST(server_id_from_cmdline("ro quiet hull.server_id=42\n") ==
               std::optional<mb::ServerId>{42});
    BOOST_TEST(server_id_from_cmdline("hull.server_id=1 hull.server_id=7") ==
               std::optional<mb::ServerId>{7});
    BOOST_TEST(server_id_from_cmdline("hull.server_id=18446744073709551615") ==
               std::optional<mb::ServerId>{UINT64_MAX});
    BOOST_TEST(!server_id_from_cmdline("ro quiet\n").has_value());
    BOOST_TEST(!server_id_from_cmdline("hull.server_id=0").has_value());
    BOOST_TEST(!server_id_from_cmdline("hull.server_id=").has_value());
    BOOST_TEST(!server_id_from_cmdline("hull.server_id=-1").has_value());
    BOOST_TEST(!server_id_from_cmdline("hull.server_id=0x10").has_value());
    BOOST_TEST(!server_id_from_cmdline("hull.server_id=18446744073709551616").has_value());
    BOOST_TEST(!server_id_from_cmdline("xhull.server_id=5").has_value());
}

BOOST_AUTO_TEST_CASE(from_a_provisioning_file) {
    BOOST_TEST(server_id_from_text("12\n") == std::optional<mb::ServerId>{12});
    BOOST_TEST(server_id_from_text("12") == std::optional<mb::ServerId>{12});
    BOOST_TEST(!server_id_from_text("12\n\n").has_value());
    BOOST_TEST(!server_id_from_text(" 12").has_value());
    BOOST_TEST(!server_id_from_text("").has_value());
    BOOST_TEST(!server_id_from_text("0\n").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(discovery, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(finds_the_mailbox_and_each_slots_functions) {
    FakeSysfs sys;
    sys.standard_host();
    const auto found = discover(*parse_host_config(good_config), sys.root());
    BOOST_TEST_REQUIRE(found.has_value());
    BOOST_TEST(found->mailbox_bdf == "0000:00:1f.0");
    BOOST_TEST_REQUIRE(found->functions.size() == 3U);
    // Numbered per slot in address order; the PF and the VF behind the
    // unlisted port are not the host's to hand out.
    const auto& f = found->functions;
    BOOST_TEST(f[0].bdf == "0000:01:01.0");
    BOOST_TEST(f[0].ref.slot == 0U);
    BOOST_TEST(f[0].ref.function == 0U);
    BOOST_TEST(f[0].ref.type == mb::DeviceType::nic_vf);
    BOOST_TEST(f[0].reset == ResetMethod::flr);
    BOOST_TEST(f[1].bdf == "0000:01:01.1");
    BOOST_TEST(f[1].ref.function == 1U);
    BOOST_TEST(f[2].bdf == "0000:02:00.0");
    BOOST_TEST(f[2].ref.slot == 1U);
    BOOST_TEST(f[2].ref.function == 0U);
    BOOST_TEST(f[2].ref.type == mb::DeviceType::blk_fn);
    BOOST_TEST(f[2].reset == ResetMethod::bus);
}

BOOST_AUTO_TEST_CASE(refuses_a_missing_or_ambiguous_mailbox) {
    FakeSysfs none;
    none.device("0000:00:02.0", {}, "8086:7a39", 6);
    const auto missing = discover(*parse_host_config(good_config), none.root());
    BOOST_TEST_REQUIRE(!missing.has_value());
    BOOST_TEST(missing.error().step == "mailbox");

    FakeSysfs two;
    two.device("0000:00:1e.0", {}, "1af4:10ff", 1);
    two.device("0000:00:1f.0", {}, "1af4:10ff", 2);
    const auto ambiguous = discover(*parse_host_config(good_config), two.root());
    BOOST_TEST_REQUIRE(!ambiguous.has_value());
    BOOST_TEST(ambiguous.error().step == "mailbox");
}

BOOST_AUTO_TEST_CASE(binds_to_vfio_pci) {
    FakeSysfs sys;
    sys.device("0000:00:05.0", {}, "8086:1889", 3, true, "ixgbevf");
    BOOST_TEST(!bound_to_vfio("0000:00:05.0", sys.root()));
    BOOST_TEST_REQUIRE(bind_to_vfio("0000:00:05.0", sys.root()).has_value());
    BOOST_TEST(slurp(sys.root() / "bus/pci/devices/0000:00:05.0/driver_override") == "vfio-pci");
    BOOST_TEST(slurp(sys.root() / "bus/pci/drivers/ixgbevf/unbind") == "0000:00:05.0");
    BOOST_TEST(slurp(sys.root() / "bus/pci/drivers_probe") == "0000:00:05.0");

    // Already vfio-pci's: only the override is written.
    FakeSysfs bound;
    bound.device("0000:00:05.0", {}, "8086:1889", 3, true, "vfio-pci");
    BOOST_TEST(bound_to_vfio("0000:00:05.0", bound.root()));
    BOOST_TEST_REQUIRE(bind_to_vfio("0000:00:05.0", bound.root()).has_value());
    BOOST_TEST(slurp(bound.root() / "bus/pci/drivers_probe").empty());

    const auto bad = bind_to_vfio("../../x", sys.root());
    BOOST_TEST_REQUIRE(!bad.has_value());
    BOOST_TEST(bad.error().step == "bind");
    const auto gone = bind_to_vfio("0000:00:06.0", sys.root());
    BOOST_TEST_REQUIRE(!gone.has_value());
    BOOST_TEST(gone.error().sys_errno == ENOENT);
}

BOOST_AUTO_TEST_CASE(requires_a_function_alone_in_its_group) {
    FakeSysfs sys;
    sys.device("0000:00:05.0", {}, "8086:1889", 11);
    sys.device("0000:00:06.0", {}, "8086:1889", 12);
    sys.device("0000:00:06.1", {}, "8086:1889", 12);
    sys.touch("bus/pci/devices/0000:00:07.0/vendor");

    const auto alone = isolated_group("0000:00:05.0", sys.root());
    BOOST_TEST_REQUIRE(alone.has_value());
    BOOST_TEST(*alone == 11U);
    const auto shared = isolated_group("0000:00:06.0", sys.root());
    BOOST_TEST_REQUIRE(!shared.has_value());
    BOOST_TEST(shared.error().step == "iommu");
    BOOST_TEST(shared.error().detail.find("shared") != std::string::npos);
    const auto no_iommu = isolated_group("0000:00:07.0", sys.root());
    BOOST_TEST_REQUIRE(!no_iommu.has_value());
    BOOST_TEST(no_iommu.error().detail.find("no IOMMU group") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(inventory, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips) {
    const std::vector<InventoryEntry> entries{
        {.ref = {.slot = 3, .type = mb::DeviceType::nic_vf, .function = 1},
         .bdf = "0000:03:00.1",
         .iommu_group = 11,
         .reset = ResetMethod::flr},
        {.ref = {.slot = 254, .type = mb::DeviceType::gpu_whole, .function = 0},
         .bdf = "0000:c1:00.0",
         .iommu_group = 4294967295U,
         .reset = ResetMethod::bus},
    };
    const auto text = format_inventory(entries);
    BOOST_TEST(text ==
               "3 nic_vf 1 0000:03:00.1 11 flr\n254 gpu_whole 0 0000:c1:00.0 4294967295 bus\n");
    const auto back = parse_inventory(text);
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((*back == entries));
    BOOST_TEST(parse_inventory("")->empty());
}

BOOST_AUTO_TEST_CASE(rejects_a_bad_inventory) {
    const auto line = [](std::string_view t) {
        const auto r = parse_inventory(t);
        return r ? std::size_t{0} : r.error().line;
    };
    BOOST_TEST(line("3 nic_vf 1 0000:03:00.1 11\n") == 1U);
    BOOST_TEST(line("3 nic_vf 1 0000:03:00.1 11 reset\n") == 1U);
    BOOST_TEST(line("255 nic_vf 1 0000:03:00.1 11 flr\n") == 1U);
    BOOST_TEST(line("3 nic 1 0000:03:00.1 11 flr\n") == 1U);
    BOOST_TEST(line("3 nic_vf 65536 0000:03:00.1 11 flr\n") == 1U);
    BOOST_TEST(line("3 nic_vf 1 03:00.1 11 flr\n") == 1U);
    BOOST_TEST(line("3 nic_vf 1 0000:03:00.1 -1 flr\n") == 1U);
    // A function, address or group twice.
    BOOST_TEST(line("3 nic_vf 1 0000:03:00.1 11 flr\n3 nic_vf 1 0000:03:00.2 12 flr\n") == 2U);
    BOOST_TEST(line("3 nic_vf 1 0000:03:00.1 11 flr\n3 nic_vf 2 0000:03:00.1 12 flr\n") == 2U);
    BOOST_TEST(line("3 nic_vf 1 0000:03:00.1 11 flr\n3 nic_vf 2 0000:03:00.2 11 flr\n") == 2U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(controller_keys, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(parses_compiled_keys) {
    const std::string k1(64, 'a');
    const std::string k2 = "00" + std::string(60, '1') + "ff";
    const auto keys = parse_controller_keys("1:" + k1 + ";65535:" + k2);
    BOOST_TEST_REQUIRE(keys.has_value());
    BOOST_TEST_REQUIRE(keys->size() == 2U);
    BOOST_TEST((*keys)[0].id == 1U);
    BOOST_TEST(((*keys)[0].key[0] == std::byte{0xaa}));
    BOOST_TEST((*keys)[1].id == 65535U);
    BOOST_TEST(((*keys)[1].key[0] == std::byte{0x00}));
    BOOST_TEST(((*keys)[1].key[1] == std::byte{0x11}));
    BOOST_TEST(((*keys)[1].key[31] == std::byte{0xff}));
    BOOST_TEST(parse_controller_keys("")->empty());
}

BOOST_AUTO_TEST_CASE(rejects_bad_keys) {
    const std::string k(64, 'a');
    BOOST_TEST(!parse_controller_keys(k).has_value());
    BOOST_TEST(!parse_controller_keys("0:" + k).has_value());
    BOOST_TEST(!parse_controller_keys("65536:" + k).has_value());
    BOOST_TEST(!parse_controller_keys("1:" + k.substr(1)).has_value());
    BOOST_TEST(!parse_controller_keys("1:" + k + "a").has_value());
    BOOST_TEST(!parse_controller_keys("1:" + std::string(64, 'A')).has_value());
    BOOST_TEST(parse_controller_keys("1:" + k + ";")->size() ==
               1U);  // a trailing ';' ends the list
    const auto second = parse_controller_keys("1:" + k + ";2:xyz");
    BOOST_TEST_REQUIRE(!second.has_value());
    BOOST_TEST(second.error().line == 2U);
}

BOOST_AUTO_TEST_SUITE_END()

// hull-init with --no-mount over the fake tree: it binds (the functions
// are already vfio-pci's, since nothing here plays the PCI core), checks
// groups, writes the inventory and execs the agent, which here is a
// stand-in that writes its arguments to a file.
BOOST_AUTO_TEST_SUITE(init_binary, *boost::unit_test::timeout(unit_timeout_seconds))

namespace {

auto run_init(const FakeSysfs& sys, std::string_view config, std::string_view cmdline) -> int {
    const auto dir = sys.root() / "init";
    fs::create_directories(dir);
    std::ofstream{dir / "hull.conf"} << config;
    std::ofstream{dir / "cmdline"} << cmdline;
    const auto agent = dir / "agent";
    std::ofstream{agent} << "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > \""
                         << (dir / "args").string() << "\"\n";
    fs::permissions(agent, fs::perms::owner_all);
    const std::string init = HULL_INIT_PATH;
    const std::vector<std::string> args{init,        "--no-mount",
                                        "--sysfs",   sys.root().string(),
                                        "--config",  (dir / "hull.conf").string(),
                                        "--cmdline", (dir / "cmdline").string(),
                                        "--run-dir", (dir / "run").string(),
                                        "--agent",   agent.string(),
                                        "--",        "--vmm-stderr"};
    const pid_t pid = ::fork();
    if (pid == 0) {
        std::vector<char*> argv;
        for (const auto& a : args) {
            argv.push_back(const_cast<char*>(a.c_str()));
        }
        argv.push_back(nullptr);
        ::execv(init.c_str(), argv.data());
        ::_exit(127);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

BOOST_AUTO_TEST_CASE(writes_the_inventory_and_execs_the_agent) {
    FakeSysfs sys;
    sys.standard_host();
    BOOST_TEST_REQUIRE(run_init(sys, good_config, "ro hull.server_id=77\n") == 0);
    const auto dir = sys.root() / "init";
    BOOST_TEST(slurp(dir / "run/inventory") ==
               "0 nic_vf 0 0000:01:01.0 4 flr\n0 nic_vf 1 0000:01:01.1 5 flr\n1 blk_fn 0 "
               "0000:02:00.0 7 bus\n");
    BOOST_TEST(slurp(dir / "args") == "--mailbox\n0000:00:1f.0\n--inventory\n" +
                                          (dir / "run/inventory").string() +
                                          "\n--server-id\n77\n--vmm-stderr\n");
}

BOOST_AUTO_TEST_CASE(fails_closed) {
    {
        FakeSysfs sys;
        sys.standard_host();
        BOOST_TEST(run_init(sys, good_config, "ro\n") == 1);  // no server ID
        BOOST_TEST(!fs::exists(sys.root() / "init/args"));
    }
    {
        FakeSysfs sys;
        sys.standard_host();
        // A second function in the block function's group.
        fs::create_symlink(sys.root() / "devices/pci0000:00/0000:00:02.0",
                           sys.root() / "kernel/iommu_groups/7/devices/0000:00:02.0");
        BOOST_TEST(run_init(sys, good_config, "hull.server_id=1\n") == 1);
        BOOST_TEST(!fs::exists(sys.root() / "init/args"));
    }
    {
        // vfio-pci never takes the function (nothing binds in a fake tree).
        FakeSysfs sys;
        sys.standard_host();
        sys.device("0000:01:02.0", "0000:00:01.0", "8086:1889", 20, true, "ixgbevf");
        BOOST_TEST(run_init(sys, good_config, "hull.server_id=1\n") == 1);
        BOOST_TEST(!fs::exists(sys.root() / "init/args"));
    }
    {
        FakeSysfs sys;
        sys.standard_host();
        BOOST_TEST(run_init(sys, "mailbox 1af4:10ff\n", "hull.server_id=1\n") == 1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
