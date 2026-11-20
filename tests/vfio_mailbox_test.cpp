// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 4: finding the mailbox's IOMMU group and
// failing cleanly, with the step named, when VFIO is not there. Opening a
// real function needs vfio-pci and is covered in harbor.

#define BOOST_TEST_MODULE vfio_mailbox_test
#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <filesystem>
#include <string>

#include "hull/vfio_mailbox.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
using ak::test::unit_timeout_seconds;

namespace {

constexpr auto bdf = "0000:01:00.0";

struct FakeRoot {
    fs::path root;
    FakeRoot() {
        std::string tmpl = (fs::temp_directory_path() / "ak-vfio-XXXXXX").string();
        root = ::mkdtemp(tmpl.data());
        fs::create_directories(root / "sys/bus/pci/devices" / bdf);
        fs::create_directories(root / "sys/kernel/iommu_groups/17");
        fs::create_directories(root / "dev/vfio");
    }
    FakeRoot(const FakeRoot&) = delete;
    auto operator=(const FakeRoot&) -> FakeRoot& = delete;
    FakeRoot(FakeRoot&&) = delete;
    auto operator=(FakeRoot&&) -> FakeRoot& = delete;
    ~FakeRoot() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    auto link_group(const std::string& target) const -> void {
        fs::create_symlink(target, root / "sys/bus/pci/devices" / bdf / "iommu_group");
    }
    [[nodiscard]] auto sys() const -> std::string { return (root / "sys").string(); }
    [[nodiscard]] auto dev() const -> std::string { return (root / "dev").string(); }
};

}  // namespace

BOOST_AUTO_TEST_CASE(finds_iommu_group, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const FakeRoot r;
    BOOST_TEST(!ak::hull::iommu_group_of(bdf, r.sys()).has_value());  // no link yet
    r.link_group("../../../../kernel/iommu_groups/17");
    const auto g = ak::hull::iommu_group_of(bdf, r.sys());
    BOOST_REQUIRE(g.has_value());
    BOOST_TEST(*g == "17");
}

BOOST_AUTO_TEST_CASE(rejects_odd_group_link, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const FakeRoot r;
    r.link_group("../../../../kernel/iommu_groups/not-a-number");
    const auto g = ak::hull::iommu_group_of(bdf, r.sys());
    BOOST_REQUIRE(!g.has_value());
    BOOST_TEST(g.error().error == 0);
}

BOOST_AUTO_TEST_CASE(open_names_failing_step, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const FakeRoot r;
    r.link_group("../../../../kernel/iommu_groups/17");
    const auto m = ak::hull::VfioMailbox::open(bdf, r.sys(), r.dev());
    BOOST_REQUIRE(!m.has_value());
    BOOST_TEST(m.error().step == "open /dev/vfio/vfio");
    BOOST_TEST(ak::hull::to_string(m.error()).find("No such file") != std::string::npos);
}
