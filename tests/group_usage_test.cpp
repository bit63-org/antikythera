// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirement 11 (task 13): helm keeps and
// fans out the controller's GroupPolicy frames and reports the network
// roles' multicast meters as group_usage reports.

#define BOOST_TEST_MODULE group_usage_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <variant>
#include <vector>

#include "helm/group_usage.hpp"
#include "proto/group_policy.hpp"
#include "proto/report.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace oar = ak::helm::oar;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::LinkError;
using namespace std::chrono_literals;

namespace {

struct FakeNet final : helm::OarPort {
    std::vector<std::vector<std::byte>> policies;
    std::vector<oar::UsageEntry> meters;
    bool fail_policy = false;
    bool fail_read = false;
    int reads = 0;

    auto prepare_function(const oar::PrepareFunction& /*r*/)
        -> std::expected<void, LinkError> override {
        return {};
    }
    auto clean_function(const oar::CleanFunction& /*r*/)
        -> std::expected<void, LinkError> override {
        return {};
    }
    auto deliver_key(oar::FunctionNumber /*fn*/, helm::VolumeId /*volume*/, helm::ScopedKey /*key*/)
        -> std::expected<void, LinkError> override {
        return {};
    }
    auto drop_key(const oar::DropKey& /*r*/) -> std::expected<void, LinkError> override {
        return {};
    }
    auto create_volume(const oar::CreateVolume& /*r*/) -> std::expected<void, LinkError> override {
        return {};
    }
    auto delete_volume(const oar::DeleteVolume& /*r*/) -> std::expected<void, LinkError> override {
        return {};
    }
    auto rewrap_volume(const oar::RewrapVolume& /*r*/) -> std::expected<void, LinkError> override {
        return {};
    }
    auto group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError> override {
        if (fail_policy) {
            return std::unexpected(LinkError{.code = helm::LinkErrc::timed_out});
        }
        policies.emplace_back(frame.begin(), frame.end());
        return {};
    }
    auto group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> override {
        ++reads;
        if (fail_read) {
            return std::unexpected(LinkError{.code = helm::LinkErrc::timed_out});
        }
        // Like the role's pager: a detached reading is handed over once.
        auto out = meters;
        std::erase_if(meters, [](const oar::UsageEntry& e) { return e.detached; });
        return out;
    }
};

struct Reports final : helm::ReportSink {
    std::vector<proto::GroupUsage> sent;
    auto report(proto::ReportBody body) -> void override {
        auto* usage = std::get_if<proto::GroupUsage>(&body);
        BOOST_REQUIRE(usage != nullptr);
        sent.push_back(std::move(*usage));
    }
};

struct Fixture {
    helm::GroupUsageConfig::Clock::time_point t{};
    Reports reports;
    helm::GroupUsageReporter reporter{{.interval = 60s, .clock = [this] { return t; }}, reports};
    FakeNet net1;
    FakeNet net2;
};

auto policy(std::uint32_t vni, std::uint64_t version) -> proto::GroupPolicy {
    return {.server_id = 1,
            .key_id = 1,
            .vni = vni,
            .mode = proto::GroupMode::drop,
            .policy_version = version};
}

auto frame_of(const proto::GroupPolicy& p) -> std::vector<std::byte> {
    auto b = proto::encode_group_policy(p);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto meter(oar::NicId nic, std::uint64_t attachment, std::uint64_t frames) -> oar::UsageEntry {
    return {.nic_id = nic,
            .vni = 5,
            .attachment = attachment,
            .frames = frames,
            .bytes = frames * 100,
            .replicas_remote = frames * 2,
            .replica_bytes_remote = frames * 200};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(group_usage, *boost::unit_test::timeout(unit_timeout_seconds))

// The newest frame per VNI goes, unmodified, to every role; a role added
// later gets every kept frame; older versions are ignored.
BOOST_FIXTURE_TEST_CASE(policies_fan_out_and_replay, Fixture) {
    reporter.add_slot(1, net1);
    const auto v2 = frame_of(policy(5, 2));
    reporter.on_group_policy(policy(5, 2), v2);
    BOOST_REQUIRE(net1.policies.size() == 1U);
    BOOST_TEST((net1.policies[0] == v2));

    reporter.on_group_policy(policy(5, 2), v2);  // same version
    reporter.on_group_policy(policy(5, 1), frame_of(policy(5, 1)));
    BOOST_TEST(net1.policies.size() == 1U);
    BOOST_TEST(reporter.stats().policies_stale == 2U);

    const auto other = frame_of(policy(9, 1));
    reporter.on_group_policy(policy(9, 1), other);
    reporter.add_slot(2, net2);
    BOOST_REQUIRE(net2.policies.size() == 2U);
    BOOST_TEST((net2.policies[0] == v2));
    BOOST_TEST((net2.policies[1] == other));
    BOOST_TEST(reporter.stats().policies_kept == 2U);
    BOOST_TEST(reporter.stats().policies_forwarded == 4U);
}

BOOST_FIXTURE_TEST_CASE(forward_failures_are_counted, Fixture) {
    net1.fail_policy = true;
    reporter.add_slot(1, net1);
    reporter.on_group_policy(policy(5, 1), frame_of(policy(5, 1)));
    BOOST_TEST(reporter.stats().policy_forward_failures == 1U);
    BOOST_TEST(reporter.stats().policies_forwarded == 0U);
}

// Only moved counters are reported, in (slot, nic, attachment) order, and
// reads happen once per interval.
BOOST_FIXTURE_TEST_CASE(reports_what_moved_each_interval, Fixture) {
    reporter.add_slot(2, net2);
    reporter.add_slot(1, net1);
    net1.meters = {meter(10, 1, 5), meter(11, 1, 0)};
    net2.meters = {meter(3, 1, 7)};
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 1U);
    const auto& first = reports.sent[0].entries;
    BOOST_REQUIRE(first.size() == 3U);
    BOOST_TEST(first[0].slot == 1U);
    BOOST_TEST(first[0].nic_id == 10U);
    BOOST_TEST(first[0].replica_bytes_remote == 1000U);
    BOOST_TEST(first[1].nic_id == 11U);
    BOOST_TEST(first[2].slot == 2U);
    BOOST_TEST(first[2].nic_id == 3U);

    t += 30s;
    net1.meters[0].frames = 6;
    reporter.poll();  // not due
    BOOST_TEST(reports.sent.size() == 1U);
    BOOST_TEST(net1.reads == 1);

    t += 30s;
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 2U);
    BOOST_REQUIRE(reports.sent[1].entries.size() == 1U);
    BOOST_TEST(reports.sent[1].entries[0].nic_id == 10U);
    BOOST_TEST(reports.sent[1].entries[0].frames == 6U);

    t += 60s;
    reporter.poll();  // nothing moved: no report
    BOOST_TEST(reports.sent.size() == 2U);
    BOOST_TEST(reporter.stats().reads == 6U);
}

// A detach is read on the next poll, its final reading always reported
// (even unchanged), and the series then forgotten.
BOOST_FIXTURE_TEST_CASE(detached_nics_report_their_final_reading_now, Fixture) {
    reporter.add_slot(1, net1);
    net1.meters = {meter(10, 1, 5)};
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 1U);

    t += 1s;
    net1.meters[0].detached = true;
    reporter.poll();  // not due, no detach signalled
    BOOST_TEST(reports.sent.size() == 1U);
    reporter.nic_detached();
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 2U);
    BOOST_REQUIRE(reports.sent[1].entries.size() == 1U);
    BOOST_TEST(reports.sent[1].entries[0].detached);
    BOOST_TEST(reports.sent[1].entries[0].frames == 5U);

    // The NIC comes back as a new attachment: a new series.
    t += 60s;
    net1.meters = {meter(10, 2, 0)};
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 3U);
    BOOST_TEST(reports.sent[2].entries[0].attachment == 2U);
    BOOST_TEST(!reports.sent[2].entries[0].detached);
}

BOOST_FIXTURE_TEST_CASE(read_failures_skip_the_role, Fixture) {
    reporter.add_slot(1, net1);
    reporter.add_slot(2, net2);
    net1.fail_read = true;
    net2.meters = {meter(3, 1, 1)};
    reporter.poll();
    BOOST_TEST(reporter.stats().read_failures == 1U);
    BOOST_REQUIRE(reports.sent.size() == 1U);
    BOOST_TEST(reports.sent[0].entries.size() == 1U);
}

// A removed slot is no longer read; re-added, its series start over.
BOOST_FIXTURE_TEST_CASE(removed_slots_are_forgotten, Fixture) {
    reporter.add_slot(1, net1);
    net1.meters = {meter(10, 1, 5)};
    reporter.poll();
    reporter.remove_slot(1);
    t += 60s;
    reporter.poll();
    BOOST_TEST(net1.reads == 1);
    reporter.add_slot(1, net1);
    t += 60s;
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 2U);
    BOOST_TEST(reports.sent[1].entries[0].frames == 5U);
}

// More changed entries than one report holds are split, in order.
BOOST_FIXTURE_TEST_CASE(large_reads_split_into_reports, Fixture) {
    reporter.add_slot(1, net1);
    reporter.add_slot(2, net2);
    for (std::uint64_t n = 1; n <= proto::max_group_usage_entries; ++n) {
        net1.meters.push_back(meter(n, 1, n));
    }
    net2.meters = {meter(1, 1, 1), meter(2, 1, 2)};
    reporter.poll();
    BOOST_REQUIRE(reports.sent.size() == 2U);
    BOOST_TEST(reports.sent[0].entries.size() == proto::max_group_usage_entries);
    BOOST_TEST(reports.sent[1].entries.size() == 2U);
    BOOST_TEST(reports.sent[1].entries[0].slot == 2U);
    BOOST_TEST(reporter.stats().entries_reported == proto::max_group_usage_entries + 2U);
    for (const auto& r : reports.sent) {
        auto b = proto::encode_report({.server_id = 1, .report_seq = 1, .body = r});
        BOOST_TEST(b.has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()
