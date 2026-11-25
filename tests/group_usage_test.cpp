// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirement 11 (task 13): helm keeps and
// fans out the controller's GroupPolicy frames and reports the network
// roles' multicast meters as group_usage reports; oar-net task 14.2: it
// fans out GroupMembers frames the same way and reports each role's
// snooped joins as group_membership reports when they change.

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
#include "proto/group_members.hpp"
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
    auto deliver_key(oar::FunctionNumber /*fn*/, helm::VolumeId /*volume*/, helm::ScopedKey /*key*/,
                     std::optional<helm::ScopedKey> /*image_key*/)
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
    std::vector<std::vector<std::byte>> members;
    auto group_members(std::span<const std::byte> frame)
        -> std::expected<void, LinkError> override {
        if (fail_policy) {
            return std::unexpected(LinkError{.code = helm::LinkErrc::timed_out});
        }
        members.emplace_back(frame.begin(), frame.end());
        return {};
    }
    // Snooping, off unless a test turns it on (then the role answers like
    // NetRole: unchanged when helm already has `generation`).
    bool snoops = false;
    std::uint32_t generation = 0;
    std::vector<oar::MembershipEntry> joins;
    std::vector<std::optional<std::uint32_t>> asked;  // `since` of every read
    auto group_membership(std::optional<std::uint32_t> since)
        -> std::expected<std::optional<helm::OarLink::Memberships>, LinkError> override {
        asked.push_back(since);
        if (!snoops || fail_read) {
            return std::unexpected(LinkError{.code = helm::LinkErrc::timed_out});
        }
        if (since == generation) {
            return std::nullopt;
        }
        return helm::OarLink::Memberships{.generation = generation, .entries = joins};
    }
};

struct Reports final : helm::ReportSink {
    std::vector<proto::GroupUsage> sent;
    std::vector<proto::GroupMembership> joins;
    auto report(proto::ReportBody body) -> void override {
        if (auto* m = std::get_if<proto::GroupMembership>(&body)) {
            joins.push_back(std::move(*m));
            return;
        }
        auto* usage = std::get_if<proto::GroupUsage>(&body);
        BOOST_REQUIRE(usage != nullptr);
        sent.push_back(std::move(*usage));
    }
};

struct Fixture {
    helm::GroupUsageConfig::Clock::time_point t{};
    Reports reports;
    helm::GroupUsageReporter reporter{
        {.interval = 60s, .membership_interval = 1s, .clock = [this] { return t; }}, reports};
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

auto members(std::uint32_t vni, std::uint64_t version) -> proto::GroupMembers {
    return {.server_id = 1, .key_id = 1, .vni = vni, .members_version = version};
}

auto frame_of(const proto::GroupMembers& m) -> std::vector<std::byte> {
    auto b = proto::encode_group_members(m);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto join(oar::NicId nic, bool ipv6, std::uint8_t last) -> oar::MembershipEntry {
    oar::MembershipEntry e{.nic_id = nic, .vni = 5, .ipv6 = ipv6, .group = {}};
    e.group[0] = ipv6 ? std::byte{0xFF} : std::byte{239};
    e.group[ipv6 ? 15 : 3] = std::byte{last};
    return e;
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

// GroupMembers frames are kept and fanned out like policies, after them
// when a role is added.
BOOST_FIXTURE_TEST_CASE(member_lists_fan_out_and_replay, Fixture) {
    reporter.add_slot(1, net1);
    const auto v3 = frame_of(members(5, 3));
    reporter.on_group_members(members(5, 3), v3);
    BOOST_REQUIRE(net1.members.size() == 1U);
    BOOST_TEST((net1.members[0] == v3));
    reporter.on_group_members(members(5, 3), v3);
    reporter.on_group_members(members(5, 2), frame_of(members(5, 2)));
    BOOST_TEST(net1.members.size() == 1U);
    BOOST_TEST(reporter.stats().members_stale == 2U);

    reporter.on_group_policy(policy(5, 1), frame_of(policy(5, 1)));
    reporter.add_slot(2, net2);
    BOOST_TEST(net2.policies.size() == 1U);
    BOOST_REQUIRE(net2.members.size() == 1U);
    BOOST_TEST((net2.members[0] == v3));
    BOOST_TEST(reporter.stats().members_kept == 1U);
    BOOST_TEST(reporter.stats().members_forwarded == 2U);

    net1.fail_policy = true;
    reporter.on_group_members(members(5, 4), frame_of(members(5, 4)));
    BOOST_TEST(reporter.stats().members_forward_failures == 1U);
    BOOST_TEST(net2.members.size() == 2U);
}

// The first read after add_slot is reported even when empty; afterwards
// only a change is, read with the generation last reported.
BOOST_FIXTURE_TEST_CASE(joins_are_reported_when_they_change, Fixture) {
    net1.snoops = true;
    reporter.add_slot(1, net1);
    reporter.poll();
    BOOST_REQUIRE(reports.joins.size() == 1U);
    BOOST_TEST(reports.joins[0].slot == 1U);
    BOOST_TEST(reports.joins[0].entries.empty());
    BOOST_TEST((net1.asked.back() == std::nullopt));

    t += 500ms;
    net1.generation = 1;
    net1.joins = {join(10, false, 1), join(10, true, 1), join(11, false, 2)};
    reporter.poll();  // not due
    BOOST_TEST(net1.asked.size() == 1U);

    t += 500ms;
    reporter.poll();
    BOOST_TEST((net1.asked.back() == std::optional<std::uint32_t>{0}));
    BOOST_REQUIRE(reports.joins.size() == 2U);
    const auto& e = reports.joins[1].entries;
    BOOST_REQUIRE(e.size() == 3U);
    BOOST_TEST(e[0].nic_id == 10U);
    BOOST_TEST((e[0].family == proto::RouteFamily::ipv4));
    BOOST_TEST((e[0].group[0] == std::byte{239}));
    BOOST_TEST((e[1].family == proto::RouteFamily::ipv6));
    BOOST_TEST((e[1].group[15] == std::byte{1}));
    BOOST_TEST(e[2].vni == 5U);
    auto b = proto::encode_report({.server_id = 1, .report_seq = 1, .body = reports.joins[1]});
    BOOST_TEST(b.has_value());  // the order the report requires

    t += 1s;
    reporter.poll();  // unchanged
    BOOST_TEST((net1.asked.back() == std::optional<std::uint32_t>{1}));
    BOOST_TEST(reports.joins.size() == 2U);
    BOOST_TEST(reporter.stats().membership_reads == 3U);
    BOOST_TEST(reporter.stats().membership_reports == 2U);
    // The meters' own interval is untouched by membership polls.
    BOOST_TEST(net1.reads == 1);
}

// A failed read is retried next interval with the same generation.
BOOST_FIXTURE_TEST_CASE(failed_membership_reads_are_retried, Fixture) {
    net1.snoops = true;
    net1.fail_read = true;
    reporter.add_slot(1, net1);
    reporter.poll();
    BOOST_TEST(reporter.stats().membership_read_failures == 1U);
    BOOST_TEST(reports.joins.empty());
    net1.fail_read = false;
    t += 1s;
    reporter.poll();
    BOOST_TEST((net1.asked.back() == std::nullopt));
    BOOST_TEST(reports.joins.size() == 1U);
}

// A role that had listed joins and goes away is reported empty; one that
// listed none is not reported again. Re-added, it is read afresh.
BOOST_FIXTURE_TEST_CASE(removed_roles_report_no_joins, Fixture) {
    net1.snoops = true;
    net2.snoops = true;
    net1.joins = {join(10, false, 1)};
    net1.generation = 4;
    reporter.add_slot(1, net1);
    reporter.add_slot(2, net2);
    reporter.poll();
    BOOST_REQUIRE(reports.joins.size() == 2U);

    reporter.remove_slot(2);
    BOOST_TEST(reports.joins.size() == 2U);
    reporter.remove_slot(1);
    BOOST_REQUIRE(reports.joins.size() == 3U);
    BOOST_TEST(reports.joins[2].slot == 1U);
    BOOST_TEST(reports.joins[2].entries.empty());
    reporter.remove_slot(1);  // already gone
    BOOST_TEST(reports.joins.size() == 3U);

    reporter.add_slot(1, net1);
    t += 1s;
    reporter.poll();
    BOOST_TEST((net1.asked.back() == std::nullopt));
    BOOST_REQUIRE(reports.joins.size() == 4U);
    BOOST_TEST(reports.joins[3].entries.size() == 1U);
}

BOOST_AUTO_TEST_SUITE_END()
