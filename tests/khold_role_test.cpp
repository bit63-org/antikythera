// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kythira .kiro/specs/khold-block-service/ task 17: the khold role's end of
// helm's sideband. Layouts must decode, name this server and verify under a
// controller key before the node sees them (Requirement 16.3); a restarted
// node gets them all again; the node's reports come out as encoded
// proto::Reports in order, each once; capacity reports merge the node's
// placement with the self-test's measurements (Requirement 12.1).

#define BOOST_TEST_MODULE khold_role_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <ostream>
#include <span>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "khold/khold_role.hpp"
#include "proto/report.hpp"
#include "proto/volume_layout.hpp"

namespace ak::helm::oar {
auto operator<<(std::ostream& os, Status s) -> std::ostream& {
    return os << static_cast<int>(s);
}
auto operator<<(std::ostream& os, Role r) -> std::ostream& {
    return os << static_cast<int>(r);
}
auto operator<<(std::ostream& os, HealthState h) -> std::ostream& {
    return os << static_cast<int>(h);
}
}  // namespace ak::helm::oar

namespace {

namespace proto = ak::proto;
namespace oar = ak::helm::oar;
using namespace ak::khold;
using Bytes = std::vector<std::byte>;
using namespace std::chrono_literals;

constexpr std::uint64_t me = 0x21;
constexpr std::uint16_t good_key = 3;
constexpr auto good_sig = std::byte{0xA5};
constexpr std::uint64_t gib = std::uint64_t{1} << 30U;

class FakeNode final : public KholdNode {
public:
    struct Applied {
        std::uint64_t volume{0};
        std::uint64_t epoch{0};
        Bytes frame;
    };
    std::vector<Applied> applied;
    std::vector<proto::ReportBody> pending;
    std::uint64_t gen{1};
    bool up{true};
    bool refuse{false};

    auto apply_layout(std::uint64_t volume_id, std::uint64_t epoch,
                      std::span<const std::byte> frame) -> bool override {
        if (refuse) {
            return false;
        }
        applied.push_back(
            {.volume = volume_id, .epoch = epoch, .frame = {frame.begin(), frame.end()}});
        return true;
    }
    auto take_reports() -> std::vector<proto::ReportBody> override {
        return std::exchange(pending, {});
    }
    [[nodiscard]] auto generation() const -> std::uint64_t override { return gen; }
    [[nodiscard]] auto running() const -> bool override { return up; }
};

auto member(std::uint64_t server) -> proto::LayoutMember {
    proto::LayoutMember m{.server_id = server, .endpoint = {}, .port = 7400};
    m.endpoint[0] = std::byte{0xFD};
    m.endpoint[15] = std::byte{static_cast<std::uint8_t>(server)};
    return m;
}

// A layout for `server` with one group of three data members starting at
// `first`.
auto layout(std::uint64_t volume, std::uint64_t epoch, std::uint64_t first = me,
            std::uint64_t server = me) -> proto::VolumeLayout {
    proto::VolumeLayout l;
    l.key_id = good_key;
    l.server_id = server;
    l.volume_id = volume;
    l.epoch = epoch;
    l.lineage_id = 0x2EE;
    l.capacity_blocks = 1024;
    l.qos = {.iops = 100, .mib_per_s = 10, .burst_iops = 100, .burst_mib = 10};
    l.timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900};
    l.groups = {
        {.group_id = 0x5001, .members = {member(first), member(first + 1), member(first + 2)}}};
    l.signature.fill(good_sig);
    return l;
}

auto frame_of(const proto::VolumeLayout& l) -> Bytes {
    auto b = proto::encode_volume_layout(l);
    BOOST_TEST_REQUIRE(b.has_value());
    return *b;
}

auto drive(std::uint8_t n, std::uint64_t capacity) -> proto::DriveCapacity {
    return {.drive = n,
            .state = proto::DriveState::ok,
            .capacity_bytes = capacity,
            .allocated_bytes = 0,
            .reserved_bytes = 0,
            .read_iops = 0,
            .write_iops = 0,
            .read_mib_per_s = 0,
            .write_mib_per_s = 0,
            .replicas = 0};
}

// Takes the next whole report (all reports here fit one chunk),
// acknowledging the one before.
auto next_report(KholdRole& role, std::uint64_t& ack) -> std::optional<proto::Report> {
    auto chunk = role.hold_reports({.ack = ack, .offset = 0});
    BOOST_TEST_REQUIRE(chunk.has_value());
    if (chunk->total == 0) {
        return std::nullopt;
    }
    BOOST_TEST_REQUIRE(chunk->chunk.size() == chunk->total);
    ack = chunk->report_seq;
    auto r = proto::decode_report(chunk->chunk);
    BOOST_TEST_REQUIRE(r.has_value());
    return *r;
}

struct Rig {
    // A stand-in for Ed25519: verifies when every signature byte is good_sig
    // and the key is known.
    FrameVerifier verify = [](std::span<const std::byte> /*msg*/,
                              std::span<const std::byte, 64> sig, std::uint16_t key) {
        return key == good_key &&
               std::ranges::all_of(sig, [](std::byte b) { return b == good_sig; });
    };
    FakeNode node;
    std::atomic<int> tests_run{0};
    proto::Capacity measured{.slot = 0,
                             .link_mbps = 25000,
                             .drives = {{.drive = 0,
                                         .state = proto::DriveState::ok,
                                         .capacity_bytes = 4 * gib,
                                         .allocated_bytes = 0,
                                         .reserved_bytes = 0,
                                         .read_iops = 90000,
                                         .write_iops = 40000,
                                         .read_mib_per_s = 3000,
                                         .write_mib_per_s = 2000,
                                         .replicas = 0}}};
    SelfTestFn self_test = [this] {
        ++tests_run;
        return measured;
    };
    std::optional<KholdRole> role;
    std::uint64_t ack{0};

    explicit Rig(bool with_test = true) {
        role.emplace(node, me, verify, 500, with_test ? self_test : SelfTestFn{});
    }

    // Pumps until the self-test the role started has finished.
    auto settle() -> void {
        for (int i = 0; i < 1000 && role->self_test_running(); ++i) {
            role->pump();
            std::this_thread::sleep_for(1ms);
        }
        role->pump();
    }
    auto drain() -> std::vector<proto::ReportBody> {
        std::vector<proto::ReportBody> out;
        while (auto r = next_report(*role, ack)) {
            out.push_back(std::move(r->body));
        }
        return out;
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(khold_role)

BOOST_AUTO_TEST_CASE(inventory_names_a_khold_role_without_functions) {
    Rig r{false};
    const auto inv = r.role->function_inventory();
    BOOST_REQUIRE(inv.has_value());
    BOOST_TEST((inv->role == oar::Role::khold));
    BOOST_TEST(inv->functions.empty());
    BOOST_TEST((r.role->prepare_function({}) == oar::Status::unknown_function));
    BOOST_TEST((r.role->map_update({}) == oar::Status::unsupported));
    BOOST_TEST((r.role->replica_config({}) == oar::Status::unsupported));  // hold's, not khold's
    BOOST_TEST((r.role->cert_request().error() == oar::Status::unsupported));  // no enrollment set
    BOOST_TEST((r.role->self_test() == oar::Status::unsupported));             // no self-test set
}

BOOST_AUTO_TEST_CASE(layouts_reach_the_node_only_when_they_verify_and_name_this_server) {
    Rig r{false};
    const auto f2 = frame_of(layout(0x200, 2));
    BOOST_TEST((r.role->volume_layout(f2) == oar::Status::ok));
    BOOST_REQUIRE(r.node.applied.size() == 1U);
    BOOST_TEST(r.node.applied[0].volume == 0x200U);
    BOOST_TEST(r.node.applied[0].epoch == 2U);
    BOOST_TEST((r.node.applied[0].frame == f2));  // byte for byte

    // Not decodable, for another server, under a bad key or signature.
    BOOST_TEST((r.role->volume_layout(std::span{f2}.first(40)) == oar::Status::bad_request));
    BOOST_TEST(
        (r.role->volume_layout(frame_of(layout(0x201, 1, me, me + 1))) == oar::Status::failed));
    auto bad_key = layout(0x202, 1);
    bad_key.key_id = good_key + 1;
    BOOST_TEST((r.role->volume_layout(frame_of(bad_key)) == oar::Status::failed));
    auto bad_sig = layout(0x203, 1);
    bad_sig.signature[7] = std::byte{0};
    BOOST_TEST((r.role->volume_layout(frame_of(bad_sig)) == oar::Status::failed));

    // Older is refused (fencing); the same again is helm's replay: ok, and
    // the node is not bothered.
    BOOST_TEST((r.role->volume_layout(frame_of(layout(0x200, 1))) == oar::Status::failed));
    BOOST_TEST((r.role->volume_layout(f2) == oar::Status::ok));
    BOOST_TEST(r.node.applied.size() == 1U);
    BOOST_TEST(r.role->stats().refused == 5U);
    BOOST_TEST(r.role->stats().layouts == 1U);
    BOOST_TEST(r.role->kept_layouts() == 1U);

    // A node that will not take one: refused, not kept.
    r.node.refuse = true;
    BOOST_TEST((r.role->volume_layout(frame_of(layout(0x204, 1))) == oar::Status::failed));
    BOOST_TEST(r.role->kept_layouts() == 1U);
}

BOOST_AUTO_TEST_CASE(a_layout_that_moves_the_volume_away_is_delivered_then_forgotten) {
    Rig r{false};
    BOOST_TEST((r.role->volume_layout(frame_of(layout(0x200, 2))) == oar::Status::ok));
    const auto away = frame_of(layout(0x200, 3, me + 1));  // members me+1..me+3
    BOOST_TEST((r.role->volume_layout(away) == oar::Status::ok));
    BOOST_REQUIRE(r.node.applied.size() == 2U);
    BOOST_TEST((r.node.applied[1].frame == away));
    BOOST_TEST(r.role->kept_layouts() == 0U);
    BOOST_TEST(r.role->stats().layouts_dropped == 1U);
}

BOOST_AUTO_TEST_CASE(a_restarted_node_gets_every_kept_layout_again) {
    Rig r{false};
    const auto a = frame_of(layout(0x300, 4));
    const auto b = frame_of(layout(0x200, 7));
    BOOST_TEST((r.role->volume_layout(a) == oar::Status::ok));
    BOOST_TEST((r.role->volume_layout(b) == oar::Status::ok));
    r.role->pump();
    BOOST_TEST(r.node.applied.size() == 2U);  // same generation: nothing replayed

    // Down: nothing to replay to yet.
    r.node.up = false;
    r.node.gen = 2;
    r.role->pump();
    BOOST_TEST(r.node.applied.size() == 2U);
    const auto health = r.role->health();
    BOOST_REQUIRE(health.has_value());
    BOOST_TEST((health->state == oar::HealthState::degraded));
    BOOST_TEST(health->fault_code == fault_node_down);

    r.node.up = true;
    r.role->pump();
    BOOST_REQUIRE(r.node.applied.size() == 4U);
    BOOST_TEST(r.node.applied[2].volume == 0x200U);  // in volume order
    BOOST_TEST((r.node.applied[2].frame == b));
    BOOST_TEST((r.node.applied[3].frame == a));
    BOOST_TEST(r.role->stats().replays == 2U);
    r.role->pump();
    BOOST_TEST(r.node.applied.size() == 4U);  // once per restart
    BOOST_TEST((r.role->health()->state == oar::HealthState::ok));
}

BOOST_AUTO_TEST_CASE(node_reports_are_relayed_in_order_and_once) {
    Rig r{false};
    const proto::GroupFault fault{.volume_id = 0x200,
                                  .group_id = 0x5001,
                                  .epoch = 2,
                                  .term = 3,
                                  .suspect = me + 1,
                                  .kind = proto::GroupFaultKind::media_error,
                                  .slot = 0,
                                  .drive = 0};
    const proto::GroupStatus status{.slot = 0, .entries = {}};
    r.node.pending = {
        fault, proto::DemotionConfirmed{.volume_id = 1, .epoch = 1, .last_seq = 1, .slot = 0},
        status};
    r.role->pump();
    const auto got = r.drain();
    BOOST_REQUIRE(got.size() == 2U);
    BOOST_TEST((std::get<proto::GroupFault>(got[0]) == fault));
    BOOST_TEST((std::get<proto::GroupStatus>(got[1]) == status));
    BOOST_TEST(r.role->stats().reports_dropped == 1U);  // a hold kind: not the node's to send
    BOOST_TEST(r.drain().empty());
}

// Requirement 12.1: a self-test at start (enrollment) and on demand, its
// result merged with what the node placed on each drive.
BOOST_AUTO_TEST_CASE(capacity_merges_the_self_test_with_the_node) {
    Rig r;
    r.settle();
    BOOST_TEST(r.tests_run.load() == 1);  // at start
    auto got = r.drain();
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST((std::get<proto::Capacity>(got[0]) == r.measured));

    // The node's figures for what it holds, and a drive the test does not
    // know (reported as the node has it).
    auto from_node = drive(0, 3 * gib);
    from_node.allocated_bytes = 2 * gib;
    from_node.reserved_bytes = gib / 2;
    from_node.replicas = 12;
    from_node.state = proto::DriveState::warning;
    auto other = drive(1, gib);
    r.node.pending = {proto::Capacity{.slot = 0, .link_mbps = 1000, .drives = {from_node, other}}};
    r.role->pump();
    got = r.drain();
    BOOST_REQUIRE(got.size() == 1U);
    const auto merged = std::get<proto::Capacity>(got[0]);
    BOOST_TEST(merged.link_mbps == 25000U);  // measured, not the node's guess
    BOOST_REQUIRE(merged.drives.size() == 2U);
    auto want = r.measured.drives[0];
    want.allocated_bytes = 2 * gib;
    want.reserved_bytes = gib / 2;
    want.replicas = 12;
    want.state = proto::DriveState::warning;
    BOOST_TEST((merged.drives[0] == want));
    BOOST_TEST((merged.drives[1] == other));

    // The same picture again is not reported again.
    r.node.pending = {proto::Capacity{.slot = 0, .link_mbps = 1000, .drives = {from_node, other}}};
    r.role->pump();
    BOOST_TEST(r.drain().empty());

    // On demand: the drive has failed since.
    r.measured.drives[0].state = proto::DriveState::failed;
    r.measured.drives[0].read_iops = 0;
    BOOST_TEST((r.role->self_test() == oar::Status::ok));
    r.settle();
    BOOST_TEST(r.tests_run.load() == 2);
    got = r.drain();
    BOOST_REQUIRE(got.size() == 1U);
    const auto after = std::get<proto::Capacity>(got[0]);
    BOOST_TEST((after.drives[0].state == proto::DriveState::failed));
    BOOST_TEST(after.drives[0].read_iops == 0U);
    BOOST_TEST(after.drives[0].allocated_bytes == 2 * gib);
    BOOST_TEST(r.role->health()->fault_code == fault_drive_failed);
    BOOST_TEST(r.role->stats().self_tests == 2U);
}

BOOST_AUTO_TEST_CASE(allocation_never_exceeds_the_measured_capacity) {
    Rig r;
    r.settle();
    (void)r.drain();
    auto big = drive(0, 8 * gib);
    big.allocated_bytes = 6 * gib;  // more than the 4 GiB the test measured
    r.node.pending = {proto::Capacity{.slot = 0, .link_mbps = 0, .drives = {big}}};
    r.role->pump();
    const auto got = r.drain();
    BOOST_REQUIRE(got.size() == 1U);
    const auto c = std::get<proto::Capacity>(got[0]);
    BOOST_TEST(c.drives[0].capacity_bytes == 4 * gib);
    BOOST_TEST(c.drives[0].allocated_bytes == 4 * gib);
}

BOOST_AUTO_TEST_CASE(a_self_test_requested_while_one_runs_starts_nothing) {
    std::atomic<bool> release{false};
    FakeNode node;
    std::atomic<int> runs{0};
    {
        KholdRole role{node, me,
                       [](std::span<const std::byte>, std::span<const std::byte, 64>,
                          std::uint16_t) { return true; },
                       1,
                       [&] {
                           ++runs;
                           while (!release.load()) {
                               std::this_thread::sleep_for(1ms);
                           }
                           return proto::Capacity{};
                       }};
        BOOST_TEST(role.self_test_running());
        BOOST_TEST((role.self_test() == oar::Status::ok));
        BOOST_TEST((role.self_test() == oar::Status::ok));
        release = true;
    }  // the destructor waits for the test
    BOOST_TEST(runs.load() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
