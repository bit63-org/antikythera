// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 12: the hold role's end of helm's
// sideband. Configs and ops must decode, name this server and verify
// under a controller key before the server sees them (Requirement 13.1);
// lease grants reach the server; the server's reports come out as encoded
// proto::Reports in order, each once.

#define BOOST_TEST_MODULE hold_role_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ostream>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include "hold/server/hold_role.hpp"
#include "hold/server/server.hpp"
#include "hold/store/file_layer.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "proto/volume_op.hpp"

namespace ak::helm::oar {
auto operator<<(std::ostream& os, Status s) -> std::ostream& {
    return os << static_cast<int>(s);
}
auto operator<<(std::ostream& os, Role r) -> std::ostream& {
    return os << static_cast<int>(r);
}
}  // namespace ak::helm::oar

namespace {

namespace proto = ak::proto;
namespace oar = ak::helm::oar;
using namespace ak::hold;
using Bytes = std::vector<std::byte>;
using namespace std::chrono_literals;

constexpr std::uint64_t me = 1;
constexpr std::uint64_t vol = 7;
constexpr std::uint16_t good_key = 3;
constexpr auto good_sig = std::byte{0xA5};

class NullSink final : public SessionSink {
public:
    auto send(SessionId /*session*/, Bytes /*frame*/) -> void override {}
};

auto config(std::uint64_t epoch, std::uint64_t server = me) -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = good_key;
    c.server_id = server;
    c.volume_id = vol;
    c.epoch = epoch;
    c.lineage_id = 9;
    c.capacity_blocks = 64;
    c.block_size = 512;
    c.qos = {.iops = 1000, .mib_per_s = 100, .burst_iops = 1000, .burst_mib = 100};
    c.lease_ms = 4000;
    proto::ReplicaMember m;
    m.server_id = me;
    m.endpoint[15] = std::byte{1};
    m.port = 4430;
    m.role = proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    c.signature.fill(good_sig);
    return c;
}

auto frame_of(const proto::ReplicaConfig& c) -> Bytes {
    auto b = proto::encode_replica_config(c);
    BOOST_TEST_REQUIRE(b.has_value());
    return *b;
}

auto op(std::uint64_t server = me,
        proto::VolumeOpArgs args = proto::DeleteReplica{.replica_gen = 1}) -> proto::VolumeOp {
    proto::VolumeOp o{.key_id = good_key,
                      .server_id = server,
                      .volume_id = vol,
                      .epoch = 1,
                      .op_id = 44,
                      .args = std::move(args),
                      .signature = {}};
    o.signature.fill(good_sig);
    return o;
}

auto frame_of(const proto::VolumeOp& o) -> Bytes {
    auto b = proto::encode_volume_op(o);
    BOOST_TEST_REQUIRE(b.has_value());
    return *b;
}

// Takes the next whole report (all reports here fit one chunk), acknowledging
// the one before.
auto next_report(HoldRole& role, std::uint64_t& ack) -> std::optional<proto::Report> {
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
    // A stand-in for Ed25519: verifies when the message is the frame less
    // its signature, every signature byte is good_sig and the key is known.
    FrameVerifier verify = [this](std::span<const std::byte> msg,
                                  std::span<const std::byte, 64> sig, std::uint16_t key) {
        ++verified;
        last_message = msg.size();
        return key == good_key &&
               std::ranges::all_of(sig, [](std::byte b) { return b == good_sig; });
    };
    Clock::time_point now{std::chrono::seconds{1000}};
    store::MemFiles files;
    NullSink sink;
    HoldServer server{files, {.server_id = me, .data_dir = "/d"}, sink};
    HoldRole role{server, me, verify, 500, [this] { return now; }};
    int verified{0};
    std::size_t last_message{0};
};

BOOST_AUTO_TEST_CASE(inventory_names_a_hold_role_without_functions) {
    Rig r;
    const auto inv = r.role.function_inventory();
    BOOST_REQUIRE(inv.has_value());
    BOOST_TEST(inv->role == oar::Role::hold);
    BOOST_TEST(inv->functions.empty());
    BOOST_TEST(r.role.prepare_function({}) == oar::Status::unknown_function);
    BOOST_TEST(r.role.map_update({}) == oar::Status::unsupported);
    r.now += 90s;
    BOOST_TEST(r.role.health()->uptime_seconds == 90U);
}

BOOST_AUTO_TEST_CASE(a_verified_config_is_applied) {
    Rig r;
    const auto f = frame_of(config(1));
    BOOST_TEST(r.role.replica_config(f) == oar::Status::ok);
    BOOST_TEST(r.last_message == f.size() - 64);  // the signed bytes, not the frame
    BOOST_TEST((r.server.epoch(vol) == std::optional<std::uint64_t>{1}));
    BOOST_TEST(r.role.stats().configs == 1U);
}

BOOST_AUTO_TEST_CASE(configs_that_fail_a_check_never_reach_the_server) {
    Rig r;
    auto bad_sig = config(1);
    bad_sig.signature[63] = std::byte{0};
    BOOST_TEST(r.role.replica_config(frame_of(bad_sig)) == oar::Status::failed);
    auto unknown_key = config(1);
    unknown_key.key_id = good_key + 1;
    BOOST_TEST(r.role.replica_config(frame_of(unknown_key)) == oar::Status::failed);
    // Signed for another server: refused before the signature is checked.
    const int before = r.verified;
    BOOST_TEST(r.role.replica_config(frame_of(config(1, me + 1))) == oar::Status::failed);
    BOOST_TEST(r.verified == before);
    auto junk = frame_of(config(1));
    junk.resize(junk.size() - 1);
    BOOST_TEST(r.role.replica_config(junk) == oar::Status::bad_request);
    BOOST_TEST(!r.server.epoch(vol).has_value());
    BOOST_TEST(r.role.stats().refused == 4U);
    // One the server itself refuses (a stale epoch) is a failure too.
    BOOST_TEST(r.role.replica_config(frame_of(config(2))) == oar::Status::ok);
    BOOST_TEST(r.role.replica_config(frame_of(config(1))) == oar::Status::failed);
    BOOST_TEST((r.server.epoch(vol) == std::optional<std::uint64_t>{2}));
}

BOOST_AUTO_TEST_CASE(verified_ops_are_answered_unsupported_for_now) {
    Rig r;
    std::uint64_t ack = 0;
    auto bad = op();
    bad.signature[0] = std::byte{0};
    BOOST_TEST(r.role.volume_op(frame_of(bad)) == oar::Status::failed);
    BOOST_TEST(r.role.volume_op(frame_of(op(me + 1))) == oar::Status::failed);
    BOOST_TEST(r.role.volume_op(Bytes(10)) == oar::Status::bad_request);
    BOOST_TEST(!next_report(r.role, ack).has_value());

    const auto f = frame_of(op());
    BOOST_TEST(r.role.volume_op(f) == oar::Status::ok);
    BOOST_TEST(r.last_message == f.size() - 64);
    const auto rep = next_report(r.role, ack);
    BOOST_REQUIRE(rep.has_value());
    BOOST_TEST(rep->server_id == me);
    BOOST_TEST(rep->report_seq == 500U);
    const auto* out = std::get_if<proto::OpOutcome>(&rep->body);
    BOOST_REQUIRE(out != nullptr);
    BOOST_TEST(out->op_id == 44U);
    BOOST_TEST((out->kind == proto::VolumeOpKind::delete_replica));
    BOOST_TEST((out->status == proto::OpStatus::unsupported));
}

BOOST_AUTO_TEST_CASE(a_scrub_op_runs_on_the_server) {
    Rig r;
    std::uint64_t ack = 0;
    const auto scrub = frame_of(op(me, proto::ScrubVolume{.mib_per_s = 50}));
    // No replica of the volume here.
    BOOST_TEST(r.role.volume_op(scrub) == oar::Status::ok);
    r.role.pump(r.now);
    std::optional<proto::OpOutcome> out;
    while (auto rep = next_report(r.role, ack)) {
        if (const auto* o = std::get_if<proto::OpOutcome>(&rep->body)) {
            out = *o;
        }
    }
    BOOST_REQUIRE(out.has_value());
    BOOST_TEST((out->status == proto::OpStatus::unknown_volume));

    BOOST_REQUIRE(r.role.replica_config(frame_of(config(1))) == oar::Status::ok);
    BOOST_TEST(r.role.volume_op(scrub) == oar::Status::ok);
    BOOST_TEST(r.server.scrubbing(vol));
    r.server.run(r.now);  // an empty replica: nothing to read
    BOOST_TEST(!r.server.scrubbing(vol));
    r.role.pump(r.now);
    out.reset();
    while (auto rep = next_report(r.role, ack)) {
        if (const auto* o = std::get_if<proto::OpOutcome>(&rep->body)) {
            out = *o;
        }
    }
    BOOST_REQUIRE(out.has_value());
    BOOST_TEST(out->op_id == 44U);
    BOOST_TEST((out->kind == proto::VolumeOpKind::scrub));
    BOOST_TEST((out->status == proto::OpStatus::ok));
    BOOST_TEST(out->detail == 0U);
}

BOOST_AUTO_TEST_CASE(server_reports_go_up_in_order_and_once) {
    Rig r;
    BOOST_REQUIRE(r.role.replica_config(frame_of(config(1))) == oar::Status::ok);
    // A lone primary asks for its lease at once: a ReplicaStatus.
    r.role.pump(r.now);
    BOOST_REQUIRE(r.role.queued_reports() >= 1U);
    std::uint64_t ack = 0;
    std::uint64_t seq = 0;
    bool status = false;
    while (auto rep = next_report(r.role, ack)) {
        BOOST_TEST(rep->report_seq > seq);
        seq = rep->report_seq;
        status = status || std::holds_alternative<proto::ReplicaStatus>(rep->body);
    }
    BOOST_TEST(status);
    BOOST_TEST(r.role.queued_reports() == 0U);  // the last was acknowledged by the empty poll
}

BOOST_AUTO_TEST_CASE(a_lease_grant_reaches_the_server) {
    Rig r;
    BOOST_REQUIRE(r.role.replica_config(frame_of(config(1))) == oar::Status::ok);
    r.role.pump(r.now);  // sends the lease request
    BOOST_TEST(!r.server.has_lease(vol, r.now));
    BOOST_TEST(r.role.lease_grant({.volume_id = vol, .epoch = 1}) == oar::Status::ok);
    BOOST_TEST(r.server.has_lease(vol, r.now));
    BOOST_TEST(r.role.stats().grants == 1U);
}

}  // namespace
