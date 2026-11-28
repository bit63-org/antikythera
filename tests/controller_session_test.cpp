// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirements 1.4, 2.3 and 3: the
// ControllerSession protocol, driven byte by byte with no network.

#define BOOST_TEST_MODULE controller_session_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "helm/controller_link.hpp"
#include "helm/mailbox.hpp"
#include "proto/group_policy.hpp"
#include "proto/link.hpp"
#include "proto/group_members.hpp"
#include "proto/instance_metadata.hpp"
#include "proto/vpc_config.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::SessionError;
using proto::RecordType;

namespace {

constexpr std::uint64_t server = 0x5E'0001;
constexpr std::uint64_t other_server = 0x5E'0002;
constexpr std::uint64_t boot = 0xB007;
constexpr proto::KeyId key = 3;

struct RecordingSink final : helm::ControllerSink {
    std::vector<proto::Envelope> envelopes;
    std::vector<std::pair<proto::MapUpdate, std::vector<std::byte>>> updates;
    std::vector<std::pair<proto::GroupPolicy, std::vector<std::byte>>> policies;
    std::vector<std::pair<proto::TunnelPeers, std::vector<std::byte>>> peer_sets;
    std::vector<std::pair<proto::ReplicaConfig, std::vector<std::byte>>> configs;
    std::vector<std::pair<proto::VolumeOp, std::vector<std::byte>>> ops;
    std::vector<std::pair<proto::VolumeKey, std::vector<std::byte>>> keys;
    std::vector<std::pair<proto::ImageKey, std::vector<std::byte>>> image_keys;
    std::vector<proto::LeaseGrant> grants;
    std::vector<std::pair<proto::VpcConfigFrame, std::vector<std::byte>>> vpc_configs;
    std::vector<std::pair<proto::GroupMembers, std::vector<std::byte>>> members;
    std::vector<std::pair<proto::InstanceMetadata, std::vector<std::byte>>> metadata;

    auto on_envelope(const proto::Envelope& e) -> void override { envelopes.push_back(e); }
    auto on_map_update(const proto::MapUpdate& u, std::span<const std::byte> frame)
        -> void override {
        updates.emplace_back(u, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_group_policy(const proto::GroupPolicy& p, std::span<const std::byte> frame)
        -> void override {
        policies.emplace_back(p, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_tunnel_peers(const proto::TunnelPeers& t, std::span<const std::byte> frame)
        -> void override {
        peer_sets.emplace_back(t, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_replica_config(const proto::ReplicaConfig& c, std::span<const std::byte> frame)
        -> void override {
        configs.emplace_back(c, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_volume_op(const proto::VolumeOp& o, std::span<const std::byte> frame) -> void override {
        ops.emplace_back(o, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_volume_key(const proto::VolumeKey& k, std::span<const std::byte> frame)
        -> void override {
        keys.emplace_back(k, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_image_key(const proto::ImageKey& k, std::span<const std::byte> frame) -> void override {
        image_keys.emplace_back(k, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_lease_grant(const proto::LeaseGrant& g) -> void override { grants.push_back(g); }
    auto on_vpc_config(const proto::VpcConfigFrame& c, std::span<const std::byte> frame)
        -> void override {
        vpc_configs.emplace_back(c, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_group_members(const proto::GroupMembers& m, std::span<const std::byte> frame)
        -> void override {
        members.emplace_back(m, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    auto on_instance_metadata(const proto::InstanceMetadata& m, std::span<const std::byte> frame)
        -> void override {
        metadata.emplace_back(m, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<std::pair<proto::VolumeLayout, std::vector<std::byte>>> layouts;
    auto on_volume_layout(const proto::VolumeLayout& l, std::span<const std::byte> frame)
        -> void override {
        layouts.emplace_back(l, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<proto::SelfTest> self_tests;
    auto on_self_test(const proto::SelfTest& t) -> void override { self_tests.push_back(t); }
    std::vector<std::pair<proto::StandingSet, std::vector<std::byte>>> standing_sets;
    auto on_standing_set(const proto::StandingSet& set, std::span<const std::byte> frame)
        -> void override {
        standing_sets.emplace_back(set, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<std::pair<proto::PowerPolicy, std::vector<std::byte>>> power_policies;
    auto on_power_policy(const proto::PowerPolicy& p, std::span<const std::byte> frame)
        -> void override {
        power_policies.emplace_back(p, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<std::pair<proto::HostPower, std::vector<std::byte>>> host_powers;
    auto on_host_power(const proto::HostPower& p, std::span<const std::byte> frame)
        -> void override {
        host_powers.emplace_back(p, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<std::pair<proto::Decommission, std::vector<std::byte>>> decommissions;
    auto on_decommission(const proto::Decommission& d, std::span<const std::byte> frame)
        -> void override {
        decommissions.emplace_back(d, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<std::pair<proto::BootImage, std::vector<std::byte>>> boot_images;
    auto on_boot_image(const proto::BootImage& b, std::span<const std::byte> frame)
        -> void override {
        boot_images.emplace_back(b, std::vector<std::byte>{frame.begin(), frame.end()});
    }
    std::vector<proto::RoleCertificate> certificates;
    auto on_role_certificate(const proto::RoleCertificate& c) -> void override {
        certificates.push_back(c);
    }
};

// A sink that keeps ControllerSink's default for tunnel peer sets.
struct DefaultSink final : helm::ControllerSink {
    int envelopes = 0;
    auto on_envelope(const proto::Envelope& /*e*/) -> void override { ++envelopes; }
    auto on_map_update(const proto::MapUpdate& /*u*/, std::span<const std::byte> /*frame*/)
        -> void override {}
};

struct Fixture {
    RecordingSink sink;
    int inventories = 0;
    helm::ControllerSession session{server, boot,
                                    [this] {
                                        ++inventories;
                                        proto::Inventory inv;
                                        inv.boot_id = 1;  // the session overrides it
                                        inv.cores_total = 8;
                                        inv.cores_free = static_cast<std::uint16_t>(inventories);
                                        return inv;
                                    },
                                    sink};
};

// Parses everything the session wrote into records.
auto records(std::vector<std::byte> bytes) -> std::vector<proto::Record> {
    proto::RecordDecoder d;
    d.feed(bytes);
    std::vector<proto::Record> out;
    for (;;) {
        auto r = d.next();
        BOOST_REQUIRE(r.has_value());
        if (!r->has_value()) {
            BOOST_TEST(d.buffered() == 0U);
            return out;
        }
        out.push_back(std::move(**r));
    }
}

auto as_report(const proto::Record& r) -> proto::Report {
    BOOST_REQUIRE((r.type == RecordType::report));
    auto rep = proto::decode_report(r.payload);
    BOOST_REQUIRE(rep.has_value());
    return *rep;
}

auto framed(RecordType t, const std::vector<std::byte>& payload) -> std::vector<std::byte> {
    auto b = proto::encode_record(t, payload);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto envelope_record(std::uint64_t to, std::uint64_t seq) -> std::vector<std::byte> {
    const mb::Header h{.type = mb::Type::list_vms, .seq = seq, .key_id = key, .server_id = to};
    std::array<std::byte, mb::signature_size> sig{};
    auto slot = mb::encode(h, {}, sig);
    BOOST_REQUIRE(slot.has_value());
    auto env = proto::encode_envelope({.server_id = to, .key_id = key, .slot = *slot});
    BOOST_REQUIRE(env.has_value());
    return framed(RecordType::envelope, {env->begin(), env->end()});
}

auto map_update_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::MapUpdate m{.server_id = to,
                       .key_id = key,
                       .vni = 5,
                       .map_version = 1,
                       .entries = {},
                       .ipv4 = {},
                       .ipv6 = {},
                       .signature = {}};
    auto b = proto::encode_map_update(m);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::map_update, *b);
}

auto replica_config_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::ReplicaConfig c;
    c.key_id = key;
    c.server_id = to;
    c.volume_id = 0x100;
    c.epoch = 2;
    c.lineage_id = 0x1EE;
    c.capacity_blocks = 1024;
    c.block_size = proto::block_size_4096;
    c.lease_ms = 4000;
    c.qos = {.iops = 100, .mib_per_s = 10, .burst_iops = 100, .burst_mib = 10};
    proto::ReplicaMember m;
    m.server_id = to;
    m.endpoint[0] = std::byte{0xFD};
    m.endpoint[15] = std::byte{1};
    m.port = 7300;
    m.role = proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    auto b = proto::encode_replica_config(c);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::replica_config, *b);
}

auto volume_op_record(std::uint64_t to) -> std::vector<std::byte> {
    const proto::VolumeOp op{.key_id = key,
                             .server_id = to,
                             .volume_id = 0x100,
                             .epoch = 2,
                             .op_id = 0x0B,
                             .args = proto::ScrubVolume{.mib_per_s = 50},
                             .signature = {}};
    auto b = proto::encode_volume_op(op);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::volume_op, *b);
}

auto volume_key_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::VolumeKey k{.server_id = to,
                       .volume_id = 0x100,
                       .attachment_id = 0xA1,
                       .generation = 2,
                       .hpke_enc = {},
                       .wrapped_key = {}};
    k.hpke_enc.fill(std::byte{0x11});
    auto b = proto::encode_volume_key(k);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::volume_key, *b);
}

auto image_key_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::ImageKey k{
        .server_id = to, .volume_id = 0x100, .owner_vm = 0xB2, .hpke_enc = {}, .wrapped_key = {}};
    k.hpke_enc.fill(std::byte{0x11});
    auto b = proto::encode_image_key(k);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::image_key, *b);
}

auto lease_grant_record(std::uint64_t to) -> std::vector<std::byte> {
    auto b = proto::encode_lease_grant({.server_id = to, .volume_id = 0x100, .epoch = 2});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::lease_grant, *b);
}

auto group_policy_record(std::uint64_t to) -> std::vector<std::byte> {
    const proto::GroupPolicy p{.server_id = to,
                               .key_id = key,
                               .vni = 5,
                               .mode = proto::GroupMode::drop,
                               .policy_version = 2};
    auto b = proto::encode_group_policy(p);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::group_policy, *b);
}

auto vpc_config_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::VpcConfigFrame c{};
    c.server_id = to;
    c.key_id = key;
    c.vni = 5;
    c.config_version = 3;
    c.gateway_mac = {std::byte{0x02}, std::byte{0}, std::byte{0},
                     std::byte{0},    std::byte{0}, std::byte{0xFE}};
    // One block, one subnet, the main table with the block's local route.
    const proto::Ipv4Address ten{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}};
    c.ipv4_blocks = {{.prefix = ten, .length = 24}};
    c.subnets = {{.subnet_id = 1, .table = 1, .ipv4_prefix = ten, .ipv4_length = 24}};
    proto::VpcRoute local{.kind = proto::RouteKind::local, .length = 24, .prefix = {}};
    std::ranges::copy(ten, local.prefix.begin());
    c.tables = {{.table = 1, .main = true, .routes = {local}}};
    c.lease_seconds = 3600;
    auto b = proto::encode_vpc_config(c);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::vpc_config, *b);
}

auto group_members_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::GroupMembers m{.server_id = to, .key_id = key, .vni = 5, .members_version = 4};
    proto::MemberGroup g{.family = proto::RouteFamily::ipv4, .group = {}, .vteps = {{}}};
    g.group[0] = std::byte{239};
    g.group[3] = std::byte{1};
    g.vteps[0][0] = std::byte{0xFD};
    g.vteps[0][15] = std::byte{2};
    m.groups.push_back(g);
    auto b = proto::encode_group_members(m);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::group_members, *b);
}

auto instance_metadata_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::InstanceMetadata m{};
    m.server_id = to;
    m.key_id = key;
    m.nic_id = 0x11;
    m.metadata_version = 6;
    m.vni = 5;
    m.instance_id = "i-0abc";
    m.image_id = "ami-0abc";
    m.instance_type = "m5.large";
    m.account_id = "123456789012";
    m.local_hostname = "ip-10-0-0-17.ec2.internal";
    m.availability_zone = "harbor-1a";
    m.region = "harbor-1";
    m.interface_id = "eni-0abc";
    m.vpc_id = "vpc-0abc";
    auto b = proto::encode_instance_metadata(m);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::instance_metadata, *b);
}

auto volume_layout_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::VolumeLayout l;
    l.key_id = key;
    l.server_id = to;
    l.volume_id = 0x200;
    l.epoch = 3;
    l.lineage_id = 0x2EE;
    l.capacity_blocks = 1024;
    l.qos = {.iops = 100, .mib_per_s = 10, .burst_iops = 100, .burst_mib = 10};
    l.timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900};
    proto::LayoutMember m{.server_id = to, .endpoint = {}, .port = 7400};
    m.endpoint[0] = std::byte{0xFD};
    m.endpoint[15] = std::byte{1};
    l.groups = {{.group_id = 0x5001, .members = {m}}};
    auto b = proto::encode_volume_layout(l);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::volume_layout, *b);
}

auto self_test_record(std::uint64_t to) -> std::vector<std::byte> {
    auto b =
        proto::encode_self_test({.server_id = to, .slot = 4, .scope = proto::SelfTestScope::slot});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::self_test, *b);
}

auto standing_set_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::StandingSet set{};
    set.server_id = to;
    set.key_id = key;
    set.generation = 2;
    auto b = proto::encode_standing_set(set);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::standing_set, *b);
}

auto power_policy_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::PowerPolicy p{};
    p.server_id = to;
    p.key_id = key;
    p.policy_version = 3;
    p.tier = 0;
    auto b = proto::encode_power_policy(p);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::power_policy, *b);
}

auto host_power_record(std::uint64_t to) -> std::vector<std::byte> {
    auto b = proto::encode_host_power({.key_id = key,
                                       .server_id = to,
                                       .seq = 9,
                                       .action = proto::HostPowerAction::off,
                                       .force = false,
                                       .signature = {}});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::host_power, *b);
}

auto decommission_record(std::uint64_t to) -> std::vector<std::byte> {
    auto b =
        proto::encode_decommission({.key_id = key, .server_id = to, .seq = 10, .signature = {}});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::decommission, *b);
}

auto boot_image_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::BootImage b{
        .key_id = key, .server_id = to, .assignment_version = 2, .image = {}, .signature = {}};
    b.image = {.key_id = 1,
               .image_version = 3,
               .size = 4096,
               .kind = proto::HostImageKind::hull,
               .digest = {},
               .signature = {}};
    b.image.digest.fill(std::byte{0xC4});
    auto f = proto::encode_boot_image(b);
    BOOST_REQUIRE(f.has_value());
    return framed(RecordType::boot_image, *f);
}

auto tunnel_peers_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::TunnelPeers t{
        .server_id = to,
        .key_id = key,
        .vtep = {},
        .peers_version = 4,
        .peers = {{.vtep = {}, .mode = proto::TunnelMode::wireguard, .spi = 0, .key = {}}},
        .signature = {}};
    t.vtep[0] = std::byte{0xFD};
    t.vtep[15] = std::byte{1};
    t.peers[0].vtep = t.vtep;
    t.peers[0].vtep[15] = std::byte{2};
    t.peers[0].key.fill(std::byte{0x42});
    auto b = proto::encode_tunnel_peers(t);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::tunnel_peers, *b);
}

auto ack_record(std::uint64_t seq, std::uint64_t to = server) -> std::vector<std::byte> {
    auto b = proto::encode_report_ack({.server_id = to, .report_seq = seq});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::report_ack, *b);
}

auto exited(std::uint64_t vm) -> proto::ReportBody {
    return proto::VmExitedReport{
        .vm_id = vm, .exit_status = 0, .reason = proto::ExitReason::guest_shutdown};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(controller_session, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_FIXTURE_TEST_CASE(registration_is_hello_then_inventory, Fixture) {
    session.on_connected();
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 2U);
    BOOST_REQUIRE((recs[0].type == RecordType::hello));
    auto hello = proto::decode_hello(recs[0].payload);
    BOOST_REQUIRE(hello.has_value());
    BOOST_TEST(hello->server_id == server);
    BOOST_TEST(hello->boot_id == boot);
    const auto inv = as_report(recs[1]);
    BOOST_TEST(inv.server_id == server);
    BOOST_TEST(inv.report_seq == 1U);
    BOOST_REQUIRE(std::holds_alternative<proto::Inventory>(inv.body));
    BOOST_TEST(std::get<proto::Inventory>(inv.body).boot_id == boot);
    BOOST_TEST(session.take_outbound().empty());
}

BOOST_FIXTURE_TEST_CASE(reports_go_out_immediately_when_connected, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    BOOST_TEST(session.report(exited(7)) == 2U);
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 1U);
    BOOST_TEST(as_report(recs[0]).report_seq == 2U);
}

BOOST_FIXTURE_TEST_CASE(reconnect_replays_unacked_then_fresh_inventory, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    (void)session.report(exited(7));  // seq 2
    (void)session.report(exited(8));  // seq 3
    BOOST_TEST(session.on_bytes(ack_record(2)).has_value());
    BOOST_TEST(session.last_acked() == 2U);
    session.on_disconnected();
    (void)session.report(exited(9));  // seq 4, queued while down
    BOOST_TEST(session.take_outbound().empty());

    session.on_connected();
    const auto recs = records(session.take_outbound());
    // hello, seq 3 and 4 (the inventory, seq 1, was acked by 2), then a
    // fresh inventory as seq 5.
    BOOST_REQUIRE(recs.size() == 4U);
    BOOST_TEST((recs[0].type == RecordType::hello));
    BOOST_TEST(as_report(recs[1]).report_seq == 3U);
    BOOST_TEST(as_report(recs[2]).report_seq == 4U);
    const auto inv = as_report(recs[3]);
    BOOST_TEST(inv.report_seq == 5U);
    BOOST_TEST(std::get<proto::Inventory>(inv.body).cores_free == 2U);
}

BOOST_FIXTURE_TEST_CASE(unacked_inventory_is_superseded_not_replayed, Fixture) {
    session.on_connected();  // inventory seq 1, never acked
    (void)session.take_outbound();
    session.on_disconnected();
    session.on_connected();
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 2U);
    BOOST_TEST(as_report(recs[1]).report_seq == 2U);
    BOOST_TEST(session.pending_reports() == 1U);
}

BOOST_FIXTURE_TEST_CASE(acks_only_move_forward, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    (void)session.report(exited(7));
    (void)session.report(exited(8));
    BOOST_TEST(session.on_bytes(ack_record(3)).has_value());
    BOOST_TEST(session.pending_reports() == 0U);
    BOOST_TEST(session.on_bytes(ack_record(1)).has_value());  // late duplicate
    BOOST_TEST(session.last_acked() == 3U);
}

BOOST_FIXTURE_TEST_CASE(envelopes_and_updates_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    auto stream = envelope_record(server, 10);
    const auto upd = map_update_record(server);
    stream.insert(stream.end(), upd.begin(), upd.end());
    const auto peers = tunnel_peers_record(server);
    stream.insert(stream.end(), peers.begin(), peers.end());
    // Byte at a time: reassembly is the decoder's job.
    for (const auto b : stream) {
        BOOST_REQUIRE(session.on_bytes(std::span{&b, 1}).has_value());
    }
    BOOST_REQUIRE(sink.envelopes.size() == 1U);
    BOOST_TEST(proto::slot_seq(sink.envelopes[0].slot) == 10U);
    const auto env_bytes = proto::encode_envelope(sink.envelopes[0]);
    BOOST_TEST(std::ranges::equal(
        *env_bytes, std::span{stream}.subspan(proto::record_header_size, proto::envelope_size)));
    BOOST_REQUIRE(sink.updates.size() == 1U);
    BOOST_TEST(sink.updates[0].first.vni == 5U);
    BOOST_TEST(std::ranges::equal(sink.updates[0].second,
                                  std::span{upd}.subspan(proto::record_header_size)));
    BOOST_REQUIRE(sink.peer_sets.size() == 1U);
    BOOST_TEST(sink.peer_sets[0].first.peers_version == 4U);
    BOOST_TEST(sink.peer_sets[0].first.peers.size() == 1U);
    BOOST_TEST(std::ranges::equal(sink.peer_sets[0].second,
                                  std::span{peers}.subspan(proto::record_header_size)));
}

BOOST_FIXTURE_TEST_CASE(block_volume_records_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    std::vector<std::byte> stream;
    for (const auto& r :
         {replica_config_record(server), volume_op_record(server), volume_key_record(server),
          lease_grant_record(server), image_key_record(server)}) {
        stream.insert(stream.end(), r.begin(), r.end());
    }
    for (const auto b : stream) {
        BOOST_REQUIRE(session.on_bytes(std::span{&b, 1}).has_value());
    }
    BOOST_REQUIRE(sink.configs.size() == 1U);
    BOOST_TEST(sink.configs[0].first.epoch == 2U);
    const auto config = replica_config_record(server);
    BOOST_TEST(std::ranges::equal(sink.configs[0].second,
                                  std::span{config}.subspan(proto::record_header_size)));
    BOOST_REQUIRE(sink.ops.size() == 1U);
    BOOST_TEST(sink.ops[0].first.op_id == 0x0BU);
    BOOST_TEST(sink.ops[0].second.size() == proto::volume_op_size);
    BOOST_REQUIRE(sink.keys.size() == 1U);
    BOOST_TEST(sink.keys[0].first.attachment_id == 0xA1U);
    BOOST_TEST(sink.keys[0].second.size() == proto::volume_key_size);
    BOOST_REQUIRE(sink.image_keys.size() == 1U);
    BOOST_TEST(sink.image_keys[0].first.owner_vm == 0xB2U);
    const auto image = image_key_record(server);
    BOOST_TEST(std::ranges::equal(sink.image_keys[0].second,
                                  std::span{image}.subspan(proto::record_header_size)));
    BOOST_REQUIRE(sink.grants.size() == 1U);
    BOOST_TEST(
        (sink.grants[0] == proto::LeaseGrant{.server_id = server, .volume_id = 0x100, .epoch = 2}));
}

BOOST_FIXTURE_TEST_CASE(block_volume_records_for_another_server_end_the_connection, Fixture) {
    for (const auto& r : {replica_config_record(other_server), volume_op_record(other_server),
                          volume_key_record(other_server), lease_grant_record(other_server),
                          image_key_record(other_server)}) {
        session.on_connected();
        auto res = session.on_bytes(r);
        BOOST_REQUIRE(!res.has_value());
        BOOST_TEST((res.error() == SessionError::wrong_server));
        session.on_disconnected();
    }
    auto bad = lease_grant_record(server);
    std::fill(bad.end() - 8, bad.end(), std::byte{0});  // epoch 0
    session.on_connected();
    auto res = session.on_bytes(bad);
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::bad_record));
    BOOST_TEST(sink.grants.empty());
}

// kythira khold-block-service task 17.
BOOST_FIXTURE_TEST_CASE(khold_records_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto layout = volume_layout_record(server);
    const auto test = self_test_record(server);
    BOOST_REQUIRE(session.on_bytes(layout).has_value());
    BOOST_REQUIRE(session.on_bytes(test).has_value());
    BOOST_REQUIRE(sink.layouts.size() == 1U);
    BOOST_TEST(sink.layouts[0].first.epoch == 3U);
    BOOST_TEST(std::ranges::equal(sink.layouts[0].second,
                                  std::span{layout}.subspan(proto::record_header_size)));
    BOOST_REQUIRE(sink.self_tests.size() == 1U);
    BOOST_TEST(
        (sink.self_tests[0] ==
         proto::SelfTest{.server_id = server, .slot = 4, .scope = proto::SelfTestScope::slot}));
    for (const auto& r : {volume_layout_record(other_server), self_test_record(other_server)}) {
        session.on_disconnected();
        session.on_connected();
        auto res = session.on_bytes(r);
        BOOST_REQUIRE(!res.has_value());
        BOOST_TEST((res.error() == SessionError::wrong_server));
    }
    auto bad = volume_layout_record(server);
    bad.back() = std::byte{0};
    bad[proto::record_header_size + 0x46] = std::byte{1};  // a reserved byte
    session.on_disconnected();
    session.on_connected();
    auto res = session.on_bytes(bad);
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::bad_record));
    BOOST_TEST(sink.layouts.size() == 1U);
}

// .kiro/specs/cold-start/ task 1.
BOOST_FIXTURE_TEST_CASE(cold_start_records_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto set = standing_set_record(server);
    const auto policy = power_policy_record(server);
    BOOST_REQUIRE(session.on_bytes(set).has_value());
    BOOST_REQUIRE(session.on_bytes(policy).has_value());
    BOOST_REQUIRE(sink.standing_sets.size() == 1U);
    BOOST_TEST(sink.standing_sets[0].first.generation == 2U);
    BOOST_TEST(std::ranges::equal(sink.standing_sets[0].second,
                                  std::span{set}.subspan(proto::record_header_size)));
    BOOST_REQUIRE(sink.power_policies.size() == 1U);
    BOOST_TEST(sink.power_policies[0].first.policy_version == 3U);
    BOOST_TEST(std::ranges::equal(sink.power_policies[0].second,
                                  std::span{policy}.subspan(proto::record_header_size)));
    for (const auto& r : {standing_set_record(other_server), power_policy_record(other_server)}) {
        session.on_disconnected();
        session.on_connected();
        auto res = session.on_bytes(r);
        BOOST_REQUIRE(!res.has_value());
        BOOST_TEST((res.error() == SessionError::wrong_server));
    }
    auto bad = power_policy_record(server);
    bad[proto::record_header_size + 0x20] = std::byte{4};  // tier 4
    session.on_disconnected();
    session.on_connected();
    auto res = session.on_bytes(bad);
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::bad_record));
    BOOST_TEST(sink.power_policies.size() == 1U);
}

// .kiro/specs/server-provisioning/ task 1.
BOOST_FIXTURE_TEST_CASE(host_lifecycle_records_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto power = host_power_record(server);
    const auto order = decommission_record(server);
    BOOST_REQUIRE(session.on_bytes(power).has_value());
    BOOST_REQUIRE(session.on_bytes(order).has_value());
    BOOST_REQUIRE(sink.host_powers.size() == 1U);
    BOOST_TEST((sink.host_powers[0].first.action == proto::HostPowerAction::off));
    BOOST_TEST(std::ranges::equal(sink.host_powers[0].second,
                                  std::span{power}.subspan(proto::record_header_size)));
    BOOST_REQUIRE(sink.decommissions.size() == 1U);
    BOOST_TEST(sink.decommissions[0].first.seq == 10U);
    BOOST_TEST(std::ranges::equal(sink.decommissions[0].second,
                                  std::span{order}.subspan(proto::record_header_size)));
    for (const auto& r : {host_power_record(other_server), decommission_record(other_server)}) {
        session.on_disconnected();
        session.on_connected();
        auto res = session.on_bytes(r);
        BOOST_REQUIRE(!res.has_value());
        BOOST_TEST((res.error() == SessionError::wrong_server));
    }
    auto bad = host_power_record(server);
    bad[proto::record_header_size + 0x18] = std::byte{9};  // no such action
    session.on_disconnected();
    session.on_connected();
    auto res = session.on_bytes(bad);
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::bad_record));
    BOOST_TEST(sink.host_powers.size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(boot_image_assignments_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto assignment = boot_image_record(server);
    BOOST_REQUIRE(session.on_bytes(assignment).has_value());
    BOOST_REQUIRE(sink.boot_images.size() == 1U);
    BOOST_TEST(sink.boot_images[0].first.assignment_version == 2U);
    BOOST_TEST(std::ranges::equal(sink.boot_images[0].second,
                                  std::span{assignment}.subspan(proto::record_header_size)));
    session.on_disconnected();
    session.on_connected();
    auto res = session.on_bytes(boot_image_record(other_server));
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::wrong_server));
}

BOOST_AUTO_TEST_CASE(block_volume_records_default_to_dropped) {
    DefaultSink sink;
    helm::ControllerSession session{server, boot,
                                    [] {
                                        proto::Inventory inv;
                                        inv.boot_id = 1;
                                        return inv;
                                    },
                                    sink};
    session.on_connected();
    BOOST_TEST(session.on_bytes(replica_config_record(server)).has_value());
    BOOST_TEST(session.on_bytes(lease_grant_record(server)).has_value());
    BOOST_TEST(session.on_bytes(envelope_record(server, 10)).has_value());
    BOOST_TEST(sink.envelopes == 1);
}

BOOST_AUTO_TEST_CASE(tunnel_peers_default_to_dropped) {
    DefaultSink sink;
    helm::ControllerSession session{server, boot,
                                    [] {
                                        proto::Inventory inv;
                                        inv.boot_id = 1;
                                        return inv;
                                    },
                                    sink};
    session.on_connected();
    BOOST_TEST(session.on_bytes(tunnel_peers_record(server)).has_value());
    BOOST_TEST(session.on_bytes(envelope_record(server, 10)).has_value());
    BOOST_TEST(sink.envelopes == 1);
}

namespace {

auto enrollment(std::uint8_t fill) -> proto::Enrollment {
    proto::Enrollment e;
    e.transport_key.fill(std::byte{fill});
    return e;
}

auto role_certificate_record(std::uint64_t to) -> std::vector<std::byte> {
    auto b = proto::encode_role_certificate(
        {.server_id = to, .slot = 2, .chain = ak::test::bytes_of(0x30, 0x01, 0x05)});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::role_certificate, *b);
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(enrollment_follows_the_inventory_on_every_connection, Fixture) {
    session.set_enrollment(enrollment(0x11));  // before any connection: nothing sent yet
    BOOST_TEST(session.take_outbound().empty());
    session.on_connected();
    auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 3U);
    BOOST_TEST(std::holds_alternative<proto::Inventory>(as_report(recs[1]).body));
    const auto e = as_report(recs[2]);
    BOOST_TEST(e.report_seq == 2U);
    BOOST_TEST((std::get<proto::Enrollment>(e.body) == enrollment(0x11)));

    // A new key while connected goes out now, and supersedes the old one.
    session.set_enrollment(enrollment(0x22));
    recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 1U);
    BOOST_TEST((std::get<proto::Enrollment>(as_report(recs[0]).body) == enrollment(0x22)));

    // Nothing acknowledged: a reconnect restates both, freshly numbered,
    // and replays neither old copy.
    session.on_disconnected();
    session.on_connected();
    recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 3U);
    BOOST_TEST(as_report(recs[1]).report_seq == 4U);
    const auto again = as_report(recs[2]);
    BOOST_TEST(again.report_seq == 5U);
    BOOST_TEST((std::get<proto::Enrollment>(again.body) == enrollment(0x22)));
    BOOST_TEST(session.pending_reports() == 2U);
}

BOOST_FIXTURE_TEST_CASE(a_boot_cache_follows_every_inventory, Fixture) {
    std::optional<proto::BootCache> cache;  // nothing to send yet
    session.set_boot_cache_source([&cache] { return cache; });
    session.on_connected();
    auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 2U);  // hello, inventory
    BOOST_TEST(std::holds_alternative<proto::Inventory>(as_report(recs[1]).body));

    cache = proto::BootCache{.standing_generation = 3,
                             .policy_version = 7,
                             .store_free_bytes = 100,
                             .store_total_bytes = 400};
    // A later inventory (a change helm reports) brings the boot cache
    // right behind it; other reports do not.
    (void)session.report(exited(5));
    proto::Inventory changed;
    changed.boot_id = boot;
    changed.cores_total = 8;
    (void)session.report(changed);
    recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 3U);
    BOOST_TEST(std::holds_alternative<proto::Inventory>(as_report(recs[1]).body));
    const auto b = as_report(recs[2]);
    BOOST_TEST(b.report_seq == as_report(recs[1]).report_seq + 1);
    BOOST_TEST((std::get<proto::BootCache>(b.body) == *cache));

    // Nothing acknowledged: a reconnect replays the exit only, then a fresh
    // inventory and boot cache.
    cache->policy_version = 8;
    session.on_disconnected();
    session.on_connected();
    recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 4U);
    BOOST_TEST(std::holds_alternative<proto::VmExitedReport>(as_report(recs[1]).body));
    BOOST_TEST(std::holds_alternative<proto::Inventory>(as_report(recs[2]).body));
    BOOST_TEST(std::get<proto::BootCache>(as_report(recs[3]).body).policy_version == 8U);
    BOOST_TEST(session.pending_reports() == 3U);
}

BOOST_FIXTURE_TEST_CASE(role_certificates_reach_the_sink, Fixture) {
    session.on_connected();
    BOOST_TEST(session.on_bytes(role_certificate_record(server)).has_value());
    BOOST_REQUIRE(sink.certificates.size() == 1U);
    BOOST_TEST(sink.certificates[0].slot == 2U);
    BOOST_TEST((sink.certificates[0].chain == ak::test::bytes_of(0x30, 0x01, 0x05)));

    auto res = session.on_bytes(role_certificate_record(other_server));
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::wrong_server));
    session.on_disconnected();

    auto bad = role_certificate_record(server);
    bad.back() = std::byte{0};
    bad[bad.size() - 2] = std::byte{0x02};  // the chain is no longer a SEQUENCE
    bad[bad.size() - 3] = std::byte{0x02};
    session.on_connected();
    res = session.on_bytes(bad);
    BOOST_REQUIRE(!res.has_value());
    BOOST_TEST((res.error() == SessionError::bad_record));
    BOOST_TEST(sink.certificates.size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(protocol_violations_end_the_connection, Fixture) {
    struct Case {
        std::vector<std::byte> bytes;
        SessionError want;
    };
    auto bad_envelope = envelope_record(server, 10);
    bad_envelope[proto::record_header_size] = std::byte{0};  // envelope magic
    auto bad_peers = tunnel_peers_record(server);
    bad_peers[proto::record_header_size] = std::byte{0};  // TunnelPeers magic
    auto report_payload =
        proto::encode_report({.server_id = server, .report_seq = 1, .body = exited(1)});
    auto hello_payload = proto::encode_hello({.server_id = server, .boot_id = 1});
    auto bad_policy = group_policy_record(server);
    bad_policy[proto::record_header_size] = std::byte{0};  // policy magic
    auto bad_vpc = vpc_config_record(server);
    bad_vpc[proto::record_header_size] = std::byte{0};  // VpcConfig magic
    auto bad_members = group_members_record(server);
    bad_members[proto::record_header_size] = std::byte{0};  // GroupMembers magic
    auto bad_metadata = instance_metadata_record(server);
    bad_metadata[proto::record_header_size] = std::byte{0};  // InstanceMetadata magic
    const Case cases[] = {
        {envelope_record(other_server, 10), SessionError::wrong_server},
        {map_update_record(other_server), SessionError::wrong_server},
        {group_policy_record(other_server), SessionError::wrong_server},
        {tunnel_peers_record(other_server), SessionError::wrong_server},
        {bad_policy, SessionError::bad_record},
        {vpc_config_record(other_server), SessionError::wrong_server},
        {bad_vpc, SessionError::bad_record},
        {group_members_record(other_server), SessionError::wrong_server},
        {bad_members, SessionError::bad_record},
        {instance_metadata_record(other_server), SessionError::wrong_server},
        {bad_metadata, SessionError::bad_record},
        {bad_envelope, SessionError::bad_record},
        {bad_peers, SessionError::bad_record},
        {framed(RecordType::report, *report_payload), SessionError::wrong_direction},
        {framed(RecordType::hello, *hello_payload), SessionError::wrong_direction},
        {ack_record(99), SessionError::bad_ack},
        {ack_record(1, other_server), SessionError::bad_ack},
        {ak::test::bytes_of(0, 0, 0, 0, 9, 0, 0, 0), SessionError::bad_record},
    };
    for (const auto& c : cases) {
        Fixture f;
        f.session.on_connected();
        auto r = f.session.on_bytes(c.bytes);
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == c.want));
        BOOST_TEST(f.sink.envelopes.empty());
        BOOST_TEST(f.sink.updates.empty());
        BOOST_TEST(f.sink.policies.empty());
        BOOST_TEST(f.sink.vpc_configs.empty());
        BOOST_TEST(f.sink.members.empty());
        BOOST_TEST(f.sink.metadata.empty());
    }
}

// Requirement 11.4: a NIC's InstanceMetadata for this server reaches the
// sink as its exact frame, for helm to forward unmodified.
BOOST_FIXTURE_TEST_CASE(instance_metadata_reaches_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto rec = instance_metadata_record(server);
    BOOST_REQUIRE(session.on_bytes(rec).has_value());
    BOOST_REQUIRE(sink.metadata.size() == 1U);
    BOOST_TEST(sink.metadata[0].first.nic_id == 0x11U);
    BOOST_TEST(sink.metadata[0].first.metadata_version == 6U);
    BOOST_TEST(std::ranges::equal(sink.metadata[0].second,
                                  std::span{rec}.subspan(proto::record_header_size)));
    // A sink that predates it drops it quietly.
    DefaultSink quiet;
    helm::ControllerSession other{server, boot,
                                  [] {
                                      proto::Inventory inv;
                                      inv.boot_id = 1;
                                      return inv;
                                  },
                                  quiet};
    other.on_connected();
    BOOST_TEST(other.on_bytes(rec).has_value());
}

// Requirement 7.9: a GroupMembers frame for this server reaches the sink as
// its exact frame, for helm to forward unmodified.
BOOST_FIXTURE_TEST_CASE(group_members_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto rec = group_members_record(server);
    BOOST_REQUIRE(session.on_bytes(rec).has_value());
    BOOST_REQUIRE(sink.members.size() == 1U);
    BOOST_TEST(sink.members[0].first.vni == 5U);
    BOOST_TEST(sink.members[0].first.members_version == 4U);
    BOOST_TEST(std::ranges::equal(sink.members[0].second,
                                  std::span{rec}.subspan(proto::record_header_size)));
}

// Requirement 10.3: a VpcConfig for this server reaches the sink as its
// exact frame, for helm to forward unmodified.
BOOST_FIXTURE_TEST_CASE(vpc_configs_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto rec = vpc_config_record(server);
    BOOST_REQUIRE(session.on_bytes(rec).has_value());
    BOOST_REQUIRE(sink.vpc_configs.size() == 1U);
    BOOST_TEST(sink.vpc_configs[0].first.vni == 5U);
    BOOST_TEST(sink.vpc_configs[0].first.config_version == 3U);
    BOOST_TEST(std::ranges::equal(sink.vpc_configs[0].second,
                                  std::span{rec}.subspan(proto::record_header_size)));
}

// A sink that keeps ControllerSink's default drops a VpcConfig quietly.
BOOST_AUTO_TEST_CASE(a_sink_without_a_network_role_ignores_vpc_configs) {
    DefaultSink sink;
    helm::ControllerSession session{server, boot,
                                    [] {
                                        proto::Inventory inv;
                                        inv.boot_id = 1;
                                        return inv;
                                    },
                                    sink};
    session.on_connected();
    BOOST_TEST(session.on_bytes(vpc_config_record(server)).has_value());
    BOOST_TEST(session.on_bytes(group_members_record(server)).has_value());
    BOOST_TEST(session.on_bytes(envelope_record(server, 10)).has_value());
    BOOST_TEST(sink.envelopes == 1);
}

// Requirement 7.3: a GroupPolicy for this server reaches the sink as its
// exact frame, for helm to forward unmodified.
BOOST_FIXTURE_TEST_CASE(group_policies_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    const auto rec = group_policy_record(server);
    BOOST_REQUIRE(session.on_bytes(rec).has_value());
    BOOST_REQUIRE(sink.policies.size() == 1U);
    BOOST_TEST(sink.policies[0].first.vni == 5U);
    BOOST_TEST(sink.policies[0].first.policy_version == 2U);
    BOOST_TEST(std::ranges::equal(sink.policies[0].second,
                                  std::span{rec}.subspan(proto::record_header_size)));
}

BOOST_FIXTURE_TEST_CASE(bytes_without_a_connection_are_refused, Fixture) {
    auto r = session.on_bytes(envelope_record(server, 1));
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error() == SessionError::not_connected));
    BOOST_TEST(sink.envelopes.empty());
}

BOOST_FIXTURE_TEST_CASE(a_new_connection_starts_a_fresh_stream, Fixture) {
    session.on_connected();
    const auto env = envelope_record(server, 1);
    // Half a record, then the connection drops.
    BOOST_TEST(session.on_bytes(std::span{env}.first(10)).has_value());
    session.on_disconnected();
    session.on_connected();
    BOOST_TEST(session.on_bytes(env).has_value());
    BOOST_TEST(sink.envelopes.size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(pending_reports_are_bounded, Fixture) {
    for (std::size_t i = 0; i < helm::max_pending_reports + 5; ++i) {
        (void)session.report(exited(i + 1));
    }
    BOOST_TEST(session.pending_reports() == helm::max_pending_reports);
    BOOST_TEST(session.dropped_reports() == 5U);
    session.on_connected();
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == helm::max_pending_reports + 2);
    BOOST_TEST(as_report(recs[1]).report_seq == 6U);  // the oldest five went
}

BOOST_FIXTURE_TEST_CASE(invalid_reports_are_dropped_not_sent, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    (void)session.report(proto::VmExitedReport{});  // vm_id 0
    BOOST_TEST(session.take_outbound().empty());
    BOOST_TEST(session.dropped_reports() == 1U);
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e :
         {SessionError::bad_record, SessionError::wrong_direction, SessionError::wrong_server,
          SessionError::bad_ack, SessionError::not_connected}) {
        BOOST_TEST(std::string_view{helm::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
