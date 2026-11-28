// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 5.2 and 1.5 (task 7): helm's
// StandingFrames. It keeps, across a power loss, the newest verified map,
// VPC configuration, instance metadata and peer set for the standing
// set's NICs and nothing else, replays them in dependency order, follows
// a new set's NICs, and trusts nothing from a store that opened rolled
// back.

#define BOOST_TEST_MODULE standing_frames_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "helm/flash.hpp"
#include "helm/sealed_store.hpp"
#include "helm/standing_frames.hpp"
#include "helm/store_anchor.hpp"
#include "proto/instance_metadata.hpp"
#include "proto/map_update.hpp"
#include "proto/standing_set.hpp"
#include "proto/tunnel_peers.hpp"
#include "proto/vpc_config.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::FrameVerdict;
using proto::RecordType;

namespace {

constexpr std::uint64_t server = 42;
constexpr std::uint64_t flash_size = 256 * 1024;
constexpr std::byte good_sig{0x01};
constexpr std::byte bad_sig{0x02};
constexpr std::uint32_t vni = 7;
constexpr std::uint32_t other_vni = 8;
constexpr std::uint64_t nic = 0x21;

// Accepts a signature whose first byte is 0x01 under key 1, until the key
// is retired.
struct FakeVerifier final : helm::RecordVerifier {
    bool retired{false};
    [[nodiscard]] auto verify(std::span<const std::byte> /*message*/,
                              std::span<const std::byte, proto::ed25519_signature_size> sig,
                              std::uint16_t key_id) const -> bool override {
        return !retired && key_id == 1 && sig[0] == good_sig;
    }
};

auto standing(bool with_nic = true) -> proto::StandingSet {
    proto::StandingSet s{.server_id = server,
                         .key_id = 1,
                         .generation = 1,
                         .time_floor = 0,
                         .instances = {},
                         .signature = {}};
    proto::StandingInstance in;
    in.vm_id = 0x1001;
    if (with_nic) {
        in.nics.push_back({.nic_id = nic, .vni = vni});
    }
    s.instances.push_back(in);
    return s;
}

auto map(std::uint32_t net, std::uint64_t version, std::byte sig = good_sig,
         std::uint64_t to = server) -> std::vector<std::byte> {
    proto::MapUpdate m{.server_id = to,
                       .key_id = 1,
                       .vni = net,
                       .map_version = version,
                       .entries = {},
                       .ipv4 = {},
                       .ipv6 = {},
                       .signature = {}};
    m.signature.fill(sig);
    auto b = proto::encode_map_update(m);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto vpc(std::uint32_t net, std::uint64_t version) -> std::vector<std::byte> {
    proto::VpcConfigFrame c{};
    c.server_id = server;
    c.key_id = 1;
    c.vni = net;
    c.config_version = version;
    c.gateway_mac = {std::byte{0x02}, std::byte{0}, std::byte{0},
                     std::byte{0},    std::byte{0}, std::byte{0xFE}};
    const proto::Ipv4Address ten{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}};
    c.ipv4_blocks = {{.prefix = ten, .length = 24}};
    c.subnets = {{.subnet_id = 1, .table = 1, .ipv4_prefix = ten, .ipv4_length = 24}};
    proto::VpcRoute local{.kind = proto::RouteKind::local, .length = 24, .prefix = {}};
    std::ranges::copy(ten, local.prefix.begin());
    c.tables = {{.table = 1, .main = true, .routes = {local}}};
    c.lease_seconds = 60;
    c.signature.fill(good_sig);
    auto b = proto::encode_vpc_config(c);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto metadata(std::uint64_t id, std::uint32_t net, std::uint64_t version)
    -> std::vector<std::byte> {
    proto::InstanceMetadata m;
    m.key_id = 1;
    m.server_id = server;
    m.nic_id = id;
    m.metadata_version = version;
    m.vni = net;
    m.instance_id = "i-0123456789abcdef0";
    m.image_id = "ami-0123456789abcdef0";
    m.instance_type = "m1.small";
    m.account_id = "123456789012";
    m.local_hostname = "ip-10-0-0-5.internal";
    m.availability_zone = "zone-a";
    m.region = "region-1";
    m.interface_id = "eni-0123456789abcdef0";
    m.vpc_id = "vpc-0123456789abcdef0";
    m.signature.fill(good_sig);
    auto b = proto::encode_instance_metadata(m);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto peers(std::uint64_t version) -> std::vector<std::byte> {
    proto::TunnelPeers t{};
    t.server_id = server;
    t.key_id = 1;
    t.vtep.back() = std::byte{0x01};
    t.peers_version = version;
    proto::TunnelPeer p{};
    p.vtep.back() = std::byte{0x02};
    p.key.fill(std::byte{0x09});
    t.peers.push_back(p);
    t.signature.fill(good_sig);
    auto b = proto::encode_tunnel_peers(t);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto open_store(helm::Flash& f, helm::StoreAnchor& a) -> helm::SealedStore {
    auto s = helm::SealedStore::open(f, a);
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

auto make_anchor() -> std::unique_ptr<helm::SoftwareStoreAnchor> {
    auto a = helm::SoftwareStoreAnchor::ephemeral();
    BOOST_REQUIRE(a.has_value());
    return std::move(*a);
}

auto stored_frames(const helm::SealedStore& store) -> std::size_t {
    return static_cast<std::size_t>(std::ranges::count_if(store.names(), [](const auto& n) {
        return std::string_view{n}.starts_with(helm::standing_frame_prefix);
    }));
}

}  // namespace

BOOST_AUTO_TEST_SUITE(frames, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(nothing_pinned_keeps_nothing) {
    FakeVerifier v;
    helm::StandingFrames f{server, nullptr, &v};
    BOOST_TEST(f.load(nullptr) == 0U);
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::not_standing));
    f.retain(nullptr);
    BOOST_TEST(f.frames().empty());
}

BOOST_AUTO_TEST_CASE(only_frames_for_standing_nics_are_kept) {
    FakeVerifier v;
    helm::StandingFrames f{server, nullptr, &v};
    const auto set = standing();
    (void)f.load(&set);
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::kept));
    BOOST_TEST((f.offer(RecordType::vpc_config, vpc(vni, 1)) == FrameVerdict::kept));
    BOOST_TEST(
        (f.offer(RecordType::instance_metadata, metadata(nic, vni, 1)) == FrameVerdict::kept));
    BOOST_TEST((f.offer(RecordType::tunnel_peers, peers(1)) == FrameVerdict::kept));
    // Another VNI, another NIC, or the NIC on a VNI it is not on.
    BOOST_TEST((f.offer(RecordType::map_update, map(other_vni, 1)) == FrameVerdict::not_standing));
    BOOST_TEST((f.offer(RecordType::vpc_config, vpc(other_vni, 1)) == FrameVerdict::not_standing));
    BOOST_TEST((f.offer(RecordType::instance_metadata, metadata(nic + 1, vni, 1)) ==
                FrameVerdict::not_standing));
    BOOST_TEST((f.offer(RecordType::instance_metadata, metadata(nic, other_vni, 1)) ==
                FrameVerdict::not_standing));
    // A kind not kept.
    BOOST_TEST((f.offer(RecordType::volume_key, map(vni, 2)) == FrameVerdict::not_standing));
    BOOST_TEST(f.size() == 4U);
}

BOOST_AUTO_TEST_CASE(only_newer_signed_frames_for_this_server_are_kept) {
    FakeVerifier v;
    helm::StandingFrames f{server, nullptr, &v};
    const auto set = standing();
    (void)f.load(&set);
    BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 2)) == FrameVerdict::kept));
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 2)) == FrameVerdict::stale));
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::stale));
    BOOST_TEST(
        (f.offer(RecordType::map_update, map(vni, 3, bad_sig)) == FrameVerdict::bad_signature));
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 3, good_sig, server + 1)) ==
                FrameVerdict::wrong_server));
    const std::vector<std::byte> junk(8, std::byte{0xEE});
    BOOST_TEST((f.offer(RecordType::map_update, junk) == FrameVerdict::corrupt));
    const auto three = map(vni, 3);
    BOOST_TEST((f.offer(RecordType::map_update, three) == FrameVerdict::kept));
    BOOST_REQUIRE(f.frames().size() == 1U);
    BOOST_TEST((f.frames()[0].frame == three));

    helm::StandingFrames unverified{server, nullptr, nullptr};
    (void)unverified.load(&set);
    BOOST_TEST(
        (unverified.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::bad_signature));
}

BOOST_AUTO_TEST_CASE(frames_survive_a_restart_in_replay_order) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = make_anchor();
    FakeVerifier v;
    const auto set = standing();
    const auto m = metadata(nic, vni, 4);
    const auto u = map(vni, 3);
    const auto c = vpc(vni, 2);
    const auto p = peers(1);
    {
        auto store = open_store(flash, *anchor);
        helm::StandingFrames f{server, &store, &v};
        (void)f.load(&set);
        // Offered in the wrong order; replayed in the right one.
        BOOST_REQUIRE((f.offer(RecordType::instance_metadata, m) == FrameVerdict::kept));
        BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::kept));
        BOOST_REQUIRE((f.offer(RecordType::map_update, u) == FrameVerdict::kept));
        BOOST_REQUIRE((f.offer(RecordType::vpc_config, c) == FrameVerdict::kept));
        BOOST_REQUIRE((f.offer(RecordType::tunnel_peers, p) == FrameVerdict::kept));
        BOOST_TEST(stored_frames(store) == 4U);  // one object per frame
    }
    auto store = open_store(flash, *anchor);
    helm::StandingFrames f{server, &store, &v};
    BOOST_TEST(f.load(&set) == 4U);
    const auto out = f.frames();
    BOOST_REQUIRE(out.size() == 4U);
    BOOST_TEST((out[0] == helm::StandingFrame{.type = RecordType::tunnel_peers, .frame = p}));
    BOOST_TEST((out[1] == helm::StandingFrame{.type = RecordType::vpc_config, .frame = c}));
    BOOST_TEST((out[2] == helm::StandingFrame{.type = RecordType::map_update, .frame = u}));
    BOOST_TEST((out[3] == helm::StandingFrame{.type = RecordType::instance_metadata, .frame = m}));
    // The stored versions still bound what is newer.
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 3)) == FrameVerdict::stale));
}

BOOST_AUTO_TEST_CASE(a_new_set_drops_the_frames_of_nics_it_no_longer_names) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = make_anchor();
    FakeVerifier v;
    auto store = open_store(flash, *anchor);
    helm::StandingFrames f{server, &store, &v};
    const auto set = standing();
    (void)f.load(&set);
    BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::kept));
    BOOST_REQUIRE((f.offer(RecordType::tunnel_peers, peers(1)) == FrameVerdict::kept));
    f.retain(&set);  // the same NICs: nothing changes
    BOOST_TEST(f.size() == 2U);
    const auto unpinned = standing(false);
    f.retain(&unpinned);
    BOOST_TEST(f.size() == 0U);
    BOOST_TEST(stored_frames(store) == 0U);
    BOOST_TEST((f.offer(RecordType::map_update, map(vni, 2)) == FrameVerdict::not_standing));
}

BOOST_AUTO_TEST_CASE(load_drops_frames_that_no_longer_verify_or_belong) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = make_anchor();
    FakeVerifier v;
    const auto set = standing();
    {
        auto store = open_store(flash, *anchor);
        helm::StandingFrames f{server, &store, &v};
        (void)f.load(&set);
        BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::kept));
        BOOST_REQUIRE((f.offer(RecordType::vpc_config, vpc(vni, 1)) == FrameVerdict::kept));
    }
    {
        // Stored under a set whose NIC moved to another VNI: the old VNI's
        // frames go.
        auto store = open_store(flash, *anchor);
        auto moved = set;
        moved.instances[0].nics[0].vni = other_vni;
        helm::StandingFrames f{server, &store, &v};
        BOOST_TEST(f.load(&moved) == 0U);
        BOOST_TEST(stored_frames(store) == 0U);
    }
    {
        auto store = open_store(flash, *anchor);
        helm::StandingFrames f{server, &store, &v};
        (void)f.load(&set);
        BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 2)) == FrameVerdict::kept));
    }
    // The controller key retired since: nothing stored verifies.
    v.retired = true;
    auto store = open_store(flash, *anchor);
    helm::StandingFrames f{server, &store, &v};
    BOOST_TEST(f.load(&set) == 0U);
    BOOST_TEST(stored_frames(store) == 0U);
}

// Requirement 1.5: a rolled-back store may hold older frames; none is kept.
BOOST_AUTO_TEST_CASE(a_rolled_back_store_loses_its_frames) {
    helm::MemoryFlash flash{flash_size};
    auto anchor = make_anchor();
    FakeVerifier v;
    const auto set = standing();
    std::vector<std::byte> old_copy;
    {
        auto store = open_store(flash, *anchor);
        helm::StandingFrames f{server, &store, &v};
        (void)f.load(&set);
        BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 1)) == FrameVerdict::kept));
        old_copy = flash.bytes();
        BOOST_REQUIRE((f.offer(RecordType::map_update, map(vni, 2)) == FrameVerdict::kept));
    }
    flash.bytes() = old_copy;
    auto store = open_store(flash, *anchor);
    BOOST_REQUIRE(store.rolled_back());
    helm::StandingFrames f{server, &store, &v};
    BOOST_TEST(f.load(&set) == 0U);
    BOOST_TEST(stored_frames(store) == 0U);
}

BOOST_AUTO_TEST_CASE(verdicts_name_themselves) {
    BOOST_TEST(std::string_view{helm::to_string(FrameVerdict::kept)} == "kept");
    BOOST_TEST(std::string_view{helm::to_string(FrameVerdict::not_standing)} ==
               "not for a standing NIC");
    BOOST_TEST(std::string_view{helm::to_string(FrameVerdict::store_failed)} ==
               "sealed store failed");
}

BOOST_AUTO_TEST_SUITE_END()
