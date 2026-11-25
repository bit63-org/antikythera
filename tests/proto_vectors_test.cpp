// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirements 1.1 and 5.2 and
// .kiro/specs/block-volume-service/ Requirement 13.4 (and kythira's khold
// Requirement 11.5 for the volume layout): the signing test
// vectors in src/proto/test_vectors.hpp. For each vector this checks
// that encoding the listed fields and signing with the listed RFC 8032 key
// reproduces the bytes exactly, that the frame decodes back to the fields,
// and that the signature verifies under hull's verifier.

#define BOOST_TEST_MODULE proto_vectors_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/envelope.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"
#include "proto/test_vectors.hpp"
#include "proto/volume_layout.hpp"
#include "proto/volume_op.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
namespace vec = ak::proto::vectors;
using ak::test::from_hex;
using ak::test::TestSigner;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::uint8_t local_unicast = 0x02;
constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::uint64_t map2_nic_a = 0x10;
constexpr std::uint64_t map2_nic_b = 0x11;
constexpr std::size_t last = 15;
constexpr std::uint8_t guest_net = 10;
constexpr std::uint8_t guest_ula_second = 0x12;
constexpr std::uint16_t rcfg4_port = 7300;
constexpr std::uint16_t layout6_port = 7400;

auto verifier() -> ak::hull::SignatureVerifier {
    const std::array keys{ak::test::controller_key(vec::envelope1_key_id, vec::key1_public),
                          ak::test::controller_key(vec::map0_key_id, vec::key2_public)};
    auto v = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(v.has_value());
    return std::move(*v);
}

auto map2_entry(std::uint64_t nic, std::uint8_t vtep_last, bool source_dest_check = true)
    -> proto::MapEntry {
    proto::MapEntry e{.nic_id = nic};
    e.source_dest_check = source_dest_check;
    e.mac[0] = std::byte{local_unicast};
    e.mac[proto::mac_size - 1] = std::byte{static_cast<std::uint8_t>(nic)};
    e.owner_vtep[0] = std::byte{ula_prefix};
    e.owner_vtep[last] = std::byte{vtep_last};
    return e;
}

// 10.0.0.<nic> and fd12::<nic>: the guest addresses in vector 2.
auto guest_ipv4(std::uint64_t nic) -> proto::GuestIpv4 {
    return {.nic_id = nic,
            .address = {std::byte{guest_net}, {}, {}, std::byte{static_cast<std::uint8_t>(nic)}}};
}

auto guest_ipv6(std::uint64_t nic) -> proto::GuestIpv6 {
    proto::GuestIpv6 g{.nic_id = nic, .address = {}};
    g.address[0] = std::byte{ula_prefix};
    g.address[1] = std::byte{guest_ula_second};
    g.address[last] = std::byte{static_cast<std::uint8_t>(nic)};
    return g;
}

auto signed_map_update(const proto::MapUpdate& m, const TestSigner& signer)
    -> std::vector<std::byte> {
    auto frame = proto::encode_map_update(m);
    BOOST_REQUIRE(frame.has_value());
    const auto sig = signer.sign(proto::map_update_signed_bytes(*frame));
    proto::set_map_update_signature(*frame, sig);
    return *frame;
}

auto check_map_vector(std::string_view frame_hex, std::string_view sig_hex,
                      const proto::MapUpdate& fields, const TestSigner& signer) -> void {
    const auto want = from_hex(frame_hex);
    BOOST_TEST(signed_map_update(fields, signer) == want);
    BOOST_TEST(
        std::ranges::equal(std::span{want}.last(proto::ed25519_signature_size), from_hex(sig_hex)));

    auto m = proto::decode_map_update(want);
    BOOST_REQUIRE(m.has_value());
    auto expect = fields;
    std::ranges::copy(from_hex(sig_hex), expect.signature.begin());
    BOOST_TEST((*m == expect));

    const auto v = verifier();
    const auto sig = std::span<const std::byte, proto::ed25519_signature_size>{m->signature};
    BOOST_TEST(v.verify(proto::map_update_signed_bytes(want), sig, m->key_id).has_value());
    // The key ID is signed: the same bytes under the other key fail.
    const proto::KeyId other = m->key_id == vec::map2_key_id ? vec::map0_key_id : vec::map2_key_id;
    BOOST_TEST(!v.verify(proto::map_update_signed_bytes(want), sig, other).has_value());
}

// Checks a signed frame vector: encoding `frame` and signing it with
// `signer` reproduces the bytes, decoding gives the fields back, and the
// signature verifies under its key_id and fails under the other one.
template<typename Frame, typename Encode, typename Decode, typename Signed, typename SetSig>
auto check_signed_vector(std::string_view frame_hex, std::string_view sig_hex, const Frame& fields,
                         const TestSigner& signer, Encode encode, Decode decode,
                         Signed signed_bytes, SetSig set_signature) -> void {
    const auto want = from_hex(frame_hex);
    auto frame = encode(fields);
    BOOST_REQUIRE(frame.has_value());
    set_signature(*frame, signer.sign(signed_bytes(*frame)));
    BOOST_TEST(*frame == want);
    BOOST_TEST(
        std::ranges::equal(std::span{want}.last(proto::ed25519_signature_size), from_hex(sig_hex)));

    auto got = decode(want);
    BOOST_REQUIRE(got.has_value());
    auto expect = fields;
    std::ranges::copy(from_hex(sig_hex), expect.signature.begin());
    BOOST_TEST((*got == expect));

    const auto v = verifier();
    const auto sig = std::span<const std::byte, proto::ed25519_signature_size>{got->signature};
    BOOST_TEST(v.verify(signed_bytes(want), sig, got->key_id).has_value());
    const proto::KeyId other =
        got->key_id == vec::envelope1_key_id ? vec::map0_key_id : vec::envelope1_key_id;
    BOOST_TEST(!v.verify(signed_bytes(want), sig, other).has_value());
}

auto rcfg4_member(std::uint64_t server, proto::ReplicaRole role) -> proto::ReplicaMember {
    proto::ReplicaMember m{
        .server_id = server, .endpoint = {}, .port = rcfg4_port, .role = role, .replica_gen = 1};
    m.endpoint[0] = std::byte{ula_prefix};
    m.endpoint[last] = std::byte{static_cast<std::uint8_t>(server)};
    return m;
}

auto layout6_member(std::uint64_t server, proto::MemberKind kind, std::uint8_t drive)
    -> proto::LayoutMember {
    proto::LayoutMember m{
        .server_id = server, .endpoint = {}, .port = layout6_port, .kind = kind, .drive = drive};
    m.endpoint[0] = std::byte{ula_prefix};
    m.endpoint[last] = std::byte{static_cast<std::uint8_t>(server)};
    return m;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(vectors, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(vector_keys_are_rfc8032_test_keys) {
    BOOST_TEST(vec::key1_secret == ak::test::rfc_test1_secret);
    BOOST_TEST(vec::key1_public == ak::test::rfc_test1_public);
    BOOST_TEST(vec::key2_secret == ak::test::rfc_test2_secret);
    BOOST_TEST(vec::key2_public == ak::test::rfc_test2_public);
}

BOOST_AUTO_TEST_CASE(envelope1_reproduces_and_hull_accepts_it) {
    const TestSigner signer{vec::key1_secret};
    const auto body = mb::encode_body(mb::CreateVm{.vm_id = vec::envelope1_vm_id,
                                                   .vcpus = vec::envelope1_vcpus,
                                                   .memory_mib = vec::envelope1_memory_mib,
                                                   .boot_mode = mb::BootMode::volume});
    const mb::Header h{.type = mb::Type::create_vm,
                       .seq = vec::envelope1_seq,
                       .body_len = static_cast<std::uint16_t>(body.size()),
                       .key_id = vec::envelope1_key_id,
                       .server_id = vec::envelope1_server_id};
    const auto slot = signer.signed_slot(h, body);
    auto bytes = proto::encode_envelope(
        {.server_id = vec::envelope1_server_id, .key_id = vec::envelope1_key_id, .slot = slot});
    BOOST_REQUIRE(bytes.has_value());

    const auto want = from_hex(vec::envelope1);
    BOOST_TEST(std::ranges::equal(*bytes, want));
    BOOST_TEST(std::ranges::equal(std::span{slot}.subspan(mb::signature_offset),
                                  from_hex(vec::envelope1_signature)));

    auto env = proto::decode_envelope(want);
    BOOST_REQUIRE(env.has_value());
    BOOST_TEST(env->server_id == vec::envelope1_server_id);
    BOOST_TEST(env->key_id == vec::envelope1_key_id);
    BOOST_TEST(proto::slot_seq(env->slot) == vec::envelope1_seq);
    BOOST_TEST(proto::slot_server_id(env->slot) == vec::envelope1_server_id);

    // What helm relays is what hull checks: a strict slot decode, then the
    // signature under the key the signed slot header names.
    auto msg = mb::decode(env->slot);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.key_id == vec::envelope1_key_id);
    BOOST_TEST(msg->header.server_id == vec::envelope1_server_id);
    BOOST_TEST(verifier().verify_slot(env->slot, msg->header.key_id).has_value());
}

BOOST_AUTO_TEST_CASE(map2_reproduces_and_verifies) {
    check_map_vector(vec::map2, vec::map2_signature,
                     {.server_id = vec::map2_server_id,
                      .key_id = vec::map2_key_id,
                      .vni = vec::map2_vni,
                      .map_version = vec::map2_map_version,
                      .entries = {map2_entry(map2_nic_a, 1), map2_entry(map2_nic_b, 2, false)},
                      .ipv4 = {guest_ipv4(map2_nic_a), guest_ipv4(map2_nic_b)},
                      .ipv6 = {guest_ipv6(map2_nic_a)},
                      .signature = {}},
                     TestSigner{vec::key1_secret});
}

BOOST_AUTO_TEST_CASE(map0_reproduces_and_verifies) {
    check_map_vector(vec::map0, vec::map0_signature,
                     {.server_id = vec::map0_server_id,
                      .key_id = vec::map0_key_id,
                      .vni = vec::map0_vni,
                      .map_version = vec::map0_map_version,
                      .entries = {},
                      .ipv4 = {},
                      .ipv6 = {},
                      .signature = {}},
                     TestSigner{vec::key2_secret});
}

BOOST_AUTO_TEST_CASE(rcfg4_reproduces_and_verifies) {
    const proto::ReplicaConfig fields{
        .key_id = vec::rcfg4_key_id,
        .server_id = vec::rcfg4_server_id,
        .volume_id = vec::rcfg4_volume_id,
        .epoch = vec::rcfg4_epoch,
        .lineage_id = 0x1EE,
        .capacity_blocks = 1U << 18,
        .block_size = proto::block_size_4096,
        .flags = proto::replica_flags::multi_attach,
        .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16000, .burst_mib = 1000},
        .lease_ms = 4000,
        .resync_window_s = 900,
        .source = {},
        .members = {rcfg4_member(0x21, proto::ReplicaRole::primary),
                    rcfg4_member(0x22, proto::ReplicaRole::secondary)},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = 7,
                         .generation = 2,
                         .mode = proto::AttachMode::rw},
                        {.attachment_id = 0xA2,
                         .server_id = 8,
                         .generation = 1,
                         .mode = proto::AttachMode::rw}},
        .signature = {}};
    check_signed_vector(
        vec::rcfg4, vec::rcfg4_signature, fields, TestSigner{vec::key1_secret},
        [](const proto::ReplicaConfig& c) { return proto::encode_replica_config(c); },
        [](std::span<const std::byte> b) { return proto::decode_replica_config(b); },
        [](std::span<const std::byte> b) { return proto::replica_config_signed_bytes(b); },
        [](std::span<std::byte> b, const auto& sig) {
            proto::set_replica_config_signature(b, sig);
        });
}

BOOST_AUTO_TEST_CASE(vop5_reproduces_and_verifies) {
    const proto::VolumeOp fields{
        .key_id = vec::vop5_key_id,
        .server_id = vec::vop5_server_id,
        .volume_id = vec::vop5_volume_id,
        .epoch = vec::vop5_epoch,
        .op_id = vec::vop5_op_id,
        .args = proto::SnapshotCommit{.cut_id = vec::vop5_cut_id, .uploader = vec::vop5_server_id},
        .signature = {}};
    check_signed_vector(
        vec::vop5, vec::vop5_signature, fields, TestSigner{vec::key2_secret},
        [](const proto::VolumeOp& op) { return proto::encode_volume_op(op); },
        [](std::span<const std::byte> b) { return proto::decode_volume_op(b); },
        [](std::span<const std::byte> b) { return proto::volume_op_signed_bytes(b); },
        [](std::span<std::byte> b, const auto& sig) { proto::set_volume_op_signature(b, sig); });
}

BOOST_AUTO_TEST_CASE(layout6_reproduces_and_verifies) {
    using K = proto::MemberKind;
    const proto::VolumeLayout fields{
        .key_id = vec::layout6_key_id,
        .server_id = vec::layout6_server_id,
        .volume_id = vec::layout6_volume_id,
        .epoch = vec::layout6_epoch,
        .lineage_id = 0x2EE,
        .capacity_blocks = 1U << 20,
        .block_size = proto::block_size_4096,
        .stripe_unit = 1U << 20,
        .flags = 0,
        .commit_rule = proto::CommitRule::all_in_sync,
        .group_skew_pct = 10,
        .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16000, .burst_mib = 1000},
        .timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900},
        .mirror = {},
        .groups = {{.group_id = 0x5001,
                    .members = {layout6_member(0x21, K::data, 0), layout6_member(0x22, K::data, 1),
                                layout6_member(0x23, K::witness, 0)}},
                   {.group_id = 0x5002,
                    .members = {layout6_member(0x22, K::data, 0), layout6_member(0x23, K::data, 1),
                                layout6_member(0x24, K::witness, 0)}}},
        .gateways = {},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = 7,
                         .generation = 2,
                         .mode = proto::AttachMode::rw}},
        .signature = {}};
    check_signed_vector(
        vec::layout6, vec::layout6_signature, fields, TestSigner{vec::key1_secret},
        [](const proto::VolumeLayout& l) { return proto::encode_volume_layout(l); },
        [](std::span<const std::byte> b) { return proto::decode_volume_layout(b); },
        [](std::span<const std::byte> b) { return proto::volume_layout_signed_bytes(b); },
        [](std::span<std::byte> b, const auto& sig) {
            proto::set_volume_layout_signature(b, sig);
        });
}

BOOST_AUTO_TEST_SUITE_END()
