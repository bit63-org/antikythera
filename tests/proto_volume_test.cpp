// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ Requirements 6.1-6.2, 12.2 and 13.4:
// the ReplicaConfig, VolumeOp and VolumeKey codecs, their canonical form,
// and their strict decode.

#define BOOST_TEST_MODULE proto_volume_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "proto/replica_config.hpp"
#include "proto/volume_key.hpp"
#include "proto/volume_op.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::uint8_t sig_fill = 0x5A;
constexpr std::size_t last = 15;
constexpr std::uint16_t hold_port = 7300;

// ReplicaConfig header offsets, for targeted corruption.
constexpr std::size_t off_version = 0x08;
constexpr std::size_t off_key_id = 0x0A;
constexpr std::size_t off_member_count = 0x0C;
constexpr std::size_t off_attachment_count = 0x0D;
constexpr std::size_t off_reserved = 0x0E;
constexpr std::size_t off_block_size = 0x38;
constexpr std::size_t off_flags = 0x3C;
constexpr std::size_t off_source = 0x58;
constexpr std::size_t off_members = proto::replica_config_header_size;

auto endpoint(std::uint8_t tag) -> proto::StorageEndpoint {
    proto::StorageEndpoint a{};
    a[0] = std::byte{ula_prefix};
    a[last] = std::byte{tag};
    return a;
}

auto member(std::uint64_t server, proto::ReplicaRole role) -> proto::ReplicaMember {
    return {.server_id = server,
            .endpoint = endpoint(static_cast<std::uint8_t>(server)),
            .port = hold_port,
            .role = role,
            .replica_gen = static_cast<std::uint32_t>(server)};
}

auto manifest(std::uint8_t tag) -> proto::ManifestName {
    proto::ManifestName m{};
    m[0] = std::byte{tag};
    m[proto::manifest_name_size - 1] = std::byte{tag};
    return m;
}

// Three members (server 0x21 primary), one read-write attachment on server
// 7 and one read-only on server 8, restored from a snapshot.
auto sample_config() -> proto::ReplicaConfig {
    proto::ReplicaConfig c{
        .key_id = 1,
        .server_id = 7,
        .volume_id = 0x100,
        .epoch = 9,
        .lineage_id = 0x1EE,
        .capacity_blocks = 1U << 18,
        .block_size = proto::block_size_4096,
        .flags = proto::replica_flags::impaired,
        .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16000, .burst_mib = 1000},
        .lease_ms = 4000,
        .resync_window_s = 900,
        .source = {.kind = proto::SourceKind::snapshot,
                   .store_id = 1,
                   .hydrate_mib_per_s = 300,
                   .manifest_name = manifest(0xAB)},
        .members = {member(0x21, proto::ReplicaRole::primary),
                    member(0x22, proto::ReplicaRole::secondary),
                    member(0x23, proto::ReplicaRole::joining)},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = 7,
                         .generation = 2,
                         .mode = proto::AttachMode::rw},
                        {.attachment_id = 0xA2,
                         .server_id = 8,
                         .generation = 1,
                         .mode = proto::AttachMode::ro}},
        .signature = {}};
    c.signature.fill(std::byte{sig_fill});
    return c;
}

auto encoded(const proto::ReplicaConfig& c) -> std::vector<std::byte> {
    auto b = proto::encode_replica_config(c);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto c = proto::decode_replica_config(b);
    BOOST_REQUIRE(!c.has_value());
    return c.error();
}

auto encode_error(const proto::ReplicaConfig& c) -> DecodeError {
    auto b = proto::encode_replica_config(c);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto le64_at(std::span<const std::byte> b, std::size_t off) -> std::uint64_t {
    ak::wire::Reader r{b.subspan(off)};
    return r.le64().value_or(0);
}

auto set_le32(std::vector<std::byte>& b, std::size_t off, std::uint32_t v) -> void {
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(off)};
    BOOST_REQUIRE(w.write(v, ak::wire::Order::little).has_value());
}

auto sample_op(proto::VolumeOpArgs args) -> proto::VolumeOp {
    proto::VolumeOp op{.key_id = 2,
                       .server_id = 0x21,
                       .volume_id = 0x100,
                       .epoch = 9,
                       .op_id = 0x0B,
                       .args = std::move(args),
                       .signature = {}};
    op.signature.fill(std::byte{sig_fill});
    return op;
}

auto every_op() -> std::vector<proto::VolumeOp> {
    return {
        sample_op(proto::SnapshotPrepare{.cut_id = 0xC07, .timeout_ms = 100}),
        sample_op(proto::SnapshotCommit{.cut_id = 0xC07, .uploader = 0x22}),
        sample_op(proto::SnapshotAbort{.cut_id = 0xC07}),
        sample_op(proto::SnapshotUpload{.cut_id = 0xC07, .store_id = 1, .parent_manifest = {}}),
        sample_op(proto::SnapshotUpload{
            .cut_id = 0xC07, .store_id = 1, .parent_manifest = manifest(0xAB)}),
        sample_op(
            proto::CloneVolume{.cut_id = 0xC08, .new_volume_id = 0x101, .new_replica_gen = 1}),
        sample_op(proto::ScrubVolume{.mib_per_s = 50}),
        sample_op(proto::DeleteReplica{.replica_gen = 0x21}),
    };
}

auto sample_key() -> proto::VolumeKey {
    proto::VolumeKey k{.server_id = 7,
                       .volume_id = 0x100,
                       .attachment_id = 0xA1,
                       .generation = 2,
                       .hpke_enc = {},
                       .wrapped_key = {}};
    k.hpke_enc.fill(std::byte{0x11});
    k.wrapped_key.fill(std::byte{0x22});
    return k;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(replica_config, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_canonically) {
    const auto c = sample_config();
    const auto b = encoded(c);
    BOOST_TEST(b.size() == proto::replica_config_size(3, 2));
    auto back = proto::decode_replica_config(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == c));
    BOOST_TEST((encoded(*back) == b));
    BOOST_TEST(proto::primary_member(*back)->server_id == 0x21U);
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian) {
    const auto b = encoded(sample_config());
    const std::string_view magic{"AKRCFG\0\0", 8};
    for (std::size_t i = 0; i < magic.size(); ++i) {
        BOOST_TEST(std::to_integer<char>(b[i]) == magic[i]);
    }
    BOOST_TEST(std::to_integer<int>(b[off_version]) == 1);
    BOOST_TEST(std::to_integer<int>(b[off_key_id]) == 1);
    BOOST_TEST(std::to_integer<int>(b[off_member_count]) == 3);
    BOOST_TEST(std::to_integer<int>(b[off_attachment_count]) == 2);
    BOOST_TEST(le64_at(b, 0x10) == 7U);                               // server_id
    BOOST_TEST(le64_at(b, 0x18) == 0x100U);                           // volume_id
    BOOST_TEST(le64_at(b, 0x20) == 9U);                               // epoch
    BOOST_TEST(le64_at(b, 0x28) == 0x1EEU);                           // lineage_id
    BOOST_TEST(le64_at(b, 0x30) == 1U << 18);                         // capacity_blocks
    BOOST_TEST(std::to_integer<int>(b[off_block_size + 1]) == 0x10);  // 4096
    BOOST_TEST(std::to_integer<int>(b[off_flags]) == 4);              // impaired
    BOOST_TEST(std::to_integer<int>(b[off_source]) == 1);             // snapshot
    BOOST_TEST(std::to_integer<int>(b[off_source + 16]) == 0xAB);     // manifest_name
    BOOST_TEST(le64_at(b, off_members) == 0x21U);
    BOOST_TEST(std::to_integer<int>(b[off_members + 0x08]) == ula_prefix);  // endpoint
    BOOST_TEST(std::to_integer<int>(b[off_members + 0x1A]) == 1);           // primary
    const std::size_t att = off_members + (3 * proto::replica_member_size);
    BOOST_TEST(le64_at(b, att) == 0xA1U);
    BOOST_TEST(le64_at(b, att + 8) == 7U);
    BOOST_TEST(std::to_integer<int>(b[att + 0x14]) == 1);  // rw
    BOOST_TEST(std::to_integer<int>(b[b.size() - 1]) == sig_fill);
    BOOST_TEST(proto::replica_config_signed_bytes(b).size() ==
               b.size() - proto::ed25519_signature_size);
}

BOOST_AUTO_TEST_CASE(set_signature_writes_the_trailer) {
    auto b = encoded(sample_config());
    std::array<std::byte, proto::ed25519_signature_size> sig{};
    sig.fill(std::byte{0x77});
    proto::set_replica_config_signature(b, sig);
    auto c = proto::decode_replica_config(b);
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST((c->signature == sig));
}

BOOST_AUTO_TEST_CASE(rules_are_enforced_both_ways) {
    struct Case {
        void (*mutate)(proto::ReplicaConfig&);
        DecodeError want;
    };
    const Case cases[] = {
        {[](proto::ReplicaConfig& c) { c.key_id = proto::no_key_id; }, DecodeError::bad_key_id},
        {[](proto::ReplicaConfig& c) { c.server_id = 0; }, DecodeError::bad_server_id},
        {[](proto::ReplicaConfig& c) { c.volume_id = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaConfig& c) { c.lineage_id = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaConfig& c) { c.capacity_blocks = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaConfig& c) { c.lease_ms = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaConfig& c) { c.epoch = 0; }, DecodeError::bad_epoch},
        {[](proto::ReplicaConfig& c) { c.block_size = 1024; }, DecodeError::bad_block_size},
        {[](proto::ReplicaConfig& c) { c.flags = 0x10; }, DecodeError::reserved_not_zero},
        {[](proto::ReplicaConfig& c) { c.qos.iops = 0; }, DecodeError::bad_qos},
        {[](proto::ReplicaConfig& c) { c.qos.mib_per_s = 0; }, DecodeError::bad_qos},
        {[](proto::ReplicaConfig& c) { c.qos.burst_iops = c.qos.iops - 1; }, DecodeError::bad_qos},
        {[](proto::ReplicaConfig& c) { c.qos.burst_mib = c.qos.mib_per_s - 1; },
         DecodeError::bad_qos},
        {[](proto::ReplicaConfig& c) { c.source.kind = static_cast<proto::SourceKind>(3); },
         DecodeError::unknown_value},
        {[](proto::ReplicaConfig& c) { c.source.store_id = 0; }, DecodeError::bad_source},
        {[](proto::ReplicaConfig& c) { c.source.hydrate_mib_per_s = 0; }, DecodeError::bad_source},
        {[](proto::ReplicaConfig& c) { c.source.manifest_name = {}; }, DecodeError::bad_source},
        {[](proto::ReplicaConfig& c) { c.source.kind = proto::SourceKind::none; },
         DecodeError::bad_source},
        {[](proto::ReplicaConfig& c) { c.members.clear(); }, DecodeError::too_many_members},
        {[](proto::ReplicaConfig& c) {
             for (std::uint64_t s = 0x24; s <= 0x26; ++s) {
                 c.members.push_back(member(s, proto::ReplicaRole::secondary));
             }
         },
         DecodeError::too_many_members},
        {[](proto::ReplicaConfig& c) { c.members[1].role = static_cast<proto::ReplicaRole>(0); },
         DecodeError::unknown_value},
        {[](proto::ReplicaConfig& c) { c.members[1].server_id = 0; }, DecodeError::bad_server_id},
        {[](proto::ReplicaConfig& c) { c.members[1].endpoint = {}; }, DecodeError::bad_member},
        {[](proto::ReplicaConfig& c) { c.members[1].endpoint[0] = std::byte{0xFF}; },
         DecodeError::bad_member},
        {[](proto::ReplicaConfig& c) { c.members[1].port = 0; }, DecodeError::bad_member},
        {[](proto::ReplicaConfig& c) { c.members[1].replica_gen = 0; }, DecodeError::bad_member},
        {[](proto::ReplicaConfig& c) { std::swap(c.members[0], c.members[1]); },
         DecodeError::not_ascending},
        {[](proto::ReplicaConfig& c) { c.members[2].server_id = c.members[1].server_id; },
         DecodeError::not_ascending},
        {[](proto::ReplicaConfig& c) { c.members[1].role = proto::ReplicaRole::primary; },
         DecodeError::bad_roles},
        {[](proto::ReplicaConfig& c) { c.members[0].role = proto::ReplicaRole::secondary; },
         DecodeError::bad_roles},
        {[](proto::ReplicaConfig& c) {
             c.members[1].role = proto::ReplicaRole::primary;
             c.flags |= proto::replica_flags::io_suspended;
         },
         DecodeError::bad_roles},
        {[](proto::ReplicaConfig& c) {
             c.attachments.resize(proto::max_volume_attachments + 1, c.attachments[1]);
         },
         DecodeError::too_many_attachments},
        {[](proto::ReplicaConfig& c) { c.attachments[0].mode = static_cast<proto::AttachMode>(3); },
         DecodeError::unknown_value},
        {[](proto::ReplicaConfig& c) { c.attachments[0].attachment_id = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaConfig& c) { c.attachments[0].generation = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaConfig& c) { c.attachments[0].server_id = 0; },
         DecodeError::bad_server_id},
        {[](proto::ReplicaConfig& c) { std::swap(c.attachments[0], c.attachments[1]); },
         DecodeError::not_ascending},
        {[](proto::ReplicaConfig& c) { c.attachments[1].mode = proto::AttachMode::rw; },
         DecodeError::bad_attachment_mode},
    };
    for (const auto& c : cases) {
        auto cfg = sample_config();
        c.mutate(cfg);
        BOOST_TEST((encode_error(cfg) == c.want));
    }

    // The decoder enforces the same rules on bytes the encoder refused to
    // make: patch a good frame so the secondary claims to be primary too.
    auto b = encoded(sample_config());
    b[off_members + proto::replica_member_size + 0x1A] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::bad_roles));
}

BOOST_AUTO_TEST_CASE(accepted_edge_cases) {
    // io_suspended with no primary, two writers with multi_attach, a
    // fresh volume with no source and no attachments, 512-byte blocks.
    auto c = sample_config();
    c.flags = proto::replica_flags::io_suspended | proto::replica_flags::impaired;
    c.members[0].role = proto::ReplicaRole::secondary;
    BOOST_TEST(proto::decode_replica_config(encoded(c)).has_value());
    BOOST_TEST(proto::primary_member(c) == nullptr);

    c = sample_config();
    c.flags = proto::replica_flags::multi_attach;
    c.attachments[1].mode = proto::AttachMode::rw;
    BOOST_TEST(proto::decode_replica_config(encoded(c)).has_value());

    c = sample_config();
    c.source = {};
    c.attachments.clear();
    c.block_size = proto::block_size_512;
    c.members.resize(1);
    const auto b = encoded(c);
    BOOST_TEST(b.size() == proto::replica_config_size(1, 0));
    auto back = proto::decode_replica_config(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == c));

    c = sample_config();
    for (std::uint64_t s = 0x24; s <= 0x25; ++s) {
        c.members.push_back(member(s, proto::ReplicaRole::leaving));
    }
    c.attachments.clear();
    for (std::uint64_t a = 1; a <= proto::max_volume_attachments; ++a) {
        c.attachments.push_back(
            {.attachment_id = a, .server_id = a, .generation = 1, .mode = proto::AttachMode::ro});
    }
    BOOST_TEST(encoded(c).size() == proto::max_replica_config_size);
}

BOOST_AUTO_TEST_CASE(header_and_reserved_bytes) {
    const auto good = encoded(sample_config());
    auto b = good;
    b[7] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[off_version] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    const std::size_t att = off_members + (3 * proto::replica_member_size);
    for (const std::size_t off :
         {off_reserved, off_reserved + 1, off_source + 1, off_source + 3, off_source + 12,
          off_source + 15, off_members + 0x1B, att + 0x15, att + 0x17}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
    b = good;
    set_le32(b, off_flags, 0x8000'0000);
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(lengths_and_hostile_counts) {
    const auto good = encoded(sample_config());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));

    b = good;
    b[off_member_count] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_members));
    b[off_member_count] = std::byte{6};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_members));
    b = good;
    b[off_attachment_count] = std::byte{17};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_attachments));
    b = good;
    b[off_attachment_count] = std::byte{3};
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
    b = good;
    b[off_attachment_count] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(volume_op, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(every_kind_round_trips_canonically) {
    std::uint8_t kind = 0;
    for (const auto& op : every_op()) {
        auto b = proto::encode_volume_op(op);
        BOOST_REQUIRE(b.has_value());
        BOOST_TEST(b->size() == proto::volume_op_size);
        auto back = proto::decode_volume_op(*b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == op));
        auto again = proto::encode_volume_op(*back);
        BOOST_REQUIRE(again.has_value());
        BOOST_TEST((*again == *b));
        // Kinds are numbered in variant order (the upload appears twice).
        const auto k = std::to_integer<std::uint8_t>((*b)[0x28]);
        BOOST_TEST(k >= kind);
        kind = k;
        BOOST_TEST(k == static_cast<std::uint8_t>(proto::volume_op_kind(op.args)));
    }
    BOOST_TEST(kind == static_cast<std::uint8_t>(proto::VolumeOpKind::delete_replica));
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian) {
    auto b = proto::encode_volume_op(sample_op(
        proto::CloneVolume{.cut_id = 0xC08, .new_volume_id = 0x101, .new_replica_gen = 1}));
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(std::to_integer<char>((*b)[0]) == 'A');
    BOOST_TEST(std::to_integer<char>((*b)[3]) == 'O');
    BOOST_TEST(std::to_integer<int>((*b)[6]) == 2);     // key_id
    BOOST_TEST(le64_at(*b, 0x08) == 0x21U);             // server_id
    BOOST_TEST(le64_at(*b, 0x10) == 0x100U);            // volume_id
    BOOST_TEST(le64_at(*b, 0x18) == 9U);                // epoch
    BOOST_TEST(le64_at(*b, 0x20) == 0x0BU);             // op_id
    BOOST_TEST(std::to_integer<int>((*b)[0x28]) == 5);  // clone
    BOOST_TEST(le64_at(*b, 0x30) == 0xC08U);            // cut_id
    BOOST_TEST(le64_at(*b, 0x38) == 0x101U);            // new_volume_id
    BOOST_TEST(std::to_integer<int>((*b)[0x40]) == 1);  // new_replica_gen
    BOOST_TEST(proto::volume_op_signed_bytes(*b).size() == 0x60U);
}

BOOST_AUTO_TEST_CASE(rules_are_enforced_both_ways) {
    const std::pair<proto::VolumeOp, DecodeError> cases[] = {
        {[] {
             auto op = sample_op(proto::SnapshotAbort{.cut_id = 1});
             op.key_id = 0;
             return op;
         }(),
         DecodeError::bad_key_id},
        {[] {
             auto op = sample_op(proto::SnapshotAbort{.cut_id = 1});
             op.server_id = 0;
             return op;
         }(),
         DecodeError::bad_server_id},
        {[] {
             auto op = sample_op(proto::SnapshotAbort{.cut_id = 1});
             op.epoch = 0;
             return op;
         }(),
         DecodeError::bad_epoch},
        {[] {
             auto op = sample_op(proto::SnapshotAbort{.cut_id = 1});
             op.volume_id = 0;
             return op;
         }(),
         DecodeError::bad_id},
        {[] {
             auto op = sample_op(proto::SnapshotAbort{.cut_id = 1});
             op.op_id = 0;
             return op;
         }(),
         DecodeError::bad_id},
        {sample_op(proto::SnapshotPrepare{.cut_id = 0, .timeout_ms = 1}), DecodeError::bad_id},
        {sample_op(proto::SnapshotPrepare{.cut_id = 1, .timeout_ms = 0}), DecodeError::bad_id},
        {sample_op(proto::SnapshotCommit{.cut_id = 1, .uploader = 0}), DecodeError::bad_id},
        {sample_op(proto::SnapshotAbort{.cut_id = 0}), DecodeError::bad_id},
        {sample_op(proto::SnapshotUpload{.cut_id = 1, .store_id = 0, .parent_manifest = {}}),
         DecodeError::bad_id},
        {sample_op(proto::CloneVolume{.cut_id = 1, .new_volume_id = 0, .new_replica_gen = 1}),
         DecodeError::bad_id},
        {sample_op(proto::CloneVolume{.cut_id = 1, .new_volume_id = 1, .new_replica_gen = 0}),
         DecodeError::bad_id},
        {sample_op(proto::ScrubVolume{.mib_per_s = 0}), DecodeError::bad_id},
        {sample_op(proto::DeleteReplica{.replica_gen = 0}), DecodeError::bad_id},
    };
    for (const auto& [op, want] : cases) {
        auto b = proto::encode_volume_op(op);
        BOOST_REQUIRE(!b.has_value());
        BOOST_TEST((b.error() == want));
    }

    // Decode: patch a good frame so the scrub rate is 0.
    auto b = proto::encode_volume_op(sample_op(proto::ScrubVolume{.mib_per_s = 1}));
    BOOST_REQUIRE(b.has_value());
    (*b)[0x30] = std::byte{0};
    auto op = proto::decode_volume_op(*b);
    BOOST_REQUIRE(!op.has_value());
    BOOST_TEST((op.error() == DecodeError::bad_id));
}

BOOST_AUTO_TEST_CASE(strict_decode) {
    auto good =
        proto::encode_volume_op(sample_op(proto::SnapshotPrepare{.cut_id = 1, .timeout_ms = 100}));
    BOOST_REQUIRE(good.has_value());
    const auto refused = [](std::span<const std::byte> b) {
        auto op = proto::decode_volume_op(b);
        BOOST_REQUIRE(!op.has_value());
        return op.error();
    };
    for (std::size_t n = 0; n < good->size(); ++n) {
        BOOST_TEST((refused(std::span{*good}.first(n)) == DecodeError::truncated));
    }
    auto b = *good;
    b.push_back(std::byte{0});
    BOOST_TEST((refused(b) == DecodeError::trailing_bytes));
    b = *good;
    b[0] = std::byte{0};
    BOOST_TEST((refused(b) == DecodeError::bad_magic));
    b = *good;
    b[4] = std::byte{2};
    BOOST_TEST((refused(b) == DecodeError::bad_version));
    for (const std::uint8_t kind : {std::uint8_t{0}, std::uint8_t{8}, std::uint8_t{0xFF}}) {
        b = *good;
        b[0x28] = std::byte{kind};
        BOOST_TEST((refused(b) == DecodeError::unknown_value));
    }
    // Header padding, and args bytes the kind does not use.
    for (const std::size_t off : {0x29U, 0x2FU, 0x3CU, 0x5FU}) {
        b = *good;
        b[off] = std::byte{1};
        BOOST_TEST((refused(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
    // snapshot_upload's own reserved word.
    auto up = proto::encode_volume_op(
        sample_op(proto::SnapshotUpload{.cut_id = 1, .store_id = 1, .parent_manifest = {}}));
    BOOST_REQUIRE(up.has_value());
    (*up)[0x3C] = std::byte{1};
    BOOST_TEST((refused(*up) == DecodeError::reserved_not_zero));
    // A relabelled kind: abort's bytes read as delete_replica see the cut
    // ID's low word as replica_gen and its high bytes as padding.
    b = proto::encode_volume_op(sample_op(proto::SnapshotAbort{.cut_id = 0x1'0000'0001})).value();
    b[0x28] = std::byte{static_cast<std::uint8_t>(proto::VolumeOpKind::delete_replica)};
    BOOST_TEST((refused(b) == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(volume_key, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_and_lays_out) {
    const auto k = sample_key();
    auto b = proto::encode_volume_key(k);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::volume_key_size);
    BOOST_TEST(proto::volume_key_size == 0x98U);
    BOOST_TEST(std::to_integer<char>((*b)[3]) == 'K');
    BOOST_TEST(le64_at(*b, 0x08) == 7U);
    BOOST_TEST(le64_at(*b, 0x10) == 0x100U);
    BOOST_TEST(le64_at(*b, 0x18) == 0xA1U);
    BOOST_TEST(std::to_integer<int>((*b)[0x20]) == 2);
    BOOST_TEST(std::to_integer<int>((*b)[0x28]) == 0x11);
    BOOST_TEST(std::to_integer<int>((*b)[0x48]) == 0x22);
    BOOST_TEST(std::to_integer<int>((*b)[0x97]) == 0x22);
    BOOST_TEST(proto::volume_key_aad(*b).size() == proto::volume_key_aad_size);
    auto back = proto::decode_volume_key(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == k));
}

BOOST_AUTO_TEST_CASE(strict_decode) {
    const auto good = proto::encode_volume_key(sample_key()).value();
    const auto refused = [](std::span<const std::byte> b) {
        auto k = proto::decode_volume_key(b);
        BOOST_REQUIRE(!k.has_value());
        return k.error();
    };
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((refused(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((refused(b) == DecodeError::trailing_bytes));
    b = good;
    b[1] = std::byte{0};
    BOOST_TEST((refused(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{0};
    BOOST_TEST((refused(b) == DecodeError::bad_version));
    for (const std::size_t off : {0x06U, 0x07U, 0x24U, 0x27U}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((refused(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
    const std::pair<std::size_t, DecodeError> ids[] = {
        {0x08, DecodeError::bad_server_id},
        {0x10, DecodeError::bad_id},
        {0x18, DecodeError::bad_id},
        {0x20, DecodeError::bad_id},
    };
    for (const auto& [off, want] : ids) {
        b = good;
        std::ranges::fill(std::span{b}.subspan(off, off == 0x20 ? 4 : 8), std::byte{0});
        BOOST_TEST((refused(b) == want), "offset " << off);
    }
    b = good;
    std::ranges::fill(std::span{b}.subspan(0x28, proto::hpke_enc_size), std::byte{0});
    BOOST_TEST((refused(b) == DecodeError::bad_id));

    auto k = sample_key();
    k.hpke_enc = {};
    BOOST_TEST((proto::encode_volume_key(k).error() == DecodeError::bad_id));
    k = sample_key();
    k.server_id = 0;
    BOOST_TEST((proto::encode_volume_key(k).error() == DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(errors_have_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (auto e :
         {DecodeError::bad_epoch, DecodeError::bad_block_size, DecodeError::bad_member,
          DecodeError::bad_roles, DecodeError::too_many_members, DecodeError::too_many_attachments,
          DecodeError::bad_attachment_mode, DecodeError::bad_qos, DecodeError::bad_source}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}
