// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kythira .kiro/specs/khold-block-service/ Requirements 3.1, 5.1, 5.2,
// 6.1-6.5 and 11.5 (task 2): the VolumeLayout codec. Layouts round-trip
// canonically; every decoder rule (stripe bounds, five members per group,
// at most one witness, at least one data member, distinct servers, unique
// groups, attachments, QoS, timings, mirror) is enforced both ways; and
// hostile counts are refused before they cost anything.

#define BOOST_TEST_MODULE proto_volume_layout_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "proto/volume_layout.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using K = proto::MemberKind;

namespace {

constexpr std::uint16_t port = 7400;
constexpr std::uint8_t ula = 0xFD;
constexpr std::size_t last = 15;
constexpr std::size_t off_width = 0x0C;
constexpr std::size_t off_gateways = 0x0E;
constexpr std::size_t off_attachments = 0x0F;
constexpr std::size_t off_reserved = 0x46;
constexpr std::size_t off_timing_reserved = 0x64;
constexpr std::size_t off_mirror_reserved = 0x6A;
constexpr std::size_t off_first_group = proto::volume_layout_header_size;

auto member(std::uint64_t server, K kind = K::data, std::uint8_t drive = 0) -> proto::LayoutMember {
    proto::LayoutMember m{
        .server_id = server, .endpoint = {}, .port = port, .kind = kind, .drive = drive};
    m.endpoint[0] = std::byte{ula};
    m.endpoint[last] = std::byte{static_cast<std::uint8_t>(server)};
    return m;
}

auto general_group(std::uint64_t id, std::uint64_t first) -> proto::StripeGroup {
    return {.group_id = id,
            .members = {member(first), member(first + 1), member(first + 2, K::witness)}};
}

auto sample() -> proto::VolumeLayout {
    proto::VolumeLayout l{
        .key_id = 1,
        .server_id = 0x21,
        .volume_id = 0x200,
        .epoch = 3,
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
        .groups = {general_group(0x5001, 0x21), general_group(0x5002, 0x22)},
        .gateways = {},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = 7,
                         .generation = 2,
                         .mode = proto::AttachMode::rw}},
        .signature = {}};
    l.signature[0] = std::byte{0x5A};
    return l;
}

// The largest layout format 1 allows.
auto biggest() -> proto::VolumeLayout {
    auto l = sample();
    l.flags = proto::layout_flags::multi_attach;
    l.groups.clear();
    for (std::uint64_t g = 0; g < proto::max_stripe_width; ++g) {
        l.groups.push_back({.group_id = 0x5000 + g,
                            .members = {member(1), member(2), member(3), member(4, K::learner),
                                        member(5, K::witness)}});
    }
    for (std::uint64_t i = 0; i < proto::max_layout_gateways; ++i) {
        l.gateways.push_back(
            {.server_id = 0x100 + i, .endpoint = member(9).endpoint, .port = port});
    }
    l.attachments.clear();
    for (std::uint64_t i = 0; i < proto::max_volume_attachments; ++i) {
        l.attachments.push_back({.attachment_id = 0xA0 + i,
                                 .server_id = 7,
                                 .generation = 1,
                                 .mode = proto::AttachMode::rw});
    }
    return l;
}

auto encoded(const proto::VolumeLayout& l) -> std::vector<std::byte> {
    auto b = proto::encode_volume_layout(l);
    BOOST_REQUIRE_MESSAGE(b.has_value(), proto::to_string(b.error()));
    return *b;
}

auto encode_error(const proto::VolumeLayout& l) -> DecodeError {
    auto b = proto::encode_volume_layout(l);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto l = proto::decode_volume_layout(b);
    BOOST_REQUIRE(!l.has_value());
    return l.error();
}

template<std::unsigned_integral T>
auto set_at(std::vector<std::byte>& b, std::size_t off, T v) -> void {
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(off)};
    BOOST_REQUIRE(w.write(v, ak::wire::Order::little).has_value());
}

auto le64_at(std::span<const std::byte> b, std::size_t off) -> std::uint64_t {
    ak::wire::Reader r{b.subspan(off)};
    return r.le64().value_or(0);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(volume_layout, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(layouts_round_trip_canonically) {
    auto split = sample();
    split.gateways = {{.server_id = 0x31, .endpoint = member(0x31).endpoint, .port = port},
                      {.server_id = 0x32, .endpoint = member(0x32).endpoint, .port = port}};
    auto mirroring = sample();
    mirroring.flags = proto::layout_flags::mirror_target | proto::layout_flags::no_space_warning;
    mirroring.mirror = {.peer_backend = proto::MirrorBackend::hold,
                        .phase = proto::MirrorPhase::copy,
                        .peer_volume = 0x100};
    auto provisioned = sample();
    provisioned.commit_rule = proto::CommitRule::majority;
    provisioned.block_size = proto::block_size_512;
    provisioned.stripe_unit = proto::min_stripe_unit;
    provisioned.groups = {{.group_id = 9, .members = {member(1), member(2), member(3)}}};
    auto single = sample();
    single.groups = {{.group_id = 9, .members = {member(1)}}};
    single.attachments = {};
    for (const auto& l : {sample(), split, mirroring, provisioned, single, biggest()}) {
        const auto b = encoded(l);
        BOOST_TEST(b.size() == proto::volume_layout_size(l));
        auto back = proto::decode_volume_layout(b);
        BOOST_REQUIRE_MESSAGE(back.has_value(), proto::to_string(back.error()));
        BOOST_TEST((*back == l));
        BOOST_TEST((encoded(*back) == b));
    }
    BOOST_TEST(encoded(biggest()).size() == proto::max_volume_layout_size);
}

BOOST_AUTO_TEST_CASE(layout_bytes) {
    const auto b = encoded(sample());
    BOOST_TEST(std::to_integer<char>(b[0]) == 'A');
    BOOST_TEST(std::to_integer<char>(b[5]) == 'Y');
    BOOST_TEST(std::to_integer<int>(b[off_width]) == 2);
    BOOST_TEST(le64_at(b, 0x10) == 0x21U);
    BOOST_TEST(le64_at(b, 0x18) == 0x200U);
    BOOST_TEST(std::to_integer<int>(b[0x3E]) == 0x10);  // 1 MiB stripe unit
    BOOST_TEST(std::to_integer<int>(b[0x44]) == 1);     // all_in_sync
    BOOST_TEST(std::to_integer<int>(b[0x45]) == 10);    // skew
    BOOST_TEST(le64_at(b, off_first_group) == 0x5001U);
    BOOST_TEST(std::to_integer<int>(b[off_first_group + 8]) == 3);  // members
    // Third member of the first group: the witness, kind 2.
    BOOST_TEST(std::to_integer<int>(b[off_first_group + 16 + (2 * 32) + 0x1A]) == 2);
    const auto signed_bytes = proto::volume_layout_signed_bytes(b);
    BOOST_TEST(signed_bytes.size() == b.size() - proto::ed25519_signature_size);
}

BOOST_AUTO_TEST_CASE(striping_helpers) {
    const auto l = sample();  // 1 MiB units of 4 KiB blocks: 256 blocks per unit
    BOOST_TEST(proto::group_index_of(l, 0) == 0U);
    BOOST_TEST(proto::group_index_of(l, 255) == 0U);
    BOOST_TEST(proto::group_index_of(l, 256) == 1U);
    BOOST_TEST(proto::group_index_of(l, 512) == 0U);
    BOOST_TEST(proto::group_index_of(l, l.capacity_blocks) == l.groups.size());
    BOOST_TEST(proto::find_member(l, 0x5001, 0x23) != nullptr);
    BOOST_TEST((proto::find_member(l, 0x5001, 0x23)->kind == K::witness));
    BOOST_TEST(proto::find_member(l, 0x5001, 0x24) == nullptr);
    BOOST_TEST(proto::find_member(l, 0x5003, 0x21) == nullptr);
}

BOOST_AUTO_TEST_CASE(rules_are_enforced_both_ways) {
    struct Case {
        proto::VolumeLayout l;
        DecodeError want;
    };
    auto with = [](auto mutate) {
        auto l = sample();
        mutate(l);
        return l;
    };
    using L = proto::VolumeLayout;
    const Case cases[] = {
        {with([](L& l) { l.key_id = 0; }), DecodeError::bad_key_id},
        {with([](L& l) { l.server_id = 0; }), DecodeError::bad_server_id},
        {with([](L& l) { l.volume_id = 0; }), DecodeError::bad_id},
        {with([](L& l) { l.lineage_id = 0; }), DecodeError::bad_id},
        {with([](L& l) { l.capacity_blocks = 0; }), DecodeError::bad_id},
        {with([](L& l) { l.epoch = 0; }), DecodeError::bad_epoch},
        {with([](L& l) { l.block_size = 1024; }), DecodeError::bad_block_size},
        {with([](L& l) { l.stripe_unit = 3U << 20; }), DecodeError::bad_stripe},
        {with([](L& l) { l.stripe_unit = proto::max_stripe_unit * 2; }), DecodeError::bad_stripe},
        {with([](L& l) { l.stripe_unit = proto::min_stripe_unit / 2; }), DecodeError::bad_stripe},
        {with([](L& l) { l.groups.clear(); }), DecodeError::bad_stripe},
        {with([](L& l) { l.flags = 0x40; }), DecodeError::reserved_not_zero},
        {with([](L& l) { l.commit_rule = static_cast<proto::CommitRule>(3); }),
         DecodeError::unknown_value},
        {with([](L& l) { l.qos.iops = 0; }), DecodeError::bad_qos},
        {with([](L& l) { l.qos.burst_mib = 1; }), DecodeError::bad_qos},
        {with([](L& l) { l.group_skew_pct = 101; }), DecodeError::bad_qos},
        {with([](L& l) { l.timings.member_deadline_ms = 0; }), DecodeError::bad_id},
        {with([](L& l) { l.timings.election_min_ms = 0; }), DecodeError::bad_id},
        // Mirror fields follow the flags, and a volume is never both sides.
        {with([](L& l) { l.flags = proto::layout_flags::mirror_source; }), DecodeError::bad_mirror},
        {with([](L& l) {
             l.flags = proto::layout_flags::mirror_source | proto::layout_flags::mirror_target;
             l.mirror = {.peer_backend = proto::MirrorBackend::hold,
                         .phase = proto::MirrorPhase::mirror,
                         .peer_volume = 1};
         }),
         DecodeError::bad_mirror},
        {with([](L& l) { l.mirror.peer_volume = 1; }), DecodeError::bad_mirror},
        {with([](L& l) {
             l.flags = proto::layout_flags::mirror_target;
             l.mirror = {.peer_backend = proto::MirrorBackend::khold,
                         .phase = proto::MirrorPhase::none,
                         .peer_volume = 1};
         }),
         DecodeError::bad_mirror},
        {with([](L& l) { l.mirror.peer_backend = static_cast<proto::MirrorBackend>(3); }),
         DecodeError::unknown_value},
        // Groups.
        {with([](L& l) { l.groups[1].group_id = 0; }), DecodeError::bad_id},
        {with([](L& l) { l.groups[1].group_id = l.groups[0].group_id; }), DecodeError::bad_id},
        {with([](L& l) { l.groups[0].members.clear(); }), DecodeError::too_many_members},
        {with([](L& l) {
             l.groups[0].members = {member(1), member(2), member(3),
                                    member(4), member(5), member(6)};
         }),
         DecodeError::too_many_members},
        {with([](L& l) { l.groups[0].members = {member(1, K::witness), member(2, K::learner)}; }),
         DecodeError::bad_group_members},
        {with([](L& l) {
             l.groups[0].members = {member(1), member(2, K::witness), member(3, K::witness)};
         }),
         DecodeError::bad_group_members},
        {with([](L& l) { l.groups[0].members = {member(2), member(1)}; }),
         DecodeError::not_ascending},
        {with([](L& l) { l.groups[0].members = {member(1), member(1, K::witness)}; }),
         DecodeError::not_ascending},
        {with([](L& l) { l.groups[0].members[0].server_id = 0; }), DecodeError::bad_server_id},
        {with([](L& l) { l.groups[0].members[0].port = 0; }), DecodeError::bad_member},
        {with([](L& l) { l.groups[0].members[0].endpoint = {}; }), DecodeError::bad_member},
        {with([](L& l) { l.groups[0].members[0].kind = static_cast<K>(4); }),
         DecodeError::unknown_value},
        {with([](L& l) {
             l.groups.resize(proto::max_stripe_width + 1, l.groups[0]);
             for (std::size_t i = 0; i < l.groups.size(); ++i) {
                 l.groups[i].group_id = i + 1;
             }
         }),
         DecodeError::bad_stripe},
        // Gateways.
        {with([](L& l) {
             l.gateways = {{.server_id = 0, .endpoint = member(1).endpoint, .port = port}};
         }),
         DecodeError::bad_server_id},
        {with([](L& l) {
             l.gateways = {{.server_id = 2, .endpoint = member(2).endpoint, .port = port},
                           {.server_id = 1, .endpoint = member(1).endpoint, .port = port}};
         }),
         DecodeError::not_ascending},
        // Attachments.
        {with([](L& l) {
             l.attachments.push_back({.attachment_id = 0xA2,
                                      .server_id = 8,
                                      .generation = 1,
                                      .mode = proto::AttachMode::rw});
         }),
         DecodeError::bad_attachment_mode},
        {with([](L& l) {
             l.attachments.push_back({.attachment_id = 0xA1,
                                      .server_id = 8,
                                      .generation = 1,
                                      .mode = proto::AttachMode::ro});
         }),
         DecodeError::not_ascending},
        {with([](L& l) { l.attachments[0].generation = 0; }), DecodeError::bad_id},
        {with([](L& l) { l.attachments[0].server_id = 0; }), DecodeError::bad_server_id},
        {with([](L& l) { l.attachments[0].mode = static_cast<proto::AttachMode>(3); }),
         DecodeError::unknown_value},
    };
    for (const auto& c : cases) {
        BOOST_TEST((encode_error(c.l) == c.want),
                   "got " << proto::to_string(proto::encode_volume_layout(c.l).error()));
    }

    // The decoder makes the same checks: patch an encoded frame so the
    // encoder's guard is bypassed.
    auto b = encoded(sample());
    auto two_witnesses = b;
    two_witnesses[off_first_group + 16 + 0x1A] = std::byte{2};  // first member: witness too
    BOOST_TEST((decode_error(two_witnesses) == DecodeError::bad_group_members));
    auto dup_group = b;
    set_at<std::uint64_t>(dup_group, off_first_group, 0x5002);
    BOOST_TEST((decode_error(dup_group) == DecodeError::bad_id));
}

BOOST_AUTO_TEST_CASE(reserved_bytes_and_versions) {
    const auto good = encoded(sample());
    for (std::size_t off : {off_reserved, off_timing_reserved, off_mirror_reserved,
                            off_first_group + 9, off_first_group + 16 + 0x1C}) {
        auto b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[8] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
}

BOOST_AUTO_TEST_CASE(lengths_and_hostile_counts) {
    const auto good = encoded(sample());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated),
                   "length " << n);
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));

    b = good;
    set_at<std::uint16_t>(b, off_width, 0);
    BOOST_TEST((decode_error(b) == DecodeError::bad_stripe));
    set_at<std::uint16_t>(b, off_width, 0xFFFF);
    BOOST_TEST((decode_error(b) == DecodeError::bad_stripe));
    b = good;
    b[off_gateways] = std::byte{0xFF};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    b[off_attachments] = std::byte{0xFF};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_attachments));
    b = good;
    b[off_first_group + 8] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_members));
    b[off_first_group + 8] = std::byte{6};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_members));

    std::vector<std::byte> huge(proto::max_volume_layout_size + 1);
    BOOST_TEST((decode_error(huge) == DecodeError::record_too_large));
}

BOOST_AUTO_TEST_SUITE_END()
