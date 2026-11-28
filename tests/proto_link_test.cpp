// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 2, design "ControllerLink":
// record framing on the controller <-> helm stream and the report ack.

#define BOOST_TEST_MODULE proto_link_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "proto/link.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using proto::RecordType;

namespace {

auto framed(RecordType t, const std::vector<std::byte>& payload) -> std::vector<std::byte> {
    auto b = proto::encode_record(t, payload);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto drain(proto::RecordDecoder& d) -> std::vector<proto::Record> {
    std::vector<proto::Record> out;
    for (;;) {
        auto r = d.next();
        BOOST_REQUIRE(r.has_value());
        if (!r->has_value()) {
            return out;
        }
        out.push_back(std::move(**r));
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(records, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(record_header_layout) {
    const auto b = framed(RecordType::report, bytes_of(0xAA, 0xBB, 0xCC));
    BOOST_TEST((b == bytes_of(3, 0, 0, 0, 3, 0, 0, 0, 0xAA, 0xBB, 0xCC)));
    static_assert(proto::max_record_payload == proto::max_map_update_size);
    static_assert(proto::max_record_payload >= proto::max_report_size);
}

BOOST_AUTO_TEST_CASE(records_split_at_every_byte_reassemble) {
    std::vector<std::byte> stream;
    const std::vector<proto::Record> want{
        {.type = RecordType::envelope, .payload = bytes_of(1, 2, 3, 4)},
        {.type = RecordType::report_ack, .payload = {}},
        {.type = RecordType::map_update, .payload = std::vector<std::byte>(300, std::byte{7})},
        {.type = RecordType::tunnel_peers, .payload = bytes_of(5, 6)},
    };
    for (const auto& r : want) {
        const auto b = framed(r.type, r.payload);
        stream.insert(stream.end(), b.begin(), b.end());
    }
    for (std::size_t chunk = 1; chunk <= stream.size(); ++chunk) {
        proto::RecordDecoder d;
        std::vector<proto::Record> got;
        for (std::size_t i = 0; i < stream.size(); i += chunk) {
            d.feed(std::span{stream}.subspan(i, std::min(chunk, stream.size() - i)));
            auto more = drain(d);
            got.insert(got.end(), more.begin(), more.end());
        }
        BOOST_TEST((got == want), "chunk " << chunk);
        BOOST_TEST(d.buffered() == 0U);
    }
}

BOOST_AUTO_TEST_CASE(oversized_record_fails_before_its_payload_arrives) {
    proto::RecordDecoder d;
    const auto too_big = static_cast<std::uint32_t>(proto::max_record_payload + 1);
    d.feed(bytes_of(too_big & 0xFF, (too_big >> 8) & 0xFF, (too_big >> 16) & 0xFF,
                    (too_big >> 24) & 0xFF, 1, 0, 0, 0));
    auto r = d.next();
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error() == DecodeError::record_too_large));
    // Sticky: the stream is out of sync.
    d.feed(framed(RecordType::envelope, bytes_of(1)));
    auto again = d.next();
    BOOST_REQUIRE(!again.has_value());
    BOOST_TEST((again.error() == DecodeError::record_too_large));
    BOOST_TEST(d.buffered() == 0U);
}

BOOST_AUTO_TEST_CASE(bad_type_and_reserved_break_the_stream) {
    for (const auto& [bytes, want] :
         {std::pair{bytes_of(0, 0, 0, 0, 0, 0, 0, 0), DecodeError::bad_record_type},
          std::pair{bytes_of(0, 0, 0, 0, 19, 0, 0, 0), DecodeError::bad_record_type},
          std::pair{bytes_of(0, 0, 0, 0, 1, 0, 0, 1), DecodeError::reserved_not_zero}}) {
        proto::RecordDecoder d;
        d.feed(bytes);
        auto r = d.next();
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == want));
    }
}

BOOST_AUTO_TEST_CASE(largest_tunnel_peer_set_fits_a_record) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::tunnel_peers) == 7U);
    BOOST_TEST(proto::max_record_payload >= proto::max_tunnel_peers_size);
}

BOOST_AUTO_TEST_CASE(largest_group_members_fits_a_record) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::group_members) == 15U);
    BOOST_TEST(proto::max_record_payload >= proto::max_group_members_size);
}

BOOST_AUTO_TEST_CASE(largest_instance_metadata_fits_a_record) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::instance_metadata) == 16U);
    BOOST_TEST(proto::max_record_payload >= proto::max_instance_metadata_size);
}

BOOST_AUTO_TEST_CASE(largest_volume_layout_fits_a_record) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::volume_layout) == 17U);
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::self_test) == 18U);
    BOOST_TEST(proto::max_record_payload >= proto::max_volume_layout_size);
}

BOOST_AUTO_TEST_CASE(self_test_round_trips_and_is_strict) {
    const proto::SelfTest t{
        .server_id = 0x0102'0304'0506'0708, .slot = 4, .scope = proto::SelfTestScope::slot};
    auto b = proto::encode_self_test(t);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::self_test_size);
    const auto want = ak::test::bytes_of(0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x04, 0x01,
                                         0, 0, 0, 0, 0, 0);
    BOOST_TEST((*b == want));
    auto back = proto::decode_self_test(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == t));
    for (std::size_t n = 0; n < b->size(); ++n) {
        BOOST_TEST(
            (proto::decode_self_test(std::span{*b}.first(n)).error() == DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_self_test(longer).error() == DecodeError::trailing_bytes));
    for (std::size_t off = 10; off < proto::self_test_size; ++off) {
        auto reserved = *b;
        reserved[off] = std::byte{1};
        BOOST_TEST((proto::decode_self_test(reserved).error() == DecodeError::reserved_not_zero));
    }
    auto scope = *b;
    scope[9] = std::byte{3};
    BOOST_TEST((proto::decode_self_test(scope).error() == DecodeError::unknown_value));
    BOOST_TEST((proto::encode_self_test({.server_id = 0}).error() == DecodeError::bad_server_id));
    // Scope all names no slot.
    BOOST_TEST(
        proto::encode_self_test({.server_id = 1, .slot = 0, .scope = proto::SelfTestScope::all})
            .has_value());
    BOOST_TEST(
        (proto::encode_self_test({.server_id = 1, .slot = 2, .scope = proto::SelfTestScope::all})
             .error() == DecodeError::reserved_not_zero));
}

// fleet-scale-networking task 1.
BOOST_AUTO_TEST_CASE(rotate_vtep_key_round_trips_and_is_strict) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::rotate_vtep_key) == 35U);
    const proto::RotateVtepKey k{
        .server_id = 0x0102'0304'0506'0708, .slot = 3, .key_epoch = 0x1234};
    auto b = proto::encode_rotate_vtep_key(k);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::rotate_vtep_key_size);
    const auto want = ak::test::bytes_of(0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x03, 0, 0,
                                         0, 0x34, 0x12, 0, 0);
    BOOST_TEST((*b == want));
    auto back = proto::decode_rotate_vtep_key(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == k));
    for (std::size_t n = 0; n < b->size(); ++n) {
        BOOST_TEST((proto::decode_rotate_vtep_key(std::span{*b}.first(n)).error() ==
                    DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_rotate_vtep_key(longer).error() == DecodeError::trailing_bytes));
    for (std::size_t off = 9; off < 12; ++off) {
        auto reserved = *b;
        reserved[off] = std::byte{1};
        BOOST_TEST(
            (proto::decode_rotate_vtep_key(reserved).error() == DecodeError::reserved_not_zero));
    }
    // Epoch 0 is never used, and an epoch must fit the credential's 16 bits.
    for (const std::uint32_t epoch : {0U, proto::max_key_epoch + 1}) {
        auto bad = *b;
        for (std::size_t i = 0; i < 4; ++i) {
            bad[12 + i] = static_cast<std::byte>((epoch >> (8U * i)) & 0xFFU);
        }
        BOOST_TEST((proto::decode_rotate_vtep_key(bad).error() == DecodeError::unknown_value));
    }
    BOOST_TEST(
        (proto::encode_rotate_vtep_key({.server_id = 0, .slot = 0, .key_epoch = 1}).error() ==
         DecodeError::bad_server_id));
    // The record framing knows it although 19-29 and 32-34 are not yet
    // defined.
    BOOST_TEST(proto::encode_record(RecordType::rotate_vtep_key, *b).has_value());
    BOOST_TEST(!proto::encode_record(static_cast<RecordType>(34), {}).has_value());
    BOOST_TEST(!proto::encode_record(static_cast<RecordType>(36), {}).has_value());
}

// fleet-scale-networking task 2: the records are numbered by the spec, a
// full revocation list fits one record, and the gaps stay unknown.
BOOST_AUTO_TEST_CASE(credential_records_are_framed) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::vtep_credential) == 30U);
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::credential_revocations) == 31U);
    BOOST_TEST(proto::max_record_payload >= proto::max_credential_revocations_size);
    const std::vector<std::byte> credential(proto::vtep_credential_size);
    BOOST_TEST(proto::encode_record(RecordType::vtep_credential, credential).has_value());
    const std::vector<std::byte> full(proto::max_credential_revocations_size);
    auto rec = proto::encode_record(RecordType::credential_revocations, full);
    BOOST_REQUIRE(rec.has_value());
    proto::RecordDecoder d;
    d.feed(*rec);
    const auto back = drain(d);
    BOOST_REQUIRE(back.size() == 1U);
    BOOST_TEST((back[0].type == RecordType::credential_revocations));
    BOOST_TEST(back[0].payload.size() == full.size());
    for (const std::uint16_t t : {std::uint16_t{29}, std::uint16_t{32}, std::uint16_t{34}}) {
        BOOST_TEST(!proto::encode_record(static_cast<RecordType>(t), {}).has_value());
    }
}

// fleet-scale-networking task 11: link record 33 and the 56-byte notice
// helm passes to its network roles (vendor type 0x33).
BOOST_AUTO_TEST_CASE(frame_notices_round_trip_and_are_strict) {
    BOOST_TEST(static_cast<std::uint16_t>(RecordType::frame_notice) == 33U);
    BOOST_TEST(proto::max_record_payload >= proto::frame_notice_record_size);
    proto::FrameNotice n{.kind = proto::FrameKind::vpc_stream,
                         .vni_or_scope = 0xAB0001,
                         .sequence_or_version = 0x0102'0304'0506'0708,
                         .size = 0x0002'0000,
                         .sha256 = {}};
    for (std::size_t i = 0; i < n.sha256.size(); ++i) {
        n.sha256[i] = static_cast<std::byte>(0xA0 + i);
    }
    const auto b = proto::encode_frame_notice(n);
    BOOST_REQUIRE(b.has_value());
    BOOST_REQUIRE(b->size() == proto::frame_notice_size);
    const auto head = ak::test::bytes_of(0x01, 0, 0, 0, 0x01, 0x00, 0xAB, 0, 0x08, 0x07, 0x06, 0x05,
                                         0x04, 0x03, 0x02, 0x01, 0, 0, 0x02, 0, 0, 0, 0, 0);
    BOOST_TEST(std::ranges::equal(std::span{*b}.first(head.size()), head));
    BOOST_TEST(std::to_integer<int>((*b)[0x18]) == 0xA0);
    BOOST_TEST(std::to_integer<int>((*b)[0x37]) == 0xA0 + 31);
    BOOST_TEST((proto::decode_frame_notice(*b).value() == n));
    for (std::size_t len = 0; len < b->size(); ++len) {
        BOOST_TEST((proto::decode_frame_notice(std::span{*b}.first(len)).error() ==
                    DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_frame_notice(longer).error() == DecodeError::trailing_bytes));
    for (const std::size_t off : {1U, 2U, 3U, 0x14U, 0x15U, 0x16U, 0x17U}) {
        auto bad = *b;
        bad[off] = std::byte{1};
        BOOST_TEST((proto::decode_frame_notice(bad).error() == DecodeError::reserved_not_zero));
    }
    const auto refused = [](proto::FrameNotice m) {
        const auto e = proto::encode_frame_notice(m);
        return e ? std::optional<DecodeError>{} : std::optional<DecodeError>{e.error()};
    };
    auto m = n;
    m.kind = static_cast<proto::FrameKind>(4);
    BOOST_TEST((refused(m) == DecodeError::unknown_value));
    m = n;
    m.kind = static_cast<proto::FrameKind>(0);
    BOOST_TEST((refused(m) == DecodeError::unknown_value));
    m = n;
    m.vni_or_scope = 0;
    BOOST_TEST((refused(m) == DecodeError::bad_vni));
    m.vni_or_scope = proto::max_notice_vni + 1;
    BOOST_TEST((refused(m) == DecodeError::bad_vni));
    m.kind = proto::FrameKind::security_policy;  // a scope, not a VNI: any value
    BOOST_TEST(!refused(m).has_value());
    m = n;
    m.sequence_or_version = 0;
    BOOST_TEST((refused(m) == DecodeError::bad_id));
    m = n;
    m.size = 0;
    BOOST_TEST((refused(m) == DecodeError::bad_frame_size));
    m.size = proto::max_notice_frame_size + 1;
    BOOST_TEST((refused(m) == DecodeError::bad_frame_size));
    m.size = proto::max_notice_frame_size;
    BOOST_TEST(!refused(m).has_value());
    // The decoder refuses what the encoder would: a zero size on the wire.
    auto zero = *b;
    zero[0x12] = std::byte{0};
    BOOST_TEST((proto::decode_frame_notice(zero).error() == DecodeError::bad_frame_size));

    // The record: the server, then the notice.
    const proto::FrameNoticeRecord rec{.server_id = 7, .notice = n};
    const auto rb = proto::encode_frame_notice_record(rec);
    BOOST_REQUIRE(rb.has_value());
    BOOST_REQUIRE(rb->size() == proto::frame_notice_record_size);
    BOOST_TEST(std::to_integer<int>((*rb)[0]) == 7);
    BOOST_TEST(std::ranges::equal(std::span{*rb}.subspan(8), *b));
    BOOST_TEST((proto::decode_frame_notice_record(*rb).value() == rec));
    BOOST_TEST((proto::encode_frame_notice_record({.server_id = 0, .notice = n}).error() ==
                DecodeError::bad_server_id));
    auto no_server = *rb;
    no_server[0] = std::byte{0};
    BOOST_TEST(
        (proto::decode_frame_notice_record(no_server).error() == DecodeError::bad_server_id));
    BOOST_TEST((proto::decode_frame_notice_record(std::span{*rb}.first(60)).error() ==
                DecodeError::truncated));
    auto rlonger = *rb;
    rlonger.push_back(std::byte{0});
    BOOST_TEST((proto::decode_frame_notice_record(rlonger).error() == DecodeError::trailing_bytes));
    BOOST_TEST(proto::encode_record(RecordType::frame_notice, *rb).has_value());
    BOOST_TEST(std::string_view{proto::to_string(DecodeError::bad_frame_size)} ==
               "frame notice size is zero or too large");
}

BOOST_AUTO_TEST_CASE(encode_refuses_what_decode_would) {
    auto bad_type = proto::encode_record(static_cast<RecordType>(19), {});
    BOOST_REQUIRE(!bad_type.has_value());
    BOOST_TEST((bad_type.error() == DecodeError::bad_record_type));
    const std::vector<std::byte> huge(proto::max_record_payload + 1);
    auto too_big = proto::encode_record(RecordType::report, huge);
    BOOST_REQUIRE(!too_big.has_value());
    BOOST_TEST((too_big.error() == DecodeError::record_too_large));
    const std::vector<std::byte> max(proto::max_record_payload);
    BOOST_TEST(proto::encode_record(RecordType::report, max).has_value());
}

BOOST_AUTO_TEST_CASE(report_ack_round_trips_and_is_strict) {
    const proto::ReportAck ack{.server_id = 0x0102'0304'0506'0708, .report_seq = 9};
    auto b = proto::encode_report_ack(ack);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::report_ack_size);
    auto back = proto::decode_report_ack(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == ack));

    for (std::size_t n = 0; n < b->size(); ++n) {
        auto r = proto::decode_report_ack(std::span{*b}.first(n));
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_report_ack(longer).error() == DecodeError::trailing_bytes));
    BOOST_TEST((proto::decode_report_ack(std::vector<std::byte>(16)).error() ==
                DecodeError::bad_server_id));
    BOOST_TEST((proto::encode_report_ack({.server_id = 1, .report_seq = 0}).error() ==
                DecodeError::bad_report_seq));
    BOOST_TEST((proto::encode_report_ack({.server_id = 0, .report_seq = 1}).error() ==
                DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_CASE(hello_round_trips_and_is_strict) {
    const proto::Hello hello{.server_id = 0x0102'0304'0506'0708, .boot_id = 0xB007};
    auto b = proto::encode_hello(hello);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::hello_size);
    auto back = proto::decode_hello(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == hello));
    for (std::size_t n = 0; n < b->size(); ++n) {
        BOOST_TEST((proto::decode_hello(std::span{*b}.first(n)).error() == DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_hello(longer).error() == DecodeError::trailing_bytes));
    auto zero_boot = *b;
    std::ranges::fill(std::span{zero_boot}.subspan(8), std::byte{0});
    BOOST_TEST((proto::decode_hello(zero_boot).error() == DecodeError::bad_boot_id));
    BOOST_TEST(
        (proto::decode_hello(std::vector<std::byte>(16)).error() == DecodeError::bad_server_id));
    BOOST_TEST(
        (proto::encode_hello({.server_id = 1, .boot_id = 0}).error() == DecodeError::bad_boot_id));
    BOOST_TEST((proto::encode_hello({.server_id = 0, .boot_id = 1}).error() ==
                DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(lease_grant_round_trips_and_is_strict) {
    const proto::LeaseGrant g{.server_id = 0x0102'0304'0506'0708, .volume_id = 7, .epoch = 3};
    auto b = proto::encode_lease_grant(g);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::lease_grant_size);
    BOOST_TEST((*b == bytes_of(0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x07, 0, 0, 0, 0, 0,
                               0, 0, 0x03, 0, 0, 0, 0, 0, 0, 0)));
    auto back = proto::decode_lease_grant(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == g));
    for (std::size_t n = 0; n < b->size(); ++n) {
        BOOST_TEST(
            (proto::decode_lease_grant(std::span{*b}.first(n)).error() == DecodeError::truncated));
    }
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_lease_grant(longer).error() == DecodeError::trailing_bytes));
    BOOST_TEST((proto::encode_lease_grant({.server_id = 0, .volume_id = 7, .epoch = 3}).error() ==
                DecodeError::bad_server_id));
    BOOST_TEST((proto::encode_lease_grant({.server_id = 1, .volume_id = 0, .epoch = 3}).error() ==
                DecodeError::bad_id));
    BOOST_TEST((proto::encode_lease_grant({.server_id = 1, .volume_id = 7, .epoch = 0}).error() ==
                DecodeError::bad_epoch));
    auto zero_epoch = *b;
    std::ranges::fill(std::span{zero_epoch}.subspan(16), std::byte{0});
    BOOST_TEST((proto::decode_lease_grant(zero_epoch).error() == DecodeError::bad_epoch));
}

BOOST_AUTO_TEST_CASE(block_volume_frames_fit_a_record) {
    BOOST_TEST(proto::max_record_payload >= proto::max_replica_config_size);
    BOOST_TEST(proto::max_record_payload >= proto::volume_op_size);
    BOOST_TEST(proto::max_record_payload >= proto::volume_key_size);
    BOOST_TEST(proto::max_record_payload >= proto::image_key_size);
    for (const auto t : {RecordType::replica_config, RecordType::volume_op, RecordType::volume_key,
                         RecordType::lease_grant, RecordType::image_key}) {
        BOOST_TEST(proto::encode_record(t, std::vector<std::byte>(4)).has_value());
    }
    BOOST_TEST(
        proto::encode_record(RecordType::role_certificate, std::vector<std::byte>(4)).has_value());
    BOOST_TEST(!proto::encode_record(static_cast<RecordType>(19), {}).has_value());
}

namespace {

// A DER SEQUENCE of n content bytes, its length in the shortest form.
auto der_cert(std::size_t n, std::uint8_t fill) -> std::vector<std::byte> {
    std::vector<std::byte> out{std::byte{0x30}};
    if (n < 0x80) {
        out.push_back(static_cast<std::byte>(n));
    } else {
        out.push_back(std::byte{0x82});
        out.push_back(static_cast<std::byte>(n >> 8U));
        out.push_back(static_cast<std::byte>(n & 0xFFU));
    }
    out.insert(out.end(), n, static_cast<std::byte>(fill));
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(role_certificate_round_trips_and_is_strict) {
    auto chain = der_cert(600, 1);
    const auto issuer = der_cert(500, 2);
    chain.insert(chain.end(), issuer.begin(), issuer.end());
    const proto::RoleCertificate c{.server_id = 0x0102'0304'0506'0708, .slot = 3, .chain = chain};
    auto b = proto::encode_role_certificate(c);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(b->size() == proto::role_certificate_fixed_size + chain.size());
    BOOST_TEST(std::to_integer<int>((*b)[0]) == 0x08);  // server_id, little-endian
    BOOST_TEST(std::to_integer<int>((*b)[8]) == 3);     // slot
    BOOST_TEST(std::to_integer<int>((*b)[12]) == static_cast<int>(chain.size() & 0xFFU));
    BOOST_TEST(std::to_integer<int>((*b)[16]) == 0x30);
    auto back = proto::decode_role_certificate(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == c));
    for (const std::size_t n : {std::size_t{0}, std::size_t{8}, std::size_t{15}}) {
        BOOST_TEST((proto::decode_role_certificate(std::span{*b}.first(n)).error() ==
                    DecodeError::truncated));
    }
    // A chain_len past the end is truncated; short of it, trailing bytes.
    BOOST_TEST((proto::decode_role_certificate(std::span{*b}.first(b->size() - 1)).error() ==
                DecodeError::truncated));
    auto longer = *b;
    longer.push_back(std::byte{0});
    BOOST_TEST((proto::decode_role_certificate(longer).error() == DecodeError::trailing_bytes));
    auto bad = *b;
    bad[9] = std::byte{1};
    BOOST_TEST((proto::decode_role_certificate(bad).error() == DecodeError::reserved_not_zero));

    auto with = [&](std::uint64_t server, std::vector<std::byte> ch) {
        return proto::encode_role_certificate(
            {.server_id = server, .slot = 1, .chain = std::move(ch)});
    };
    BOOST_TEST((with(0, chain).error() == DecodeError::bad_server_id));
    BOOST_TEST((with(1, {}).error() == DecodeError::bad_der));
    BOOST_TEST((with(1, bytes_of(0x04, 0x00)).error() == DecodeError::bad_der));
    std::vector<std::byte> five;
    for (int i = 0; i < 5; ++i) {
        const auto one = der_cert(10, 3);
        five.insert(five.end(), one.begin(), one.end());
    }
    BOOST_TEST((with(1, five).error() == DecodeError::bad_der));  // more than four
    five.resize(five.size() - der_cert(10, 3).size());
    BOOST_TEST(with(1, five).has_value());
    BOOST_TEST((with(1, der_cert(proto::max_cert_chain_size, 4)).error() == DecodeError::bad_der));
    BOOST_TEST(with(1, der_cert(proto::max_cert_chain_size - 4, 4)).has_value());
    BOOST_TEST(proto::max_record_payload >=
               proto::role_certificate_fixed_size + proto::max_cert_chain_size);
}
