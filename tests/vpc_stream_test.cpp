// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/fleet-scale-networking/ task 5: the VpcStream codec. Every
// record type round-trips, headers and bodies are held to their rules,
// snapshots are ordered and put-only, deltas carry removes in change
// order, and no prefix of a frame decodes.

#define BOOST_TEST_MODULE vpc_stream_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include "proto/vpc_stream.hpp"
#include "vpc_stream_support.hpp"

namespace proto = ak::proto;
namespace st = ak::test::stream;
using proto::DecodeError;
using proto::StreamRecordType;
using K = proto::StreamRouteKind;

namespace {

auto encode_error(const proto::VpcStream& s) -> DecodeError {
    const auto e = proto::encode_vpc_stream(s);
    // An accepted frame answers a value no check expects, so the failing
    // BOOST_TEST names its own line.
    return e ? static_cast<DecodeError>(0xFF) : e.error();
}

// The frame for `s` with a one-record body edit applied after encoding
// (so encode's own checks do not stop it), decoded.
auto decode_edited(const proto::VpcStream& s,
                   const std::function<void(std::vector<std::byte>&)>& edit)
    -> std::expected<proto::VpcStream, DecodeError> {
    auto frame = proto::encode_vpc_stream(s);
    BOOST_REQUIRE(frame.has_value());
    edit(*frame);
    return proto::decode_vpc_stream(*frame);
}

auto one(proto::StreamRecord r) -> proto::VpcStream {
    auto s = st::delta(4, 4);
    s.records.push_back(std::move(r));
    return s;
}

auto refused(proto::StreamRecord r) -> DecodeError {
    return encode_error(one(std::move(r)));
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_record_type_round_trips_in_a_snapshot) {
    auto s = st::snapshot(9);
    s.records = st::every_type();
    s.lookup = true;
    s.cell_scope = 3;
    s.signature[0] = std::byte{0xAA};
    const auto frame = proto::encode_vpc_stream(s);
    BOOST_REQUIRE(frame.has_value());
    std::size_t bodies = 0;
    for (const auto& r : s.records) {
        bodies += proto::stream_record_header_size + r.body.size();
    }
    BOOST_TEST(frame->size() == proto::min_vpc_stream_size + bodies);
    const auto back = proto::decode_vpc_stream(*frame);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == s));
    BOOST_TEST(proto::vpc_stream_signed_bytes(*frame).size() == frame->size() - 64);

    std::vector<std::byte> copy = *frame;
    std::array<std::byte, 64> sig{};
    sig.fill(std::byte{0x5C});
    proto::set_vpc_stream_signature(copy, sig);
    BOOST_TEST(proto::decode_vpc_stream(copy).value().signature == sig);
}

BOOST_AUTO_TEST_CASE(a_delta_carries_puts_and_removes_in_change_order) {
    auto s = st::delta(10, 12);
    const auto every = st::every_type();
    // Change order, not key order, and the same key twice.
    s.records.push_back(st::nic_binding(0x40, 0, 9, 0x40));
    s.records.push_back(st::remove_of(st::nic_binding(0x11, 0, 1, 0x11)));
    s.records.push_back(st::nic_binding(0x40, 0, 9, 0x41));
    for (const auto& r : every) {
        if (r.type != StreamRecordType::vpc_settings) {
            s.records.push_back(st::remove_of(r));
        }
    }
    s.records.push_back(st::vpc_settings());
    const auto frame = proto::encode_vpc_stream(s);
    BOOST_REQUIRE(frame.has_value());
    BOOST_TEST((proto::decode_vpc_stream(*frame).value() == s));
    // A delta may be empty: the controller advanced the sequence.
    BOOST_TEST(proto::encode_vpc_stream(st::delta(5, 5)).has_value());
}

BOOST_AUTO_TEST_CASE(headers_obey_the_snapshot_and_delta_rules) {
    BOOST_TEST(proto::encode_vpc_stream(st::snapshot(1)).has_value());
    auto s = st::snapshot(1);
    s.key_id = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_key_id));
    s = st::snapshot(1);
    s.vpc_id = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_id));
    s = st::snapshot(1);
    s.incarnation = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_id));
    s = st::snapshot(1);
    s.vni = 0x0100'0000;
    BOOST_TEST((encode_error(s) == DecodeError::bad_vni));
    s = st::snapshot(0);
    BOOST_TEST((encode_error(s) == DecodeError::bad_stream_header));
    s = st::snapshot(1);
    s.snapshot_id = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_stream_header));
    s = st::snapshot(1);
    s.part = 1;  // of 1
    BOOST_TEST((encode_error(s) == DecodeError::bad_stream_header));
    s.part_count = proto::max_stream_parts;
    BOOST_TEST(proto::encode_vpc_stream(s).has_value());
    s.part_count = proto::max_stream_parts + 1;
    BOOST_TEST((encode_error(s) == DecodeError::bad_stream_header));
    s = st::snapshot(1);
    s.from_sequence = 1;
    BOOST_TEST((encode_error(s) == DecodeError::bad_stream_header));

    BOOST_TEST((encode_error(st::delta(0, 3)) == DecodeError::bad_stream_header));
    BOOST_TEST((encode_error(st::delta(4, 3)) == DecodeError::bad_stream_header));
    auto d = st::delta(1, 3);
    d.snapshot_id = 9;
    BOOST_TEST((encode_error(d) == DecodeError::bad_stream_header));
    d = st::delta(1, 3);
    d.part_count = 2;
    BOOST_TEST((encode_error(d) == DecodeError::bad_stream_header));

    // Fields only the decoder sees.
    const auto base = st::delta(1, 3);
    BOOST_TEST((decode_edited(base, [](auto& f) { f[0] = std::byte{0}; }).error() ==
                DecodeError::bad_magic));
    BOOST_TEST((decode_edited(base, [](auto& f) { f[4] = std::byte{2}; }).error() ==
                DecodeError::bad_version));
    BOOST_TEST((decode_edited(base, [](auto& f) { f[0x1C] = std::byte{3}; }).error() ==
                DecodeError::unknown_value));
    BOOST_TEST((decode_edited(base, [](auto& f) { f[0x1D] = std::byte{2}; }).error() ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((decode_edited(base, [](auto& f) { f[0x25] = std::byte{1}; }).error() ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((decode_edited(base, [](auto& f) { f[0x44] = std::byte{1}; }).error() ==
                DecodeError::bad_stream_header));
    BOOST_TEST((decode_edited(base, [](auto& f) { f[0x40] = std::byte{1}; }).error() ==
                DecodeError::truncated));
    BOOST_TEST((decode_edited(base, [](auto& f) { f.push_back(std::byte{0}); }).error() ==
                DecodeError::bad_stream_header));
}

BOOST_AUTO_TEST_CASE(snapshots_are_put_only_and_strictly_ordered) {
    auto s = st::snapshot(2);
    s.records = {st::nic_binding(0x12, 0, 1, 0x12), st::nic_binding(0x11, 0, 2, 0x11)};
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));
    s.records = {st::nic_binding(0x11, 0, 1, 0x11), st::nic_binding(0x11, 0, 2, 0x12)};
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));  // the same key twice
    s.records = {st::ipv4_address({10, 0, 1, 5}, 1), st::nic_binding(0x11, 0, 1, 0x11)};
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));  // type order
    // Keys compare as values: NIC 0x100 sorts after 0xFF though its
    // little-endian bytes would not.
    s.records = {st::nic_binding(0xFF, 0, 1, 0x11), st::nic_binding(0x100, 0, 2, 0x12)};
    BOOST_TEST(proto::encode_vpc_stream(s).has_value());
    // Routes sort by table, family, prefix, then length.
    s.records = {st::route4(1, 9, K::nic, 1), st::route4(2, 1, K::nic, 1)};
    BOOST_TEST(proto::encode_vpc_stream(s).has_value());
    s.records = {st::route4(2, 1, K::nic, 1), st::route4(1, 9, K::nic, 1)};
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));
    s.records = {st::remove_of(st::nic_binding(0x11, 0, 1, 0x11))};
    BOOST_TEST((encode_error(s) == DecodeError::bad_stream_record));
    // VPC settings are never removed, in a delta either.
    auto d = st::delta(1, 1);
    d.records = {
        {.type = StreamRecordType::vpc_settings, .op = proto::StreamOp::remove, .body = {}}};
    BOOST_TEST((encode_error(d) == DecodeError::bad_stream_record));
}

BOOST_AUTO_TEST_CASE(record_bodies_obey_their_types_rules) {
    // Unknown types and ops; sizes.
    BOOST_TEST((refused({.type = static_cast<StreamRecordType>(17),
                         .op = proto::StreamOp::put,
                         .body = {}}) == DecodeError::unknown_value));
    auto r = st::lookup_interest(5);
    r.op = static_cast<proto::StreamOp>(3);
    BOOST_TEST((refused(r) == DecodeError::unknown_value));
    r = st::nic_binding(1, 0, 1, 1);
    r.body.pop_back();
    BOOST_TEST((refused(r) == DecodeError::truncated));
    r = st::nic_binding(1, 0, 1, 1);
    r.body.push_back(std::byte{0});
    BOOST_TEST((refused(r) == DecodeError::trailing_bytes));
    auto rm = st::remove_of(st::route4(1, 2, K::nic, 1));
    rm.body.push_back(std::byte{0});
    BOOST_TEST((refused(rm) == DecodeError::trailing_bytes));

    // NIC bindings and addresses.
    BOOST_TEST((refused(st::nic_binding(0, 0, 1, 1)) == DecodeError::bad_nic_id));
    BOOST_TEST((refused(st::nic_binding(~std::uint64_t{0}, 0, 1, 1)) == DecodeError::bad_nic_id));
    r = st::nic_binding(1, 0, 1, 1);
    r.body[16] = std::byte{0xFF};  // a multicast VTEP
    BOOST_TEST((refused(r) == DecodeError::bad_vtep));
    r = st::nic_binding(1, 0, 1, 1);
    r.body[32] = std::byte{0x00};  // universally administered
    BOOST_TEST((refused(r) == DecodeError::bad_mac));
    BOOST_TEST((refused(st::nic_binding(1, 0, 1, 1, 0x80)) == DecodeError::reserved_not_zero));
    BOOST_TEST((refused(st::ipv4_address({224, 0, 0, 1}, 1)) == DecodeError::bad_guest_address));
    BOOST_TEST((refused(st::ipv4_address({10, 0, 0, 1}, 0)) == DecodeError::bad_nic_id));
    auto multicast6 = st::ipv6_address(1, 1);
    multicast6.body[0] = std::byte{0xFF};
    BOOST_TEST((refused(multicast6) == DecodeError::bad_guest_address));

    // VPC settings.
    r = st::vpc_settings();
    r.body[6] = std::byte{0};  // no blocks: the block's bytes are left over
    BOOST_TEST((refused(r) == DecodeError::trailing_bytes));
    r.body.erase(r.body.begin() + 36, r.body.begin() + 44);
    BOOST_TEST((refused(r) == DecodeError::bad_vpc_config));
    r = st::vpc_settings();
    r.body[12] = std::byte{1};  // lease 1 s
    r.body[13] = std::byte{0};
    BOOST_TEST((refused(r) == DecodeError::bad_vpc_config));
    r = st::vpc_settings();
    r.body[40] = std::byte{15};  // a /15 block
    BOOST_TEST((refused(r) == DecodeError::bad_vpc_config));
    r = st::vpc_settings();
    r.body.back() = std::byte{'-'};  // ec2.interna-
    BOOST_TEST((refused(r) == DecodeError::bad_vpc_config));
    r = st::vpc_settings();
    r.body[7] = std::byte{0};  // IPv6 block present without the flag
    BOOST_TEST((refused(r) == DecodeError::bad_vpc_config));

    // Subnets, tables, routes.
    r = st::subnet(1, 1, 1);
    r.body[15] = std::byte{29};
    BOOST_TEST((refused(r) == DecodeError::bad_vpc_config));
    BOOST_TEST((refused(st::subnet(0, 1, 1)) == DecodeError::bad_id));
    r = st::route_table(1, true);
    r.body[2] = std::byte{2};
    BOOST_TEST((refused(r) == DecodeError::reserved_not_zero));
    BOOST_TEST((refused(st::route4(1, 2, K::local, 7)) == DecodeError::bad_route));
    BOOST_TEST((refused(st::route4(1, 2, K::nic, 0)) == DecodeError::bad_nic_id));
    BOOST_TEST((refused(st::route4(1, 2, K::eigw, 7)) == DecodeError::bad_route));  // IPv6 only
    BOOST_TEST((refused(st::route4(1, 2, K::igw, 0)) == DecodeError::bad_route));
    BOOST_TEST((refused(st::route4(1, 2, static_cast<K>(6), 7)) == DecodeError::unknown_value));
    r = st::route4(1, 2, K::nic, 7);
    r.body[3] = std::byte{16};  // 10.0.2.0/16 has host bits
    BOOST_TEST((refused(r) == DecodeError::bad_route));
    r = st::route4(1, 2, K::nic, 7);
    r.body[2] = std::byte{5};
    BOOST_TEST((refused(r) == DecodeError::unknown_value));
    BOOST_TEST((refused(st::remove_of(r)) == DecodeError::unknown_value));

    // Gateways and NAT blocks.
    BOOST_TEST((refused(st::nat_gateway(1, 0, {{10, 0, 1, 9}})) == DecodeError::bad_stream_record));
    BOOST_TEST((refused(st::nat_gateway(1, 2, {})) == DecodeError::bad_stream_record));
    BOOST_TEST((refused(st::nat_gateway(1, 2, {{10, 0, 1, 9}, {10, 0, 1, 9}})) ==
                DecodeError::bad_stream_record));
    BOOST_TEST((refused(st::internet_gateway(0)) == DecodeError::bad_id));
    BOOST_TEST((refused(st::nat_block(1, 8, 0, 7)) == DecodeError::bad_stream_record));
    BOOST_TEST((refused(st::nat_block(1, 0, 63, 7)) == DecodeError::bad_stream_record));
    BOOST_TEST((refused(st::nat_block(1, 0, 0, 0)) == DecodeError::bad_id));

    // Security groups.
    BOOST_TEST((refused(st::security_group(0)) == DecodeError::bad_id));
    BOOST_TEST((refused(st::sg_rule_tcp(1, 80, 22)) == DecodeError::bad_stream_record));
    r = st::sg_rule_tcp(1, 22, 22);
    r.body[8] = std::byte{3};  // direction
    BOOST_TEST((refused(r) == DecodeError::unknown_value));
    r = st::sg_rule_tcp(1, 22, 22);
    r.body[16] = std::byte{1};  // ICMP from an IPv4 prefix: type 22, code 22 is fine
    BOOST_TEST(proto::encode_vpc_stream(one(r)).has_value());
    r.body[18] = std::byte{6};  // ICMP needs IPv4
    r.body[19] = std::byte{0};
    r.body[32] = std::byte{0};
    BOOST_TEST((refused(r) == DecodeError::bad_stream_record));
    BOOST_TEST((refused(st::membership(1, {})) == DecodeError::too_many_entries));
    BOOST_TEST((refused(st::membership(1, {5, 4})) == DecodeError::not_ascending));
    BOOST_TEST((refused(st::membership(1, {0})) == DecodeError::bad_id));
    r = st::tracking(1);
    r.body[8] = std::byte{1};  // tcp_established below 60
    r.body[9] = std::byte{0};
    r.body[10] = std::byte{0};
    BOOST_TEST((refused(r) == DecodeError::bad_stream_record));

    // Multicast.
    r = st::group_policy(1);
    r.body[8] = std::byte{0};  // rate_frames 0
    BOOST_TEST((refused(r) == DecodeError::bad_group_limits));
    BOOST_TEST((refused(st::member_list4(3, {})) == DecodeError::too_many_entries));
    BOOST_TEST((refused(st::member_list4(3, {2, 1})) == DecodeError::not_ascending));
    r = st::member_list4(3, {1});
    r.body[8] = std::byte{10};  // not a group
    BOOST_TEST((refused(r) == DecodeError::bad_group));
    BOOST_TEST((refused(st::lookup_interest(0)) == DecodeError::bad_nic_id));
}

BOOST_AUTO_TEST_CASE(no_prefix_of_a_frame_decodes_and_size_is_bounded) {
    auto s = st::snapshot(9);
    s.records = st::every_type();
    const auto frame = proto::encode_vpc_stream(s).value();
    for (std::size_t n = 0; n < frame.size(); ++n) {
        BOOST_TEST_CONTEXT("prefix " << n) {
            BOOST_TEST(!proto::decode_vpc_stream(std::span{frame}.first(n)).has_value());
        }
    }
    // Fill a delta to the limit with 40-byte bindings.
    auto big = st::delta(1, 1);
    const auto per = proto::stream_record_header_size + proto::stream_nic_binding_size;
    const auto fit = (proto::max_vpc_stream_size - proto::min_vpc_stream_size) / per;
    for (std::size_t i = 0; i < fit; ++i) {
        big.records.push_back(st::nic_binding(i + 1, 0, 1, 1));
    }
    const auto full = proto::encode_vpc_stream(big);
    BOOST_REQUIRE(full.has_value());
    BOOST_TEST(full->size() <= proto::max_vpc_stream_size);
    BOOST_TEST(proto::decode_vpc_stream(*full).has_value());
    big.records.push_back(st::nic_binding(fit + 1, 0, 1, 1));
    BOOST_TEST((encode_error(big) == DecodeError::record_too_large));
    std::vector<std::byte> over(proto::max_vpc_stream_size + 1);
    BOOST_TEST((proto::decode_vpc_stream(over).error() == DecodeError::record_too_large));
}
