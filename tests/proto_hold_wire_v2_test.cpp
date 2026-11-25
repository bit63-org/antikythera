// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kythira .kiro/specs/khold-block-service/ Requirement 11 (task 2): the
// hold wire version 2 codec. Every frame round-trips canonically and
// streams (header, then payload); the header rules, payload rules and
// lengths are enforced both ways; the test vectors reproduce byte for byte;
// and version 1 and version 2 refuse each other's frames.

#define BOOST_TEST_MODULE proto_hold_wire_v2_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"
#include "proto/hold_wire.hpp"
#include "proto/hold_wire_v2.hpp"
#include "proto/test_vectors.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
namespace vec = ak::proto::vectors;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using proto::HoldV2Opcode;
using Op = proto::HoldV2Opcode;
using St = proto::HoldV2Status;

namespace {

constexpr std::uint64_t volume = 0x200;
constexpr std::uint64_t epoch = 3;
constexpr std::uint64_t attachment = 0xA1;
constexpr std::uint32_t generation = 2;
constexpr std::uint64_t lba = 0x1000;
constexpr std::uint64_t group = 0x5001;
constexpr std::uint64_t term = 4;
constexpr std::size_t off_flags = 0x06;
constexpr std::size_t off_payload_len = 0x08;
constexpr std::size_t off_status = 0x0C;
constexpr std::size_t off_reserved = 0x0E;
constexpr std::size_t off_blocks = 0x34;
constexpr std::size_t off_group = 0x40;
constexpr std::size_t off_reserved2 = 0x50;
constexpr std::uint16_t redirect_port = 7400;
constexpr std::uint8_t ula = 0xFD;
constexpr std::size_t last = 15;

auto from_hex(std::string_view hex) -> std::vector<std::byte> {
    const auto nibble = [](char c) -> unsigned {
        return c <= '9' ? static_cast<unsigned>(c - '0') : static_cast<unsigned>(c - 'a' + 10);
    };
    std::vector<std::byte> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = std::byte{
            static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4U) | nibble(hex[(2 * i) + 1]))};
    }
    return out;
}

auto endpoint(std::uint8_t tail) -> proto::StorageEndpoint {
    proto::StorageEndpoint e{};
    e[0] = std::byte{ula};
    e[last] = std::byte{tail};
    return e;
}

// Owns the bytes BlockData spans point at.
struct Blocks {
    std::vector<std::byte> data;
    std::vector<std::byte> crcs;
    std::uint32_t block_size;

    Blocks(std::uint32_t n, std::uint32_t bs) : data(std::size_t{n} * bs), block_size{bs} {
        for (std::size_t i = 0; i < data.size(); ++i) {
            data[i] = std::byte{static_cast<std::uint8_t>((i * 13U) + 1U)};
        }
        crcs = proto::block_crcs(data, bs);
    }
    [[nodiscard]] auto view() const -> proto::BlockData {
        return {.block_size = block_size, .crcs = crcs, .data = data};
    }
};

auto header(Op op, std::uint32_t blocks = 0, bool response = false) -> proto::HoldV2Header {
    return {.opcode = op,
            .flags = response ? proto::hold_flags::response : std::uint16_t{0},
            .payload_len = 0,
            .status = St::ok,
            .request_id = 77,
            .volume_id = volume,
            .epoch = epoch,
            .attachment_id = attachment,
            .generation = generation,
            .blocks = blocks,
            .lba = blocks != 0 ? lba : 0,
            .group_id = group,
            .term = term};
}

auto copier_header(Op op, std::uint32_t blocks = 0, bool response = false) -> proto::HoldV2Header {
    auto h = header(op, blocks, response);
    h.attachment_id = 0;
    h.generation = 0;
    return h;
}

auto redirect_header() -> proto::HoldV2Header {
    auto h = header(Op::redirect, 0, true);
    h.status = St::not_leader;
    return h;
}

auto leader() -> proto::HoldV2Redirect {
    return {.leader_server = 0x22,
            .endpoint = endpoint(0x22),
            .port = redirect_port,
            .leader_term = term + 1};
}

auto encoded(const proto::HoldV2Frame& f) -> std::vector<std::byte> {
    auto b = proto::encode_hold_v2_frame(f);
    BOOST_REQUIRE_MESSAGE(b.has_value(), proto::to_string(b.error()));
    return *b;
}

auto encode_error(const proto::HoldV2Frame& f) -> DecodeError {
    auto b = proto::encode_hold_v2_frame(f);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto f = proto::decode_hold_v2_frame(b);
    BOOST_REQUIRE(!f.has_value());
    return f.error();
}

auto reseal(std::vector<std::byte>& b) -> void {
    const auto crc = ak::crc32c::of(std::span{b}.first(proto::hold_v2_header_crc_offset));
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(proto::hold_v2_header_crc_offset)};
    BOOST_REQUIRE(w.write(crc, ak::wire::Order::little).has_value());
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

const Blocks four_k{3, proto::block_size_4096};
const Blocks five_twelve{3, proto::block_size_512};

auto every_frame() -> std::vector<proto::HoldV2Frame> {
    using F = proto::HoldV2Frame;
    auto failed_read = header(Op::read, 3, true);
    failed_read.status = St::repairing;
    auto no_space = header(Op::write, 3, true);
    no_space.status = St::no_space;
    auto hydrate = copier_header(Op::write, 3);
    hydrate.flags = proto::hold_flags::hydrate;
    auto session_ping = header(Op::ping);
    session_ping.group_id = 0;
    auto hello = header(Op::hello);
    hello.group_id = 0;
    auto gateway_hello = copier_header(Op::hello);
    gateway_hello.group_id = 0;
    return {
        F{hello, proto::HoldV2Hello{.role = proto::HoldV2Role::initiator}},
        F{gateway_hello, proto::HoldV2Hello{.role = proto::HoldV2Role::gateway}},
        F{copier_header(Op::hello), proto::HoldV2Hello{.role = proto::HoldV2Role::copier}},
        F{header(Op::hello_ok, 0, true), proto::HoldV2HelloOk{.block_size = 4096,
                                                              .capacity_blocks = 1U << 20,
                                                              .stripe_unit = 1U << 20,
                                                              .stripe_width = 8}},
        F{header(Op::read, 3), std::monostate{}},
        F{header(Op::read, 3, true), four_k.view()},
        F{failed_read, std::monostate{}},
        F{header(Op::write, 3), four_k.view()},
        F{header(Op::write, 3), five_twelve.view()},
        F{hydrate, four_k.view()},
        F{header(Op::write, 3, true), std::monostate{}},
        F{no_space, std::monostate{}},
        F{header(Op::write_zeroes, 8), std::monostate{}},
        F{header(Op::discard, 8, true), std::monostate{}},
        F{header(Op::flush), std::monostate{}},
        F{header(Op::flush, 0, true), std::monostate{}},
        F{session_ping, std::monostate{}},
        F{header(Op::ping, 0, true), std::monostate{}},
        F{redirect_header(), leader()},
        F{redirect_header(), proto::HoldV2Redirect{}},
    };
}

}  // namespace

BOOST_AUTO_TEST_SUITE(hold_wire_v2, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(every_frame_round_trips_canonically) {
    for (const auto& f : every_frame()) {
        const auto b = encoded(f);
        auto back = proto::decode_hold_v2_frame(b);
        BOOST_REQUIRE_MESSAGE(back.has_value(), "opcode " << static_cast<int>(f.header.opcode)
                                                          << ": "
                                                          << proto::to_string(back.error()));
        auto want = f;
        want.header.payload_len = static_cast<std::uint32_t>(b.size() - proto::hold_v2_header_size);
        BOOST_TEST((*back == want));
        BOOST_TEST((encoded(*back) == b));

        auto h = proto::decode_hold_v2_header(std::span{b}.first(proto::hold_v2_header_size));
        BOOST_REQUIRE(h.has_value());
        auto p =
            proto::decode_hold_v2_payload(*h, std::span{b}.subspan(proto::hold_v2_header_size));
        BOOST_REQUIRE(p.has_value());
        BOOST_TEST((*p == f.payload));

        auto split = proto::encode_hold_v2_header(f.header, h->payload_len);
        BOOST_REQUIRE(split.has_value());
        BOOST_TEST(std::ranges::equal(*split, std::span{b}.first(proto::hold_v2_header_size)));
        BOOST_TEST(proto::hold_frame_version(b).value_or(0) == 2);
    }
}

BOOST_AUTO_TEST_CASE(vectors_reproduce) {
    const Blocks one{1, proto::block_size_512};
    auto w = header(Op::write, 1);
    BOOST_TEST(std::ranges::equal(encoded({w, one.view()}), from_hex(vec::hold_v2_write7)));

    auto r = redirect_header();
    r.request_id = 78;
    r.term = term + 1;
    BOOST_TEST(std::ranges::equal(encoded({r, leader()}), from_hex(vec::hold_v2_redirect8)));

    auto ok = header(Op::hello_ok, 0, true);
    ok.request_id = 1;
    ok.group_id = 0;
    ok.term = 0;
    BOOST_TEST(std::ranges::equal(encoded({ok, proto::HoldV2HelloOk{.block_size = 4096,
                                                                    .capacity_blocks = 1U << 20,
                                                                    .stripe_unit = 1U << 20,
                                                                    .stripe_width = 2}}),
                                  from_hex(vec::hold_v2_hello_ok9)));

    for (auto hex : {vec::hold_v2_write7, vec::hold_v2_redirect8, vec::hold_v2_hello_ok9}) {
        const auto bytes = from_hex(hex);
        auto f = proto::decode_hold_v2_frame(bytes);
        BOOST_REQUIRE(f.has_value());
        BOOST_TEST((encoded(*f) == bytes));
    }
}

BOOST_AUTO_TEST_CASE(header_layout_is_little_endian) {
    const auto b = encoded({header(Op::write, 3), four_k.view()});
    BOOST_TEST(b.size() == proto::hold_v2_header_size + (3 * (4 + 4096)));
    const std::string_view magic{"AKHW"};
    for (std::size_t i = 0; i < magic.size(); ++i) {
        BOOST_TEST(std::to_integer<char>(b[i]) == magic[i]);
    }
    BOOST_TEST(std::to_integer<int>(b[4]) == 2);  // version
    BOOST_TEST(std::to_integer<int>(b[5]) == 4);  // write
    BOOST_TEST(le64_at(b, 0x10) == 77U);
    BOOST_TEST(le64_at(b, 0x18) == volume);
    BOOST_TEST(le64_at(b, 0x20) == epoch);
    BOOST_TEST(le64_at(b, 0x28) == attachment);
    BOOST_TEST(std::to_integer<int>(b[0x30]) == 2);  // generation
    BOOST_TEST(std::to_integer<int>(b[0x34]) == 3);  // blocks
    BOOST_TEST(le64_at(b, 0x38) == lba);
    BOOST_TEST(le64_at(b, off_group) == group);
    BOOST_TEST(le64_at(b, 0x48) == term);
    ak::wire::Reader r{std::span{b}.subspan(proto::hold_v2_header_crc_offset)};
    BOOST_TEST(r.le32().value_or(0) ==
               ak::crc32c::of(std::span{b}.first(proto::hold_v2_header_crc_offset)));
    BOOST_TEST(
        std::ranges::equal(std::span{b}.subspan(proto::hold_v2_header_size, 12), four_k.crcs));
    BOOST_TEST(
        std::ranges::equal(std::span{b}.subspan(proto::hold_v2_header_size + 12), four_k.data));
}

BOOST_AUTO_TEST_CASE(payload_layouts) {
    constexpr std::size_t p = proto::hold_v2_header_size;
    auto b = encoded({redirect_header(), leader()});
    BOOST_TEST(le64_at(b, p) == 0x22U);
    BOOST_TEST(std::to_integer<int>(b[p + 8]) == ula);
    BOOST_TEST(std::to_integer<int>(b[p + 8 + last]) == 0x22);
    BOOST_TEST(std::to_integer<int>(b[p + 24]) == (redirect_port & 0xFF));
    BOOST_TEST(le64_at(b, p + 32) == term + 1);

    b = encoded(
        {header(Op::hello_ok, 0, true),
         proto::HoldV2HelloOk{
             .block_size = 512, .capacity_blocks = 9, .stripe_unit = 1U << 16, .stripe_width = 3}});
    BOOST_TEST(std::to_integer<int>(b[p + 1]) == 2);  // 512
    BOOST_TEST(le64_at(b, p + 8) == 9U);
    BOOST_TEST(std::to_integer<int>(b[p + 18]) == 1);  // 64 KiB
    BOOST_TEST(std::to_integer<int>(b[p + 20]) == 3);

    b = encoded({copier_header(Op::hello), proto::HoldV2Hello{.role = proto::HoldV2Role::copier}});
    BOOST_TEST(std::to_integer<int>(b[p]) == 3);
}

BOOST_AUTO_TEST_CASE(versions_refuse_each_other) {
    const auto v2 = encoded({header(Op::flush), std::monostate{}});
    BOOST_TEST((proto::decode_hold_frame(v2).error() == DecodeError::bad_version));
    BOOST_TEST((proto::decode_hold_header(std::span{v2}.first(proto::hold_header_size)).error() ==
                DecodeError::bad_version));

    const auto v1 = proto::encode_hold_frame({proto::HoldHeader{.opcode = proto::HoldOpcode::flush,
                                                                .volume_id = volume,
                                                                .epoch = epoch,
                                                                .attachment_id = attachment,
                                                                .generation = generation},
                                              std::monostate{}});
    BOOST_REQUIRE(v1.has_value());
    BOOST_TEST(proto::hold_frame_version(*v1).value_or(0) == 1);
    std::vector<std::byte> padded = *v1;
    padded.resize(proto::hold_v2_header_size);
    BOOST_TEST((decode_error(padded) == DecodeError::bad_version));

    BOOST_TEST(
        (proto::hold_frame_version(std::span{v2}.first(4)).error() == DecodeError::truncated));
    auto bad = v2;
    bad[0] = std::byte{0};
    BOOST_TEST((proto::hold_frame_version(bad).error() == DecodeError::bad_magic));
}

BOOST_AUTO_TEST_CASE(header_checksum_is_checked_first) {
    const auto good = encoded({header(Op::flush), std::monostate{}});
    for (std::size_t off = 5; off < proto::hold_v2_header_size; ++off) {
        auto b = good;
        b[off] ^= std::byte{0x40};
        BOOST_TEST((decode_error(b) == DecodeError::bad_header_crc), "offset " << off);
    }
}

BOOST_AUTO_TEST_CASE(header_rules_in_decode) {
    const auto good = encoded({header(Op::flush), std::monostate{}});
    const auto refused = [&](auto mutate) {
        auto b = good;
        mutate(b);
        reseal(b);
        return decode_error(std::span{b}.first(proto::hold_v2_header_size));
    };
    // Version 1's hold-to-hold opcodes are not version 2 opcodes.
    for (int op : {0, 8, 9, 10, 11, 12, 15}) {
        BOOST_TEST((refused([op](auto& b) { b[5] = std::byte{static_cast<std::uint8_t>(op)}; }) ==
                    DecodeError::unknown_value),
                   "opcode " << op);
    }
    BOOST_TEST((refused([](auto& b) { set_at<std::uint16_t>(b, off_flags, 4); }) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((refused([](auto& b) { b[off_reserved] = std::byte{1}; }) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((refused([](auto& b) { b[off_reserved2 + 3] = std::byte{1}; }) ==
                DecodeError::reserved_not_zero));
    BOOST_TEST((refused([](auto& b) {
                    set_at<std::uint32_t>(
                        b, off_payload_len,
                        static_cast<std::uint32_t>(proto::max_hold_v2_payload + 1));
                }) == DecodeError::record_too_large));
    BOOST_TEST((refused([](auto& b) { set_at<std::uint16_t>(b, off_status, 16); }) ==
                DecodeError::unknown_value));
    BOOST_TEST((refused([](auto& b) { set_at<std::uint16_t>(b, off_status, 13); }) ==
                DecodeError::bad_hold_direction));
    BOOST_TEST((refused([](auto& b) { set_at<std::uint32_t>(b, off_blocks, 1); }) ==
                DecodeError::bad_block_range));
}

BOOST_AUTO_TEST_CASE(header_rules_in_encode) {
    struct Case {
        proto::HoldV2Header h;
        DecodeError want;
    };
    auto h = [](auto mutate) {
        auto x = header(Op::read, 1);
        mutate(x);
        return x;
    };
    const Case cases[] = {
        {h([](auto& x) { x.volume_id = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.epoch = 0; }), DecodeError::bad_epoch},
        {h([](auto& x) { x.generation = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.attachment_id = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.group_id = 0; }), DecodeError::bad_id},
        {h([](auto& x) { x.blocks = 0; }), DecodeError::bad_block_range},
        {h([](auto& x) { x.blocks = proto::max_hold_blocks + 1; }), DecodeError::bad_block_range},
        {h([](auto& x) { x.lba = UINT64_MAX; }), DecodeError::bad_block_range},
        {h([](auto& x) { x.flags = proto::hold_flags::hydrate; }), DecodeError::bad_hold_direction},
        {h([](auto& x) { x.flags = proto::hold_flags::last; }), DecodeError::reserved_not_zero},
        {h([](auto& x) { x.opcode = Op::hello_ok; }), DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.opcode = Op::redirect;
             x.blocks = 0;
             x.lba = 0;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.opcode = Op::redirect;
             x.flags = proto::hold_flags::response;
             x.status = St::stale_epoch;
             x.blocks = 0;
             x.lba = 0;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.opcode = Op::redirect;
             x.flags = proto::hold_flags::response;
             x.status = St::not_leader;
             x.group_id = 0;
             x.blocks = 0;
             x.lba = 0;
         }),
         DecodeError::bad_id},
        {h([](auto& x) {
             x.opcode = Op::hello;
             x.flags = proto::hold_flags::response;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) {
             x.flags = proto::hold_flags::response | proto::hold_flags::hydrate;
             x.opcode = Op::write;
         }),
         DecodeError::bad_hold_direction},
        {h([](auto& x) { x.opcode = Op::ping; }), DecodeError::bad_block_range},
    };
    for (const auto& c : cases) {
        auto b = proto::encode_hold_v2_header(c.h, 0);
        BOOST_REQUIRE(!b.has_value());
        BOOST_TEST((b.error() == c.want), proto::to_string(b.error()));
    }
    BOOST_TEST(
        (proto::encode_hold_v2_header(header(Op::flush), proto::max_hold_v2_payload + 1).error() ==
         DecodeError::record_too_large));
}

BOOST_AUTO_TEST_CASE(payload_rules) {
    using F = proto::HoldV2Frame;
    auto big_read = header(Op::read, 2048, true);
    std::vector<std::byte> big(std::size_t{2048} * 4096);
    std::vector<std::byte> big_crcs(std::size_t{2048} * 4);
    auto ok_with = [](proto::HoldV2HelloOk o) { return F{header(Op::hello_ok, 0, true), o}; };
    const proto::HoldV2HelloOk good_ok{
        .block_size = 4096, .capacity_blocks = 1, .stripe_unit = 1U << 20, .stripe_width = 1};
    auto bad_unit = good_ok;
    bad_unit.stripe_unit = 3U << 20;
    auto small_unit = good_ok;
    small_unit.stripe_unit = 1U << 15;
    auto big_unit = good_ok;
    big_unit.stripe_unit = 8U << 20;
    auto no_width = good_ok;
    no_width.stripe_width = 0;
    auto wide = good_ok;
    wide.stripe_width = proto::max_stripe_width + 1;
    auto odd_block = good_ok;
    odd_block.block_size = 1024;
    auto empty = good_ok;
    empty.capacity_blocks = 0;
    auto half = leader();
    half.port = 0;
    auto no_term = leader();
    no_term.leader_term = 0;
    auto multicast = leader();
    multicast.endpoint[0] = std::byte{0xFF};
    auto unknown_with_port = proto::HoldV2Redirect{};
    unknown_with_port.port = redirect_port;
    const std::pair<F, DecodeError> cases[] = {
        {F{header(Op::read, 3), four_k.view()}, DecodeError::bad_payload_size},
        {F{header(Op::write, 3), std::monostate{}}, DecodeError::bad_payload_size},
        {F{header(Op::write, 2), four_k.view()}, DecodeError::bad_payload_size},
        {F{header(Op::ping), four_k.view()}, DecodeError::bad_payload_size},
        {F{redirect_header(), std::monostate{}}, DecodeError::bad_payload_size},
        {F{big_read, proto::BlockData{.block_size = 4096, .crcs = big_crcs, .data = big}},
         DecodeError::record_too_large},
        {F{header(Op::hello), proto::HoldV2Hello{.role = proto::HoldV2Role::gateway}},
         DecodeError::bad_id},
        {F{copier_header(Op::hello), proto::HoldV2Hello{.role = proto::HoldV2Role::initiator}},
         DecodeError::bad_id},
        {F{header(Op::hello), proto::HoldV2Hello{.role = static_cast<proto::HoldV2Role>(4)}},
         DecodeError::unknown_value},
        {ok_with(odd_block), DecodeError::bad_block_size},
        {ok_with(empty), DecodeError::bad_id},
        {ok_with(bad_unit), DecodeError::bad_stripe},
        {ok_with(small_unit), DecodeError::bad_stripe},
        {ok_with(big_unit), DecodeError::bad_stripe},
        {ok_with(no_width), DecodeError::bad_stripe},
        {ok_with(wide), DecodeError::bad_stripe},
        {F{redirect_header(), half}, DecodeError::bad_redirect},
        {F{redirect_header(), no_term}, DecodeError::bad_redirect},
        {F{redirect_header(), multicast}, DecodeError::bad_redirect},
        {F{redirect_header(), unknown_with_port}, DecodeError::bad_redirect},
    };
    for (const auto& [f, want] : cases) {
        BOOST_TEST((encode_error(f) == want),
                   "opcode " << static_cast<int>(f.header.opcode) << " got "
                             << proto::to_string(proto::encode_hold_v2_frame(f).error()));
    }
    BOOST_TEST(proto::valid_stripe_unit(proto::min_stripe_unit));
    BOOST_TEST(proto::valid_stripe_unit(proto::max_stripe_unit));
    BOOST_TEST(!proto::valid_stripe_unit(0));
}

BOOST_AUTO_TEST_CASE(payload_decode_is_strict) {
    const auto with = [](const proto::HoldV2Frame& f, std::size_t off) {
        auto v = encoded(f);
        v[proto::hold_v2_header_size + off] = std::byte{1};
        return decode_error(v);
    };
    BOOST_TEST(
        (with({copier_header(Op::hello), proto::HoldV2Hello{.role = proto::HoldV2Role::copier}},
              3) == DecodeError::reserved_not_zero));
    const proto::HoldV2HelloOk ok{
        .block_size = 4096, .capacity_blocks = 1, .stripe_unit = 1U << 20, .stripe_width = 1};
    BOOST_TEST((with({header(Op::hello_ok, 0, true), ok}, 5) == DecodeError::reserved_not_zero));
    BOOST_TEST((with({header(Op::hello_ok, 0, true), ok}, 22) == DecodeError::reserved_not_zero));
    BOOST_TEST((with({redirect_header(), leader()}, 27) == DecodeError::reserved_not_zero));

    auto b = encoded({header(Op::write, 3), four_k.view()});
    b.resize(b.size() - 3);
    set_at<std::uint32_t>(b, off_payload_len,
                          static_cast<std::uint32_t>(b.size() - proto::hold_v2_header_size));
    reseal(b);
    BOOST_TEST((decode_error(b) == DecodeError::bad_payload_size));

    const auto good = encoded({header(Op::ping), std::monostate{}});
    auto h = proto::decode_hold_v2_header(std::span{good}.first(proto::hold_v2_header_size));
    BOOST_REQUIRE(h.has_value());
    const std::array<std::byte, 1> extra{};
    BOOST_TEST((proto::decode_hold_v2_payload(*h, extra).error() == DecodeError::bad_payload_size));
}

BOOST_AUTO_TEST_CASE(lengths) {
    const auto good = encoded({header(Op::write, 3), five_twelve.view()});
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
    BOOST_TEST((proto::decode_hold_v2_header(std::span{good}.first(proto::hold_v2_header_size + 1))
                    .error() == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_stripe, DecodeError::bad_redirect,
                   DecodeError::bad_group_members, DecodeError::bad_mirror}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
