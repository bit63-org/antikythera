// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 3 and 4.1.

#define BOOST_TEST_MODULE geneve_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "oar/net/geneve.hpp"
#include "test_support.hpp"

namespace geneve = ak::oar::net::geneve;
using ak::test::unit_timeout_seconds;
using geneve::DecodeError;
using geneve::NicId;

namespace {

constexpr std::size_t default_payload = 32;
constexpr std::uint8_t byte_mask = 0xFF;

constexpr std::uint32_t sample_vni = 0x00ABCDEF;
constexpr std::uint32_t sample_vni_word = sample_vni << geneve::vni_shift;
constexpr NicId sample_src{0x1111'2222'3333'4444};
constexpr NicId sample_dst{0x5555'6666'7777'8888};

constexpr std::uint8_t expected_first_byte =
    geneve::nic_pair_option_size / geneve::bytes_per_word;  // Ver 0, Opt Len 5
constexpr std::uint8_t flag_oam = 0x80;
constexpr std::uint8_t flag_critical = 0x40;
constexpr unsigned version_shift = 6;
constexpr std::uint8_t opt_len_mask = 0x3F;
constexpr std::uint8_t nic_pair_length_words = 4;

constexpr std::uint32_t builder_vni = 42;
constexpr std::uint64_t builder_src = 7;
constexpr std::uint64_t builder_dst = 9;
constexpr NicId builder_src_id{builder_src};

constexpr std::uint8_t bad_version = 1;
constexpr int one_word_too_many = 1;
constexpr int three_words_too_few = -3;

constexpr std::uint16_t foreign_option_class = 0x0102;
constexpr std::uint8_t foreign_critical_type = 0x85;
constexpr std::uint8_t foreign_noncritical_type = 0x05;
constexpr std::size_t one_word = 4;
constexpr std::size_t two_words = 8;
constexpr std::size_t three_words = 12;

constexpr std::uint16_t protocol_ipv6 = 0x86DD;
constexpr std::uint16_t protocol_none = 0x0000;
constexpr std::size_t oam_payload = 4;

constexpr std::uint64_t all_ones = ~std::uint64_t{0};

auto ethernet_frame(std::size_t payload = default_payload) -> std::vector<std::byte> {
    std::vector<std::byte> f(geneve::ethernet_header_size + payload);
    for (std::size_t i = 0; i < f.size(); ++i) {
        f[i] = static_cast<std::byte>(i & byte_mask);
    }
    return f;
}

auto params() -> geneve::EncodeParams {
    return {.vni = sample_vni, .nics = {sample_src, sample_dst}, .oam = false};
}

auto encoded() -> std::vector<std::byte> {
    return *geneve::encode(params(), ethernet_frame());
}

// Builds a Geneve payload by hand so malformed variants can be expressed.
struct Builder {
    std::uint8_t version{0};
    bool oam{false};
    bool critical_flag{true};
    std::uint16_t protocol{geneve::protocol_ethernet};
    std::uint32_t vni{builder_vni};
    std::vector<std::byte> options;
    std::vector<std::byte> inner{ethernet_frame()};
    int opt_len_adjust{0};  // lie about Opt Len

    auto add_option(std::uint16_t cls, std::uint8_t type, const std::vector<std::byte>& data)
        -> void {
        ak::wire::Writer w{options};
        w.be16(cls);
        w.u8(type);
        w.u8(static_cast<std::uint8_t>(data.size() / geneve::bytes_per_word));
        w.bytes(data);
    }

    auto add_nic_pair(std::uint64_t src, std::uint64_t dst) -> void {
        std::vector<std::byte> d;
        ak::wire::Writer w{d};
        w.be64(src);
        w.be64(dst);
        add_option(geneve::option_class, geneve::option_type_nic_pair, d);
    }

    [[nodiscard]] auto build() const -> std::vector<std::byte> {
        std::vector<std::byte> out;
        ak::wire::Writer w{out};
        const int words =
            static_cast<int>(options.size() / geneve::bytes_per_word) + opt_len_adjust;
        w.u8(static_cast<std::uint8_t>((version << version_shift) | (words & opt_len_mask)));
        w.u8(static_cast<std::uint8_t>((oam ? flag_oam : 0) | (critical_flag ? flag_critical : 0)));
        w.be16(protocol);
        w.be32(vni << geneve::vni_shift);
        w.bytes(options);
        w.bytes(inner);
        return out;
    }
};

auto valid_builder() -> Builder {
    Builder b;
    b.add_nic_pair(builder_src, builder_dst);
    return b;
}

auto decode_error(const std::vector<std::byte>& pkt) -> DecodeError {
    auto r = geneve::decode(pkt);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(encode_produces_the_documented_header,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto pkt = encoded();
    BOOST_TEST(pkt.size() ==
               geneve::base_header_size + geneve::nic_pair_option_size + ethernet_frame().size());
    ak::wire::Reader r{pkt};
    BOOST_TEST(*r.u8() == expected_first_byte);
    BOOST_TEST(*r.u8() == flag_critical);  // C set, O clear
    BOOST_TEST(*r.be16() == geneve::protocol_ethernet);
    BOOST_TEST(*r.be32() == sample_vni_word);  // reserved byte zero
    BOOST_TEST(*r.be16() == geneve::option_class);
    BOOST_TEST(*r.u8() == geneve::option_type_nic_pair);
    BOOST_TEST(*r.u8() == nic_pair_length_words);
    BOOST_TEST(*r.be64() == sample_src.value);
    BOOST_TEST(*r.be64() == sample_dst.value);
    const auto frame = ethernet_frame();
    BOOST_TEST(std::ranges::equal(r.rest(), frame));
}

BOOST_AUTO_TEST_CASE(round_trip, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto pkt = encoded();
    auto d = geneve::decode(pkt);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->vni == sample_vni);
    BOOST_TEST(!d->oam);
    BOOST_REQUIRE(d->nics.has_value());
    BOOST_TEST((d->nics->src == sample_src));
    BOOST_TEST((d->nics->dst == sample_dst));
    const auto frame = ethernet_frame();
    BOOST_TEST(std::ranges::equal(d->inner, frame));
}

BOOST_AUTO_TEST_CASE(broadcast_destination_is_accepted,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto p = params();
    p.nics.dst = geneve::nic_broadcast;
    auto d = geneve::decode(*geneve::encode(p, ethernet_frame()));
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((d->nics->dst == geneve::nic_broadcast));
}

BOOST_AUTO_TEST_CASE(encode_rejects_bad_parameters,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto p = params();
    p.vni = geneve::vni_max + 1;
    BOOST_TEST(
        (geneve::encode(p, ethernet_frame()).error() == geneve::EncodeError::vni_out_of_range));
    p = params();
    p.nics.src = geneve::nic_broadcast;
    BOOST_TEST(
        (geneve::encode(p, ethernet_frame()).error() == geneve::EncodeError::invalid_nic_id));
    p = params();
    p.nics.dst = geneve::nic_invalid;
    BOOST_TEST(
        (geneve::encode(p, ethernet_frame()).error() == geneve::EncodeError::invalid_nic_id));
    p = params();
    BOOST_TEST((geneve::encode(p, ethernet_frame(0)).has_value()));
    std::vector<std::byte> short_frame(geneve::ethernet_header_size - 1);
    BOOST_TEST(
        (geneve::encode(p, short_frame).error() == geneve::EncodeError::inner_frame_too_short));
}

BOOST_AUTO_TEST_CASE(every_truncation_of_a_valid_packet_is_rejected,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto pkt = encoded();
    const std::size_t min_valid =
        geneve::base_header_size + geneve::nic_pair_option_size + geneve::ethernet_header_size;
    for (std::size_t len = 0; len < min_valid; ++len) {
        std::vector<std::byte> cut(pkt.begin(), pkt.begin() + static_cast<std::ptrdiff_t>(len));
        BOOST_TEST(!geneve::decode(cut).has_value(), "length " << len << " accepted");
    }
}

BOOST_AUTO_TEST_CASE(rejects_nonzero_version, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.version = bad_version;
    BOOST_TEST((decode_error(b.build()) == DecodeError::bad_version));
}

BOOST_AUTO_TEST_CASE(rejects_opt_len_past_end, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.inner.clear();
    b.opt_len_adjust = one_word_too_many;
    BOOST_TEST((decode_error(b.build()) == DecodeError::options_overrun));
}

BOOST_AUTO_TEST_CASE(rejects_option_running_past_opt_len,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Option header claims 16 bytes of data but Opt Len covers only 8.
    auto b = valid_builder();
    b.opt_len_adjust = three_words_too_few;
    BOOST_TEST((decode_error(b.build()) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_critical_option,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.add_option(foreign_option_class, foreign_critical_type, std::vector<std::byte>(one_word));
    BOOST_TEST((decode_error(b.build()) == DecodeError::unknown_critical_option));
}

BOOST_AUTO_TEST_CASE(skips_unknown_non_critical_option,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.add_option(foreign_option_class, foreign_noncritical_type, std::vector<std::byte>(two_words));
    auto d = geneve::decode(b.build());
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((d->nics->src == builder_src_id));
}

BOOST_AUTO_TEST_CASE(rejects_critical_option_without_c_flag,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.critical_flag = false;
    BOOST_TEST((decode_error(b.build()) == DecodeError::critical_flag_mismatch));
}

BOOST_AUTO_TEST_CASE(rejects_missing_and_duplicate_nic_pair,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Builder none;
    none.critical_flag = false;
    BOOST_TEST((decode_error(none.build()) == DecodeError::missing_nic_pair));

    auto dup = valid_builder();
    dup.add_nic_pair(builder_src, builder_dst);
    BOOST_TEST((decode_error(dup.build()) == DecodeError::duplicate_nic_pair));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_nic_pair_length,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Builder b;
    b.add_option(geneve::option_class, geneve::option_type_nic_pair,
                 std::vector<std::byte>(three_words));
    BOOST_TEST((decode_error(b.build()) == DecodeError::bad_option_length));
}

BOOST_AUTO_TEST_CASE(rejects_reserved_nic_ids, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::pair<std::uint64_t, std::uint64_t> reserved_pairs[] = {
        {0, builder_dst},         // invalid source
        {all_ones, builder_dst},  // broadcast is never a source
        {builder_src, 0},         // invalid destination
    };
    for (const auto& [src, dst] : reserved_pairs) {
        Builder b;
        b.add_nic_pair(src, dst);
        BOOST_TEST((decode_error(b.build()) == DecodeError::invalid_nic_id));
    }
}

BOOST_AUTO_TEST_CASE(rejects_non_ethernet_data_packet,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.protocol = protocol_ipv6;
    BOOST_TEST((decode_error(b.build()) == DecodeError::bad_protocol));
}

BOOST_AUTO_TEST_CASE(rejects_short_inner_frame, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto b = valid_builder();
    b.inner.resize(geneve::ethernet_header_size - 1);
    BOOST_TEST((decode_error(b.build()) == DecodeError::inner_frame_too_short));
}

BOOST_AUTO_TEST_CASE(oam_packet_needs_no_nic_pair,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Builder b;
    b.oam = true;
    b.critical_flag = false;
    b.protocol = protocol_none;
    b.inner.resize(oam_payload);
    auto d = geneve::decode(b.build());
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->oam);
    BOOST_TEST(!d->nics.has_value());
}
