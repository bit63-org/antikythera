// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE geneve_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <vector>

#include "common/wire.hpp"
#include "oar/net/geneve.hpp"

namespace geneve = ak::oar::net::geneve;
using geneve::DecodeError;
using geneve::NicId;

namespace {

std::vector<std::byte> ethernet_frame(std::size_t payload = 32) {
    std::vector<std::byte> f(geneve::ethernet_header_size + payload);
    for (std::size_t i = 0; i < f.size(); ++i) {
        f[i] = static_cast<std::byte>(i & 0xFF);
    }
    return f;
}

geneve::EncodeParams params() {
    return {.vni = 0x00ABCDEF, .nics = {NicId{0x1111'2222'3333'4444}, NicId{0x5555'6666'7777'8888}}, .oam = false};
}

std::vector<std::byte> encoded() { return *geneve::encode(params(), ethernet_frame()); }

// Builds a Geneve payload by hand so malformed variants can be expressed.
struct Builder {
    std::uint8_t version{0};
    bool oam{false};
    bool critical_flag{true};
    std::uint16_t protocol{geneve::protocol_ethernet};
    std::uint32_t vni{42};
    std::vector<std::byte> options;
    std::vector<std::byte> inner{ethernet_frame()};
    int opt_len_adjust{0};  // lie about Opt Len

    void add_option(std::uint16_t cls, std::uint8_t type, std::vector<std::byte> data) {
        ak::wire::Writer w{options};
        w.be16(cls);
        w.u8(type);
        w.u8(static_cast<std::uint8_t>(data.size() / 4));
        w.bytes(data);
    }

    void add_nic_pair(std::uint64_t src, std::uint64_t dst) {
        std::vector<std::byte> d;
        ak::wire::Writer w{d};
        w.be64(src);
        w.be64(dst);
        add_option(geneve::option_class, geneve::option_type_nic_pair, d);
    }

    [[nodiscard]] std::vector<std::byte> build() const {
        std::vector<std::byte> out;
        ak::wire::Writer w{out};
        const int words = static_cast<int>(options.size() / 4) + opt_len_adjust;
        w.u8(static_cast<std::uint8_t>((version << 6) | (words & 0x3F)));
        w.u8(static_cast<std::uint8_t>((oam ? 0x80 : 0) | (critical_flag ? 0x40 : 0)));
        w.be16(protocol);
        w.be32(vni << 8);
        w.bytes(options);
        w.bytes(inner);
        return out;
    }
};

Builder valid_builder() {
    Builder b;
    b.add_nic_pair(7, 9);
    return b;
}

DecodeError decode_error(const std::vector<std::byte>& pkt) {
    auto r = geneve::decode(pkt);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(encode_produces_the_documented_header) {
    const auto pkt = encoded();
    BOOST_TEST(pkt.size() == geneve::base_header_size + geneve::nic_pair_option_size + ethernet_frame().size());
    ak::wire::Reader r{pkt};
    BOOST_TEST(*r.u8() == 0x05u);  // Ver 0, Opt Len 5 words
    BOOST_TEST(*r.u8() == 0x40u);  // C set, O clear
    BOOST_TEST(*r.be16() == 0x6558u);
    BOOST_TEST(*r.be32() == 0xABCDEF00u);  // VNI, reserved byte zero
    BOOST_TEST(*r.be16() == geneve::option_class);
    BOOST_TEST(*r.u8() == 0x81u);  // critical | type 1
    BOOST_TEST(*r.u8() == 0x04u);  // 16 bytes of data
    BOOST_TEST(*r.be64() == 0x1111'2222'3333'4444ull);
    BOOST_TEST(*r.be64() == 0x5555'6666'7777'8888ull);
    const auto frame = ethernet_frame();
    BOOST_TEST(std::ranges::equal(r.rest(), frame));
}

BOOST_AUTO_TEST_CASE(round_trip) {
    const auto pkt = encoded();
    auto d = geneve::decode(pkt);
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->vni == 0x00ABCDEFu);
    BOOST_TEST(!d->oam);
    BOOST_REQUIRE(d->nics.has_value());
    BOOST_TEST((d->nics->src == params().nics.src));
    BOOST_TEST((d->nics->dst == params().nics.dst));
    const auto frame = ethernet_frame();
    BOOST_TEST(std::ranges::equal(d->inner, frame));
}

BOOST_AUTO_TEST_CASE(broadcast_destination_is_accepted) {
    auto p = params();
    p.nics.dst = geneve::nic_broadcast;
    auto d = geneve::decode(*geneve::encode(p, ethernet_frame()));
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((d->nics->dst == geneve::nic_broadcast));
}

BOOST_AUTO_TEST_CASE(encode_rejects_bad_parameters) {
    auto p = params();
    p.vni = geneve::vni_max + 1;
    BOOST_TEST((geneve::encode(p, ethernet_frame()).error() == geneve::EncodeError::vni_out_of_range));
    p = params();
    p.nics.src = geneve::nic_broadcast;
    BOOST_TEST((geneve::encode(p, ethernet_frame()).error() == geneve::EncodeError::invalid_nic_id));
    p = params();
    p.nics.dst = geneve::nic_invalid;
    BOOST_TEST((geneve::encode(p, ethernet_frame()).error() == geneve::EncodeError::invalid_nic_id));
    p = params();
    BOOST_TEST((geneve::encode(p, ethernet_frame(0)).has_value()));
    std::vector<std::byte> short_frame(geneve::ethernet_header_size - 1);
    BOOST_TEST((geneve::encode(p, short_frame).error() == geneve::EncodeError::inner_frame_too_short));
}

BOOST_AUTO_TEST_CASE(every_truncation_of_a_valid_packet_is_rejected) {
    const auto pkt = encoded();
    const std::size_t min_valid = geneve::base_header_size + geneve::nic_pair_option_size + geneve::ethernet_header_size;
    for (std::size_t len = 0; len < min_valid; ++len) {
        std::vector<std::byte> cut(pkt.begin(), pkt.begin() + static_cast<std::ptrdiff_t>(len));
        BOOST_TEST(!geneve::decode(cut).has_value(), "length " << len << " accepted");
    }
}

BOOST_AUTO_TEST_CASE(rejects_nonzero_version) {
    auto b = valid_builder();
    b.version = 1;
    BOOST_TEST((decode_error(b.build()) == DecodeError::bad_version));
}

BOOST_AUTO_TEST_CASE(rejects_opt_len_past_end) {
    auto b = valid_builder();
    b.inner.clear();
    b.opt_len_adjust = 1;
    BOOST_TEST((decode_error(b.build()) == DecodeError::options_overrun));
}

BOOST_AUTO_TEST_CASE(rejects_option_running_past_opt_len) {
    // Option header claims 16 bytes of data but Opt Len covers only 8.
    auto b = valid_builder();
    b.opt_len_adjust = -3;
    BOOST_TEST((decode_error(b.build()) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_critical_option) {
    auto b = valid_builder();
    b.add_option(0x0102, 0x85, std::vector<std::byte>(4));
    BOOST_TEST((decode_error(b.build()) == DecodeError::unknown_critical_option));
}

BOOST_AUTO_TEST_CASE(skips_unknown_non_critical_option) {
    auto b = valid_builder();
    b.add_option(0x0102, 0x05, std::vector<std::byte>(8));
    auto d = geneve::decode(b.build());
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST((d->nics->src == NicId{7}));
}

BOOST_AUTO_TEST_CASE(rejects_critical_option_without_c_flag) {
    auto b = valid_builder();
    b.critical_flag = false;
    BOOST_TEST((decode_error(b.build()) == DecodeError::critical_flag_mismatch));
}

BOOST_AUTO_TEST_CASE(rejects_missing_and_duplicate_nic_pair) {
    Builder none;
    none.critical_flag = false;
    BOOST_TEST((decode_error(none.build()) == DecodeError::missing_nic_pair));

    auto dup = valid_builder();
    dup.add_nic_pair(7, 9);
    BOOST_TEST((decode_error(dup.build()) == DecodeError::duplicate_nic_pair));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_nic_pair_length) {
    Builder b;
    b.add_option(geneve::option_class, geneve::option_type_nic_pair, std::vector<std::byte>(12));
    BOOST_TEST((decode_error(b.build()) == DecodeError::bad_option_length));
}

BOOST_AUTO_TEST_CASE(rejects_reserved_nic_ids) {
    for (const auto& [src, dst] : {std::pair{0ull, 9ull}, std::pair{~0ull, 9ull}, std::pair{7ull, 0ull}}) {
        Builder b;
        b.add_nic_pair(src, dst);
        BOOST_TEST((decode_error(b.build()) == DecodeError::invalid_nic_id));
    }
}

BOOST_AUTO_TEST_CASE(rejects_non_ethernet_data_packet) {
    auto b = valid_builder();
    b.protocol = 0x86DD;
    BOOST_TEST((decode_error(b.build()) == DecodeError::bad_protocol));
}

BOOST_AUTO_TEST_CASE(rejects_short_inner_frame) {
    auto b = valid_builder();
    b.inner.resize(geneve::ethernet_header_size - 1);
    BOOST_TEST((decode_error(b.build()) == DecodeError::inner_frame_too_short));
}

BOOST_AUTO_TEST_CASE(oam_packet_needs_no_nic_pair) {
    Builder b;
    b.oam = true;
    b.critical_flag = false;
    b.protocol = 0x0000;
    b.inner.resize(4);
    auto d = geneve::decode(b.build());
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->oam);
    BOOST_TEST(!d->nics.has_value());
}
