// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 10.5 (task 14): reading
// IGMP and MLD membership reports and building the gateway's queries.

#define BOOST_TEST_MODULE igmp_test
#include <boost/test/unit_test.hpp>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/wire.hpp"
#include "net_frames.hpp"
#include "oar/net/igmp.hpp"
#include "oar/net/packet.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace igmp = ak::oar::net::igmp;
namespace pk = ak::oar::net::packet;
namespace fr = ak::test::frames;
using ak::test::unit_timeout_seconds;

namespace {

const net::MacAddress guest_mac{std::byte{0x02}, std::byte{0}, std::byte{0},
                                std::byte{0},    std::byte{0}, std::byte{0x11}};
const net::MacAddress v4_group_mac{std::byte{0x01}, std::byte{0x00}, std::byte{0x5E},
                                   std::byte{0x00}, std::byte{0x00}, std::byte{0x16}};
const net::MacAddress v6_group_mac{std::byte{0x33}, std::byte{0x33}, std::byte{0},
                                   std::byte{0},    std::byte{0},    std::byte{0x16}};
const pk::Ipv4Address guest4{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{11}};
const pk::Ipv4Address v3_reports{std::byte{224}, std::byte{0}, std::byte{0}, std::byte{22}};

auto v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> pk::Ipv4Address {
    return {std::byte{a}, std::byte{b}, std::byte{c}, std::byte{d}};
}

auto v6(std::uint8_t first, std::uint8_t second, std::uint8_t last) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{first};
    a[1] = std::byte{second};
    a[15] = std::byte{last};
    return a;
}

auto link_local() -> net::Ipv6Address {
    return v6(0xFE, 0x80, 0x11);
}

auto group4(const pk::Ipv4Address& a) -> igmp::Group {
    igmp::Group g{.ipv6 = false, .address = {}};
    std::ranges::copy(a, g.address.begin());
    return g;
}

auto group6(const net::Ipv6Address& a) -> igmp::Group {
    return {.ipv6 = true, .address = a};
}

// An IGMP message with its checksum filled.
auto igmp_message(std::vector<std::byte> m) -> std::vector<std::byte> {
    m[2] = std::byte{0};
    m[3] = std::byte{0};
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < m.size(); i += 2) {
        sum +=
            (std::to_integer<std::uint32_t>(m[i]) << 8U) | std::to_integer<std::uint32_t>(m[i + 1]);
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    const auto c = static_cast<std::uint16_t>(~sum & 0xFFFFU);
    m[2] = static_cast<std::byte>(c >> 8U);
    m[3] = static_cast<std::byte>(c & 0xFFU);
    return m;
}

auto igmp_v2(std::uint8_t type, const pk::Ipv4Address& group) -> std::vector<std::byte> {
    std::vector<std::byte> m;
    ak::wire::Writer w{m};
    w.u8(type);
    w.u8(0);
    w.be16(0);
    w.bytes(group);
    return igmp_message(m);
}

struct Record4 {
    std::uint8_t type;
    pk::Ipv4Address group;
    std::uint16_t sources{0};
    std::uint8_t aux_words{0};
};

auto igmp_v3(const std::vector<Record4>& records) -> std::vector<std::byte> {
    std::vector<std::byte> m;
    ak::wire::Writer w{m};
    w.u8(igmp::igmp_v3_report);
    w.u8(0);
    w.be16(0);
    w.be16(0);
    w.be16(static_cast<std::uint16_t>(records.size()));
    for (const auto& r : records) {
        w.u8(r.type);
        w.u8(r.aux_words);
        w.be16(r.sources);
        w.bytes(r.group);
        for (std::uint16_t s = 0; s < r.sources; ++s) {
            w.bytes(v4(10, 9, 9, static_cast<std::uint8_t>(s + 1)));
        }
        for (std::uint8_t a = 0; a < r.aux_words; ++a) {
            w.be32(0);
        }
    }
    return igmp_message(m);
}

auto ipv4_frame(const std::vector<std::byte>& igmp_bytes) -> std::vector<std::byte> {
    return fr::ipv4(v4_group_mac, guest_mac, guest4, v3_reports, igmp::ipproto_igmp, igmp_bytes);
}

struct Record6 {
    std::uint8_t type;
    net::Ipv6Address group;
    std::uint16_t sources{0};
};

auto mld_v2_body(const std::vector<Record6>& records) -> std::vector<std::byte> {
    std::vector<std::byte> b;
    ak::wire::Writer w{b};
    w.be16(0);
    w.be16(static_cast<std::uint16_t>(records.size()));
    for (const auto& r : records) {
        w.u8(r.type);
        w.u8(0);
        w.be16(r.sources);
        w.bytes(r.group);
        for (std::uint16_t s = 0; s < r.sources; ++s) {
            w.bytes(v6(0xFD, 0x99, static_cast<std::uint8_t>(s + 1)));
        }
    }
    return b;
}

auto mld_frame(std::uint8_t type, const std::vector<std::byte>& body) -> std::vector<std::byte> {
    const auto dst = v6(0xFF, 0x02, 0x16);
    return fr::ipv6(v6_group_mac, guest_mac, link_local(), dst, pk::ipproto_icmpv6,
                    fr::icmpv6(link_local(), dst, type, 0, body), 1);
}

auto mld_v1(std::uint8_t type, const net::Ipv6Address& group) -> std::vector<std::byte> {
    std::vector<std::byte> body;
    ak::wire::Writer w{body};
    w.be16(0);
    w.be16(0);
    w.bytes(group);
    return mld_frame(type, body);
}

auto parsed(const std::vector<std::byte>& f) -> pk::ParsedPacket {
    auto p = pk::parse(f);
    BOOST_REQUIRE(p.has_value());
    return *p;
}

auto changes(const std::vector<std::byte>& f) -> std::vector<igmp::Change> {
    const auto p = parsed(f);
    BOOST_REQUIRE((igmp::classify(p) == igmp::Kind::report));
    auto c = igmp::parse_report(p);
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? "" : igmp::to_string(c.error())));
    return *c;
}

auto error(const std::vector<std::byte>& f) -> igmp::SnoopError {
    auto c = igmp::parse_report(parsed(f));
    BOOST_REQUIRE(!c.has_value());
    return c.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(snooping, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(classifies_membership_messages) {
    BOOST_TEST(
        (igmp::classify(parsed(ipv4_frame(igmp_v2(igmp::igmp_query, {})))) == igmp::Kind::query));
    BOOST_TEST((igmp::classify(parsed(ipv4_frame(igmp_v2(0x13, {})))) == igmp::Kind::other));
    BOOST_TEST((igmp::classify(parsed(mld_v1(igmp::mld_query, {}))) == igmp::Kind::query));
    BOOST_TEST(
        (igmp::classify(parsed(mld_v1(igmp::mld_v1_done, v6(0xFF, 5, 1)))) == igmp::Kind::report));
    // UDP and other ICMPv6 are not membership messages.
    const auto udp =
        fr::ipv4(guest_mac, guest_mac, guest4, guest4, pk::ipproto_udp, fr::udp(1, 2, {}));
    BOOST_TEST(!igmp::classify(parsed(udp)).has_value());
    BOOST_TEST(!igmp::classify(parsed(mld_v1(128, {}))).has_value());  // echo request
    // A fragment never is.
    BOOST_TEST(!igmp::classify(
                    parsed(fr::ipv4(v4_group_mac, guest_mac, guest4, v3_reports, igmp::ipproto_igmp,
                                    igmp_v2(igmp::igmp_v2_report, v4(239, 1, 1, 1)), 0x2000)))
                    .has_value());
}

BOOST_AUTO_TEST_CASE(igmp_v1_and_v2) {
    const auto g = v4(239, 1, 2, 3);
    BOOST_TEST((changes(ipv4_frame(igmp_v2(igmp::igmp_v2_report, g))) ==
                std::vector<igmp::Change>{{.group = group4(g), .join = true}}));
    BOOST_TEST((changes(ipv4_frame(igmp_v2(igmp::igmp_v1_report, g))) ==
                std::vector<igmp::Change>{{.group = group4(g), .join = true}}));
    BOOST_TEST((changes(ipv4_frame(igmp_v2(igmp::igmp_v2_leave, g))) ==
                std::vector<igmp::Change>{{.group = group4(g), .join = false}}));
    // A unicast "group" is skipped, not an error.
    BOOST_TEST(changes(ipv4_frame(igmp_v2(igmp::igmp_v2_report, guest4))).empty());
}

BOOST_AUTO_TEST_CASE(igmp_v3_records) {
    const auto a = v4(239, 0, 0, 1);
    const auto b = v4(239, 0, 0, 2);
    const auto c = v4(239, 0, 0, 3);
    const auto d = v4(232, 1, 1, 1);
    const auto got = changes(ipv4_frame(igmp_v3({
        {.type = 2, .group = a},                                // MODE_IS_EXCLUDE: join
        {.type = 4, .group = b, .sources = 0, .aux_words = 1},  // CHANGE_TO_EXCLUDE: join
        {.type = 3, .group = c},                                // CHANGE_TO_INCLUDE {}: leave
        {.type = 5, .group = d, .sources = 2},                  // ALLOW_NEW_SOURCES: join
        {.type = 6, .group = a, .sources = 1},                  // BLOCK_OLD_SOURCES: nothing
        {.type = 1, .group = d, .sources = 1},                  // MODE_IS_INCLUDE {S}: join
        {.type = 5, .group = c},                                // ALLOW {}: nothing
    })));
    const std::vector<igmp::Change> want{{.group = group4(a), .join = true},
                                         {.group = group4(b), .join = true},
                                         {.group = group4(c), .join = false},
                                         {.group = group4(d), .join = true},
                                         {.group = group4(d), .join = true}};
    BOOST_TEST((got == want));
}

BOOST_AUTO_TEST_CASE(mld_v1_and_v2) {
    const auto g = v6(0xFF, 0x05, 0x42);
    BOOST_TEST((changes(mld_v1(igmp::mld_v1_report, g)) ==
                std::vector<igmp::Change>{{.group = group6(g), .join = true}}));
    BOOST_TEST((changes(mld_v1(igmp::mld_v1_done, g)) ==
                std::vector<igmp::Change>{{.group = group6(g), .join = false}}));
    // A guest's solicited-node join is skipped: neighbor discovery owns it.
    auto solicited = v6(0xFF, 0x02, 0x11);
    solicited[11] = std::byte{0x01};
    solicited[12] = std::byte{0xFF};
    const auto got = changes(
        mld_frame(igmp::mld_v2_report, mld_v2_body({{.type = 4, .group = solicited},
                                                    {.type = 4, .group = g},
                                                    {.type = 3, .group = v6(0xFF, 0x0E, 1)},
                                                    {.type = 1, .group = g, .sources = 1}})));
    const std::vector<igmp::Change> want{{.group = group6(g), .join = true},
                                         {.group = group6(v6(0xFF, 0x0E, 1)), .join = false},
                                         {.group = group6(g), .join = true}};
    BOOST_TEST((got == want));
}

BOOST_AUTO_TEST_CASE(refuses_broken_reports) {
    auto m = igmp_v2(igmp::igmp_v2_report, v4(239, 1, 2, 3));
    m[3] ^= std::byte{1};
    BOOST_TEST((error(ipv4_frame(m)) == igmp::SnoopError::bad_checksum));
    // Shorter than an IGMP header.
    BOOST_TEST((error(ipv4_frame(igmp_message({std::byte{0x16}, std::byte{0}, std::byte{0},
                                               std::byte{0}}))) == igmp::SnoopError::malformed));
    // A record count past the end, and a source count past the end.
    auto v3 = igmp_v3({{.type = 2, .group = v4(239, 0, 0, 1)}});
    v3[7] = std::byte{2};
    BOOST_TEST((error(ipv4_frame(igmp_message(v3))) == igmp::SnoopError::malformed));
    v3 = igmp_v3({{.type = 2, .group = v4(239, 0, 0, 1)}});
    v3[11] = std::byte{1};
    BOOST_TEST((error(ipv4_frame(igmp_message(v3))) == igmp::SnoopError::malformed));
    BOOST_TEST((error(ipv4_frame(igmp_v3({{.type = 7, .group = v4(239, 0, 0, 1)}}))) ==
                igmp::SnoopError::unknown_type));
    // MLD with a wrong checksum, and an MLDv1 report too short for its group.
    auto bad = mld_v1(igmp::mld_v1_report, v6(0xFF, 5, 1));
    bad.back() ^= std::byte{1};
    BOOST_TEST((error(bad) == igmp::SnoopError::bad_checksum));
    BOOST_TEST((error(mld_frame(igmp::mld_v1_report, std::vector<std::byte>(8))) ==
                igmp::SnoopError::malformed));
    BOOST_TEST(std::string_view{igmp::to_string(igmp::SnoopError::unknown_type)} != "unknown");
}

BOOST_AUTO_TEST_CASE(queries_are_what_hosts_expect) {
    const net::MacAddress gw{std::byte{0x02}, std::byte{0xAA}, std::byte{0},
                             std::byte{0},    std::byte{0},    std::byte{1}};
    const auto q4 = igmp::build_query4(gw, v4(10, 0, 0, 1));
    const auto p4 = parsed(q4);
    BOOST_TEST(p4.hop_limit == 1U);
    BOOST_TEST((p4.dst4 == v4(224, 0, 0, 1)));
    BOOST_TEST((igmp::classify(p4) == igmp::Kind::query));
    BOOST_REQUIRE(q4.size() == 14U + 24U + 12U);
    BOOST_TEST(std::to_integer<int>(q4[14]) == 0x46);  // IHL 6: the Router Alert option
    BOOST_TEST(std::to_integer<int>(q4[34]) == 0x94);
    BOOST_TEST(fr::ipv4_header_checksum(std::span{q4}.subspan(14, 24)) == 0U);
    const auto msg = std::span{q4}.subspan(38);
    BOOST_TEST(fr::ipv4_header_checksum(msg) == 0U);  // the same sum covers IGMP
    BOOST_TEST(std::to_integer<int>(msg[1]) == 100);  // 10 s
    BOOST_TEST(std::to_integer<int>(msg[9]) == 125);  // QQIC

    const auto ll = v6(0xFE, 0x80, 0x01);
    const auto q6 = igmp::build_query6(gw, ll);
    const auto p6 = parsed(q6);
    BOOST_TEST(p6.hop_limit == 1U);
    BOOST_TEST((p6.dst6 == v6(0xFF, 0x02, 0x01)));
    BOOST_TEST((igmp::classify(p6) == igmp::Kind::query));
    BOOST_TEST(p6.l4_data.size() == 28U);
    BOOST_TEST(net::neighbor::icmpv6_checksum(ll, p6.dst6, p6.l4_data) == 0U);
    BOOST_TEST(std::to_integer<int>(q6[14 + 6]) == pk::ipproto_hop_by_hop);
    BOOST_TEST(std::to_integer<int>(q6[14 + 40 + 2]) == 0x05);  // Router Alert
}

BOOST_AUTO_TEST_SUITE_END()
