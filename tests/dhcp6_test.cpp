// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 12.4 and 12.5 (task 18):
// the DHCPv6 codec and the router advertisement body.

#define BOOST_TEST_MODULE dhcp6_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

#include "net_frames.hpp"
#include "oar/net/dhcp6.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace d6 = ak::oar::net::dhcp6;
namespace fr = ak::test::frames;
using ak::test::unit_timeout_seconds;
using d6::MessageType;
using d6::ParseError;

namespace {

constexpr std::uint32_t xid = 0x00AB'CDEF;
constexpr std::uint16_t opt_client_id = 1;
constexpr std::uint16_t opt_server_id = 2;
constexpr std::uint16_t opt_ia_na = 3;
constexpr std::uint16_t opt_status = 13;
constexpr std::uint16_t opt_rapid_commit = 14;
constexpr std::uint16_t opt_dns = 23;
constexpr std::uint16_t opt_domain = 24;
constexpr std::uint32_t iaid = 0x0102'0304;

const net::MacAddress gw{std::byte{0x02}, std::byte{0xaa}, std::byte{0},
                         std::byte{0},    std::byte{0},    std::byte{1}};

auto duid(std::uint8_t tag) -> std::vector<std::byte> {
    return {std::byte{0}, std::byte{3}, std::byte{0}, std::byte{1}, std::byte{2},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{tag}};
}

auto addr(std::uint8_t last) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[15] = std::byte{last};
    return a;
}

auto find(const std::vector<std::pair<std::uint16_t, std::vector<std::byte>>>& opts,
          std::uint16_t code) -> const std::vector<std::byte>* {
    for (const auto& [c, v] : opts) {
        if (c == code) {
            return &v;
        }
    }
    return nullptr;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(parse)

BOOST_AUTO_TEST_CASE(solicit, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto m =
        d6::parse(fr::dhcp6_message(1, xid,
                                    {{opt_client_id, duid(7)},
                                     {opt_ia_na, fr::ia_na(iaid)},
                                     {opt_rapid_commit, {}},
                                     {8, {std::byte{0}, std::byte{0}}}}));  // elapsed time: ignored
    BOOST_REQUIRE(m.has_value());
    BOOST_TEST((m->type == MessageType::solicit));
    BOOST_TEST(m->xid == xid);
    BOOST_TEST(m->client_id == duid(7));
    BOOST_TEST(!m->server_id.has_value());
    BOOST_REQUIRE(m->ia_na.has_value());
    BOOST_TEST(m->ia_na->iaid == iaid);
    BOOST_TEST(m->rapid_commit);
}

BOOST_AUTO_TEST_CASE(confirm_addresses, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto m = d6::parse(
        fr::dhcp6_message(4, xid,
                          {{opt_client_id, duid(7)},
                           {opt_ia_na, fr::ia_na(iaid, {addr(1), addr(2)})},
                           {opt_ia_na, fr::ia_na(9, {addr(3)})}}));  // only the first IA_NA counts
    BOOST_REQUIRE(m.has_value());
    BOOST_REQUIRE(m->ia_na.has_value());
    BOOST_TEST(m->ia_na->iaid == iaid);
    BOOST_REQUIRE(m->ia_na->addresses.size() == 2);
    BOOST_TEST((m->ia_na->addresses[1] == addr(2)));
}

BOOST_AUTO_TEST_CASE(errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(
        (d6::parse(std::vector<std::byte>(3, std::byte{1})).error() == ParseError::truncated));
    BOOST_TEST((d6::parse(fr::dhcp6_message(2, xid, {})).error() == ParseError::unknown_type));
    BOOST_TEST((d6::parse(fr::dhcp6_message(7, xid, {})).error() == ParseError::unknown_type));
    BOOST_TEST((d6::parse(fr::dhcp6_message(1, xid, {{opt_client_id, {}}})).error() ==
                ParseError::bad_duid));
    BOOST_TEST((d6::parse(fr::dhcp6_message(
                              1, xid, {{opt_server_id, std::vector<std::byte>(131, std::byte{1})}}))
                    .error() == ParseError::bad_duid));
    BOOST_TEST(
        (d6::parse(fr::dhcp6_message(1, xid, {{opt_ia_na, std::vector<std::byte>(11)}})).error() ==
         ParseError::bad_option));
    BOOST_TEST(
        (d6::parse(fr::dhcp6_message(1, xid, {{opt_rapid_commit, {std::byte{1}}}})).error() ==
         ParseError::bad_option));
    auto m = fr::dhcp6_message(1, xid, {{opt_client_id, duid(7)}});
    m.pop_back();  // the option now runs past the end
    BOOST_TEST((d6::parse(m).error() == ParseError::truncated));
    std::vector<net::Ipv6Address> many(d6::max_ia_addresses + 1, addr(1));
    BOOST_TEST(
        (d6::parse(fr::dhcp6_message(4, xid, {{opt_ia_na, fr::ia_na(iaid, many)}})).error() ==
         ParseError::too_many_addresses));
    BOOST_TEST((d6::parse(std::vector<std::byte>(d6::max_message_size + 1, std::byte{1})).error() ==
                ParseError::too_long));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(build)

BOOST_AUTO_TEST_CASE(reply_with_addresses, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto req = d6::parse(fr::dhcp6_message(3, xid,
                                                 {{opt_client_id, duid(7)},
                                                  {opt_server_id, d6::server_duid(gw)},
                                                  {opt_ia_na, fr::ia_na(iaid)}}));
    BOOST_REQUIRE(req.has_value());
    const auto out = d6::build_reply(*req, {.type = MessageType::reply,
                                            .server_id = d6::server_duid(gw),
                                            .iaid = iaid,
                                            .addresses = {addr(1), addr(2)},
                                            .lifetime = 3600,
                                            .dns = {addr(53)},
                                            .domain = "ec2.internal"});
    BOOST_TEST(std::to_integer<int>(out[0]) == 7);
    BOOST_TEST(std::to_integer<int>(out[3]) == 0xEF);
    const auto opts = fr::dhcp6_options(out);
    BOOST_REQUIRE(find(opts, opt_server_id) != nullptr);
    BOOST_TEST(*find(opts, opt_server_id) ==
               (std::vector<std::byte>{std::byte{0}, std::byte{3}, std::byte{0}, std::byte{1},
                                       std::byte{0x02}, std::byte{0xaa}, std::byte{0}, std::byte{0},
                                       std::byte{0}, std::byte{1}}));
    BOOST_TEST(*find(opts, opt_client_id) == duid(7));
    const auto* ia = find(opts, opt_ia_na);
    BOOST_REQUIRE(ia != nullptr);
    BOOST_TEST(ia->size() == 12 + (2 * 28));
    BOOST_TEST(find(opts, opt_dns)->size() == 16);
    const std::vector<std::byte> wire_name{
        std::byte{3},   std::byte{'e'}, std::byte{'c'}, std::byte{'2'}, std::byte{8},
        std::byte{'i'}, std::byte{'n'}, std::byte{'t'}, std::byte{'e'}, std::byte{'r'},
        std::byte{'n'}, std::byte{'a'}, std::byte{'l'}, std::byte{0}};
    BOOST_TEST(*find(opts, opt_domain) == wire_name);
    BOOST_TEST(find(opts, opt_status) == nullptr);
    // A reply is not a client message: our own parser refuses it.
    BOOST_TEST((d6::parse(out).error() == ParseError::unknown_type));
}

BOOST_AUTO_TEST_CASE(no_addresses_and_status, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto req = d6::parse(fr::dhcp6_message(1, xid, {{opt_client_id, duid(7)}}));
    BOOST_REQUIRE(req.has_value());
    const auto out = d6::build_reply(
        *req, {.type = MessageType::advertise, .server_id = d6::server_duid(gw), .iaid = iaid});
    const auto opts = fr::dhcp6_options(out);
    const auto* ia = find(opts, opt_ia_na);
    BOOST_REQUIRE(ia != nullptr);
    BOOST_TEST(ia->size() == 12 + 6);  // a NoAddrsAvail status inside
    BOOST_TEST(std::to_integer<int>((*ia)[17]) == 2);
    const auto confirm = d6::build_reply(*req, {.type = MessageType::reply,
                                                .server_id = d6::server_duid(gw),
                                                .status = d6::StatusCode::not_on_link,
                                                .rapid_commit = true});
    const auto copts = fr::dhcp6_options(confirm);
    BOOST_TEST(find(copts, opt_ia_na) == nullptr);
    BOOST_TEST(find(copts, opt_rapid_commit) != nullptr);
    BOOST_TEST(std::to_integer<int>((*find(copts, opt_status))[1]) == 4);
}

BOOST_AUTO_TEST_CASE(router_advertisement, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto body = d6::build_router_advertisement_body({.gateway_mac = gw,
                                                           .prefix = addr(0),
                                                           .mtu = 8874,
                                                           .dns = {addr(53), addr(54)},
                                                           .router_lifetime = 1800,
                                                           .dns_lifetime = 600});
    BOOST_TEST(std::to_integer<int>(body[0]) == 64);    // hop limit
    BOOST_TEST(std::to_integer<int>(body[1]) == 0xC0);  // M | O
    BOOST_TEST(std::to_integer<int>(body[2]) == 0x07);  // 1800
    BOOST_TEST(std::to_integer<int>(body[3]) == 0x08);
    // Options: source link-layer (8), MTU (8), prefix (32), RDNSS (8 + 32).
    BOOST_TEST(body.size() == 12 + 8 + 8 + 32 + 40);
    BOOST_TEST(std::ranges::equal(std::span{body}.subspan(14, 6), gw));
    const std::size_t prefix_at = 12 + 8 + 8;
    BOOST_TEST(std::to_integer<int>(body[prefix_at]) == 3);
    BOOST_TEST(std::to_integer<int>(body[prefix_at + 2]) == 64);
    BOOST_TEST(std::to_integer<int>(body[prefix_at + 3]) == 0x80);  // on-link, not autonomous
    BOOST_TEST(std::to_integer<int>(body[prefix_at + 32]) == 25);   // RDNSS
    BOOST_TEST(std::to_integer<int>(body[prefix_at + 33]) == 5);

    const auto bare = d6::build_router_advertisement_body(
        {.gateway_mac = gw, .prefix = addr(0), .router_lifetime = 1800});
    BOOST_TEST(bare.size() == 12 + 8 + 32);  // no MTU, no RDNSS
}

BOOST_AUTO_TEST_SUITE_END()
