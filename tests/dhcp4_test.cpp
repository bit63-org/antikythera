// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 12.3 (task 17): the DHCPv4
// message codec behind oar-net's stateless server.

#define BOOST_TEST_MODULE dhcp4_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <map>
#include <vector>

#include "net_frames.hpp"
#include "oar/net/dhcp4.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace d4 = ak::oar::net::dhcp4;
namespace fr = ak::test::frames;
using ak::test::unit_timeout_seconds;
using d4::MessageType;
using d4::ParseError;

namespace {

constexpr std::uint32_t xid = 0xA1B2C3D4;
constexpr std::uint8_t opt_requested_ip = 50;
constexpr std::uint8_t opt_server_id = 54;
constexpr std::size_t op_index = 0;
constexpr std::size_t htype_index = 1;
constexpr std::size_t cookie_index = 236;

const net::MacAddress client_mac{std::byte{0x02}, std::byte{0}, std::byte{0},
                                 std::byte{0},    std::byte{0}, std::byte{0x2a}};

auto ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> d4::Ipv4Address {
    return {std::byte{a}, std::byte{b}, std::byte{c}, std::byte{d}};
}

auto bytes_of(const d4::Ipv4Address& a) -> std::vector<std::byte> {
    return {a.begin(), a.end()};
}

auto options_of(const std::vector<std::byte>& m) -> std::map<std::uint8_t, std::vector<std::byte>> {
    std::map<std::uint8_t, std::vector<std::byte>> out;
    for (auto& [code, value] : fr::dhcp4_options(m)) {
        out.try_emplace(code, value);
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(parse)

BOOST_AUTO_TEST_CASE(discover, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto m = d4::parse(fr::dhcp4_request(1, client_mac, xid, {}, d4::flag_broadcast));
    BOOST_REQUIRE(m.has_value());
    BOOST_TEST((m->type == MessageType::discover));
    BOOST_TEST(m->xid == xid);
    BOOST_TEST(m->flags == d4::flag_broadcast);
    BOOST_TEST((m->chaddr == client_mac));
    BOOST_TEST(!m->requested_ip.has_value());
    BOOST_TEST(!m->server_id.has_value());
}

BOOST_AUTO_TEST_CASE(request_options, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto m = d4::parse(fr::dhcp4_request(
        3, client_mac, xid,
        {{opt_requested_ip, bytes_of(ip(10, 0, 0, 5))},
         {opt_server_id, bytes_of(ip(10, 0, 0, 1))},
         {opt_requested_ip, bytes_of(ip(10, 0, 0, 9))}},  // a second instance is ignored
        0, ip(10, 0, 0, 5)));
    BOOST_REQUIRE(m.has_value());
    BOOST_TEST((m->type == MessageType::request));
    BOOST_TEST((m->ciaddr == ip(10, 0, 0, 5)));
    BOOST_TEST((*m->requested_ip == ip(10, 0, 0, 5)));
    BOOST_TEST((*m->server_id == ip(10, 0, 0, 1)));
}

BOOST_AUTO_TEST_CASE(pads_and_missing_end, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto raw = fr::dhcp4_request(8, client_mac, xid);
    raw.pop_back();                                               // no End
    raw.insert(raw.begin() + cookie_index + 4, 3, std::byte{0});  // pads before option 53
    const auto m = d4::parse(raw);
    BOOST_REQUIRE(m.has_value());
    BOOST_TEST((m->type == MessageType::inform));
}

BOOST_AUTO_TEST_CASE(errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = fr::dhcp4_request(1, client_mac, xid);
    BOOST_TEST((d4::parse(std::span{good}.first(239)).error() == ParseError::truncated));

    auto m = good;
    m[op_index] = std::byte{2};
    BOOST_TEST((d4::parse(m).error() == ParseError::not_request));
    m = good;
    m[htype_index] = std::byte{6};  // IEEE 802 token ring
    BOOST_TEST((d4::parse(m).error() == ParseError::bad_hardware));
    m = good;
    m[cookie_index] = std::byte{0};
    BOOST_TEST((d4::parse(m).error() == ParseError::bad_cookie));

    // An option running past the end.
    m = good;
    m.pop_back();
    m.push_back(std::byte{12});
    m.push_back(std::byte{9});
    m.push_back(std::byte{'x'});
    BOOST_TEST((d4::parse(m).error() == ParseError::truncated));

    // No message type; a bad one; a server-only one; wrong lengths.
    m = good;
    m.resize(cookie_index + 4);
    m.push_back(std::byte{255});
    BOOST_TEST((d4::parse(m).error() == ParseError::missing_type));
    BOOST_TEST(
        (d4::parse(fr::dhcp4_request(9, client_mac, xid)).error() == ParseError::unknown_type));
    BOOST_TEST(
        (d4::parse(fr::dhcp4_request(2, client_mac, xid)).error() == ParseError::unknown_type));
    BOOST_TEST((d4::parse(fr::dhcp4_request(3, client_mac, xid,
                                            {{opt_requested_ip, {std::byte{10}, std::byte{0}}}}))
                    .error() == ParseError::bad_option));

    m = good;
    m.insert(m.end() - 1, d4::max_options_size, std::byte{0});
    BOOST_TEST((d4::parse(m).error() == ParseError::options_too_long));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(build)

BOOST_AUTO_TEST_CASE(offer, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto req = d4::parse(fr::dhcp4_request(1, client_mac, xid, {}, d4::flag_broadcast));
    BOOST_REQUIRE(req.has_value());
    const d4::Reply r{.type = MessageType::offer,
                      .yiaddr = ip(10, 0, 0, 5),
                      .server = ip(10, 0, 0, 1),
                      .subnet_mask = ip(255, 255, 0, 0),
                      .router = ip(10, 0, 0, 1),
                      .dns = {ip(10, 0, 0, 2), ip(1, 1, 1, 1)},
                      .domain = "ec2.internal",
                      .mtu = 8874,
                      .lease_seconds = 3600};
    const auto out = d4::build_reply(*req, r);
    BOOST_TEST(out.size() >= d4::min_message_size);
    BOOST_TEST(std::to_integer<int>(out[0]) == 2);  // BOOTREPLY
    BOOST_TEST(std::ranges::equal(std::span{out}.subspan(4, 4),
                                  std::vector<std::byte>{std::byte{0xA1}, std::byte{0xB2},
                                                         std::byte{0xC3}, std::byte{0xD4}}));
    BOOST_TEST(std::ranges::equal(std::span{out}.subspan(16, 4), ip(10, 0, 0, 5)));  // yiaddr
    BOOST_TEST(std::ranges::equal(std::span{out}.subspan(28, 6), client_mac));
    const auto opts = options_of(out);
    BOOST_TEST((opts.at(53) == std::vector<std::byte>{std::byte{2}}));
    BOOST_TEST((opts.at(54) == bytes_of(ip(10, 0, 0, 1))));
    BOOST_TEST((opts.at(1) == bytes_of(ip(255, 255, 0, 0))));
    BOOST_TEST((opts.at(3) == bytes_of(ip(10, 0, 0, 1))));
    BOOST_TEST(opts.at(6).size() == 8);
    BOOST_TEST(std::string(reinterpret_cast<const char*>(opts.at(15).data()), opts.at(15).size()) ==
               "ec2.internal");
    BOOST_TEST((opts.at(26) == std::vector<std::byte>{std::byte{0x22}, std::byte{0xAA}}));
    BOOST_TEST((opts.at(51) == std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0x0e},
                                                      std::byte{0x10}}));  // 3600
    BOOST_TEST((opts.at(58) == std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0x07},
                                                      std::byte{0x08}}));  // 1800
    BOOST_TEST((opts.at(59) == std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0x0c},
                                                      std::byte{0x4e}}));  // 3150

    // A reply is not a request: our own parser refuses it.
    BOOST_TEST((d4::parse(out).error() == ParseError::not_request));
}

BOOST_AUTO_TEST_CASE(nak_and_inform, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto req = d4::parse(fr::dhcp4_request(3, client_mac, xid, {}, 0, ip(10, 0, 0, 7)));
    BOOST_REQUIRE(req.has_value());
    const auto nak = d4::build_reply(
        *req, {.type = MessageType::nak, .server = ip(10, 0, 0, 1), .lease_seconds = 3600});
    auto opts = options_of(nak);
    BOOST_TEST(opts.size() == 2);                    // type and server identifier only
    BOOST_TEST(nak.size() == d4::min_message_size);  // padded
    BOOST_TEST((opts.at(53) == std::vector<std::byte>{std::byte{6}}));
    BOOST_TEST(std::ranges::equal(std::span{nak}.subspan(12, 4), d4::Ipv4Address{}));  // ciaddr

    const auto ack = d4::build_reply(*req, {.type = MessageType::ack,
                                            .server = ip(10, 0, 0, 1),
                                            .subnet_mask = ip(255, 255, 255, 0),
                                            .router = ip(10, 0, 0, 1)});
    opts = options_of(ack);
    BOOST_TEST(!opts.contains(51));  // no lease for an inform
    BOOST_TEST(!opts.contains(6));
    BOOST_TEST(!opts.contains(15));
    BOOST_TEST(!opts.contains(26));
    BOOST_TEST(opts.contains(1));
}

BOOST_AUTO_TEST_SUITE_END()
