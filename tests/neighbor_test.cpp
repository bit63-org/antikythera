// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 2.6 (task 8): ARP and
// neighbor solicitation parsing, and the proxy's replies.

#define BOOST_TEST_MODULE neighbor_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "oar/net/neighbor.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace nb = ak::oar::net::neighbor;
using ak::test::unit_timeout_seconds;
using nb::ParseError;

namespace {

constexpr std::size_t mac_last = 5;
constexpr std::size_t ipv6_last = 15;
constexpr std::byte locally_administered{0x02};
constexpr std::byte ula_prefix{0xfd};
constexpr std::uint8_t requester_tail = 0x0a;
constexpr std::uint8_t owner_tail = 0x0b;
constexpr std::uint16_t arp_htype_ethernet = 1;
constexpr std::uint8_t mac_size = 6;
constexpr std::uint8_t ipv4_size = 4;
constexpr std::uint8_t ipproto_hop_by_hop = 0;
constexpr std::uint8_t icmpv6_echo_request = 128;
constexpr std::uint8_t nd_option_source_lladdr = 1;
constexpr std::uint8_t nd_option_nonce = 14;
constexpr std::uint32_t ipv6_version_word = 0x6000'0000;
constexpr std::size_t ethernet_header_size = 14;
constexpr std::size_t checksum_at = ethernet_header_size + nb::ipv6_header_size + 2;
constexpr std::size_t hop_limit_at = ethernet_header_size + 7;
constexpr std::size_t arp_htype_at = ethernet_header_size;
constexpr std::size_t arp_op_at = ethernet_header_size + 7;  // low byte of the opcode
constexpr std::size_t arp_padding = 18;                      // to the 60-byte Ethernet minimum
constexpr std::uint32_t na_flags_solicited_override = 0x6000'0000;

auto mac(std::uint8_t tail) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = locally_administered;
    m[mac_last] = std::byte{tail};
    return m;
}

auto ip6(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = ula_prefix;
    a[ipv6_last] = std::byte{tail};
    return a;
}

constexpr nb::Ipv4Address ip4_requester{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}};
constexpr nb::Ipv4Address ip4_owner{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{2}};

auto broadcast_mac() -> net::MacAddress {
    net::MacAddress m{};
    m.fill(std::byte{0xff});
    return m;
}

struct ArpSpec {
    net::MacAddress frame_src = mac(requester_tail);
    net::MacAddress sender_mac = mac(requester_tail);
    std::uint16_t op = nb::arp_op_request;
};

auto arp_frame(const ArpSpec& spec) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    ak::wire::Writer w{out};
    w.bytes(broadcast_mac());
    w.bytes(spec.frame_src);
    w.be16(nb::ethertype_arp);
    w.be16(arp_htype_ethernet);
    w.be16(nb::ethertype_ipv4);
    w.u8(mac_size);
    w.u8(ipv4_size);
    w.be16(spec.op);
    w.bytes(spec.sender_mac);
    w.bytes(ip4_requester);
    w.bytes(net::MacAddress{});
    w.bytes(ip4_owner);
    return out;
}

// Solicited-node multicast address and MAC for ip6(owner_tail).
auto solicited_node() -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xff};
    a[1] = std::byte{0x02};
    a[11] = std::byte{0x01};
    a[12] = std::byte{0xff};
    a[ipv6_last] = std::byte{owner_tail};
    return a;
}

auto solicited_node_mac() -> net::MacAddress {
    return {std::byte{0x33}, std::byte{0x33}, std::byte{0xff},
            std::byte{0},    std::byte{0},    std::byte{owner_tail}};
}

struct NsSpec {
    net::Ipv6Address source = ip6(requester_tail);
    net::Ipv6Address target = ip6(owner_tail);
    std::uint8_t next_header = nb::ipproto_icmpv6;
    std::uint8_t type = nb::icmpv6_neighbor_solicitation;
    bool slla = true;
    net::MacAddress slla_mac = mac(requester_tail);
    std::uint8_t slla_units = 1;
    bool fix_checksum = true;
};

auto ns_frame(const NsSpec& spec) -> std::vector<std::byte> {
    std::vector<std::byte> message;
    ak::wire::Writer m{message};
    m.u8(spec.type);
    m.u8(0);
    m.be16(0);
    m.be32(0);
    m.bytes(spec.target);
    if (spec.slla) {
        m.u8(nd_option_source_lladdr);
        m.u8(spec.slla_units);
        m.bytes(spec.slla_mac);
        // A longer option keeps the claimed length honest.
        for (std::size_t i = 1; i < spec.slla_units; ++i) {
            m.be64(0);
        }
    }
    const auto dst = solicited_node();
    if (spec.fix_checksum) {
        const std::uint16_t sum = nb::icmpv6_checksum(spec.source, dst, message);
        message[2] = static_cast<std::byte>(sum >> CHAR_BIT);
        message[3] = static_cast<std::byte>(sum & UINT8_MAX);
    }

    std::vector<std::byte> out;
    ak::wire::Writer w{out};
    w.bytes(solicited_node_mac());
    w.bytes(mac(requester_tail));
    w.be16(nb::ethertype_ipv6);
    w.be32(ipv6_version_word);
    w.be16(static_cast<std::uint16_t>(message.size()));
    w.u8(spec.next_header);
    w.u8(nb::nd_hop_limit);
    w.bytes(spec.source);
    w.bytes(dst);
    w.bytes(message);
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(arp)

BOOST_AUTO_TEST_CASE(parses_request, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto p = nb::parse_arp(arp_frame({}));
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->op == nb::arp_op_request);
    BOOST_TEST((p->sender_mac == mac(requester_tail)));
    BOOST_TEST((p->sender_ip == ip4_requester));
    BOOST_TEST((p->target_ip == ip4_owner));
}

BOOST_AUTO_TEST_CASE(ignores_padding, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto f = arp_frame({});
    f.resize(f.size() + arp_padding);
    BOOST_TEST(nb::parse_arp(f).has_value());
}

BOOST_AUTO_TEST_CASE(rejects_malformed, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto f = arp_frame({});
    BOOST_TEST((nb::parse_arp(std::span{f}.first(f.size() - 1)).error() == ParseError::truncated));
    BOOST_TEST((nb::parse_arp(std::span{f}.first(ethernet_header_size - 1)).error() ==
                ParseError::truncated));

    auto wrong_type = f;
    wrong_type[ethernet_header_size - 1] = std::byte{0x00};  // 0x0800, IPv4
    BOOST_TEST((nb::parse_arp(wrong_type).error() == ParseError::not_arp));

    auto bad_htype = f;
    bad_htype[arp_htype_at + 1] = std::byte{6};  // IEEE 802
    BOOST_TEST((nb::parse_arp(bad_htype).error() == ParseError::bad_format));

    auto rarp = f;
    rarp[arp_op_at] = std::byte{3};
    BOOST_TEST((nb::parse_arp(rarp).error() == ParseError::unknown_op));
}

BOOST_AUTO_TEST_CASE(rejects_sender_mismatch, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = arp_frame({.sender_mac = mac(owner_tail)});
    BOOST_TEST((nb::parse_arp(f).error() == ParseError::sender_mismatch));
}

BOOST_AUTO_TEST_CASE(builds_reply, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto req = nb::parse_arp(arp_frame({}));
    BOOST_REQUIRE(req.has_value());
    const auto reply = nb::build_arp_reply(*req, mac(owner_tail));
    BOOST_TEST(reply.size() == ethernet_header_size + nb::arp_size);
    // Addressed to the requester, from the owner.
    BOOST_TEST((net::MacAddress{reply[0], reply[1], reply[2], reply[3], reply[4], reply[5]} ==
                mac(requester_tail)));
    const auto p = nb::parse_arp(reply);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->op == nb::arp_op_reply);
    BOOST_TEST((p->sender_mac == mac(owner_tail)));
    BOOST_TEST((p->sender_ip == ip4_owner));
    BOOST_TEST((p->target_mac == mac(requester_tail)));
    BOOST_TEST((p->target_ip == ip4_requester));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(neighbor_discovery)

// RFC 1071 4.1's example words sum to 0xddf2; with the IPv6 pseudo-header
// for an 8-byte ICMPv6 message between :: and :: (length 8, next header 58)
// the sum is 0xde34 and the checksum its complement.
BOOST_AUTO_TEST_CASE(checksum_vector, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto data = ak::test::bytes_of(0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7);
    BOOST_TEST(nb::icmpv6_checksum({}, {}, data) == 0x21cb);
}

BOOST_AUTO_TEST_CASE(parses_solicitation, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto ns = nb::parse_neighbor_solicitation(ns_frame({}));
    BOOST_REQUIRE(ns.has_value());
    BOOST_TEST((ns->sender_mac == mac(requester_tail)));
    BOOST_TEST((ns->source_ip == ip6(requester_tail)));
    BOOST_TEST((ns->target_ip == ip6(owner_tail)));

    BOOST_TEST(nb::parse_neighbor_solicitation(ns_frame({.slla = false})).has_value());
    const auto dad = nb::parse_neighbor_solicitation(ns_frame({.source = {}, .slla = false}));
    BOOST_REQUIRE(dad.has_value());
    BOOST_TEST((dad->source_ip == net::Ipv6Address{}));
}

BOOST_AUTO_TEST_CASE(skips_unknown_options, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A nonce option (RFC 3971) after the SLLA, built by hand.
    auto f = ns_frame({.fix_checksum = false});
    const auto nonce = ak::test::bytes_of(nd_option_nonce, 1, 1, 2, 3, 4, 5, 6);
    f.insert(f.end(), nonce.begin(), nonce.end());
    const std::size_t message_at = ethernet_header_size + nb::ipv6_header_size;
    const auto length = static_cast<std::uint16_t>(f.size() - message_at);
    f[ethernet_header_size + 4] = static_cast<std::byte>(length >> CHAR_BIT);
    f[ethernet_header_size + 5] = static_cast<std::byte>(length & UINT8_MAX);
    const std::uint16_t sum = nb::icmpv6_checksum(ip6(requester_tail), solicited_node(),
                                                  std::span{f}.subspan(message_at));
    f[checksum_at] = static_cast<std::byte>(sum >> CHAR_BIT);
    f[checksum_at + 1] = static_cast<std::byte>(sum & UINT8_MAX);
    BOOST_TEST(nb::parse_neighbor_solicitation(f).has_value());
}

BOOST_AUTO_TEST_CASE(rejects_malformed, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto parse = [](const std::vector<std::byte>& f) {
        return nb::parse_neighbor_solicitation(f);
    };
    BOOST_TEST((parse(arp_frame({})).error() == ParseError::not_icmpv6));
    BOOST_TEST(
        (parse(ns_frame({.next_header = ipproto_hop_by_hop})).error() == ParseError::not_icmpv6));
    BOOST_TEST(
        (parse(ns_frame({.type = icmpv6_echo_request})).error() == ParseError::not_solicitation));
    BOOST_TEST((parse(ns_frame({.fix_checksum = false})).error() == ParseError::bad_checksum));
    BOOST_TEST((parse(ns_frame({.target = solicited_node()})).error() == ParseError::bad_target));
    BOOST_TEST(
        (parse(ns_frame({.slla_mac = mac(owner_tail)})).error() == ParseError::sender_mismatch));
    BOOST_TEST((parse(ns_frame({.slla_units = 2})).error() == ParseError::bad_option));
    BOOST_TEST((parse(ns_frame({.slla_units = 0})).error() == ParseError::bad_option));
    BOOST_TEST((parse(ns_frame({.source = {}})).error() == ParseError::bad_option));

    auto low_hop = ns_frame({});
    low_hop[hop_limit_at] = std::byte{64};
    BOOST_TEST((parse(low_hop).error() == ParseError::bad_hop_limit));

    auto f = ns_frame({});
    BOOST_TEST((parse(std::vector(f.begin(), f.end() - 1)).error() == ParseError::truncated));
    auto v4 = f;
    v4[ethernet_header_size] = std::byte{0x40};
    BOOST_TEST((parse(v4).error() == ParseError::bad_format));
}

BOOST_AUTO_TEST_CASE(builds_advertisement, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto ns = nb::parse_neighbor_solicitation(ns_frame({}));
    BOOST_REQUIRE(ns.has_value());
    const auto na = nb::build_neighbor_advertisement(*ns, mac(owner_tail));
    const std::size_t message_at = ethernet_header_size + nb::ipv6_header_size;
    BOOST_REQUIRE(na.size() == message_at + nb::nd_message_size + 8);

    ak::wire::Reader r{na};
    BOOST_TEST(std::ranges::equal(*r.bytes(mac_size), mac(requester_tail)));
    BOOST_TEST(std::ranges::equal(*r.bytes(mac_size), mac(owner_tail)));
    BOOST_TEST(*r.be16() == nb::ethertype_ipv6);
    BOOST_TEST(*r.be32() == ipv6_version_word);
    BOOST_TEST(*r.be16() == nb::nd_message_size + 8);
    BOOST_TEST(*r.u8() == nb::ipproto_icmpv6);
    BOOST_TEST(*r.u8() == nb::nd_hop_limit);
    BOOST_TEST(std::ranges::equal(*r.bytes(16), ip6(owner_tail)));
    BOOST_TEST(std::ranges::equal(*r.bytes(16), ip6(requester_tail)));
    BOOST_TEST(nb::icmpv6_checksum(ip6(owner_tail), ip6(requester_tail), r.rest()) == 0);
    BOOST_TEST(*r.u8() == nb::icmpv6_neighbor_advertisement);
    BOOST_TEST(*r.u8() == 0);
    static_cast<void>(r.be16());
    BOOST_TEST(*r.be32() == na_flags_solicited_override);
    BOOST_TEST(std::ranges::equal(*r.bytes(16), ip6(owner_tail)));
    BOOST_TEST(*r.u8() == 2);  // target link-layer address
    BOOST_TEST(*r.u8() == 1);
    BOOST_TEST(std::ranges::equal(*r.bytes(mac_size), mac(owner_tail)));
    BOOST_TEST(r.remaining() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
