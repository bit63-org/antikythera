// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 11.2 (task 15): the L3/L4
// parser every guest IP frame goes through.

#define BOOST_TEST_MODULE packet_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "net_frames.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/packet.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace pk = ak::oar::net::packet;
namespace fr = ak::test::frames;
using ak::test::unit_timeout_seconds;
using pk::PacketError;

namespace {

constexpr std::size_t ethernet_header_size = 14;
constexpr std::size_t ip_version_index = ethernet_header_size;
constexpr std::size_t ipv4_total_length_index = ethernet_header_size + 2;
constexpr std::uint16_t more_fragments = 0x2000;
constexpr std::uint16_t dns_port = 53;
constexpr std::uint16_t client_port = 40000;
constexpr std::uint16_t https_port = 443;
constexpr std::uint8_t icmp_echo_request = 8;
constexpr std::uint8_t icmpv6_echo_request = 128;
constexpr std::uint16_t ethertype_vlan = 0x8100;

const net::MacAddress mac_a{std::byte{2}, std::byte{0}, std::byte{0},
                            std::byte{0}, std::byte{0}, std::byte{1}};
const net::MacAddress mac_b{std::byte{2}, std::byte{0}, std::byte{0},
                            std::byte{0}, std::byte{0}, std::byte{2}};
const pk::Ipv4Address ip4_a{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{1}};
const pk::Ipv4Address ip4_b{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{2}};

auto ip6(std::uint8_t last) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[15] = std::byte{last};
    return a;
}

auto bytes(std::size_t n, std::uint8_t fill = 0x5a) -> std::vector<std::byte> {
    return std::vector<std::byte>(n, std::byte{fill});
}

// An IPv6 extension header of `units` 8-byte units (hop-by-hop, routing,
// destination options) followed by `next`.
auto extension(std::uint8_t next, std::uint8_t units = 0) -> std::vector<std::byte> {
    std::vector<std::byte> h((std::size_t{units} + 1) * 8, std::byte{0});
    h[0] = std::byte{next};
    h[1] = std::byte{units};
    return h;
}

auto fragment_header(std::uint8_t next, std::uint16_t offset_units, bool more)
    -> std::vector<std::byte> {
    std::vector<std::byte> h;
    ak::wire::Writer w{h};
    w.u8(next);
    w.u8(0);
    w.be16(static_cast<std::uint16_t>((unsigned{offset_units} << 3U) | (more ? 1U : 0U)));
    w.be32(0x1234);
    return h;
}

auto concat(std::initializer_list<std::vector<std::byte>> parts) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (const auto& p : parts) {
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(ipv4)

BOOST_AUTO_TEST_CASE(udp_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp,
                            fr::udp(client_port, dns_port, bytes(12)));
    const auto p = pk::parse(f);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST((p->family == pk::IpFamily::ipv4));
    BOOST_TEST((p->src4 == ip4_a));
    BOOST_TEST((p->dst4 == ip4_b));
    BOOST_TEST(p->protocol == pk::ipproto_udp);
    BOOST_TEST(p->hop_limit == fr::default_ttl);
    BOOST_TEST(!p->fragment);
    BOOST_TEST(p->first_fragment);
    BOOST_REQUIRE(p->l4.has_value());
    BOOST_TEST(p->l4->src_port == client_port);
    BOOST_TEST(p->l4->dst_port == dns_port);
    BOOST_TEST(p->payload.size() == 12);
    BOOST_TEST(p->l4_data.size() == pk::udp_header_size + 12);
    BOOST_TEST(p->ip.size() == f.size() - ethernet_header_size);
}

BOOST_AUTO_TEST_CASE(tcp_and_icmp, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto t = pk::parse(
        fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_tcp, fr::tcp(client_port, https_port)));
    BOOST_REQUIRE(t.has_value());
    BOOST_REQUIRE(t->l4.has_value());
    BOOST_TEST(t->l4->dst_port == https_port);
    BOOST_TEST(t->payload.empty());

    std::vector<std::byte> echo{std::byte{icmp_echo_request},
                                std::byte{0},
                                std::byte{0},
                                std::byte{0},
                                std::byte{0},
                                std::byte{1}};
    const auto i = pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_icmp, echo));
    BOOST_REQUIRE(i.has_value());
    BOOST_REQUIRE(i->l4.has_value());
    BOOST_TEST(i->l4->icmp_type == icmp_echo_request);
    BOOST_TEST(i->payload.size() == 2);
}

BOOST_AUTO_TEST_CASE(padding_ignored, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto f = fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp,
                      fr::udp(client_port, dns_port, bytes(0)));
    const std::size_t ip_size = f.size() - ethernet_header_size;
    f.resize(60, std::byte{0});  // minimum Ethernet frame
    const auto p = pk::parse(f);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->ip.size() == ip_size);
    BOOST_TEST(p->payload.empty());
}

BOOST_AUTO_TEST_CASE(unknown_protocol_has_no_l4, *boost::unit_test::timeout(unit_timeout_seconds)) {
    constexpr std::uint8_t ipproto_sctp = 132;
    const auto p = pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, ipproto_sctp, bytes(3)));
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->protocol == ipproto_sctp);
    BOOST_TEST(!p->l4.has_value());
}

BOOST_AUTO_TEST_CASE(header_errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp,
                               fr::udp(client_port, dns_port, bytes(4)));

    BOOST_TEST((pk::parse(std::span{good}.first(ethernet_header_size + 19)).error() ==
                PacketError::truncated));

    auto f = good;
    f[ip_version_index] = std::byte{0x65};
    BOOST_TEST((pk::parse(f).error() == PacketError::bad_version));

    f = good;
    f[ip_version_index] = std::byte{0x44};  // IHL 4
    BOOST_TEST((pk::parse(f).error() == PacketError::bad_header_length));

    f = good;
    f[ip_version_index] = std::byte{0x4f};  // IHL 15 = 60 bytes > total length 32
    BOOST_TEST((pk::parse(f).error() == PacketError::bad_header_length));

    f = good;
    f[ipv4_total_length_index + 1] = static_cast<std::byte>(f.size());  // past the frame
    BOOST_TEST((pk::parse(f).error() == PacketError::bad_total_length));
}

BOOST_AUTO_TEST_CASE(l4_errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto u = fr::udp(client_port, dns_port, bytes(4));
    u[5] = std::byte{13};  // UDP length past the IP payload
    BOOST_TEST((pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp, u)).error() ==
                PacketError::bad_l4_header));
    u[5] = std::byte{7};  // shorter than its own header
    BOOST_TEST((pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp, u)).error() ==
                PacketError::bad_l4_header));
    u[5] = std::byte{10};  // shorter than the IP payload: the rest is ignored
    const auto p = pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp, u));
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->payload.size() == 2);

    auto t = fr::tcp(client_port, https_port);
    t[12] = std::byte{0x40};  // data offset 4
    BOOST_TEST((pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_tcp, t)).error() ==
                PacketError::bad_l4_header));
    t[12] = std::byte{0x60};  // 24 bytes, only 20 present
    BOOST_TEST((pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_tcp, t)).error() ==
                PacketError::bad_l4_header));

    BOOST_TEST(
        (pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp, bytes(7))).error() ==
         PacketError::truncated));
}

BOOST_AUTO_TEST_CASE(fragments, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // First fragment: L4 present; the UDP length may exceed this fragment.
    auto u = fr::udp(client_port, dns_port, bytes(8));
    u[5] = std::byte{200};
    const auto first =
        pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_udp, u, more_fragments));
    BOOST_REQUIRE(first.has_value());
    BOOST_TEST(first->fragment);
    BOOST_TEST(first->first_fragment);
    BOOST_REQUIRE(first->l4.has_value());
    BOOST_TEST(first->l4->dst_port == dns_port);

    // A later fragment carries no L4 header, whatever its bytes say.
    const auto later = pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_tcp, bytes(3),
                                          static_cast<std::uint16_t>(185)));
    BOOST_REQUIRE(later.has_value());
    BOOST_TEST(later->fragment);
    BOOST_TEST(!later->first_fragment);
    BOOST_TEST(!later->l4.has_value());

    // A first fragment too short for its TCP header (RFC 1858).
    BOOST_TEST(
        (pk::parse(fr::ipv4(mac_b, mac_a, ip4_a, ip4_b, pk::ipproto_tcp, bytes(8), more_fragments))
             .error() == PacketError::tiny_fragment));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ipv6)

BOOST_AUTO_TEST_CASE(udp_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_udp,
                            fr::udp(client_port, dns_port, bytes(5)), 1);
    const auto p = pk::parse(f);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST((p->family == pk::IpFamily::ipv6));
    BOOST_TEST((p->src6 == ip6(1)));
    BOOST_TEST((p->dst6 == ip6(2)));
    BOOST_TEST(p->hop_limit == 1);
    BOOST_TEST(p->protocol == pk::ipproto_udp);
    BOOST_REQUIRE(p->l4.has_value());
    BOOST_TEST(p->l4->dst_port == dns_port);
    BOOST_TEST(p->payload.size() == 5);
    BOOST_TEST(!p->fragment);
}

BOOST_AUTO_TEST_CASE(icmpv6, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto m = fr::icmpv6(ip6(1), ip6(2), icmpv6_echo_request, 0, bytes(4));
    const auto p = pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_icmpv6, m));
    BOOST_REQUIRE(p.has_value());
    BOOST_REQUIRE(p->l4.has_value());
    BOOST_TEST(p->l4->icmp_type == icmpv6_echo_request);
    // ICMP (v4) inside IPv6 is just a protocol number.
    const auto v4 = pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_icmp, m));
    BOOST_REQUIRE(v4.has_value());
    BOOST_TEST(!v4->l4.has_value());
}

BOOST_AUTO_TEST_CASE(extension_headers, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto payload =
        concat({extension(pk::ipproto_destination_options), extension(pk::ipproto_routing, 1),
                extension(pk::ipproto_udp), fr::udp(client_port, dns_port, bytes(2))});
    const auto p =
        pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_hop_by_hop, payload));
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->protocol == pk::ipproto_udp);
    BOOST_REQUIRE(p->l4.has_value());
    BOOST_TEST(p->l4->dst_port == dns_port);
    BOOST_TEST(p->payload.size() == 2);

    // AH: length in 4-byte units, plus 2.
    std::vector<std::byte> ah(12, std::byte{0});
    ah[0] = std::byte{pk::ipproto_tcp};
    ah[1] = std::byte{1};
    const auto a = pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_ah,
                                      concat({ah, fr::tcp(client_port, https_port)})));
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST(a->protocol == pk::ipproto_tcp);
    BOOST_REQUIRE(a->l4.has_value());

    // ESP and "no next header" end the walk.
    const auto esp = pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_esp, bytes(16)));
    BOOST_REQUIRE(esp.has_value());
    BOOST_TEST(esp->protocol == pk::ipproto_esp);
    BOOST_TEST(!esp->l4.has_value());
}

BOOST_AUTO_TEST_CASE(extension_errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Hop-by-hop after another header.
    const auto late_hbh = concat({extension(pk::ipproto_hop_by_hop), extension(pk::ipproto_udp),
                                  fr::udp(client_port, dns_port, bytes(0))});
    BOOST_TEST((
        pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_destination_options, late_hbh))
            .error() == PacketError::bad_extension_order));

    // Nine destination-options headers.
    std::vector<std::byte> chain;
    for (std::size_t i = 0; i < pk::max_extension_headers; ++i) {
        const auto h = extension(pk::ipproto_destination_options);
        chain.insert(chain.end(), h.begin(), h.end());
    }
    const auto last = extension(pk::ipproto_udp);
    chain.insert(chain.end(), last.begin(), last.end());
    const auto u = fr::udp(client_port, dns_port, bytes(0));
    chain.insert(chain.end(), u.begin(), u.end());
    BOOST_TEST(
        (pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_destination_options, chain))
             .error() == PacketError::too_many_extensions));

    // An extension header longer than the packet.
    // (a routing header claiming 32 bytes in a 16-byte payload)
    auto short_ext = extension(pk::ipproto_udp, 3);
    short_ext.resize(16);
    BOOST_TEST((
        pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_routing, short_ext)).error() ==
        PacketError::truncated));
    const auto f = fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_routing,
                            std::vector<std::byte>{std::byte{pk::ipproto_udp}, std::byte{3}});
    BOOST_TEST((pk::parse(f).error() == PacketError::truncated));
}

BOOST_AUTO_TEST_CASE(fragments, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto first = pk::parse(fr::ipv6(
        mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_fragment,
        concat({fragment_header(pk::ipproto_udp, 0, true), fr::udp(client_port, dns_port, {})})));
    BOOST_REQUIRE(first.has_value());
    BOOST_TEST(first->fragment);
    BOOST_TEST(first->first_fragment);
    BOOST_REQUIRE(first->l4.has_value());

    const auto later =
        pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_fragment,
                           concat({fragment_header(pk::ipproto_tcp, 100, false), bytes(3)})));
    BOOST_REQUIRE(later.has_value());
    BOOST_TEST(later->fragment);
    BOOST_TEST(!later->first_fragment);
    BOOST_TEST(later->protocol == pk::ipproto_tcp);
    BOOST_TEST(!later->l4.has_value());

    BOOST_TEST((pk::parse(fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_fragment,
                                   concat({fragment_header(pk::ipproto_tcp, 0, true), bytes(8)})))
                    .error() == PacketError::tiny_fragment));
}

BOOST_AUTO_TEST_CASE(header_errors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = fr::ipv6(mac_b, mac_a, ip6(1), ip6(2), pk::ipproto_udp,
                               fr::udp(client_port, dns_port, bytes(4)));
    BOOST_TEST((pk::parse(std::span{good}.first(ethernet_header_size + 39)).error() ==
                PacketError::truncated));
    auto f = good;
    f[ip_version_index] = std::byte{0x40};
    BOOST_TEST((pk::parse(f).error() == PacketError::bad_version));
    // Payload length past the frame.
    BOOST_TEST(
        (pk::parse(std::span{good}.first(good.size() - 1)).error() == PacketError::truncated));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(other)

BOOST_AUTO_TEST_CASE(not_ip, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::uint16_t type :
         {net::neighbor::ethertype_arp, ethertype_vlan, std::uint16_t{0x88B5}}) {
        std::vector<std::byte> f;
        ak::wire::Writer w{f};
        fr::ethernet(w, mac_b, mac_a, type);
        f.resize(64, std::byte{0x45});
        BOOST_TEST((pk::parse(f).error() == PacketError::not_ip));
        BOOST_TEST(pk::ethertype(f) == type);
    }
    BOOST_TEST((pk::parse(bytes(13)).error() == PacketError::truncated));
    BOOST_TEST(pk::ethertype(bytes(13)) == 0);
}

BOOST_AUTO_TEST_CASE(address_classes, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(pk::is_ipv4_multicast({std::byte{224}, std::byte{0}, std::byte{0}, std::byte{1}}));
    BOOST_TEST(pk::is_ipv4_multicast({std::byte{239}, std::byte{255}, std::byte{0}, std::byte{1}}));
    BOOST_TEST(!pk::is_ipv4_multicast({std::byte{240}, std::byte{0}, std::byte{0}, std::byte{1}}));
    BOOST_TEST(!pk::is_ipv4_multicast(ip4_a));
    net::Ipv6Address a{};
    BOOST_TEST(pk::is_unspecified(a));
    a[0] = std::byte{0xfe};
    a[1] = std::byte{0x80};
    BOOST_TEST(pk::is_ipv6_link_local(a));
    a[1] = std::byte{0xbf};
    BOOST_TEST(pk::is_ipv6_link_local(a));
    a[1] = std::byte{0xc0};  // fec0::/10, old site-local
    BOOST_TEST(!pk::is_ipv6_link_local(a));
    a[0] = std::byte{0xff};
    BOOST_TEST(pk::is_ipv6_multicast(a));
    BOOST_TEST(!pk::is_unspecified(a));
}

BOOST_AUTO_TEST_SUITE_END()
