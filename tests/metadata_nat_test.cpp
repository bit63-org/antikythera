// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 13.1 to 13.5 (task 21.5):
// the metadata service's aliases and translation, the endpoint over a
// datagram socket pair, and the real TUN where namespaces allow.

#define BOOST_TEST_MODULE metadata_nat_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "metadata_packets.hpp"
#include "oar/net/metadata_nat.hpp"
#include "oar/net/metadata_tap.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace pk = ak::test::metadata;
using ak::test::unit_timeout_seconds;
using net::NatDrop;
using namespace std::chrono_literals;

namespace {

constexpr net::geneve::NicId nic_a{0x5001};
constexpr net::geneve::NicId nic_b{0x5002};

const pk::Ipv4 guest4{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{5}};
const pk::Ipv4 md4 = net::metadata_ipv4;
const pk::Ipv6 md6 = net::metadata_ipv6;

auto guest6() -> pk::Ipv6 {
    pk::Ipv6 a{};
    a[0] = std::byte{0xfd};
    a[15] = std::byte{0x05};
    return a;
}

auto v4(std::span<const std::byte> p, std::size_t at) -> pk::Ipv4 {
    pk::Ipv4 a{};
    std::copy_n(p.begin() + static_cast<std::ptrdiff_t>(at), 4, a.begin());
    return a;
}

auto v6(std::span<const std::byte> p, std::size_t at) -> pk::Ipv6 {
    pk::Ipv6 a{};
    std::copy_n(p.begin() + static_cast<std::ptrdiff_t>(at), 16, a.begin());
    return a;
}

auto ip4(unsigned a, unsigned b, unsigned c, unsigned d) -> net::IpAddress {
    return net::IpAddress::from(pk::Ipv4{static_cast<std::byte>(a), static_cast<std::byte>(b),
                                         static_cast<std::byte>(c), static_cast<std::byte>(d)});
}

}  // namespace

BOOST_AUTO_TEST_SUITE(metadata_nat, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(aliases_per_pair_with_lru_and_quarantine) {
    net::AliasTable t;
    const auto t0 = net::AliasTable::Clock::time_point{} + 1h;
    const auto a = t.alias(nic_a, net::IpAddress::from(guest4), t0);
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST(!a->v6);
    BOOST_TEST(std::to_integer<unsigned>(a->bytes[0]) == 100U);
    BOOST_TEST((std::to_integer<unsigned>(a->bytes[1]) & 0xC0U) == 64U);  // inside /10
    BOOST_TEST((t.alias(nic_a, net::IpAddress::from(guest4), t0) == a));  // stable
    // The same guest address on another NIC (another VPC) gets its own.
    const auto b = t.alias(nic_b, net::IpAddress::from(guest4), t0);
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST((*b != *a));
    BOOST_TEST((t.lookup(*a)->first == nic_a));
    BOOST_TEST((t.lookup(*b)->first == nic_b));
    BOOST_TEST((t.lookup(*a)->second == net::IpAddress::from(guest4)));
    const auto c = t.alias(nic_a, net::IpAddress::from(guest6()), t0);
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(c->v6);
    BOOST_TEST(
        std::ranges::equal(std::span{c->bytes}.first(12), std::span{net::alias6_prefix}.first(12)));

    // A NIC holds at most 16: the least recently used goes.
    for (unsigned i = 0; i < net::max_aliases_per_nic - 2; ++i) {
        BOOST_REQUIRE(t.alias(nic_a, ip4(10, 0, 1, i), t0 + std::chrono::seconds{i + 1}));
    }
    BOOST_TEST(t.size(nic_a) == net::max_aliases_per_nic);
    BOOST_REQUIRE(t.alias(nic_a, net::IpAddress::from(guest4), t0 + 30s));  // touch
    BOOST_REQUIRE(t.alias(nic_a, ip4(10, 0, 2, 1), t0 + 31s));
    BOOST_TEST(t.size(nic_a) == net::max_aliases_per_nic);
    BOOST_TEST(!t.lookup(*c).has_value());  // the IPv6 one was oldest
    BOOST_TEST(t.lookup(*a).has_value());
    BOOST_TEST(t.quarantined() == 1U);

    // A cleaned NIC's aliases are quarantined, then free again.
    t.release(nic_a, t0 + 40s);
    BOOST_TEST(t.size(nic_a) == 0U);
    BOOST_TEST(!t.lookup(*a).has_value());
    BOOST_TEST(t.size() == 1U);  // b's
    BOOST_TEST(t.quarantined() == 1U + net::max_aliases_per_nic);
    BOOST_REQUIRE(t.alias(nic_a, ip4(10, 0, 3, 1), t0 + 40s + net::alias_quarantine));
    BOOST_TEST(t.quarantined() == 0U);
}

BOOST_AUTO_TEST_CASE(translates_both_ways_keeping_checksums) {
    net::AliasTable t;
    const auto now = net::AliasTable::Clock::now();
    const auto syn = pk::tcp4(guest4, md4, 40000, 80);
    const auto out = net::to_kernel(nic_a, syn, t, now);
    BOOST_REQUIRE(out.has_value());
    BOOST_TEST(pk::checksums_ok(*out));
    const auto alias = v4(*out, 12);
    BOOST_TEST(std::to_integer<unsigned>(alias[0]) == 100U);
    BOOST_TEST((v4(*out, 16) == md4));
    BOOST_TEST(out->size() == syn.size());

    const auto reply = pk::tcp4(md4, alias, 80, 40000, pk::tcp_syn | pk::tcp_ack, "HTTP/1.1 200");
    const auto in = net::to_guest(reply, t);
    BOOST_REQUIRE(in.has_value());
    BOOST_TEST((in->nic == nic_a));
    BOOST_TEST(pk::checksums_ok(in->packet));
    BOOST_TEST((v4(in->packet, 16) == guest4));
    BOOST_TEST((v4(in->packet, 12) == md4));

    // IPv6.
    const auto syn6 = pk::tcp6(guest6(), md6, 40001, 80);
    const auto out6 = net::to_kernel(nic_a, syn6, t, now);
    BOOST_REQUIRE(out6.has_value());
    BOOST_TEST(pk::checksums_ok(*out6));
    const auto alias6 = v6(*out6, 8);
    BOOST_TEST(
        std::ranges::equal(std::span{alias6}.first(12), std::span{net::alias6_prefix}.first(12)));
    const auto in6 = net::to_guest(pk::tcp6(md6, alias6, 80, 40001, pk::tcp_ack, "x"), t);
    BOOST_REQUIRE(in6.has_value());
    BOOST_TEST(pk::checksums_ok(in6->packet));
    BOOST_TEST((v6(in6->packet, 24) == guest6()));

    // Trailing padding (an Ethernet minimum frame) is dropped.
    auto padded = syn;
    padded.resize(syn.size() + 6);
    BOOST_TEST(net::to_kernel(nic_a, padded, t, now)->size() == syn.size());
}

BOOST_AUTO_TEST_CASE(drops_everything_else) {
    net::AliasTable t;
    const auto now = net::AliasTable::Clock::now();
    const auto out = [&](const std::vector<std::byte>& p) {
        return net::to_kernel(nic_a, p, t, now).error();
    };
    const auto syn = pk::tcp4(guest4, md4, 40000, 80);
    BOOST_TEST((out(pk::tcp4(guest4, md4, 40000, 443)) == NatDrop::wrong_port));
    BOOST_TEST((out(pk::tcp4(guest4, guest4, 40000, 80)) == NatDrop::wrong_address));
    auto udp = syn;
    udp[9] = std::byte{17};
    BOOST_TEST((out(udp) == NatDrop::not_tcp));
    auto fragment = syn;
    fragment[6] = std::byte{0x20};  // MF
    BOOST_TEST((out(fragment) == NatDrop::fragment));
    auto ext = pk::tcp6(guest6(), md6, 40000, 80);
    ext[6] = std::byte{0};  // hop-by-hop options
    BOOST_TEST((out(ext) == NatDrop::not_tcp));
    auto short_doff = syn;
    short_doff[20 + 12] = std::byte{0x40};
    BOOST_TEST((out(short_doff) == NatDrop::malformed));
    for (std::size_t n = 0; n < syn.size(); ++n) {
        BOOST_TEST_INFO(n);
        BOOST_TEST(!net::to_kernel(nic_a, std::span{syn}.first(n), t, now).has_value());
    }
    BOOST_TEST(t.size() == 0U);  // nothing made an alias

    // From the kernel: only TCP from port 80 of the metadata address to a
    // live alias.
    const auto alias = v4(*net::to_kernel(nic_a, syn, t, now), 12);
    const auto in = [&](const std::vector<std::byte>& p) { return net::to_guest(p, t).error(); };
    BOOST_TEST((in(pk::tcp4(md4, alias, 81, 40000)) == NatDrop::wrong_port));
    BOOST_TEST((in(pk::tcp4(guest4, alias, 80, 40000)) == NatDrop::wrong_address));
    BOOST_TEST((in(pk::tcp4(md4, guest4, 80, 40000)) == NatDrop::unknown_alias));
    auto icmp = pk::tcp4(md4, alias, 80, 40000);
    icmp[9] = std::byte{1};
    BOOST_TEST((in(icmp) == NatDrop::not_tcp));
}

BOOST_AUTO_TEST_CASE(the_endpoint_over_a_packet_pair) {
    std::array<int, 2> fds{};
    BOOST_REQUIRE(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
    const int kernel = fds[1];
    net::AliasTable aliases;
    bool ready = false;
    std::vector<std::pair<net::geneve::NicId, std::vector<std::byte>>> injected;
    bool inject_ok = true;
    net::MetadataTap tap{fds[0], aliases, [&](net::geneve::NicId) { return ready; },
                         [&](net::geneve::NicId n, std::span<const std::byte> p) {
                             injected.emplace_back(n, std::vector<std::byte>(p.begin(), p.end()));
                             return inject_ok;
                         }};
    const auto syn = pk::tcp4(guest4, md4, 40000, 80);
    tap.deliver(nic_a, syn);  // no record: no answer at all
    BOOST_TEST(tap.counters().no_record == 1U);
    ready = true;
    tap.deliver(nic_a, pk::tcp4(guest4, md4, 40000, 22));
    BOOST_TEST(tap.counters().dropped_out == 1U);
    tap.deliver(nic_a, syn);
    BOOST_TEST(tap.counters().to_kernel == 1U);
    std::array<std::byte, 2048> buf{};
    const auto n = ::recv(kernel, buf.data(), buf.size(), MSG_DONTWAIT);
    BOOST_REQUIRE(n == static_cast<ssize_t>(syn.size()));
    const auto alias = v4(buf, 12);

    const auto reply = pk::tcp4(md4, alias, 80, 40000, pk::tcp_syn | pk::tcp_ack);
    BOOST_REQUIRE(::send(kernel, reply.data(), reply.size(), 0) ==
                  static_cast<ssize_t>(reply.size()));
    const auto junk = pk::tcp4(md4, guest4, 80, 40000);
    BOOST_REQUIRE(::send(kernel, junk.data(), junk.size(), 0) == static_cast<ssize_t>(junk.size()));
    BOOST_TEST(tap.poll(8));
    BOOST_REQUIRE(injected.size() == 1U);
    BOOST_TEST((injected[0].first == nic_a));
    BOOST_TEST((v4(injected[0].second, 16) == guest4));
    BOOST_TEST(tap.counters().to_guest == 1U);
    BOOST_TEST(tap.counters().dropped_in == 1U);
    BOOST_TEST(!tap.poll(8));  // nothing left

    // The server's resolver: the alias, plain or v4-mapped, names the NIC.
    sockaddr_storage peer{};
    sockaddr_in in{};
    in.sin_family = AF_INET;
    std::memcpy(&in.sin_addr, alias.data(), 4);
    std::memcpy(&peer, &in, sizeof in);
    BOOST_TEST(net::resolve_peer(aliases, peer, sizeof in).value() == nic_a.value);
    sockaddr_in6 in6{};
    in6.sin6_family = AF_INET6;
    in6.sin6_addr.s6_addr[10] = 0xFF;
    in6.sin6_addr.s6_addr[11] = 0xFF;
    std::memcpy(&in6.sin6_addr.s6_addr[12], alias.data(), 4);
    peer = {};
    std::memcpy(&peer, &in6, sizeof in6);
    BOOST_TEST(net::resolve_peer(aliases, peer, sizeof in6).value() == nic_a.value);
    in.sin_addr.s_addr = htonl(0x0A000005);  // the guest's own address: not an alias
    peer = {};
    std::memcpy(&peer, &in, sizeof in);
    BOOST_TEST(!net::resolve_peer(aliases, peer, sizeof in).has_value());
    ::close(kernel);
}

// The real TUN, in a fresh user and network namespace: the kernel answers
// a SYN to 169.254.169.254:80 from an alias with a SYN-ACK back to it.
// Skipped where namespaces are unavailable (as for jail_test).
BOOST_AUTO_TEST_CASE(the_kernel_answers_through_the_tun) {
    constexpr int skip = 77;
    const pid_t child = ::fork();
    BOOST_REQUIRE(child >= 0);
    if (child == 0) {
        if (::unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
            ::_exit(skip);
        }
        const auto tun = net::open_metadata_tun();
        if (!tun) {
            ::_exit(skip);
        }
        const auto listener = net::open_metadata_listener();
        if (!listener) {
            ::_exit(2);
        }
        const pk::Ipv4 alias{std::byte{100}, std::byte{64}, std::byte{0}, std::byte{1}};
        const auto syn = pk::tcp4(alias, md4, 40000, 80);
        if (::write(tun->fd, syn.data(), syn.size()) != static_cast<ssize_t>(syn.size())) {
            ::_exit(3);
        }
        std::array<std::byte, 2048> buf{};
        for (int tries = 0; tries < 50; ++tries) {
            pollfd p{.fd = tun->fd, .events = POLLIN, .revents = 0};
            if (::poll(&p, 1, 100) <= 0) {
                continue;
            }
            const auto n = ::read(tun->fd, buf.data(), buf.size());
            if (n < 40 || (std::to_integer<unsigned>(buf[0]) >> 4U) != 4) {
                continue;  // IPv6 noise, say
            }
            const auto flags = std::to_integer<unsigned>(buf[20 + 13]);
            const bool syn_ack =
                (flags & (pk::tcp_syn | pk::tcp_ack)) == (pk::tcp_syn | pk::tcp_ack);
            ::_exit(v4(buf, 12) == md4 && v4(buf, 16) == alias && syn_ack ? 0 : 4);
        }
        ::_exit(5);
    }
    int status = 0;
    BOOST_REQUIRE(::waitpid(child, &status, 0) == child);
    BOOST_REQUIRE(WIFEXITED(status));
    if (WEXITSTATUS(status) == skip) {
        BOOST_TEST_MESSAGE("no user and network namespace here: skipped");
        return;
    }
    BOOST_TEST(WEXITSTATUS(status) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
