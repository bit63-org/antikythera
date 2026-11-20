// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The user-space end of the kernel WireGuard interop test
// (tests/wireguard_interop.sh, oar-net task 10). It runs ak::oar::net::Tunnel
// over a UdpEndpoint against a Linux wg device, so the handshake, key
// derivation and transport encryption are checked against the reference
// implementation in both roles:
//
//   respond   wait for the kernel to initiate; then the first authenticated
//             payload must be an IPv4/UDP packet to --udp-in carrying
//             --marker (the kernel pads it to 16 bytes; the IP header gives
//             the real length). Answer with an IPv4/UDP packet carrying
//             --reply to --peer-ip:--udp-out over the same session.
//   initiate  start a handshake (a fresh Tunnel, so it initiates), then send
//             an IPv4/UDP packet carrying --marker to --peer-ip:--udp-out.
//
// A Tunnel normally carries Geneve payloads, not IP packets (wireguard.hpp);
// here the payload is an IP packet so the kernel can deliver it.
//
// Keys are 64 hex digits. Arguments are `--name value` pairs; see usage().

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "oar/net/tunnel.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/wireguard.hpp"

namespace {

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;

constexpr int exit_ok = 0;
constexpr int exit_fail = 1;
constexpr int exit_usage = 2;
constexpr std::size_t ipv4_header_size = 20;
constexpr std::size_t udp_header_size = 8;
constexpr std::uint8_t ipv4_version_ihl = 0x45;
constexpr std::uint8_t ipv4_ttl = 64;
constexpr std::uint8_t ipproto_udp = 17;
constexpr std::size_t ipv4_checksum_offset = 10;
constexpr std::size_t max_datagram = 65536;
constexpr int poll_ms = 100;
constexpr int default_timeout_seconds = 10;
constexpr unsigned byte_bits = 8;

using Args = std::map<std::string, std::string, std::less<>>;

auto usage() -> int {
    std::fputs(
        "usage: wireguard_interop_peer respond|initiate --addr IPV6 --port N --private HEX\n"
        "           --peer IPV6 --peer-port N --peer-public HEX --psk HEX\n"
        "           --ip IPV4 --peer-ip IPV4 --udp-in N --udp-out N --marker TEXT\n"
        "           [--reply TEXT] [--timeout SECONDS]\n",
        stderr);
    return exit_usage;
}

auto parse_args(int argc, char** argv) -> std::optional<Args> {
    Args args;
    for (int i = 2; i < argc; i += 2) {
        const std::string_view key{argv[i]};
        if (!key.starts_with("--") || i + 1 >= argc) {
            return std::nullopt;
        }
        args.emplace(std::string{key.substr(2)}, argv[i + 1]);
    }
    return args;
}

auto get(const Args& args, std::string_view key) -> std::optional<std::string> {
    if (auto it = args.find(key); it != args.end()) {
        return it->second;
    }
    std::fprintf(stderr, "missing --%.*s\n", static_cast<int>(key.size()), key.data());
    return std::nullopt;
}

auto get_port(const Args& args, std::string_view key) -> std::optional<std::uint16_t> {
    auto text = get(args, key);
    if (!text) {
        return std::nullopt;
    }
    const auto v = std::strtoul(text->c_str(), nullptr, 10);
    if (v == 0 || v > UINT16_MAX) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(v);
}

auto get_key(const Args& args, std::string_view key) -> std::optional<wg::Key> {
    auto text = get(args, key);
    if (!text || text->size() != 2 * wg::key_size) {
        return std::nullopt;
    }
    wg::Key k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        const std::string octet = text->substr(2 * i, 2);
        char* end = nullptr;
        const auto v = std::strtoul(octet.c_str(), &end, 16);
        if (*end != '\0') {
            return std::nullopt;
        }
        k.at(i) = static_cast<std::byte>(v);
    }
    return k;
}

auto get_ipv6(const Args& args, std::string_view key) -> std::optional<net::Ipv6Address> {
    auto text = get(args, key);
    in6_addr a{};
    if (!text || ::inet_pton(AF_INET6, text->c_str(), &a) != 1) {
        return std::nullopt;
    }
    net::Ipv6Address out{};
    std::memcpy(out.data(), &a, out.size());
    return out;
}

auto get_ipv4(const Args& args, std::string_view key) -> std::optional<std::uint32_t> {
    auto text = get(args, key);
    in_addr a{};
    if (!text || ::inet_pton(AF_INET, text->c_str(), &a) != 1) {
        return std::nullopt;
    }
    return ntohl(a.s_addr);
}

auto put16(std::vector<std::byte>& v, std::size_t at, std::uint16_t x) -> void {
    v[at] = static_cast<std::byte>(x >> byte_bits);
    v[at + 1] = static_cast<std::byte>(x & 0xFFU);
}

auto get16(std::span<const std::byte> v, std::size_t at) -> std::uint16_t {
    return static_cast<std::uint16_t>((std::to_integer<unsigned>(v[at]) << byte_bits) |
                                      std::to_integer<unsigned>(v[at + 1]));
}

// An IPv4/UDP packet (UDP checksum 0, which IPv4 allows).
auto ipv4_udp(std::uint32_t src, std::uint32_t dst, std::uint16_t dport, std::string_view text)
    -> std::vector<std::byte> {
    const std::size_t total = ipv4_header_size + udp_header_size + text.size();
    std::vector<std::byte> p(total);
    p[0] = std::byte{ipv4_version_ihl};
    put16(p, 2, static_cast<std::uint16_t>(total));
    p[8] = std::byte{ipv4_ttl};
    p[9] = std::byte{ipproto_udp};
    put16(p, 12, static_cast<std::uint16_t>(src >> 16U));
    put16(p, 14, static_cast<std::uint16_t>(src & 0xFFFFU));
    put16(p, 16, static_cast<std::uint16_t>(dst >> 16U));
    put16(p, 18, static_cast<std::uint16_t>(dst & 0xFFFFU));
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < ipv4_header_size; i += 2) {
        sum += get16(p, i);
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    put16(p, ipv4_checksum_offset, static_cast<std::uint16_t>(~sum & 0xFFFFU));
    put16(p, ipv4_header_size, dport);  // source port = destination port
    put16(p, ipv4_header_size + 2, dport);
    put16(p, ipv4_header_size + 4, static_cast<std::uint16_t>(udp_header_size + text.size()));
    const auto b = std::as_bytes(std::span{text});
    std::copy(b.begin(), b.end(), p.begin() + ipv4_header_size + udp_header_size);
    return p;
}

// The UDP payload of an IPv4/UDP packet to `dport` (padding after the IP
// total length ignored), or nothing.
auto udp_payload(std::span<const std::byte> p, std::uint16_t dport) -> std::optional<std::string> {
    if (p.size() < ipv4_header_size + udp_header_size || p[0] != std::byte{ipv4_version_ihl} ||
        p[9] != std::byte{ipproto_udp}) {
        return std::nullopt;
    }
    const std::size_t total = get16(p, 2);
    if (total > p.size() || total < ipv4_header_size + udp_header_size ||
        get16(p, ipv4_header_size + 2) != dport) {
        return std::nullopt;
    }
    const auto body =
        p.subspan(ipv4_header_size + udp_header_size, total - ipv4_header_size - udp_header_size);
    return std::string{reinterpret_cast<const char*>(body.data()), body.size()};
}

struct Peer {
    std::unique_ptr<net::UdpEndpoint> endpoint;
    std::unique_ptr<net::Tunnel> tunnel;
    net::Ipv6Address peer{};
    std::uint16_t peer_port{0};
    std::vector<std::byte> buffer = std::vector<std::byte>(max_datagram);

    // Reads and handles one datagram if one arrives within poll_ms.
    auto step() -> std::optional<std::vector<std::byte>> {
        pollfd p{.fd = endpoint->poll_fd(), .events = POLLIN, .revents = 0};
        static_cast<void>(tunnel->tick());
        if (::poll(&p, 1, poll_ms) != 1) {
            return std::nullopt;
        }
        auto d = endpoint->receive(buffer);
        if (!d || d->truncated) {
            return std::nullopt;
        }
        auto o = tunnel->receive(std::span{buffer}.first(d->size), d->source);
        if (!o) {
            return std::nullopt;
        }
        return std::vector<std::byte>{o->payload.begin(), o->payload.end()};
    }

    auto send(std::span<const std::byte> packet) -> bool {
        return tunnel->send_to(peer, peer_port, net::flow_port_base, packet);
    }

    auto report() const -> void {
        const auto& c = tunnel->counters();
        std::fprintf(stderr,
                     "tunnel: init tx %llu rx %llu, resp tx %llu rx %llu, rx %llu packets, "
                     "%llu keepalives, tx %llu packets\n",
                     static_cast<unsigned long long>(c.initiations_tx),
                     static_cast<unsigned long long>(c.initiations_rx),
                     static_cast<unsigned long long>(c.responses_tx),
                     static_cast<unsigned long long>(c.responses_rx),
                     static_cast<unsigned long long>(c.rx_packets),
                     static_cast<unsigned long long>(c.rx_keepalives),
                     static_cast<unsigned long long>(c.tx_packets));
        for (std::size_t i = 0; i < c.rx_drop.size(); ++i) {
            if (c.rx_drop.at(i) != 0) {
                std::fprintf(stderr, "  drop %s: %llu\n",
                             net::to_string(static_cast<net::TunnelDrop>(i)),
                             static_cast<unsigned long long>(c.rx_drop.at(i)));
            }
        }
    }
};

}  // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        return usage();
    }
    const std::string_view mode{argv[1]};
    const auto args = parse_args(argc, argv);
    if (!args || (mode != "respond" && mode != "initiate")) {
        return usage();
    }
    const auto addr = get_ipv6(*args, "addr");
    const auto port = get_port(*args, "port");
    const auto priv = get_key(*args, "private");
    const auto peer_addr = get_ipv6(*args, "peer");
    const auto peer_port = get_port(*args, "peer-port");
    const auto peer_pub = get_key(*args, "peer-public");
    const auto psk = get_key(*args, "psk");
    const auto ip = get_ipv4(*args, "ip");
    const auto peer_ip = get_ipv4(*args, "peer-ip");
    const auto udp_in = get_port(*args, "udp-in");
    const auto udp_out = get_port(*args, "udp-out");
    const auto marker = get(*args, "marker");
    if (!addr || !port || !priv || !peer_addr || !peer_port || !peer_pub || !psk || !ip ||
        !peer_ip || !udp_in || !udp_out || !marker) {
        return usage();
    }
    int timeout_s = default_timeout_seconds;
    if (auto it = args->find("timeout"); it != args->end()) {
        timeout_s = std::atoi(it->second.c_str());
    }

    Peer p;
    auto ep = net::UdpEndpoint::create({.bind = *addr, .port = *port});
    if (!ep) {
        std::fprintf(stderr, "endpoint: %s\n", ep.error().c_str());
        return exit_fail;
    }
    p.endpoint = std::move(*ep);
    net::TunnelConfig config;
    config.peer_port = *peer_port;
    p.tunnel = std::move(*net::Tunnel::create(*p.endpoint, config));
    p.peer = *peer_addr;
    p.peer_port = *peer_port;
    if (!p.tunnel->set_private_key(*priv) || !p.tunnel->set_peer(*peer_addr, *peer_pub, *psk)) {
        std::fputs("keys refused\n", stderr);
        return exit_fail;
    }
    std::puts("listening");
    std::fflush(stdout);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{timeout_s};
    if (mode == "respond") {
        while (std::chrono::steady_clock::now() < deadline) {
            auto payload = p.step();
            if (!payload) {
                continue;
            }
            const auto text = udp_payload(*payload, *udp_in);
            if (!text || *text != *marker) {
                std::fprintf(stderr, "unexpected payload of %zu bytes\n", payload->size());
                continue;
            }
            std::printf("received %s\n", text->c_str());
            const auto reply = args->contains("reply") ? args->at("reply") : *marker;
            const bool sent = p.send(ipv4_udp(*ip, *peer_ip, *udp_out, reply));
            std::printf("%s %s\n", sent ? "replied" : "reply-failed", reply.c_str());
            p.report();
            return sent && p.tunnel->counters().initiations_rx >= 1 ? exit_ok : exit_fail;
        }
    } else {
        const auto packet = ipv4_udp(*ip, *peer_ip, *udp_out, *marker);
        static_cast<void>(p.send(packet));  // starts the handshake
        while (std::chrono::steady_clock::now() < deadline) {
            static_cast<void>(p.step());
            if (p.tunnel->peers().at(0).session) {
                const bool sent = p.send(packet);
                std::printf("%s %s\n", sent ? "sent" : "send-failed", marker->c_str());
                p.report();
                return sent && p.tunnel->counters().responses_rx >= 1 ? exit_ok : exit_fail;
            }
            // Retransmit as the timers say (tick() inside step()); keep the
            // packet flowing so a lost initiation is retried.
            static_cast<void>(p.send(packet));
        }
    }
    std::fputs("timed out\n", stderr);
    p.report();
    return exit_fail;
}
