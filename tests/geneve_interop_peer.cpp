// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The user-space end of the kernel Geneve interop test
// (tests/geneve_interop.sh, oar-net task 4). It speaks Geneve through a
// plain UDP socket using ak::oar::net::geneve, so the codec is exercised
// against the Linux geneve driver in both directions:
//
//   recv  bind [addr]:port, wait for a datagram whose inner frame carries
//         the marker, and check that it decodes to the expected VNI and
//         NIC pair. Any datagram the codec rejects fails the test: the
//         kernel built it, so a rejection is an interop bug.
//   send  build an inner Ethernet/IPv4/UDP frame carrying the marker,
//         encode it with the NIC-pair option and send it to [addr]:port.
//
// Arguments are `--name value` pairs; see usage() below.

#include "oar/net/geneve.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <ratio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace geneve = ak::oar::net::geneve;

constexpr int exit_ok = 0;
constexpr int exit_fail = 1;
constexpr int exit_usage = 2;

constexpr std::size_t mac_size = 6;
constexpr std::size_t ipv4_header_size = 20;
constexpr std::size_t udp_header_size = 8;
constexpr std::uint16_t ethertype_ipv4 = 0x0800;
constexpr std::uint8_t ipv4_version_ihl = 0x45;  // version 4, 5-word header
constexpr std::uint8_t ipv4_default_ttl = 64;
constexpr std::uint8_t ipproto_udp = 17;
constexpr std::uint16_t ipv4_dont_fragment = 0x4000;
constexpr std::size_t ipv4_checksum_offset = 10;
constexpr std::size_t max_datagram = 65536;
constexpr int default_timeout_seconds = 10;
constexpr unsigned byte_bits = 8;
constexpr std::uint32_t low16_mask = 0xFFFF;
constexpr int hex_base = 16;
constexpr int decimal_base = 10;

using Args = std::map<std::string, std::string, std::less<>>;
using Mac = std::array<std::byte, mac_size>;

auto usage() -> int {
    std::fputs(
        "usage: geneve_interop_peer recv --addr IPV6 [--port N] --vni N --src-nic N --dst-nic N\n"
        "                                --marker TEXT [--timeout SECONDS]\n"
        "       geneve_interop_peer send --addr IPV6 [--port N] --vni N --src-nic N --dst-nic N\n"
        "                                --marker TEXT --src-mac MAC --dst-mac MAC\n"
        "                                --src-ip IPV4 --dst-ip IPV4 --udp-port N\n",
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

auto get_u64(const Args& args, std::string_view key, int base = 0) -> std::optional<std::uint64_t> {
    auto text = get(args, key);
    if (!text) {
        return std::nullopt;
    }
    errno = 0;
    char* end = nullptr;
    const auto value = std::strtoull(text->c_str(), &end, base);
    if (errno != 0 || end == text->c_str() || *end != '\0') {
        std::fprintf(stderr, "bad number for --%.*s: %s\n", static_cast<int>(key.size()),
                     key.data(), text->c_str());
        return std::nullopt;
    }
    return value;
}

auto parse_mac(const std::string& text) -> std::optional<Mac> {
    Mac mac{};
    std::size_t pos = 0;
    for (std::size_t i = 0; i < mac_size; ++i) {
        char* end = nullptr;
        const auto octet = std::strtoul(text.c_str() + pos, &end, hex_base);
        const auto used = static_cast<std::size_t>(end - (text.c_str() + pos));
        if (used == 0 || used > 2) {
            return std::nullopt;
        }
        mac.at(i) = static_cast<std::byte>(octet);
        pos += used;
        if (i + 1 < mac_size) {
            if (pos >= text.size() || text[pos] != ':') {
                return std::nullopt;
            }
            ++pos;
        }
    }
    if (pos != text.size()) {
        return std::nullopt;
    }
    return mac;
}

auto parse_ipv4(const std::string& text) -> std::optional<std::uint32_t> {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return ntohl(addr.s_addr);
}

auto make_sockaddr(const std::string& text, std::uint16_t port) -> std::optional<sockaddr_in6> {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, text.c_str(), &sa.sin6_addr) != 1) {
        std::fprintf(stderr, "bad IPv6 address: %s\n", text.c_str());
        return std::nullopt;
    }
    return sa;
}

void put16(std::vector<std::byte>& out, std::uint16_t v) {
    out.push_back(static_cast<std::byte>(v >> byte_bits));
    out.push_back(static_cast<std::byte>(v));
}

void put32(std::vector<std::byte>& out, std::uint32_t v) {
    put16(out, static_cast<std::uint16_t>(v >> (2 * byte_bits)));
    put16(out, static_cast<std::uint16_t>(v));
}

// RFC 1071 ones' complement sum over an even-length header.
auto ipv4_checksum(std::span<const std::byte> header) -> std::uint16_t {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < header.size(); i += 2) {
        sum += (std::to_integer<std::uint32_t>(header[i]) << byte_bits) |
               std::to_integer<std::uint32_t>(header[i + 1]);
    }
    while ((sum >> (2 * byte_bits)) != 0) {
        sum = (sum & low16_mask) + (sum >> (2 * byte_bits));
    }
    return static_cast<std::uint16_t>(~sum);
}

struct InnerFrame {
    Mac src_mac{};
    Mac dst_mac{};
    std::uint32_t src_ip{0};
    std::uint32_t dst_ip{0};
    std::uint16_t udp_port{0};
    std::string_view payload;
};

// Ethernet + IPv4 + UDP (checksum 0, which IPv4 allows) + payload.
auto build_inner_frame(const InnerFrame& f) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.insert(out.end(), f.dst_mac.begin(), f.dst_mac.end());
    out.insert(out.end(), f.src_mac.begin(), f.src_mac.end());
    put16(out, ethertype_ipv4);

    const std::size_t ip_start = out.size();
    const auto udp_len = static_cast<std::uint16_t>(udp_header_size + f.payload.size());
    out.push_back(static_cast<std::byte>(ipv4_version_ihl));
    out.push_back(std::byte{0});  // DSCP/ECN
    put16(out, static_cast<std::uint16_t>(ipv4_header_size + udp_len));
    put16(out, 0);  // identification
    put16(out, ipv4_dont_fragment);
    out.push_back(static_cast<std::byte>(ipv4_default_ttl));
    out.push_back(static_cast<std::byte>(ipproto_udp));
    put16(out, 0);  // checksum, filled below
    put32(out, f.src_ip);
    put32(out, f.dst_ip);
    const auto csum = ipv4_checksum(std::span{out}.subspan(ip_start, ipv4_header_size));
    out[ip_start + ipv4_checksum_offset] = static_cast<std::byte>(csum >> byte_bits);
    out[ip_start + ipv4_checksum_offset + 1] = static_cast<std::byte>(csum);

    put16(out, f.udp_port);  // source port: same as destination, arbitrary
    put16(out, f.udp_port);
    put16(out, udp_len);
    put16(out, 0);  // no UDP checksum
    for (const char c : f.payload) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto contains(std::span<const std::byte> haystack, std::string_view needle) -> bool {
    const auto* first = reinterpret_cast<const char*>(haystack.data());
    const std::string_view hay{first, haystack.size()};
    return hay.find(needle) != std::string_view::npos;
}

class Socket {
public:
    Socket() : _fd{::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)} {}
    Socket(const Socket&) = delete;
    auto operator=(const Socket&) -> Socket& = delete;
    Socket(Socket&&) = delete;
    auto operator=(Socket&&) -> Socket& = delete;
    ~Socket() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    [[nodiscard]] auto fd() const noexcept -> int { return _fd; }

private:
    int _fd;
};

struct Expected {
    std::uint32_t vni{0};
    geneve::NicPair nics;
    std::string marker;
};

auto common_params(const Args& args) -> std::optional<std::pair<sockaddr_in6, Expected>> {
    auto addr = get(args, "addr");
    auto vni = get_u64(args, "vni", decimal_base);
    auto src = get_u64(args, "src-nic");
    auto dst = get_u64(args, "dst-nic");
    auto marker = get(args, "marker");
    std::uint64_t port = geneve::udp_port;
    if (args.contains("port")) {
        auto p = get_u64(args, "port", decimal_base);
        if (!p) {
            return std::nullopt;
        }
        port = *p;
    }
    if (!addr || !vni || !src || !dst || !marker || *vni > geneve::vni_max ||
        port > std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }
    auto sa = make_sockaddr(*addr, static_cast<std::uint16_t>(port));
    if (!sa) {
        return std::nullopt;
    }
    return std::pair{*sa,
                     Expected{static_cast<std::uint32_t>(*vni),
                              geneve::NicPair{geneve::NicId{*src}, geneve::NicId{*dst}}, *marker}};
}

auto run_recv(const Args& args) -> int {
    auto params = common_params(args);
    if (!params) {
        return usage();
    }
    const auto& [sa, want] = *params;
    std::uint64_t timeout_s = default_timeout_seconds;
    if (args.contains("timeout")) {
        auto t = get_u64(args, "timeout", decimal_base);
        if (!t) {
            return usage();
        }
        timeout_s = *t;
    }

    const Socket sock;
    if (sock.fd() < 0) {
        std::perror("socket");
        return exit_fail;
    }
    const int on = 1;
    (void)::setsockopt(sock.fd(), SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (::bind(sock.fd(), reinterpret_cast<const sockaddr*>(&sa), sizeof sa) != 0) {
        std::perror("bind");
        return exit_fail;
    }
    // Ready marker for the driver script: it starts the kernel side only
    // once the socket is bound.
    std::puts("listening");
    (void)std::fflush(stdout);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    std::vector<std::byte> buf(max_datagram);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - std::chrono::steady_clock::now());
        timeval tv{};
        tv.tv_sec = static_cast<time_t>(left.count() / std::micro::den);
        tv.tv_usec = static_cast<suseconds_t>(left.count() % std::micro::den);
        if (tv.tv_sec == 0 && tv.tv_usec == 0) {
            break;
        }
        (void)::setsockopt(sock.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        const auto n = ::recv(sock.fd(), buf.data(), buf.size(), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            std::perror("recv");
            return exit_fail;
        }
        const std::span<const std::byte> payload{buf.data(), static_cast<std::size_t>(n)};
        auto pkt = geneve::decode(payload);
        if (!pkt) {
            std::fprintf(stderr, "FAIL: codec rejected a %zd-byte kernel datagram: %s\n", n,
                         geneve::to_string(pkt.error()));
            return exit_fail;
        }
        if (!contains(pkt->inner, want.marker)) {
            std::printf("skip: %zu-byte inner frame without the marker\n", pkt->inner.size());
            continue;
        }
        std::printf("decoded: vni=%u oam=%d src_nic=%#llx dst_nic=%#llx inner=%zu bytes\n",
                    pkt->vni, pkt->oam ? 1 : 0,
                    static_cast<unsigned long long>(pkt->nics->src.value),
                    static_cast<unsigned long long>(pkt->nics->dst.value), pkt->inner.size());
        if (pkt->vni != want.vni || pkt->oam || pkt->nics != want.nics) {
            std::fputs("FAIL: decoded fields differ from the kernel's configuration\n", stderr);
            return exit_fail;
        }
        // The kernel must re-encode to the same bytes we would have sent.
        auto again =
            geneve::encode({.vni = pkt->vni, .nics = *pkt->nics, .oam = false}, pkt->inner);
        if (!again || !std::ranges::equal(*again, payload)) {
            std::fputs("FAIL: re-encoding the kernel datagram gives different bytes\n", stderr);
            return exit_fail;
        }
        std::puts("PASS: kernel -> codec");
        return exit_ok;
    }
    std::fputs("FAIL: timed out waiting for the kernel's datagram\n", stderr);
    return exit_fail;
}

auto run_send(const Args& args) -> int {
    auto params = common_params(args);
    auto src_mac_text = get(args, "src-mac");
    auto dst_mac_text = get(args, "dst-mac");
    auto src_ip_text = get(args, "src-ip");
    auto dst_ip_text = get(args, "dst-ip");
    auto udp_port = get_u64(args, "udp-port", decimal_base);
    if (!params || !src_mac_text || !dst_mac_text || !src_ip_text || !dst_ip_text || !udp_port ||
        *udp_port > std::numeric_limits<std::uint16_t>::max()) {
        return usage();
    }
    auto src_mac = parse_mac(*src_mac_text);
    auto dst_mac = parse_mac(*dst_mac_text);
    auto src_ip = parse_ipv4(*src_ip_text);
    auto dst_ip = parse_ipv4(*dst_ip_text);
    if (!src_mac || !dst_mac || !src_ip || !dst_ip) {
        std::fputs("bad MAC or IPv4 address\n", stderr);
        return usage();
    }
    const auto& [sa, want] = *params;

    const auto frame = build_inner_frame({.src_mac = *src_mac,
                                          .dst_mac = *dst_mac,
                                          .src_ip = *src_ip,
                                          .dst_ip = *dst_ip,
                                          .udp_port = static_cast<std::uint16_t>(*udp_port),
                                          .payload = want.marker});
    auto datagram = geneve::encode({.vni = want.vni, .nics = want.nics, .oam = false}, frame);
    if (!datagram) {
        std::fprintf(stderr, "encode: %s\n", geneve::to_string(datagram.error()));
        return exit_fail;
    }

    const Socket sock;
    if (sock.fd() < 0) {
        std::perror("socket");
        return exit_fail;
    }
    const auto n = ::sendto(sock.fd(), datagram->data(), datagram->size(), 0,
                            reinterpret_cast<const sockaddr*>(&sa), sizeof sa);
    if (n < 0 || static_cast<std::size_t>(n) != datagram->size()) {
        std::perror("sendto");
        return exit_fail;
    }
    std::printf("sent: %zu-byte Geneve datagram, %zu-byte inner frame\n", datagram->size(),
                frame.size());
    return exit_ok;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        return usage();
    }
    auto args = parse_args(argc, argv);
    if (!args) {
        return usage();
    }
    const std::string_view cmd{argv[1]};
    if (cmd == "recv") {
        return run_recv(*args);
    }
    if (cmd == "send") {
        return run_send(*args);
    }
    return usage();
}
