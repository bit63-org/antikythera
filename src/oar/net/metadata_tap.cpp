// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/metadata_tap.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace ak::oar::net {

namespace {

constexpr std::size_t max_packet = 65535;

// The kernel's struct in6_ifreq (linux/ipv6.h, which clashes with
// netinet/in.h).
struct In6Ifreq {
    in6_addr addr;
    std::uint32_t prefix_length;
    int ifindex;
};

auto failure(std::string_view step) -> std::string {
    return std::string{step} + ": " + std::strerror(errno);
}

class Fd {
public:
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&&) = delete;
    auto operator=(Fd&&) -> Fd& = delete;
    ~Fd() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    [[nodiscard]] auto get() const noexcept -> int { return _fd; }
    [[nodiscard]] auto release() noexcept -> int { return std::exchange(_fd, -1); }

private:
    int _fd;
};

auto name_into(ifreq& ifr, std::string_view name) -> void {
    const auto n = std::min(name.size(), sizeof ifr.ifr_name - 1);
    std::copy_n(name.begin(), n, static_cast<char*>(ifr.ifr_name));
}

auto ipv4_sockaddr(const neighbor::Ipv4Address& a) -> sockaddr {
    sockaddr_in in{};
    in.sin_family = AF_INET;
    std::memcpy(&in.sin_addr, a.data(), a.size());
    sockaddr out{};
    std::memcpy(&out, &in, sizeof in);
    return out;
}

auto set_ipv6(int ifindex, const Ipv6Address& address, std::uint32_t prefix) -> bool {
    const Fd s{::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    if (s.get() < 0) {
        return false;
    }
    In6Ifreq req{};
    std::memcpy(&req.addr, address.data(), address.size());
    req.prefix_length = prefix;
    req.ifindex = ifindex;
    if (::ioctl(s.get(), SIOCSIFADDR, &req) != 0) {
        return false;
    }
    in6_rtmsg route{};
    std::memcpy(&route.rtmsg_dst, alias6_prefix.data(), alias6_prefix.size());
    route.rtmsg_dst_len = alias6_length;
    route.rtmsg_metric = 1;
    route.rtmsg_flags = RTF_UP;
    route.rtmsg_ifindex = ifindex;
    return ::ioctl(s.get(), SIOCADDRT, &route) == 0;
}

}  // namespace

// ---- MetadataTap ----------------------------------------------------------------

MetadataTap::MetadataTap(int fd, AliasTable& aliases, Ready ready, Inject inject,
                         std::function<Clock::time_point()> clock)
    : _fd{fd},
      _aliases{aliases},
      _ready{std::move(ready)},
      _inject{std::move(inject)},
      _clock{clock ? std::move(clock) : std::function<Clock::time_point()>{Clock::now}} {
    const int flags = ::fcntl(_fd, F_GETFL);
    if (flags >= 0) {
        (void)::fcntl(_fd, F_SETFL, flags | O_NONBLOCK);
    }
}

MetadataTap::~MetadataTap() {
    if (_fd >= 0) {
        ::close(_fd);
    }
}

auto MetadataTap::deliver(geneve::NicId nic, std::span<const std::byte> ip_packet) -> void {
    if (!_ready || !_ready(nic)) {
        ++_counters.no_record;
        return;
    }
    const auto out = to_kernel(nic, ip_packet, _aliases, _clock());
    if (!out) {
        ++_counters.dropped_out;
        return;
    }
    if (::write(_fd, out->data(), out->size()) != static_cast<ssize_t>(out->size())) {
        ++_counters.write_failures;
        return;
    }
    ++_counters.to_kernel;
}

auto MetadataTap::poll(std::size_t budget) -> bool {
    std::vector<std::byte> buf(max_packet);
    bool any = false;
    for (std::size_t i = 0; i < budget; ++i) {
        const auto n = ::read(_fd, buf.data(), buf.size());
        if (n <= 0) {
            break;  // EAGAIN, or an error the next poll retries
        }
        any = true;
        const auto in = to_guest(std::span{buf}.first(static_cast<std::size_t>(n)), _aliases);
        if (!in) {
            ++_counters.dropped_in;
            continue;
        }
        if (!_inject || !_inject(in->nic, in->packet)) {
            ++_counters.inject_refused;
            continue;
        }
        ++_counters.to_guest;
    }
    return any;
}

// ---- plumbing -------------------------------------------------------------------

auto open_metadata_tun(std::string_view name) -> std::expected<MetadataTun, std::string> {
    Fd tun{::open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK)};
    if (tun.get() < 0) {
        return std::unexpected{failure("open /dev/net/tun")};
    }
    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    name_into(ifr, name);
    if (::ioctl(tun.get(), TUNSETIFF, &ifr) != 0) {
        return std::unexpected{failure("TUNSETIFF")};
    }
    const std::string device{static_cast<const char*>(ifr.ifr_name)};

    const Fd s{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    if (s.get() < 0) {
        return std::unexpected{failure("socket")};
    }
    ifreq addr{};
    name_into(addr, device);
    addr.ifr_addr = ipv4_sockaddr(metadata_ipv4);
    if (::ioctl(s.get(), SIOCSIFADDR, &addr) != 0) {
        return std::unexpected{failure("SIOCSIFADDR")};
    }
    ifreq mask{};
    name_into(mask, device);
    mask.ifr_netmask =
        ipv4_sockaddr({std::byte{255}, std::byte{255}, std::byte{255}, std::byte{255}});
    if (::ioctl(s.get(), SIOCSIFNETMASK, &mask) != 0) {
        return std::unexpected{failure("SIOCSIFNETMASK")};
    }
    ifreq flags{};
    name_into(flags, device);
    if (::ioctl(s.get(), SIOCGIFFLAGS, &flags) != 0) {
        return std::unexpected{failure("SIOCGIFFLAGS")};
    }
    flags.ifr_flags = static_cast<short>(flags.ifr_flags | IFF_UP | IFF_RUNNING);
    if (::ioctl(s.get(), SIOCSIFFLAGS, &flags) != 0) {
        return std::unexpected{failure("SIOCSIFFLAGS")};
    }
    rtentry route{};
    route.rt_dst = ipv4_sockaddr(alias4_prefix);
    route.rt_genmask = ipv4_sockaddr({std::byte{255}, std::byte{192}, std::byte{0}, std::byte{0}});
    route.rt_flags = RTF_UP;
    std::string dev = device;  // rt_dev is not const
    route.rt_dev = dev.data();
    if (::ioctl(s.get(), SIOCADDRT, &route) != 0) {
        return std::unexpected{failure("SIOCADDRT")};
    }

    const auto ifindex = static_cast<int>(::if_nametoindex(device.c_str()));
    const bool ipv6 = ifindex > 0 && set_ipv6(ifindex, metadata_ipv6, 128);
    return MetadataTun{.fd = tun.release(), .ipv6 = ipv6};
}

auto open_metadata_listener(std::uint16_t port) -> std::expected<int, std::string> {
    const int one = 1;
    const int zero = 0;
    Fd v6{::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (v6.get() >= 0) {
        sockaddr_in6 any{};
        any.sin6_family = AF_INET6;
        any.sin6_addr = in6addr_any;
        any.sin6_port = htons(port);
        if (::setsockopt(v6.get(), IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) == 0 &&
            ::setsockopt(v6.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0 &&
            ::bind(v6.get(), reinterpret_cast<const sockaddr*>(&any), sizeof any) == 0 &&
            ::listen(v6.get(), SOMAXCONN) == 0) {
            return v6.release();
        }
    }
    Fd v4{::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (v4.get() < 0) {
        return std::unexpected{failure("socket")};
    }
    sockaddr_in any{};
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    any.sin_port = htons(port);
    if (::setsockopt(v4.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        ::bind(v4.get(), reinterpret_cast<const sockaddr*>(&any), sizeof any) != 0 ||
        ::listen(v4.get(), SOMAXCONN) != 0) {
        return std::unexpected{failure("bind")};
    }
    return v4.release();
}

auto resolve_peer(const AliasTable& aliases, const sockaddr_storage& peer, socklen_t length)
    -> std::optional<std::uint64_t> {
    IpAddress alias;
    if (peer.ss_family == AF_INET && length >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        sockaddr_in in{};
        std::memcpy(&in, &peer, sizeof in);
        neighbor::Ipv4Address a{};
        std::memcpy(a.data(), &in.sin_addr, a.size());
        alias = IpAddress::from(a);
    } else if (peer.ss_family == AF_INET6 &&
               length >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        sockaddr_in6 in{};
        std::memcpy(&in, &peer, sizeof in);
        Ipv6Address a{};
        std::memcpy(a.data(), &in.sin6_addr, a.size());
        if (IN6_IS_ADDR_V4MAPPED(&in.sin6_addr)) {
            neighbor::Ipv4Address v4{};
            std::copy_n(a.begin() + 12, v4.size(), v4.begin());
            alias = IpAddress::from(v4);
        } else {
            alias = IpAddress::from(a);
        }
    } else {
        return std::nullopt;
    }
    const auto pair = aliases.lookup(alias);
    return pair ? std::optional{pair->first.value} : std::nullopt;
}

}  // namespace ak::oar::net
