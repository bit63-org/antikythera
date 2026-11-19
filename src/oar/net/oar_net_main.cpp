// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-oar-net: one virtio-net function served over vfio-user, for harbor
// (.kiro/specs/oar-net-data-plane/ task 6).
//
//   ak-oar-net --socket PATH --nic-id ID --mac MAC --mtu N [--tap IFNAME]
//
// L0 QEMU attaches with vfio-user-pci; the L1 host binds the function to
// vfio-pci and Cloud Hypervisor hands it to an L2 guest, whose stock
// virtio_net driver sees an ordinary NIC with the MAC and MTU given here.
//
// Until the VSwitch (task 8) exists, frames go to an optional TAP device in
// this process's network namespace: the guest's transmitted frames are
// written to it and frames read from it are delivered to the guest. Without
// --tap, transmitted frames are counted and dropped.

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "oar/net/virtio_net.hpp"
#include "oar/vfu/virtio_binding.hpp"

namespace {

namespace net = ak::oar::net;

constexpr std::string_view arg_socket = "--socket";
constexpr std::string_view arg_nic_id = "--nic-id";
constexpr std::string_view arg_mac = "--mac";
constexpr std::string_view arg_mtu = "--mtu";
constexpr std::string_view arg_tap = "--tap";
constexpr std::string_view tun_device = "/dev/net/tun";
constexpr int base_auto = 0;
constexpr int base_hex = 16;
constexpr std::size_t mac_text_size = 17;  // xx:xx:xx:xx:xx:xx
constexpr std::size_t mac_stride = 3;
constexpr int poll_forever = -1;
constexpr int poll_now = 0;
constexpr std::size_t poll_vfu = 0;
constexpr std::size_t poll_tap = 1;
constexpr int exit_usage = 2;

auto usage() -> int {
    std::println(stderr, "usage: ak-oar-net {} PATH {} ID {} MAC {} N [{} IFNAME]", arg_socket,
                 arg_nic_id, arg_mac, arg_mtu, arg_tap);
    return exit_usage;
}

auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    const std::string text{s};
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(text.c_str(), &end, base_auto);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return std::nullopt;
    }
    return v;
}

auto parse_mac(std::string_view s) -> std::optional<net::MacAddress> {
    if (s.size() != mac_text_size) {
        return std::nullopt;
    }
    net::MacAddress mac{};
    for (std::size_t i = 0; i < mac.size(); ++i) {
        const std::string_view part = s.substr(i * mac_stride, 2);
        if (i + 1 < mac.size() && s[(i * mac_stride) + 2] != ':') {
            return std::nullopt;
        }
        std::uint8_t b = 0;
        const auto [p, ec] = std::from_chars(part.data(), part.data() + part.size(), b, base_hex);
        if (ec != std::errc{} || p != part.data() + part.size()) {
            return std::nullopt;
        }
        mac[i] = std::byte{b};
    }
    return mac;
}

// Opens (or creates) a TAP interface; -1 on failure with errno set.
auto open_tap(const std::string& name) -> int {
    const int fd = ::open(std::string{tun_device}.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    name.copy(ifr.ifr_name, IFNAMSIZ - 1);
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

class TapSink final : public net::FrameSink {
public:
    explicit TapSink(int fd) : _fd{fd} {}
    auto transmit(const net::TxFrame& f) -> void override {
        if (_fd < 0) {
            return;  // no backend: counted by the function, dropped here
        }
        // A full TAP queue drops the frame, as a congested link would.
        static_cast<void>(::write(_fd, f.frame.data(), f.frame.size()));
    }

private:
    int _fd;
};

}  // namespace

auto main(int argc, char** argv) -> int {
    std::string socket_path;
    std::string tap_name;
    std::optional<std::uint64_t> nic_id;
    std::optional<net::MacAddress> mac;
    std::optional<std::uint64_t> mtu;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (i + 1 >= argc) {
            return usage();
        }
        const std::string_view value{argv[++i]};
        if (arg == arg_socket) {
            socket_path = value;
        } else if (arg == arg_nic_id) {
            nic_id = parse_u64(value);
        } else if (arg == arg_mac) {
            mac = parse_mac(value);
        } else if (arg == arg_mtu) {
            mtu = parse_u64(value);
        } else if (arg == arg_tap) {
            tap_name = value;
        } else {
            return usage();
        }
    }
    if (socket_path.empty() || !nic_id || !mac || !mtu || *mtu > UINT16_MAX) {
        return usage();
    }
    const net::NicIdentity identity{.nic_id = net::geneve::NicId{*nic_id},
                                    .mac = *mac,
                                    .mtu = static_cast<std::uint16_t>(*mtu)};
    if (auto ok = net::validate(identity); !ok) {
        std::println(stderr, "ak-oar-net: bad identity: {}", net::to_string(ok.error()));
        return exit_usage;
    }

    const int tap_fd = tap_name.empty() ? -1 : open_tap(tap_name);
    if (!tap_name.empty() && tap_fd < 0) {
        std::println(stderr, "ak-oar-net: open TAP {}: {}", tap_name, std::strerror(errno));
        return EXIT_FAILURE;
    }
    const std::string log_name = "ak-oar-net[" + std::to_string(*nic_id) + "]";
    auto binding = ak::oar::vfu::VirtioBinding::create(socket_path, log_name);
    if (!binding) {
        std::println(stderr, "ak-oar-net: {}", binding.error());
        return EXIT_FAILURE;
    }
    TapSink sink{tap_fd};
    auto function = net::VirtioNetFunction::create({.identity = identity}, (*binding)->memory(),
                                                   **binding, sink);
    if (!function) {
        std::println(stderr, "ak-oar-net: {}", net::to_string(function.error()));
        return EXIT_FAILURE;
    }
    if (auto ok = (*binding)->bind((*function)->pci()); !ok) {
        std::println(stderr, "ak-oar-net: {}", ok.error());
        return EXIT_FAILURE;
    }

    std::println(stderr, "{}: waiting for client on {}", log_name, socket_path);
    // One byte spare, so an oversized TAP frame is refused rather than cut.
    std::vector<std::byte> rx((*function)->max_frame() + 1);
    bool attached = false;
    bool tx_pending = false;
    for (;;) {
        std::array<pollfd, 2> fds{};
        fds[poll_vfu] = {.fd = (*binding)->poll_fd(), .events = POLLIN, .revents = 0};
        fds[poll_tap] = {.fd = attached ? tap_fd : -1, .events = POLLIN, .revents = 0};
        if (::poll(fds.data(), fds.size(), tx_pending ? poll_now : poll_forever) < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::println(stderr, "{}: poll: {}", log_name, std::strerror(errno));
            return EXIT_FAILURE;
        }
        if (!attached) {
            auto a = (*binding)->attach();
            if (!a) {
                std::println(stderr, "{}: {}", log_name, a.error());
                return EXIT_FAILURE;
            }
            attached = *a;
            if (attached) {
                std::println(stderr, "{}: client attached", log_name);
            }
            continue;
        }
        if ((fds[poll_vfu].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            auto r = (*binding)->run();
            if (!r) {
                std::println(stderr, "{}: {}", log_name, r.error());
                return EXIT_FAILURE;
            }
            if (!*r) {
                std::println(stderr, "{}: client disconnected", log_name);
                attached = false;
                tx_pending = false;
                continue;
            }
        }
        if ((fds[poll_tap].revents & POLLIN) != 0) {
            // Drain what the TAP has; the guest takes what it has room for.
            for (;;) {
                const ssize_t n = ::read(tap_fd, rx.data(), rx.size());
                if (n <= 0) {
                    break;
                }
                static_cast<void>((*function)->deliver(
                    std::span<const std::byte>{rx}.first(static_cast<std::size_t>(n))));
            }
        }
        tx_pending = (*function)->pci().poll();
    }
}
