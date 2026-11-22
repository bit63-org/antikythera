// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Sockets on the storage segment (.kiro/specs/block-volume-service/
// design "Storage traffic on the management fabric"), shared by the hold
// node and oar-blk's initiator.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>

#include "proto/replica_config.hpp"

namespace ak::proto {

// DSCP AF41 in the TOS / traffic class byte: storage I/O (design "Priority").
inline constexpr int storage_io_tos = 34 << 2;

// Marks a socket's packets as storage I/O. Whichever family the socket
// is; the other call fails harmlessly.
inline auto set_storage_class(int fd) noexcept -> void {
    const int tos = storage_io_tos;
    static_cast<void>(::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof tos));
    static_cast<void>(::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof tos));
}

// A member's endpoint as text for connecting and for pinning its IP SAN:
// a dotted quad for an IPv4-mapped address (::ffff:a.b.c.d), else IPv6.
inline auto endpoint_text(const StorageEndpoint& a) -> std::string {
    const bool mapped =
        std::all_of(a.begin(), a.begin() + 10, [](std::byte b) { return b == std::byte{0}; }) &&
        a[10] == std::byte{0xFF} && a[11] == std::byte{0xFF};
    std::array<char, INET6_ADDRSTRLEN> text{};
    const char* r = mapped ? ::inet_ntop(AF_INET, a.data() + 12, text.data(), text.size())
                           : ::inet_ntop(AF_INET6, a.data(), text.data(), text.size());
    return r != nullptr ? std::string{text.data()} : std::string{};
}

}  // namespace ak::proto
