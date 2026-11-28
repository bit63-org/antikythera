// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes what the WireGuard Tunnel reads from the underlay: wg::parse and
// Tunnel::receive, on a tunnel that has keys, a peer and a live session, so
// inputs can reach past the structural checks.
//
// The first input byte steers the rest:
//   bit 0  the datagram comes from the peer's address (else a stranger's);
//   bit 1  mac1 is recomputed for the tunnel's key, so handshake messages
//          get as far as the public-key and AEAD work;
//   bit 2  a transport message's receiver index is set to the live
//          session's, so it reaches the replay window and the AEAD.
// Checks that the views wg::parse returns lie inside the input, that
// nothing but an authenticated payload from the peer's address comes back,
// and that the payload fits inside the datagram.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "oar/net/tunnel.hpp"
#include "oar/net/wireguard.hpp"

namespace {

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;

constexpr std::uint8_t from_peer = 0x01;
constexpr std::uint8_t fix_mac1 = 0x02;
constexpr std::uint8_t fix_index = 0x04;
constexpr std::size_t ipv6_last = 15;
constexpr std::size_t index_offset = 4;

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto key(std::uint8_t fill) -> wg::Key {
    wg::Key k{};
    k.fill(std::byte{fill});
    return k;
}

auto inside(std::span<const std::byte> view, std::span<const std::byte> in) -> bool {
    return view.data() >= in.data() && view.data() + view.size() <= in.data() + in.size();
}

struct Queue final : net::DatagramSender {
    auto send_to(const net::Ipv6Address& dst, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> payload) -> bool override {
        sent.push_back({dst, {payload.begin(), payload.end()}});
        return true;
    }
    std::deque<std::pair<net::Ipv6Address, std::vector<std::byte>>> sent;
};

// The fuzzed tunnel (at VTEP 1) and a peer (VTEP 2) with a session between
// them, built once.
struct State {
    State() {
        target = std::move(*net::Tunnel::create(target_wire, {}));
        peer = std::move(*net::Tunnel::create(peer_wire, {}));
        const auto k1 = key(1);
        const auto k2 = key(2);
        static_cast<void>(target->set_private_key(k1));
        static_cast<void>(peer->set_private_key(k2));
        static_cast<void>(target->set_peer(vtep(2), *peer->public_key(), key(3)));
        static_cast<void>(peer->set_peer(vtep(1), *target->public_key(), key(3)));
        mac1_key = wg::hash(
            {std::as_bytes(std::span{std::string_view{"mac1----"}}), *target->public_key()});
        // Handshake, then one payload from the peer to learn the index.
        const std::array<std::byte, 1> x{std::byte{1}};
        static_cast<void>(peer->send_to(vtep(1), 0, 0, x));
        for (int round = 0; round < 4; ++round) {
            while (!peer_wire.sent.empty()) {
                auto d = std::move(peer_wire.sent.front());
                peer_wire.sent.pop_front();
                static_cast<void>(target->receive(d.second, vtep(2)));
            }
            while (!target_wire.sent.empty()) {
                auto d = std::move(target_wire.sent.front());
                target_wire.sent.pop_front();
                static_cast<void>(peer->receive(d.second, vtep(1)));
            }
        }
        static_cast<void>(peer->send_to(vtep(1), 0, 0, x));
        if (!peer_wire.sent.empty()) {
            const auto& m = peer_wire.sent.back().second;
            std::copy_n(m.begin() + index_offset, live_index.size(), live_index.begin());
        }
    }
    Queue target_wire;
    Queue peer_wire;
    std::unique_ptr<net::Tunnel> target;
    std::unique_ptr<net::Tunnel> peer;
    wg::Hash mac1_key{};
    std::array<std::byte, 4> live_index{};
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    static State state;
    const std::uint8_t mode = data[0];
    std::vector<std::byte> in(reinterpret_cast<const std::byte*>(data) + 1,
                              reinterpret_cast<const std::byte*>(data) + size);

    if (auto m = wg::parse(in)) {
        if ((mode & fix_mac1) != 0) {
            std::size_t offset = 0;
            if (std::holds_alternative<wg::Initiation>(*m)) {
                offset = wg::initiation_mac1_offset;
            } else if (std::holds_alternative<wg::Response>(*m)) {
                offset = wg::response_mac1_offset;
            }
            if (offset != 0) {
                const auto mac = wg::mac(state.mac1_key, std::span{in}.first(offset));
                std::copy(mac.begin(), mac.end(), in.begin() + static_cast<std::ptrdiff_t>(offset));
            }
        }
        if ((mode & fix_index) != 0 && std::holds_alternative<wg::Transport>(*m)) {
            std::copy(state.live_index.begin(), state.live_index.end(), in.begin() + index_offset);
        }
    }
    if (auto m = wg::parse(in)) {
        const bool ok = std::visit(
            [&](const auto& v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, wg::Initiation>) {
                    return inside(v.before_mac1, in) && inside(v.mac2, in);
                } else if constexpr (std::is_same_v<T, wg::Response>) {
                    return inside(v.before_mac1, in) && inside(v.mac2, in);
                } else if constexpr (std::is_same_v<T, wg::CookieReply>) {
                    return inside(v.encrypted_cookie, in);
                } else if constexpr (std::is_same_v<T, wg::Credential>) {
                    return inside(v.credential, in) &&
                           (v.flags & ~wg::credential_flag_send_yours) == 0;
                } else {
                    return inside(v.ciphertext, in) && v.ciphertext.size() >= wg::tag_size;
                }
            },
            *m);
        if (!ok) {
            std::abort();
        }
    }

    const auto source = (mode & from_peer) != 0 ? vtep(2) : vtep(9);
    if (auto opened = state.target->receive(in, source)) {
        if (opened->peer != vtep(2) || source != vtep(2) ||
            opened->payload.size() + wg::transport_overhead != in.size()) {
            std::abort();
        }
    }
    state.target_wire.sent.clear();
    static_cast<void>(state.target->tick());
    return 0;
}
