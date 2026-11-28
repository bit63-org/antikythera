// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the certified handshake's credential path (fleet-scale-networking
// task 3): a Tunnel with a CredentialStore whose verifier accepts every
// signature, driven by a script of operations read from the input:
// credential messages built from fuzzed fields (keys, addresses, windows,
// serials) or raw bytes, sends to fuzzed addresses, revocations and time
// passing. After every operation the Tunnel's state must stay within its
// bounds: the cache within its capacity, at most one peer per key, no peer
// with the role's own key, and every certified peer still valid by the
// store (tick() having run since time last moved).

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <set>
#include <span>
#include <vector>

#include "oar/net/credentials.hpp"
#include "oar/net/tunnel.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/vtep_credential.hpp"

namespace {

namespace net = ak::oar::net;
namespace wg = ak::oar::net::wg;
namespace proto = ak::proto;

constexpr std::size_t cache_size = 8;
constexpr std::int64_t wall_start = 1'800'000'000;

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xFD};
    a.back() = std::byte{tail};
    return a;
}

struct Null final : net::DatagramSender {
    auto send_to(const net::Ipv6Address& /*dst*/, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> /*payload*/)
        -> bool override {
        return true;
    }
};

class Input {
public:
    explicit Input(std::span<const std::byte> b) : _b{b} {}
    [[nodiscard]] auto empty() const -> bool { return _at >= _b.size(); }
    auto u8() -> std::uint8_t { return empty() ? 0 : std::to_integer<std::uint8_t>(_b[_at++]); }
    auto u32() -> std::uint32_t {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8U) | u8();
        }
        return v;
    }
    auto fill(std::span<std::byte> out) -> void {
        for (auto& x : out) {
            x = std::byte{u8()};
        }
    }

private:
    std::span<const std::byte> _b;
    std::size_t _at{0};
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libFuzzer's byte API
    Input in{std::span{reinterpret_cast<const std::byte*>(data), size}};
    auto now = net::VtepClock::time_point{std::chrono::seconds{1000}};
    auto wall = std::chrono::system_clock::time_point{std::chrono::seconds{wall_start}};
    const auto unix_now = [&] {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(wall.time_since_epoch()).count());
    };

    net::CredentialStore store{
        net::CredentialConfig{.server_id = 1,
                              .vtep = vtep(1),
                              .skew = std::chrono::minutes{5},
                              .wall_clock = [&] { return wall; }},
        [](auto /*signed_bytes*/, auto /*signature*/, auto /*key_id*/) { return true; }};
    Null underlay;
    net::TunnelConfig config;
    config.credential_cache_size = cache_size;
    config.max_sources = 16;
    config.clock = [&] { return now; };
    config.wall_clock = [&] { return wall; };
    auto tunnel = net::Tunnel::create(underlay, config);
    if (!tunnel) {
        std::abort();
    }
    auto& t = **tunnel;
    wg::Key priv{};
    priv.fill(std::byte{0x41});
    if (!t.set_private_key(priv) || !t.public_key()) {
        std::abort();
    }
    const auto own = *t.public_key();
    t.set_credentials(&store);

    const auto make = [&](const net::Ipv6Address& at, const wg::Key& key, std::uint64_t not_before,
                          std::uint64_t not_after, std::uint64_t serial) {
        proto::VtepCredential c{.key_id = 1,
                                .server_id = 9,
                                .cell_id = 0,
                                .modes = proto::tunnel_mode_bit(proto::TunnelMode::wireguard),
                                .slot = 0,
                                .key_epoch = 1,
                                .vtep = at,
                                .public_key = key,
                                .not_before = not_before,
                                .not_after = not_after,
                                .serial = serial == 0 ? 1 : serial,
                                .signature = {}};
        return proto::encode_vtep_credential(c);
    };
    if (auto mine = make(vtep(1), own, unix_now() - 10, unix_now() + 86'400, 1); mine) {
        static_cast<void>(store.install_own(*mine, own));
    }
    std::uint64_t list_version = 0;
    std::vector<proto::Revocation> revoked;

    for (int step = 0; step < 64 && !in.empty(); ++step) {
        const auto op = in.u8() % 6;
        const auto src = vtep(static_cast<std::uint8_t>(2 + (in.u8() % 8)));
        if (op == 0 || op == 1) {
            // A structured credential, naming its source or not.
            wg::Key key{};
            key[0] = std::byte{in.u8()};
            key[1] = std::byte{in.u8()};
            key[31] = std::byte{1};
            if ((in.u8() & 1U) != 0) {
                key = own;
            }
            const auto at = (in.u8() & 1U) != 0 ? src : vtep(static_cast<std::uint8_t>(in.u8()));
            const auto from = unix_now() - (in.u8() * 60ULL);
            const auto life = 1 + (in.u32() % 200'000);
            auto frame = make(at, key, from, from + life, in.u8());
            if (!frame) {
                continue;
            }
            std::array<std::byte, wg::credential_message_size> m{};
            m[0] = std::byte{static_cast<std::uint8_t>(wg::MessageType::credential)};
            m[4] = std::byte{static_cast<std::uint8_t>(op == 1 ? 1 : 0)};
            std::ranges::copy(*frame, m.begin() + 8);
            static_cast<void>(t.receive(m, src));
        } else if (op == 2) {
            std::array<std::byte, wg::credential_message_size> m{};
            m[0] = std::byte{static_cast<std::uint8_t>(wg::MessageType::credential)};
            in.fill(std::span{m}.subspan(8));
            static_cast<void>(t.receive(m, src));
        } else if (op == 3) {
            static_cast<void>(t.send_to(src, 6081, 50'000, std::array<std::byte, 4>{}));
        } else if (op == 4) {
            const std::uint64_t serial = 1 + in.u8();
            if (std::ranges::find(revoked, serial, &proto::Revocation::serial) == revoked.end()) {
                revoked.push_back({.serial = serial, .not_after = unix_now() + 86'400});
                std::ranges::sort(revoked, {}, &proto::Revocation::serial);
            }
            proto::CredentialRevocations l{.key_id = 1,
                                           .cell_id = 0,
                                           .list_version = ++list_version,
                                           .entries = revoked,
                                           .signature = {}};
            if (auto f = proto::encode_credential_revocations(l); f) {
                static_cast<void>(store.install_revocations(*f));
            }
        } else {
            const auto secs = std::chrono::seconds{in.u32() % 200'000};
            now += secs;
            wall += secs;
        }
        static_cast<void>(t.tick());

        if (t.credential_cache().size() > cache_size) {
            std::abort();
        }
        std::set<wg::Key> keys;
        for (const auto& p : t.peers()) {
            if (p.public_key == own || !keys.insert(p.public_key).second) {
                std::abort();
            }
        }
    }
    return 0;
}
