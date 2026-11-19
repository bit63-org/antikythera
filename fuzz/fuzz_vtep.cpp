// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes what the Vtep reads from the underlay and from guests: a UDP
// payload through Vtep::receive (Geneve decode, OAM parse, peer liveness)
// from one of a few outer sources, and the same bytes as an inner frame
// through flow_port(). Checks that every OAM message the parser accepts
// survives a re-encode, that flow ports stay in range, and that
// nothing but data packets comes back from receive().

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
#include <utility>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/oam.hpp"
#include "oar/net/vtep.hpp"

namespace {

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;
namespace oam = ak::oar::net::oam;

constexpr std::size_t ipv6_last = 15;
constexpr std::size_t mac_last = 5;
constexpr std::uint32_t vpc = 100;
constexpr std::array<std::uint8_t, 3> source_tails{1, 2, 9};  // self, peer, stranger

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xfd};
    a[ipv6_last] = std::byte{tail};
    return a;
}

auto mac(std::uint8_t tail) -> net::MacAddress {
    net::MacAddress m{};
    m[0] = std::byte{0x02};
    m[mac_last] = std::byte{tail};
    return m;
}

class NullSender final : public net::DatagramSender {
public:
    auto send_to(const net::Ipv6Address& /*dst*/, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> /*payload*/)
        -> bool override {
        return true;
    }
};

// One VTEP for the whole run, so peer state carries across inputs.
struct State {
    State() {
        static_cast<void>(table.apply(
            {.vni = vpc,
             .version = 1,
             .entries = {{.nic_id = {1}, .mac = mac(1), .owner_vtep = vtep(source_tails[0])},
                         {.nic_id = {2}, .mac = mac(2), .owner_vtep = vtep(source_tails[1])}}}));
        runtime = std::move(*net::Vtep::create(table, sender, nullptr, {}));
    }
    net::MappingTable table{vtep(source_tails[0])};
    NullSender sender;
    std::unique_ptr<net::Vtep> runtime;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::span<const std::byte> in{reinterpret_cast<const std::byte*>(data) + 1, size - 1};
    const auto source = vtep(source_tails.at(data[0] % source_tails.size()));

    if (net::flow_port(vpc, in) < net::flow_port_base) {
        std::abort();
    }

    if (auto pkt = geneve::decode(in); pkt && pkt->oam) {
        if (auto msg = oam::parse(*pkt)) {
            // Options, reserved bits and bytes are ignored on receipt, so
            // compare what was understood, not the bytes.
            const auto again = oam::encode(*msg);
            auto round = geneve::decode(again);
            if (!round || !round->oam || oam::parse(*round) != *msg) {
                std::abort();
            }
        }
    }

    static State state;
    static net::VtepClock::time_point now{};
    now += std::chrono::milliseconds{data[0]};
    static_cast<void>(state.runtime->tick(now));
    if (auto pkt = state.runtime->receive(in, source, now); pkt && pkt->oam) {
        std::abort();
    }
    return 0;
}
