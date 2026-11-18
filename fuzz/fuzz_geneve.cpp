// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes Geneve decode plus ingress policy, and checks that anything decode
// accepts re-encodes to an equivalent packet.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/geneve.hpp"
#include "oar/net/vtep_policy.hpp"

namespace {

namespace net = ak::oar::net;
namespace geneve = ak::oar::net::geneve;

class Table final : public net::MappingView {
public:
    [[nodiscard]] std::optional<net::NicBinding> lookup(geneve::NicId id) const override {
        if (id.value % 3 == 0) {
            return std::nullopt;
        }
        net::NicBinding b{};
        b.vni = static_cast<std::uint32_t>(id.value & geneve::vni_max);
        b.mac[5] = static_cast<std::byte>(id.value & 0xFF);
        return b;
    }
    [[nodiscard]] bool is_local(geneve::NicId id) const override { return (id.value & 1) != 0; }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::byte> in{reinterpret_cast<const std::byte*>(data), size};
    auto pkt = geneve::decode(in);
    if (!pkt) {
        return 0;
    }
    const Table table;
    (void)net::check_ingress(*pkt, net::Ipv6Address{}, table);

    if (!pkt->oam) {
        auto again = geneve::encode({.vni = pkt->vni, .nics = *pkt->nics, .oam = false}, pkt->inner);
        if (!again) {
            std::abort();  // decode accepted something encode refuses
        }
        auto round = geneve::decode(*again);
        if (!round || round->vni != pkt->vni || round->nics != pkt->nics || round->inner.size() != pkt->inner.size()) {
            std::abort();
        }
    }
    return 0;
}
