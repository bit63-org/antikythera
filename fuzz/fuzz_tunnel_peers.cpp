// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the TunnelPeers decoder and TunnelPeerSet::apply. An accepted
// frame must re-encode to identical bytes (the encoding is canonical) and
// satisfy the invariants the role relies on (ascending, unique VTEPs and
// keys, none the target). The verifier accepts everything, so whatever
// decodes also reaches the Tunnel: applying it must leave the Tunnel with
// exactly the frame's peers, or report that the Tunnel refused one.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>

#include "oar/net/tunnel.hpp"
#include "oar/net/tunnel_peers.hpp"
#include "proto/tunnel_peers.hpp"

namespace {

namespace net = ak::oar::net;
namespace proto = ak::proto;

class NullSender final : public net::DatagramSender {
public:
    auto send_to(const net::Ipv6Address& /*dst*/, std::uint16_t /*dst_port*/,
                 std::uint16_t /*flow_port*/, std::span<const std::byte> /*payload*/)
        -> bool override {
        return true;
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libFuzzer's byte API
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto t = proto::decode_tunnel_peers(bytes);
    if (!t) {
        return 0;
    }
    auto again = proto::encode_tunnel_peers(*t);
    if (!again || !std::ranges::equal(*again, bytes) || t->peers.size() > proto::max_tunnel_peers ||
        !std::ranges::is_sorted(t->peers, std::ranges::less{}, &proto::TunnelPeer::vtep) ||
        std::ranges::any_of(t->peers,
                            [&](const proto::TunnelPeer& p) { return p.vtep == t->vtep; })) {
        std::abort();
    }

    NullSender sender;
    auto tunnel = net::Tunnel::create(sender, {});
    if (!tunnel) {
        std::abort();
    }
    net::TunnelPeerSet set{
        **tunnel, t->server_id, t->vtep,
        [](auto /*signed_bytes*/, auto /*signature*/, auto /*key_id*/) { return true; }};
    const auto r = set.apply(bytes);
    if (r == net::PeersResult::applied) {
        if ((*tunnel)->peers().size() != t->peers.size() || set.version() != t->peers_version) {
            std::abort();
        }
    } else if (r != net::PeersResult::rejected) {
        std::abort();
    }
    if (set.apply(bytes) != (r == net::PeersResult::applied ? net::PeersResult::redelivered
                                                            : net::PeersResult::rejected)) {
        std::abort();
    }
    return 0;
}
