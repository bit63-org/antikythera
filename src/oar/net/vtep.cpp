// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/vtep.hpp"

#include <algorithm>
#include <utility>

#include "common/wire.hpp"

namespace ak::oar::net {

namespace {

// FNV-1a, 64-bit: cheap, and good enough to spread flows over ECMP paths.
// Not keyed: a guest can choose a flow that lands on a given port, which
// only steers its own traffic.
constexpr std::uint64_t fnv_offset = 0xcbf2'9ce4'8422'2325;
constexpr std::uint64_t fnv_prime = 0x0000'0100'0000'01b3;
constexpr unsigned fold_shift = 32;

constexpr std::size_t mac_size = 6;
constexpr std::uint16_t ethertype_vlan = 0x8100;
constexpr std::uint16_t ethertype_qinq = 0x88A8;
constexpr std::size_t max_vlan_tags = 2;
constexpr std::uint16_t ethertype_ipv4 = 0x0800;
constexpr std::uint16_t ethertype_ipv6 = 0x86DD;

constexpr std::uint8_t ipv4_ihl_mask = 0x0F;
constexpr std::size_t ipv4_min_header = 20;
constexpr std::size_t ipv4_address_size = 4;
constexpr std::uint16_t ipv4_fragment_mask = 0x3FFF;  // MF bit and fragment offset
constexpr std::size_t ipv6_address_size = 16;
constexpr std::uint8_t ipproto_tcp = 6;
constexpr std::uint8_t ipproto_udp = 17;
constexpr std::uint8_t ipproto_sctp = 132;
constexpr std::uint32_t initial_keepalive_sequence = 1;

class FlowHash {
public:
    auto add(std::span<const std::byte> bytes) noexcept -> void {
        for (const std::byte b : bytes) {
            _h = (_h ^ std::to_integer<std::uint64_t>(b)) * fnv_prime;
        }
    }
    auto add(std::uint64_t v) noexcept -> void {
        for (unsigned i = 0; i < sizeof v; ++i) {
            _h = (_h ^ ((v >> (i * CHAR_BIT)) & UINT8_MAX)) * fnv_prime;
        }
    }
    [[nodiscard]] auto port() const noexcept -> std::uint16_t {
        const std::uint64_t folded = _h ^ (_h >> fold_shift);
        return static_cast<std::uint16_t>(flow_port_base + (folded % flow_port_count));
    }

private:
    std::uint64_t _h{fnv_offset};
};

auto has_ports(std::uint8_t proto) noexcept -> bool {
    return proto == ipproto_tcp || proto == ipproto_udp || proto == ipproto_sctp;
}

// Adds source and destination port (the first four bytes of TCP, UDP and
// SCTP headers) if they are there.
auto add_ports(FlowHash& h, wire::Reader& r) noexcept -> void {
    if (auto ports = r.bytes(sizeof(std::uint32_t))) {
        h.add(*ports);
    }
}

auto hash_ipv4(FlowHash& h, wire::Reader r) noexcept -> bool {
    auto vihl = r.u8();
    static_cast<void>(r.skip(3));  // TOS, total length
    static_cast<void>(r.skip(2));  // identification
    auto frag = r.be16();
    static_cast<void>(r.skip(1));  // TTL
    auto proto = r.u8();
    static_cast<void>(r.skip(2));  // checksum
    auto addrs = r.bytes(2 * ipv4_address_size);
    if (!vihl || !frag || !proto || !addrs) {
        return false;
    }
    const std::size_t header =
        std::size_t{static_cast<std::uint8_t>(*vihl & ipv4_ihl_mask)} * geneve::bytes_per_word;
    if (header < ipv4_min_header) {
        return false;
    }
    h.add(*addrs);
    h.add(*proto);
    if ((*frag & ipv4_fragment_mask) == 0 && has_ports(*proto) &&
        r.skip(header - ipv4_min_header)) {
        add_ports(h, r);
    }
    return true;
}

auto hash_ipv6(FlowHash& h, wire::Reader r) noexcept -> bool {
    static_cast<void>(r.skip(sizeof(std::uint32_t)));  // version, class, flow label
    static_cast<void>(r.skip(sizeof(std::uint16_t)));  // payload length
    auto next = r.u8();
    static_cast<void>(r.skip(1));  // hop limit
    auto addrs = r.bytes(2 * ipv6_address_size);
    if (!next || !addrs) {
        return false;
    }
    h.add(*addrs);
    h.add(*next);
    // Extension headers are not walked: such a flow hashes on addresses and
    // next header alone, which keeps it on one path all the same.
    if (has_ports(*next)) {
        add_ports(h, r);
    }
    return true;
}

}  // namespace

auto flow_port(std::uint32_t vni, std::span<const std::byte> frame) noexcept -> std::uint16_t {
    FlowHash h;
    h.add(vni);
    wire::Reader r{frame};
    auto macs = r.bytes(2 * mac_size);
    auto type = r.be16();
    for (std::size_t i = 0;
         i < max_vlan_tags && type && (*type == ethertype_vlan || *type == ethertype_qinq); ++i) {
        static_cast<void>(r.skip(vlan_tag_size - sizeof(std::uint16_t)));
        type = r.be16();
    }
    if (type) {
        h.add(*type);
        const bool ip = (*type == ethertype_ipv4 && hash_ipv4(h, r)) ||
                        (*type == ethertype_ipv6 && hash_ipv6(h, r));
        if (ip) {
            return h.port();
        }
    }
    if (macs) {
        h.add(*macs);
    }
    return h.port();
}

auto to_string(PeerState s) noexcept -> const char* {
    switch (s) {
        case PeerState::pending:
            return "pending";
        case PeerState::up:
            return "up";
        case PeerState::down:
            return "down";
    }
    return "unknown";
}

auto to_string(VtepConfigError e) noexcept -> const char* {
    switch (e) {
        case VtepConfigError::bad_interval:
            return "bad_interval";
        case VtepConfigError::bad_misses:
            return "bad_misses";
        case VtepConfigError::bad_port:
            return "bad_port";
        case VtepConfigError::bad_max_payload:
            return "bad_max_payload";
        case VtepConfigError::bad_probe_interval:
            return "bad_probe_interval";
    }
    return "unknown";
}

auto Vtep::create(const MappingTable& mappings, DatagramSender& sender, PeerObserver* observer,
                  const VtepConfig& config)
    -> std::expected<std::unique_ptr<Vtep>, VtepConfigError> {
    if (config.keepalive_interval <= std::chrono::milliseconds::zero()) {
        return std::unexpected(VtepConfigError::bad_interval);
    }
    if (config.keepalive_misses == 0) {
        return std::unexpected(VtepConfigError::bad_misses);
    }
    if (config.peer_port == 0) {
        return std::unexpected(VtepConfigError::bad_port);
    }
    if (config.max_payload != 0 && config.max_payload < oam::message_size) {
        return std::unexpected(VtepConfigError::bad_max_payload);
    }
    if (config.max_payload != 0 && config.probe_interval <= std::chrono::milliseconds::zero()) {
        return std::unexpected(VtepConfigError::bad_probe_interval);
    }
    return std::unique_ptr<Vtep>(new Vtep(mappings, sender, observer, config));
}

Vtep::Vtep(const MappingTable& mappings, DatagramSender& sender, PeerObserver* observer,
           const VtepConfig& config)
    : _mappings{&mappings},
      _sender{&sender},
      _observer{observer},
      _config{config},
      _keepalive_sequence{initial_keepalive_sequence},
      _probe_sequence{initial_keepalive_sequence} {}

auto Vtep::grace() const -> VtepClock::duration {
    return _config.keepalive_interval * _config.keepalive_misses;
}

auto Vtep::send(const RemoteFrame& frame) -> void {
    auto payload =
        geneve::encode({.vni = frame.vni, .nics = frame.nics, .oam = false}, frame.frame);
    if (!payload) {
        ++_counters.tx_encode_failed;
        return;
    }
    if (_config.max_payload != 0 && payload->size() > _config.max_payload) {
        ++_counters.tx_drop_too_big;
        return;
    }
    if (!_sender->send_to(frame.vtep, _config.peer_port, flow_port(frame.vni, frame.frame),
                          *payload)) {
        ++_counters.tx_send_failed;
        return;
    }
    ++_counters.tx_packets;
    _counters.tx_bytes += payload->size();
}

auto Vtep::receive(std::span<const std::byte> payload, const Ipv6Address& outer_src,
                   VtepClock::time_point now) -> std::optional<geneve::Packet> {
    ++_counters.rx_datagrams;
    auto packet = geneve::decode(payload);
    if (!packet) {
        ++_counters.rx_drop_decode.at(static_cast<std::size_t>(packet.error()));
        return std::nullopt;
    }
    if (packet->oam) {
        handle_oam(*packet, outer_src, now);
        return std::nullopt;
    }
    ++_counters.rx_data;
    return *packet;
}

auto Vtep::handle_oam(const geneve::Packet& packet, const Ipv6Address& outer_src,
                      VtepClock::time_point now) -> void {
    auto message = oam::parse(packet);
    if (!message) {
        ++_counters.rx_drop_oam.at(static_cast<std::size_t>(message.error()));
        return;
    }
    // A keepalive can beat the first tick() after the map_update that made
    // its sender a peer.
    sync_peers(now);
    const auto it = _peers.find(outer_src);
    if (it == _peers.end()) {
        ++_counters.rx_drop_oam_unknown_peer;
        return;
    }
    Peer& peer = it->second;
    if (message->type == oam::Type::mtu_probe) {
        // Liveness is the keepalives' job; a probe only speaks for the path.
        ++_counters.probes_rx;
        ++peer.status.probes_rx;
        const std::size_t size = geneve::base_header_size + oam::body_size + message->padding;
        peer.status.largest_probe = std::max(peer.status.largest_probe, size);
        peer.status.mtu_ok =
            _config.max_payload != 0 && peer.status.largest_probe >= _config.max_payload;
        return;
    }
    ++_counters.keepalives_rx;
    ++peer.status.keepalives_rx;
    peer.status.last_sequence = message->sequence;
    peer.deadline = now + grace();
    set_state(peer, PeerState::up);
}

auto Vtep::set_state(Peer& peer, PeerState state) -> void {
    if (peer.status.state == state) {
        return;
    }
    peer.status.state = state;
    if (_observer != nullptr) {
        _observer->peer_changed(peer.status.vtep, state);
    }
}

auto Vtep::sync_peers(VtepClock::time_point now) -> void {
    auto snap = _mappings->snapshot();
    if (snap == _synced) {
        return;
    }
    const std::vector<Ipv6Address> wanted = snap->peer_vteps();
    std::erase_if(_peers, [&wanted](const auto& kv) {
        return !std::ranges::binary_search(wanted, kv.first);
    });
    for (const Ipv6Address& vtep : wanted) {
        _peers.try_emplace(vtep, Peer{.status = {.vtep = vtep},
                                      .next_keepalive = now,
                                      .next_probe = now,
                                      .deadline = now + grace()});
    }
    _synced = std::move(snap);
}

auto Vtep::tick(VtepClock::time_point now) -> VtepClock::time_point {
    sync_peers(now);
    VtepClock::time_point next = now + _config.keepalive_interval;
    for (auto& [vtep, peer] : _peers) {
        if (now >= peer.next_keepalive) {
            const auto message =
                oam::encode({.type = oam::Type::keepalive, .sequence = _keepalive_sequence++});
            if (send_oam(vtep, message)) {
                ++_counters.keepalives_tx;
            } else {
                ++_counters.keepalive_send_failed;
            }
            peer.next_keepalive = now + _config.keepalive_interval;
        }
        if (_config.max_payload != 0) {
            if (now >= peer.next_probe) {
                const auto probe = oam::encode_probe(_probe_sequence++, _config.max_payload);
                if (send_oam(vtep, probe)) {
                    ++_counters.probes_tx;
                } else {
                    ++_counters.probe_send_failed;
                }
                peer.next_probe = now + _config.probe_interval;
            }
            next = std::min(next, peer.next_probe);
        }
        if (now >= peer.deadline) {
            set_state(peer, PeerState::down);
        }
        next = std::min(next, peer.next_keepalive);
        if (peer.status.state != PeerState::down) {
            next = std::min(next, peer.deadline);
        }
    }
    return next;
}

auto Vtep::send_oam(const Ipv6Address& vtep, std::span<const std::byte> message) -> bool {
    return _sender->send_to(vtep, _config.peer_port, flow_port_base, message);
}

auto Vtep::peers() const -> std::vector<PeerStatus> {
    std::vector<PeerStatus> out;
    out.reserve(_peers.size());
    for (const auto& [vtep, peer] : _peers) {
        out.push_back(peer.status);
    }
    return out;
}

}  // namespace ak::oar::net
