// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Vtep: the tunnel endpoint between the VSwitch and the IPv6/UDP underlay
// (.kiro/specs/oar-net-data-plane/ Requirements 3 and 4.4, design "Vtep",
// task 9).
//
// Send (Underlay::send, called by the VSwitch for remote unicast and for
// each head-end replica): Geneve-encode with the {vni, src, dst} the
// VSwitch chose (src is the function's NIC ID, never guest data,
// Requirement 3.4) and hand the payload to a DatagramSender for the peer's
// port 6081. The UDP source port is a hash of the inner flow folded into
// 49152-65535 (Requirement 3.5), so ECMP in the datacenter spreads flows
// without reordering any one of them.
//
// Receive (Vtep::receive, one UDP payload from the outer IPv6 source):
// structural decode (Requirement 4.1), drops counted per DecodeError; OAM
// packets are consumed here and never returned (Requirement 3.6); a data
// packet is returned for VSwitch::receive, which runs the ingress policy
// and counts its drops per PolicyError (Requirements 4.2-4.4).
//
// Keepalives (design "Vtep"): every keepalive_interval the Vtep sends an
// OAM keepalive to each peer VTEP (MappingSnapshot::peer_vteps(): the other
// VTEPs of VNIs it has NICs in). A peer is up once a keepalive arrives from
// it and down when none has for keepalive_misses intervals; each change is
// reported to a PeerObserver, which is how helm will learn about it. Peers
// appear and disappear with map_updates. A new peer starts pending and gets
// the same grace period before it is declared down.
//
// Time is passed in rather than read, so tests drive the clock. The caller
// calls tick() at or before the time it returns.
//
// Threading: like the VSwitch, a Vtep belongs to one data-plane thread;
// every member must be called from it. Data-path problems are counted,
// never thrown.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/oam.hpp"
#include "oar/net/vswitch.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net {

using VtepClock = std::chrono::steady_clock;

// UDP source ports for Geneve flows (Requirement 3.5): the dynamic range.
inline constexpr std::uint16_t flow_port_base = 49152;
inline constexpr std::uint32_t flow_port_count = 16384;

// The UDP source port for an inner frame of `vni`: a hash of its addresses,
// IP protocol and, for unfragmented TCP, UDP and SCTP, its ports, folded
// into flow_port_base..65535. Non-IP frames hash their MAC addresses and
// EtherType. Guest VLAN tags are skipped (they are payload, Requirement
// 2.2, but should not split a flow from its untagged twin's hash). Reads
// guest data with bounds checks; never fails.
[[nodiscard]] auto flow_port(std::uint32_t vni, std::span<const std::byte> frame) noexcept
    -> std::uint16_t;

// Sends one UDP datagram. `flow_port` is the flow's source port hint;
// an implementation that cannot choose its source port per datagram maps it
// onto the ports it has. False if the datagram was not sent.
class DatagramSender {
public:
    DatagramSender() = default;
    DatagramSender(const DatagramSender&) = delete;
    auto operator=(const DatagramSender&) -> DatagramSender& = delete;
    DatagramSender(DatagramSender&&) = delete;
    auto operator=(DatagramSender&&) -> DatagramSender& = delete;
    virtual ~DatagramSender() = default;

    virtual auto send_to(const Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                         std::span<const std::byte> payload) -> bool = 0;
};

enum class PeerState : std::uint8_t {
    pending,  // in the mappings, not heard from yet, still within its grace period
    up,       // a keepalive arrived within the last keepalive_misses intervals
    down,     // none did
};

[[nodiscard]] auto to_string(PeerState s) noexcept -> const char*;

// Told when a peer goes up or down (never about pending, nor about a peer
// leaving the mappings: helm removed it, so helm knows).
class PeerObserver {
public:
    PeerObserver() = default;
    PeerObserver(const PeerObserver&) = delete;
    auto operator=(const PeerObserver&) -> PeerObserver& = delete;
    PeerObserver(PeerObserver&&) = delete;
    auto operator=(PeerObserver&&) -> PeerObserver& = delete;
    virtual ~PeerObserver() = default;

    virtual auto peer_changed(const Ipv6Address& vtep, PeerState state) -> void = 0;
};

struct PeerStatus {
    Ipv6Address vtep{};
    PeerState state{PeerState::pending};
    std::uint64_t keepalives_rx{0};
    std::uint64_t last_sequence{0};  // of the last keepalive received
};

struct VtepConfig {
    std::chrono::milliseconds keepalive_interval{std::chrono::seconds{1}};
    unsigned keepalive_misses{3};  // intervals without a keepalive before a peer is down
    std::uint16_t peer_port{geneve::udp_port};
};

enum class VtepConfigError : std::uint8_t {
    bad_interval,  // not positive
    bad_misses,    // zero
    bad_port,      // zero
};

[[nodiscard]] auto to_string(VtepConfigError e) noexcept -> const char*;

inline constexpr std::size_t decode_error_count =
    static_cast<std::size_t>(geneve::DecodeError::inner_frame_too_short) + 1;

struct VtepCounters {
    std::uint64_t tx_packets{0};        // data packets handed to the sender
    std::uint64_t tx_bytes{0};          // their Geneve payload bytes
    std::uint64_t tx_encode_failed{0};  // the VSwitch asked for something unencodable
    std::uint64_t tx_send_failed{0};    // the sender refused (full queue, no route)
    std::uint64_t rx_datagrams{0};      // payloads handed to receive()
    std::uint64_t rx_data{0};           // data packets returned for the VSwitch
    std::array<std::uint64_t, decode_error_count> rx_drop_decode{};  // by geneve::DecodeError
    std::array<std::uint64_t, oam::oam_error_count> rx_drop_oam{};   // by oam::OamError
    std::uint64_t rx_drop_oam_unknown_peer{0};  // a keepalive from a VTEP that is not a peer
    std::uint64_t keepalives_tx{0};
    std::uint64_t keepalives_rx{0};
    std::uint64_t keepalive_send_failed{0};
};

class Vtep final : public Underlay {
public:
    // `observer` may be null.
    static auto create(const MappingTable& mappings, DatagramSender& sender, PeerObserver* observer,
                       const VtepConfig& config)
        -> std::expected<std::unique_ptr<Vtep>, VtepConfigError>;

    // Encapsulates and sends a frame for another VTEP (Underlay).
    auto send(const RemoteFrame& frame) -> void override;

    // One UDP payload from `outer_src`, received at `now`. Returns the
    // decoded data packet for VSwitch::receive (its `inner` aliases
    // `payload`), or nothing if it was OAM or dropped.
    auto receive(std::span<const std::byte> payload, const Ipv6Address& outer_src,
                 VtepClock::time_point now) -> std::optional<geneve::Packet>;

    // Syncs the peer set with the mappings, sends due keepalives and
    // declares silent peers down. Returns when it next needs to run.
    auto tick(VtepClock::time_point now) -> VtepClock::time_point;

    // Every current peer, sorted by address.
    [[nodiscard]] auto peers() const -> std::vector<PeerStatus>;
    [[nodiscard]] auto counters() const noexcept -> const VtepCounters& { return _counters; }

private:
    struct Peer {
        PeerStatus status;
        VtepClock::time_point next_keepalive;
        VtepClock::time_point deadline;  // down if nothing heard by then
    };

    Vtep(const MappingTable& mappings, DatagramSender& sender, PeerObserver* observer,
         const VtepConfig& config);

    auto sync_peers(VtepClock::time_point now) -> void;
    auto handle_oam(const geneve::Packet& packet, const Ipv6Address& outer_src,
                    VtepClock::time_point now) -> void;
    auto set_state(Peer& peer, PeerState state) -> void;
    [[nodiscard]] auto grace() const -> VtepClock::duration;

    const MappingTable* _mappings;
    DatagramSender* _sender;
    PeerObserver* _observer;
    VtepConfig _config;
    // The snapshot the peer set was last synced with, to skip unchanged ones.
    std::shared_ptr<const MappingSnapshot> _synced;
    std::map<Ipv6Address, Peer> _peers;
    std::uint64_t _keepalive_sequence{0};
    VtepCounters _counters;
};

}  // namespace ak::oar::net
