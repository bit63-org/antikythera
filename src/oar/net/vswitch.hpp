// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// VSwitch: forwarding between a VTEP's local NICs and the underlay
// (.kiro/specs/oar-net-data-plane/ Requirements 2 and 7, design "VSwitch",
// task 8).
//
// Every decision is made against one MappingTable snapshot per frame, so a
// frame never sees half of one map_update. Nothing is learned from traffic
// (Requirement 2.5).
//
// Transmit (a local NIC's frame, VSwitch::transmit as its FrameSink):
//   - the source NIC must be attached here and be in the mappings as a NIC
//     of this VTEP; otherwise it is in the dead VPC and the frame is dropped
//     (Requirement 2.4);
//   - the frame's source MAC must be the NIC's mapped MAC (Requirement 2.3;
//     VirtioNetFunction checks its own identity too, this checks helm's
//     mapping);
//   - ARP frames whose sender MAC, or sender IP, belongs to someone else and
//     neighbor solicitations whose source link-layer option is not the
//     sender's MAC are dropped; a broadcast ARP request or a multicast
//     neighbor solicitation (not a DAD probe) for an address helm registered
//     for another NIC in the VNI is answered locally (Requirement 2.6), and
//     anything else is forwarded like any frame;
//   - unicast to a NIC of this VTEP is delivered to its function; unicast to
//     a NIC of another VTEP goes to the underlay with {vni, src, dst} for
//     Geneve encapsulation (Requirement 7.2: in split placement two boards
//     in one server are two VTEPs and take this path); unknown unicast is
//     dropped (Requirement 2.5);
//   - group-addressed frames the proxy did not consume follow the VNI's
//     GroupPolicy (Requirement 10). By default (GroupMode::drop, as in an
//     AWS VPC) they are dropped. A VNI that opted in to multicast
//     (GroupMode::multicast) replicates IPv4 and IPv6 multicast frames,
//     except IPv6 solicited-node groups, which belong to neighbor discovery,
//     to every other attached local NIC in the VNI and once to each other
//     VTEP hosting it with the broadcast NIC ID (head-end replication).
//     Broadcast and every other group address stay dropped. Replication is
//     limited per source NIC by a frame and byte token bucket and refused
//     when the VNI spans more remote VTEPs than the policy allows.
//
// Receive (VSwitch::receive, a decoded Geneve packet from the Vtep): the
// ingress policy (vtep_policy.hpp) runs against the same snapshot used to
// deliver, then the frame goes to the destination NIC, or for a replicated
// frame to every attached local NIC in the VNI, if this VTEP's GroupPolicy
// for the VNI admits it too (a sender with a stale or hostile policy cannot
// push group traffic into a VNI that has not opted in).
//
// Metering (Requirement 10.6): every source NIC has a GroupMeter of
// cumulative counters: group frames accepted, replicas and replica bytes
// sent to the fabric (the billable quantity) and delivered locally, and
// drops by cause. group_usage() returns the meters of attached NICs and
// the final meters of NICs detached since the last call, so helm can
// report them to the controller for billing without losing a detached
// NIC's last interval. Meters restart at zero on each attach; the
// attachment number tells the attachments of one NIC ID apart.
//
// The dead VPC (Requirement 2.4) is not a table: a NIC is in it exactly when
// it is not in the current mappings as a NIC of this VTEP. Its frames are
// dropped and nothing is delivered to it, so detaching (helm removes it from
// the VNI's map_update, Requirement 8.2) needs no other step here.
//
// ARP/ND proxy addresses come from helm through set_neighbors(), keyed by
// VNI because VPCs may reuse address space. An entry names a NIC; the reply
// carries that NIC's MAC from the current snapshot, so a NIC that leaves the
// VNI stops being answered for at once. The controller's map_update does
// not carry guest addresses yet, so helm has no wire source for them today.
//
// Threading: a VSwitch belongs to one data-plane thread. transmit(),
// receive(), attach(), detach() and set_neighbors() must all be called from
// it. The MappingTable is the only structure shared with other threads.
// Data-path problems are counted, never thrown (design "Error handling").

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/virtio_net.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net {

// A frame for another VTEP, before Geneve encapsulation. `frame` is valid
// only during Underlay::send().
struct RemoteFrame {
    Ipv6Address vtep{};
    std::uint32_t vni{0};
    geneve::NicPair nics{};  // dst is nic_broadcast for head-end replication
    std::span<const std::byte> frame;
};

// The Vtep side: encapsulates and sends (task 9).
class Underlay {
public:
    Underlay() = default;
    Underlay(const Underlay&) = delete;
    auto operator=(const Underlay&) -> Underlay& = delete;
    Underlay(Underlay&&) = delete;
    auto operator=(Underlay&&) -> Underlay& = delete;
    virtual ~Underlay() = default;

    virtual auto send(const RemoteFrame& frame) -> void = 0;
};

struct Ipv4Neighbor {
    neighbor::Ipv4Address ip{};
    geneve::NicId nic{};
};

struct Ipv6Neighbor {
    Ipv6Address ip{};
    geneve::NicId nic{};
};

// The complete set of proxied addresses of one VNI; empty lists remove it.
struct NeighborUpdate {
    std::uint32_t vni{0};
    std::vector<Ipv4Neighbor> ipv4{};
    std::vector<Ipv6Neighbor> ipv6{};
};

enum class NeighborError : std::uint8_t {
    vni_out_of_range,   // 0, or wider than 24 bits
    invalid_nic_id,     // 0 or the broadcast ID
    invalid_address,    // IPv4 0.0.0.0 or 224.0.0.0 and up; IPv6 unspecified or multicast
    duplicate_address,  // one address twice in the update
};

[[nodiscard]] auto to_string(NeighborError e) noexcept -> const char*;

enum class AttachError : std::uint8_t {
    invalid_nic_id,    // 0 or the broadcast ID
    already_attached,  // that NIC ID already has a port
};

[[nodiscard]] auto to_string(AttachError e) noexcept -> const char*;

// What a VNI does with group-addressed frames the ARP/ND proxy did not
// consume (Requirement 10).
enum class GroupMode : std::uint8_t {
    drop,       // the default: no broadcast or multicast, like an AWS VPC
    multicast,  // opted in: IP multicast replicated within the VNI, metered
};

// A VNI's group policy. Rates and bursts apply per source NIC and are hard
// limits: a multicast policy must set all of them (Requirement 10.4).
struct GroupPolicy {
    GroupMode mode{GroupMode::drop};
    std::uint32_t rate_frames{0};     // replicated frames per second
    std::uint32_t burst_frames{0};    // bucket depth in frames
    std::uint64_t rate_bytes{0};      // replicated frame bytes per second
    std::uint64_t burst_bytes{0};     // bucket depth in bytes
    std::uint32_t max_remote_vteps{0};  // flood-list cap: larger VNIs drop the frame
};

inline constexpr std::uint32_t group_rate_frames_max = 1U << 24;
inline constexpr std::uint32_t group_burst_frames_max = 1U << 20;
inline constexpr std::uint64_t group_rate_bytes_max = std::uint64_t{1} << 37;   // ~1 Tbit/s
inline constexpr std::uint64_t group_burst_bytes_max = std::uint64_t{1} << 32;
inline constexpr std::uint32_t group_max_remote_vteps_max = 1U << 16;

enum class GroupPolicyError : std::uint8_t {
    vni_out_of_range,  // 0, or wider than 24 bits
    unknown_mode,
    missing_limit,     // a multicast policy with a zero rate, burst or flood-list cap
    limit_too_large,   // above the group_*_max bounds
    nonzero_limits,    // a drop policy that carries limits
};

[[nodiscard]] auto to_string(GroupPolicyError e) noexcept -> const char*;

// Cumulative per-NIC group counters since the NIC was attached. A frame is
// counted once in `frames` and once per copy in the replica counters.
struct GroupMeter {
    std::uint64_t frames{0};                // group frames accepted for replication
    std::uint64_t bytes{0};                 // their bytes
    std::uint64_t replicas_remote{0};       // copies sent to other VTEPs (billable)
    std::uint64_t replica_bytes_remote{0};  // bytes of those copies (billable)
    std::uint64_t replicas_local{0};        // copies delivered to NICs on this VTEP
    std::uint64_t replica_bytes_local{0};
    std::uint64_t drop_policy{0};  // group frames the VNI's policy does not admit
    std::uint64_t drop_rate{0};    // over the NIC's frame or byte rate
    std::uint64_t drop_fanout{0};  // the VNI spans more remote VTEPs than allowed

    friend auto operator==(const GroupMeter&, const GroupMeter&) -> bool = default;
};

// One NIC attachment's meter, as group_usage() returns it.
struct GroupUsage {
    geneve::NicId nic{};
    std::uint64_t attachment{0};  // non-zero, increasing per VSwitch
    bool detached{false};         // final reading: the NIC is gone
    GroupMeter meter{};
};

inline constexpr std::size_t policy_error_count =
    static_cast<std::size_t>(PolicyError::broadcast_not_group) + 1;

struct SwitchCounters {
    std::uint64_t tx_frames{0};           // frames handed to transmit()
    std::uint64_t tx_local{0};            // unicast delivered to a local NIC
    std::uint64_t tx_remote{0};           // unicast sent to another VTEP
    std::uint64_t tx_flooded{0};          // group-addressed frames replicated
    std::uint64_t tx_drop_group{0};       // group frames dropped (policy, rate or fanout)
    std::uint64_t tx_replicas_local{0};   // copies of those delivered locally
    std::uint64_t tx_replicas_remote{0};  // copies of those sent to VTEPs
    std::uint64_t tx_drop_dead_vpc{0};    // source not attached or not mapped to this VTEP
    std::uint64_t tx_drop_short{0};       // shorter than an Ethernet header
    std::uint64_t tx_drop_spoofed{0};     // source MAC is not the NIC's mapped MAC
    std::uint64_t tx_drop_neighbor_spoofed{
        0};                                    // ARP/NS sender MAC, or ARP sender IP, not the NIC's
    std::uint64_t tx_drop_unknown_unicast{0};  // no NIC holds the destination MAC
    std::uint64_t tx_drop_hairpin{0};          // unicast to the sender's own MAC
    std::uint64_t tx_drop_unattached{0};       // local destination with no function attached
    std::uint64_t arp_replies{0};
    std::uint64_t nd_replies{0};
    std::uint64_t rx_frames{0};     // packets handed to receive()
    std::uint64_t rx_delivered{0};  // copies delivered to local NICs
    std::uint64_t rx_drop_unattached{0};
    std::uint64_t rx_drop_group{0};  // replicated frames this VTEP's policy does not admit
    std::array<std::uint64_t, policy_error_count> rx_drop_policy{};  // by PolicyError
    std::uint64_t deliver_failed{0};  // a port refused a frame (it counts why)
};

class VSwitch final : public FrameSink {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;

    // `now` drives the group rate limiters; tests pass a fake clock.
    VSwitch(const MappingTable& mappings, Underlay& underlay, Now now = Clock::now);

    // Connects the function serving `nic` (its NicIdentity::nic_id).
    auto attach(geneve::NicId nic, RxPort& port) -> std::expected<void, AttachError>;
    // Disconnects it; false if it was not attached.
    auto detach(geneve::NicId nic) -> bool;
    [[nodiscard]] auto attached(geneve::NicId nic) const -> bool;

    // Replaces the proxied addresses of one VNI. Validated as a whole; a bad
    // update changes nothing.
    auto set_neighbors(const NeighborUpdate& update) -> std::expected<void, NeighborError>;

    // Sets one VNI's group policy, validated as a whole; a bad policy changes
    // nothing. A drop policy restores the default. Existing rate buckets keep
    // their tokens, clamped to the new burst.
    auto set_group_policy(std::uint32_t vni, const GroupPolicy& policy)
        -> std::expected<void, GroupPolicyError>;
    [[nodiscard]] auto group_policy(std::uint32_t vni) const -> GroupPolicy;

    // The meter of an attached NIC, if it is attached.
    [[nodiscard]] auto group_meter(geneve::NicId nic) const -> std::optional<GroupMeter>;
    // Every attached NIC's meter, in NIC ID order, then the final meters of
    // NICs detached since the last call (which this call forgets).
    auto group_usage() -> std::vector<GroupUsage>;

    // A frame from a local NIC (FrameSink).
    auto transmit(const TxFrame& tx) -> void override;

    // A decoded Geneve data packet from `outer_src`. Returns the destination
    // (a local NIC or nic_broadcast), or why the ingress policy dropped it.
    auto receive(const geneve::Packet& packet, const Ipv6Address& outer_src)
        -> std::expected<geneve::NicId, PolicyError>;

    [[nodiscard]] auto counters() const noexcept -> const SwitchCounters& { return _counters; }

private:
    struct NicIdHash {
        auto operator()(geneve::NicId id) const noexcept -> std::size_t;
    };

    // A token bucket in units of 1e-9 frame (or byte): refilling by
    // rate x elapsed nanoseconds stays exact in integers.
    struct Bucket {
        std::uint64_t frames{0};
        std::uint64_t bytes{0};
        Clock::time_point last{};
        bool primed{false};  // filled to the burst on first use
    };

    struct NicGroupState {
        std::uint64_t attachment{0};
        GroupMeter meter{};
        Bucket bucket{};
    };

    struct VpcNeighbors {
        std::map<neighbor::Ipv4Address, geneve::NicId> ipv4;
        std::map<Ipv6Address, geneve::NicId> ipv6;
    };

    // True if the frame was an ARP or ND frame fully handled here (answered
    // or dropped); false to forward it normally.
    auto handle_arp(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                    std::span<const std::byte> frame, bool group) -> bool;
    auto handle_nd(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                   std::span<const std::byte> frame) -> bool;
    auto replicate(const MappingSnapshot& snap, geneve::NicId src, std::uint32_t vni,
                   std::span<const std::byte> frame) -> void;
    auto take_tokens(Bucket& bucket, const GroupPolicy& policy, std::size_t bytes) -> bool;
    auto deliver(geneve::NicId nic, std::span<const std::byte> frame) -> bool;
    auto deliver_to(RxPort& port, std::span<const std::byte> frame) -> bool;
    [[nodiscard]] auto port(geneve::NicId nic) const -> RxPort*;
    [[nodiscard]] auto neighbors(std::uint32_t vni) const -> const VpcNeighbors*;

    const MappingTable* _mappings;
    Underlay* _underlay;
    std::unordered_map<geneve::NicId, RxPort*, NicIdHash> _ports;
    std::unordered_map<std::uint32_t, VpcNeighbors> _neighbors;
    std::unordered_map<std::uint32_t, GroupPolicy> _group_policies;  // only non-drop VNIs
    std::unordered_map<geneve::NicId, NicGroupState, NicIdHash> _group;
    std::vector<GroupUsage> _retired;
    std::uint64_t _attachments{0};
    Now _now;
    SwitchCounters _counters;
};

}  // namespace ak::oar::net
