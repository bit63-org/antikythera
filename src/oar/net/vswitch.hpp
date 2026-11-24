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
//   - a VPC carries only IPv4, IPv6 and ARP (Requirement 11): every other
//     EtherType, VLAN tags included, is dropped, and IP frames go through
//     the packet parser (packet.hpp) and the source/destination check. An IP
//     source must be one of the sending NIC's guest addresses (the
//     set_neighbors() table, fed from MapUpdate v2); 0.0.0.0, :: and
//     link-local sources are only for traffic consumed here, never
//     forwarded. A unicast destination must belong to the NIC owning the
//     destination MAC, and replicated frames need an IP multicast
//     destination. Guests never act as routers or address servers: router
//     advertisements, redirects and DHCP server messages are dropped. ARP
//     senders and NA targets must be the NIC's own addresses;
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
// deliver, the inner frame gets the same EtherType and IP address checks as
// on transmit, against this VTEP's own tables (Requirement 11.8, so a
// compromised sending VTEP cannot skip them), then the frame goes to the
// destination NIC, or for a replicated
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
// VNI stops being answered for at once. The addresses arrive in the same
// signed map_update frame as the mapping (proto::MapUpdate ipv4 and ipv6,
// format v2). The same table is the source check's list of each NIC's
// addresses, so the proxy and the check cannot disagree, and a VNI with no
// addresses carries no IP.
//
// VPC gateway (Requirement 12, task 17): a VNI with a VpcConfig has a
// virtual gateway at the config's MAC. oar-net answers, for the asking NIC
// only, ARP for the gateway address and 169.254.169.254, neighbor
// solicitations for the gateway's link-local address and fd00:ec2::254
// (when the VNI has an IPv6 prefix), and DHCPv4 from the mapping: the
// NIC's lowest guest IPv4 address inside the VPC prefix, the prefix's
// mask, the gateway as router and server, the DNS servers, domain, lease
// and the NIC's MTU (given at attach). Nothing about DHCP is stored: the
// mapping is the lease database. Other IP packets for the gateway MAC are
// dropped until routing exists. Without a VpcConfig, DHCP is dropped and
// counted, never flooded. With an IPv6 prefix the gateway also answers
// router solicitations and DHCPv6 (the NIC's in-prefix IPv6 addresses in
// IA_NA), and poll() sends each attached NIC an unsolicited router
// advertisement every ra_interval, so a guest's default route never
// expires (task 18).
//
// Metadata (Requirement 13, task 19): IP packets from a NIC's own address
// to 169.254.169.254 or fd00:ec2::254 at the gateway MAC go to the
// MetadataEndpoint with the NIC ID the frame arrived on, never into the
// fabric, within a per-NIC packet rate. inject_metadata() delivers the
// endpoint's replies to that NIC only, and only from the metadata address
// to one of the NIC's own addresses.
//
// Threading: a VSwitch belongs to one data-plane thread. transmit(),
// receive(), attach(), detach(), set_neighbors() and set_vpc_config() must
// all be called from it. The MappingTable is the only structure shared with
// other threads. Data-path problems are counted, never thrown (design "Error
// handling").

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/neighbor.hpp"
#include "oar/net/packet.hpp"
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

// The instance metadata service's side of the intercept (Requirement 13).
// `ip_packet` (the IP header onward) is valid only during deliver(); `nic`
// is the function the frame arrived on, the caller's only identity.
class MetadataEndpoint {
public:
    MetadataEndpoint() = default;
    MetadataEndpoint(const MetadataEndpoint&) = delete;
    auto operator=(const MetadataEndpoint&) -> MetadataEndpoint& = delete;
    MetadataEndpoint(MetadataEndpoint&&) = delete;
    auto operator=(MetadataEndpoint&&) -> MetadataEndpoint& = delete;
    virtual ~MetadataEndpoint() = default;

    virtual auto deliver(geneve::NicId nic, std::span<const std::byte> ip_packet) -> void = 0;
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

struct Ipv4Prefix {
    neighbor::Ipv4Address address{};
    std::uint8_t length{0};

    friend auto operator==(const Ipv4Prefix&, const Ipv4Prefix&) -> bool = default;
};

// A VNI's gateway and guest configuration (Requirement 12.1). Written by the
// controller, signed (proto::VpcConfigFrame), forwarded by helm and
// applied by NetRole::vpc_config.
struct VpcConfig {
    MacAddress gateway_mac{};  // locally administered unicast, from the controller's pool
    Ipv4Prefix ipv4{};         // the VPC's IPv4 prefix, length 8..30, no host bits
    neighbor::Ipv4Address ipv4_gateway{};       // inside ipv4, not its network or broadcast address
    std::optional<Ipv6Address> ipv6_prefix{};   // a /64: low 64 bits zero
    std::vector<neighbor::Ipv4Address> dns4{};  // at most max_dns_servers
    std::vector<Ipv6Address> dns6{};            // at most max_dns_servers
    std::string domain{};                       // DNS name, at most max_domain_size bytes
    std::uint32_t lease_seconds{0};             // min_lease_seconds .. max_lease_seconds

    friend auto operator==(const VpcConfig&, const VpcConfig&) -> bool = default;
};

inline constexpr std::size_t max_dns_servers = 4;
inline constexpr std::size_t max_domain_size = 253;
inline constexpr std::uint32_t min_lease_seconds = 60;
inline constexpr std::uint32_t max_lease_seconds = 0x7FFF'FFFF;
inline constexpr std::uint8_t min_ipv4_prefix = 8;
inline constexpr std::uint8_t max_ipv4_prefix = 30;

enum class VpcConfigError : std::uint8_t {
    vni_out_of_range,  // 0, or wider than 24 bits
    bad_gateway_mac,   // zero, group, or not locally administered
    bad_ipv4_prefix,   // length outside 8..30, or host bits set
    bad_ipv4_gateway,  // outside the prefix, or its network or broadcast address
    bad_ipv6_prefix,   // low 64 bits set, or multicast, link-local or unspecified
    too_many_dns,      // more than max_dns_servers in a family
    bad_dns,           // a zero, multicast or broadcast server address
    bad_domain,        // too long, or not a DNS name
    bad_lease,         // outside min_lease_seconds .. max_lease_seconds
};

[[nodiscard]] auto to_string(VpcConfigError e) noexcept -> const char*;

// The gateway's IPv6 link-local address: fe80::/64 with the modified EUI-64
// interface ID of its MAC (RFC 4291 appendix A).
[[nodiscard]] auto gateway_link_local(const MacAddress& gateway_mac) noexcept -> Ipv6Address;

// The instance metadata addresses (Requirement 13).
inline constexpr neighbor::Ipv4Address metadata_ipv4{std::byte{169}, std::byte{254}, std::byte{169},
                                                     std::byte{254}};
inline constexpr Ipv6Address metadata_ipv6{
    std::byte{0xfd}, std::byte{0x00}, std::byte{0x0e}, std::byte{0xc2}, std::byte{0}, std::byte{0},
    std::byte{0},    std::byte{0},    std::byte{0},    std::byte{0},    std::byte{0}, std::byte{0},
    std::byte{0},    std::byte{0},    std::byte{0x02}, std::byte{0x54}};  // fd00:ec2::254

inline constexpr std::chrono::seconds ra_interval{200};
inline constexpr std::uint16_t ra_router_lifetime_seconds = 1800;
inline constexpr std::uint32_t metadata_rate_pps = 1024;  // per NIC
inline constexpr std::uint32_t metadata_burst = 256;

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
    std::uint32_t rate_frames{0};       // replicated frames per second
    std::uint32_t burst_frames{0};      // bucket depth in frames
    std::uint64_t rate_bytes{0};        // replicated frame bytes per second
    std::uint64_t burst_bytes{0};       // bucket depth in bytes
    std::uint32_t max_remote_vteps{0};  // flood-list cap: larger VNIs drop the frame
};

inline constexpr std::uint32_t group_rate_frames_max = 1U << 24;
inline constexpr std::uint32_t group_burst_frames_max = 1U << 20;
inline constexpr std::uint64_t group_rate_bytes_max = std::uint64_t{1} << 37;  // ~1 Tbit/s
inline constexpr std::uint64_t group_burst_bytes_max = std::uint64_t{1} << 32;
inline constexpr std::uint32_t group_max_remote_vteps_max = 1U << 16;

enum class GroupPolicyError : std::uint8_t {
    vni_out_of_range,  // 0, or wider than 24 bits
    unknown_mode,
    missing_limit,    // a multicast policy with a zero rate, burst or flood-list cap
    limit_too_large,  // above the group_*_max bounds
    nonzero_limits,   // a drop policy that carries limits
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
        0};  // ARP/NS sender MAC, ARP sender IP or NA target not the NIC's
    std::uint64_t tx_drop_ethertype{0};        // not IPv4, IPv6 or ARP (VLAN tags included)
    std::uint64_t tx_drop_malformed{0};        // IPv4/IPv6 frame the packet parser refused
    std::uint64_t tx_drop_ip_spoofed{0};       // IP source not one of the NIC's addresses
    std::uint64_t tx_drop_local_only{0};       // 0.0.0.0, :: or link-local source nothing consumed
    std::uint64_t tx_drop_router_msg{0};       // RA, redirect or DHCP server message from a guest
    std::uint64_t tx_drop_ip_dst{0};           // IP destination not owned by the destination NIC
    std::uint64_t tx_drop_unknown_unicast{0};  // no NIC holds the destination MAC
    std::uint64_t tx_drop_hairpin{0};          // unicast to the sender's own MAC
    std::uint64_t tx_drop_unattached{0};       // local destination with no function attached
    std::uint64_t tx_drop_no_route{0};         // IP for the gateway MAC that nothing consumed
    std::uint64_t arp_replies{0};
    std::uint64_t nd_replies{0};
    std::uint64_t dhcp4_replies{0};
    std::uint64_t dhcp4_ignored{0};     // release, decline, or a request for another server
    std::uint64_t dhcp4_no_config{0};   // the VNI has no VpcConfig
    std::uint64_t dhcp4_no_address{0};  // the NIC has no IPv4 address inside the VPC prefix
    std::uint64_t dhcp4_bad{0};         // unparsable, or chaddr is not the NIC's MAC
    std::uint64_t ra_sent{0};           // solicited and periodic router advertisements
    std::uint64_t rs_dropped{0};        // no IPv6 gateway, or a hop limit other than 255
    std::uint64_t dhcp6_replies{0};
    std::uint64_t dhcp6_ignored{0};    // names another server, or misses one it needs
    std::uint64_t dhcp6_no_config{0};  // the VNI has no IPv6 gateway
    std::uint64_t dhcp6_bad{0};        // unparsable, no client ID, or an unspecified source
    std::uint64_t metadata_tx{0};      // packets handed to the metadata endpoint
    std::uint64_t metadata_rx{0};      // endpoint replies delivered
    std::uint64_t metadata_drop_rate{0};
    std::uint64_t metadata_no_endpoint{0};
    std::uint64_t metadata_inject_refused{0};  // reply not from the metadata address to the NIC
    std::uint64_t rx_frames{0};                // packets handed to receive()
    std::uint64_t rx_delivered{0};             // copies delivered to local NICs
    std::uint64_t rx_drop_unattached{0};
    std::uint64_t rx_drop_group{0};       // replicated frames this VTEP's policy does not admit
    std::uint64_t rx_drop_ethertype{0};   // inner frame not IPv4, IPv6 or ARP
    std::uint64_t rx_drop_malformed{0};   // inner IP frame the packet parser refused
    std::uint64_t rx_drop_ip_spoofed{0};  // inner IP source not the source NIC's
    std::uint64_t rx_drop_ip_dst{0};      // inner IP destination not the destination NIC's
    std::array<std::uint64_t, policy_error_count> rx_drop_policy{};  // by PolicyError
    std::uint64_t deliver_failed{0};  // a port refused a frame (it counts why)
};

class VSwitch final : public FrameSink {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;

    // `now` drives the group rate limiters; tests pass a fake clock.
    VSwitch(const MappingTable& mappings, Underlay& underlay, Now now = Clock::now);

    // Connects the function serving `nic` (its NicIdentity::nic_id). `mtu`
    // is what the function advertises (VIRTIO_NET_F_MTU), handed to DHCP;
    // 0 leaves the MTU option out.
    auto attach(geneve::NicId nic, RxPort& port, std::uint16_t mtu = 0)
        -> std::expected<void, AttachError>;
    // Disconnects it; false if it was not attached.
    auto detach(geneve::NicId nic) -> bool;
    [[nodiscard]] auto attached(geneve::NicId nic) const -> bool;

    // Replaces the proxied addresses of one VNI. Validated as a whole; a bad
    // update changes nothing.
    auto set_neighbors(const NeighborUpdate& update) -> std::expected<void, NeighborError>;

    // Sets one VNI's gateway configuration, validated as a whole; a bad
    // config changes nothing. clear_vpc_config() removes it.
    auto set_vpc_config(std::uint32_t vni, const VpcConfig& config)
        -> std::expected<void, VpcConfigError>;
    auto clear_vpc_config(std::uint32_t vni) -> void;
    [[nodiscard]] auto vpc_config(std::uint32_t vni) const -> const VpcConfig*;

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

    // Sends the periodic router advertisements that are due (Requirement
    // 12.4). Called from the data-plane loop, as often as it likes.
    auto poll() -> void;

    // The metadata endpoint, or null to drop intercepted packets.
    auto set_metadata_endpoint(MetadataEndpoint* endpoint) -> void { _metadata = endpoint; }
    // Delivers a reply from the metadata endpoint to `nic`; false if the
    // NIC is gone or the packet is not from the metadata address to one of
    // its addresses (Requirement 13.3).
    auto inject_metadata(geneve::NicId nic, std::span<const std::byte> ip_packet) -> bool;

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
                   std::span<const std::byte> frame, bool ip_ok) -> void;
    // Group replication or unicast delivery once the frame passed every
    // check; `ip` is the parsed packet for IP frames, null for ARP.
    auto forward(const MappingSnapshot& snap, geneve::NicId src, const NicBinding& binding,
                 std::span<const std::byte> frame, const packet::ParsedPacket* ip) -> void;
    // The inner-frame checks of receive(); false if the frame was dropped.
    auto inner_allowed(const geneve::Packet& packet, geneve::NicId dst) -> bool;
    auto take_tokens(Bucket& bucket, const GroupPolicy& policy, std::size_t bytes) -> bool;
    // The NIC whose guest address is the packet's source (or destination).
    [[nodiscard]] auto owner(std::uint32_t vni, const packet::ParsedPacket& p, bool source) const
        -> std::optional<geneve::NicId>;
    [[nodiscard]] auto own_na_target(const packet::ParsedPacket& p, geneve::NicId src,
                                     std::uint32_t vni) const -> bool;
    // The gateway's ARP/ND answers and the DHCPv4 server; true if the frame
    // was consumed (answered or dropped).
    auto handle_gateway_arp(geneve::NicId src, const NicBinding& binding,
                            const neighbor::ArpPacket& arp, const MacAddress& dst_mac) -> bool;
    auto handle_gateway_nd(geneve::NicId src, const NicBinding& binding,
                           std::span<const std::byte> frame, const MacAddress& dst_mac) -> bool;
    auto handle_dhcp4(geneve::NicId src, const NicBinding& binding, const packet::ParsedPacket& p)
        -> bool;
    auto handle_rs(geneve::NicId src, const NicBinding& binding, const packet::ParsedPacket& p)
        -> void;
    auto send_ra(geneve::NicId nic, const NicBinding& binding, const VpcConfig& cfg,
                 const Ipv6Address& dst) -> void;
    auto handle_dhcp6(geneve::NicId src, const NicBinding& binding, const packet::ParsedPacket& p)
        -> void;
    auto handle_metadata(geneve::NicId src, const packet::ParsedPacket& p) -> void;
    auto take_metadata_token(Bucket& bucket) -> bool;
    // The NIC's DHCP address: its lowest guest IPv4 address inside `prefix`.
    [[nodiscard]] auto dhcp4_address(std::uint32_t vni, geneve::NicId nic,
                                     const Ipv4Prefix& prefix) const
        -> std::optional<neighbor::Ipv4Address>;
    auto deliver(geneve::NicId nic, std::span<const std::byte> frame) -> bool;
    auto deliver_to(RxPort& port, std::span<const std::byte> frame) -> bool;
    [[nodiscard]] auto port(geneve::NicId nic) const -> RxPort*;
    [[nodiscard]] auto neighbors(std::uint32_t vni) const -> const VpcNeighbors*;

    const MappingTable* _mappings;
    Underlay* _underlay;
    std::unordered_map<geneve::NicId, RxPort*, NicIdHash> _ports;
    std::unordered_map<geneve::NicId, std::uint16_t, NicIdHash> _mtus;
    std::unordered_map<std::uint32_t, VpcConfig> _vpc_configs;
    std::unordered_map<geneve::NicId, Clock::time_point, NicIdHash> _last_ra;
    std::unordered_map<geneve::NicId, Bucket, NicIdHash> _metadata_buckets;
    MetadataEndpoint* _metadata{nullptr};
    std::unordered_map<std::uint32_t, VpcNeighbors> _neighbors;
    std::unordered_map<std::uint32_t, GroupPolicy> _group_policies;  // only non-drop VNIs
    std::unordered_map<geneve::NicId, NicGroupState, NicIdHash> _group;
    std::vector<GroupUsage> _retired;
    std::uint64_t _attachments{0};
    Now _now;
    SwitchCounters _counters;
};

}  // namespace ak::oar::net
