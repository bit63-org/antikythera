// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// NetRole: the network data-plane role as helm sees it over the sideband
// (.kiro/specs/oar-net-data-plane/ Requirement 8, tasks 9 and 11; helm
// design "OarLink"). It owns one VTEP's whole data path, the MappingTable,
// the VSwitch, the Vtep, and a fixed set of virtio-net functions, and helm
// drives it with OarLink requests:
//
//   function_inventory  role net, this VTEP's underlay address, every
//                       function as a nic_vf
//   prepare_function    give a function helm's NIC ID and MAC (the MTU is
//                       the role's own, from its MTU plan) and connect it
//                       to the VSwitch (Requirement 8.1)
//   clean_function      disconnect it and put back its placeholder identity:
//                       queues and state are cleared (Requirement 8.2)
//   map_update          decode the controller's frame, check that it names
//                       this server and that its signature verifies, then
//                       apply it to the MappingTable and hand its guest
//                       addresses to the VSwitch's ARP/ND proxy
//   set_tunnel_key      the role's WireGuard private key, from helm's
//                       TunnelKeyring (Requirement 5.2)
//   tunnel_peers        the controller's signed TunnelPeers frame for this
//                       VTEP, checked and installed by a TunnelPeerSet
//   set_tunnel_peer,    a peer and pre-shared key set (or removed) by helm
//   remove_tunnel_peer  directly
//   health              ok, or degraded with fault_code bits saying why: a
//                       peer VTEP is down, a peer has not proved a full-size
//                       path (mtu_ok), or the tunnel has no key yet
//   vpc_config          decode the controller's VpcConfig frame, check it
//                       like a map_update, and set the VNI's gateway and
//                       DHCP configuration in the VSwitch (Requirement 12.1,
//                       task 20)
//   group_policy        decode the controller's GroupPolicy frame, check it
//                       like a map_update, and set the VNI's policy in the
//                       VSwitch (Requirement 10.2, task 13)
//   group_usage         page through the VSwitch's per-NIC group meters
//                       (Requirement 10.6), final readings of detached NICs
//                       included
//   group_members       decode the controller's GroupMembers frame, check
//                       it like a map_update, and set the VNI's per-group
//                       VTEP lists in the VSwitch (Requirement 10.5, task 14)
//   group_membership    page through the VSwitch's snooped joins, or answer
//                       unchanged when helm already has this generation
//   instance_metadata   verify the controller's InstanceMetadata frame and
//                       keep it for its NIC (MetadataStore, Requirement 13.4,
//                       task 21); clean_function drops the NIC's record
//
// Volume keys and volumes are not the network role's: deliver_key, drop_key
// and the volume requests answer unsupported.
//
// The tunnel (Requirement 5, task 10). With NetRoleConfig::tunnel set the
// role runs a Tunnel between the Vtep and the underlay: every Geneve
// payload leaves as a WireGuard transport message, and receive() (or
// pump()) authenticates every datagram before Geneve decode. Until helm
// delivers the private key and the controller's peers arrive, nothing
// crosses the underlay; the Vtep's keepalives start the handshakes as soon
// as both are there. Without it (rigs and tests with no tunnel, planned
// with tunnel overhead 0) Geneve goes to the underlay in the clear.
//
// MTU (Requirement 6, task 11). Every peer that is up must show mtu_ok
// (one of its full-size MTU probes arrived) within mtu_grace of coming up,
// otherwise health reports net_fault_mtu: keepalives get through but
// full-size frames would not, which is a misconfigured underlay helm
// should hear about rather than a silent black hole.
//
// Functions are created once, on their transports, and live as long as the
// role, because the client (L0 QEMU in harbor) attaches at boot. Between
// attachments a function carries a placeholder identity that is never
// connected to the VSwitch, so whatever a stray driver transmits is a
// dead-VPC drop and nothing is delivered to it. Every attachment starts
// with VirtioNetFunction::reassign, which resets the function first, so
// nothing from one tenant reaches the next.
//
// The NIC's VNI comes from helm in prepare_function, but forwarding never
// uses it: the VSwitch takes the VNI from the mappings, so a NIC whose
// mapping has not arrived yet (or has been withdrawn) is in the dead VPC
// whatever helm said at attach time.
//
// map_update: helm forwards the frame unmodified and verifies nothing
// (controller-interface design, "helm"), so the role is where the
// signature is checked, by a MapVerifier holding the controller's keys.
// Re-delivery of the version already applied for a VNI (helm resends after
// a sideband reconnect) answers ok without touching the table; an older
// version, a frame for another server, a bad signature or a mapping the
// table refuses answers failed and leaves the table unchanged. The guest
// addresses in the same frame replace the VSwitch's neighbor table for the
// VNI once the mapping is applied: they feed the ARP/ND proxy and the IP
// source and destination checks, so a VNI's addresses always match its
// signed mapping.
//
// vpc_config is checked the same way and by the same verifier: the frame
// must name this server and verify under a controller key. Each VNI keeps
// the version last applied; re-delivery of that version answers ok without
// touching the VSwitch (helm resends every kept config when the sideband
// reopens), an older one answers failed. A frame the VSwitch refuses
// leaves the previous config in place: a config is never half applied.
//
// group_policy is checked the same way and by the same verifier: the frame
// must name this server and verify under a controller key. Each VNI keeps
// the version last applied; re-delivery of that version answers ok without
// touching the VSwitch (helm replays every kept policy when the sideband
// reopens), an older one answers failed. A frame that cannot be applied
// leaves the VNI's previous policy in place, so a VNI never falls open.
//
// group_members is checked the same way: this server, a controller
// signature, then the version per VNI (the version applied answers ok
// untouched, an older one fails, and lists the VSwitch refuses leave the
// previous ones in place). The GroupPolicy's max_groups_per_nic reaches
// the VSwitch with the rest of the policy.
//
// group_membership serves helm::oar::MembershipPager pages over
// VSwitch::memberships(). The generation is the low 32 bits of
// VSwitch::membership_changes(), so helm asking with the generation it
// last read gets one small "unchanged" answer until a join or leave.
//
// group_usage serves helm::oar::UsagePager pages over VSwitch::group_usage().
// Each entry carries the VNI helm named in prepare_function for that NIC:
// the meter is billed to the attachment helm made, and a detached NIC's
// mapping may already be gone. The VNI is kept until a snapshot has taken
// the NIC's final reading.
//
// Not thread-safe: the sideband, the transports and the underlay share one
// thread, as the VSwitch and Vtep require.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "helm/oar_link.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/metadata_server.hpp"
#include "oar/net/metadata_store.hpp"
#include "oar/net/metadata_tap.hpp"
#include "oar/net/mtu.hpp"
#include "oar/net/tunnel.hpp"
#include "oar/net/tunnel_peers.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/virtio_net.hpp"
#include "oar/net/vswitch.hpp"
#include "oar/net/vtep.hpp"

namespace ak::oar::net {

inline constexpr std::size_t map_signature_size = 64;
static_assert(map_signature_size == frame_signature_size);

// health's fault_code bits for a network role (HealthState::degraded when
// any is set).
inline constexpr std::uint16_t net_fault_peer_down = 0x0001;  // a peer VTEP stopped answering
inline constexpr std::uint16_t net_fault_mtu = 0x0002;  // an up peer has not shown mtu_ok in time
inline constexpr std::uint16_t net_fault_no_tunnel_key = 0x0004;  // helm has not keyed the tunnel

// Checks a MapUpdate signature: Ed25519 over `signed_bytes` under the
// controller key `key_id`. True only if it verifies.
using MapVerifier = std::function<bool(std::span<const std::byte> signed_bytes,
                                       std::span<const std::byte, map_signature_size> signature,
                                       std::uint16_t key_id)>;

// One PCI function's transport, as the role drives it.
class NetTransport {
public:
    NetTransport() = default;
    NetTransport(const NetTransport&) = delete;
    auto operator=(const NetTransport&) -> NetTransport& = delete;
    NetTransport(NetTransport&&) = delete;
    auto operator=(NetTransport&&) -> NetTransport& = delete;
    virtual ~NetTransport() = default;

    [[nodiscard]] virtual auto memory() -> const virtio::GuestMemory& = 0;
    [[nodiscard]] virtual auto interrupts() -> virtio::InterruptSink& = 0;
    // Serves `function` for the life of the role.
    [[nodiscard]] virtual auto bind(virtio::PciFunction& function)
        -> std::expected<void, std::string> = 0;
};

struct NetRoleConfig {
    using Clock = std::chrono::steady_clock;

    Ipv6Address vtep{};          // this VTEP's underlay address
    std::uint64_t server_id{0};  // map_updates must name this server; non-zero
    MtuPlan mtu{};               // from plan_mtu(); sets every guest MTU and the Vtep's limit
    std::uint16_t queue_size{256};
    std::size_t tx_budget{256};
    // Keepalive and probe timing. max_payload is taken from `mtu`.
    VtepConfig vtep_config{};
    // WireGuard between the Vtep and the underlay; empty runs without one.
    // peer_port is taken from vtep_config. Needs an MTU plan with at least
    // wireguard_overhead of tunnel overhead.
    std::optional<TunnelConfig> tunnel;
    // How long a peer may be up without mtu_ok before health says so.
    // Zero: two probe intervals (the first probe to a new peer goes out
    // before its tunnel session exists, so it is usually lost).
    std::chrono::milliseconds mtu_grace{0};
    // Empty: steady_clock::now (health's uptime).
    std::function<Clock::time_point()> clock;
    // The metadata service (Requirement 13.4, task 21.5), owned by the role
    // from create(): a TUN from open_metadata_tun() (in tests, any
    // descriptor that passes one IP packet per read and write) and a
    // listening socket from open_metadata_listener() (-1: none). Absent:
    // intercepted metadata packets are dropped and counted.
    struct Metadata {
        int tun_fd{-1};
        int listen_fd{-1};
    };
    std::optional<Metadata> metadata;
};

struct RoleCounters {
    // VpcConfig frames (task 20), counted like map_updates.
    std::uint64_t vpc_applied{0};
    std::uint64_t vpc_redelivered{0};
    std::uint64_t vpc_undecodable{0};
    std::uint64_t vpc_wrong_server{0};
    std::uint64_t vpc_bad_signature{0};
    std::uint64_t vpc_stale{0};         // older than the version applied for the VNI
    std::uint64_t vpc_rejected{0};      // the VSwitch refused it, or it carries routes
    std::uint64_t map_applied{0};       // frames that changed the table
    std::uint64_t map_redelivered{0};   // the version already applied: ok, unchanged
    std::uint64_t map_undecodable{0};   // proto::decode_map_update refused it
    std::uint64_t map_wrong_server{0};  // for another server
    std::uint64_t map_bad_signature{0};
    std::uint64_t map_rejected{0};  // MappingTable refused it (stale version, bad entries)
    std::uint64_t map_neighbors_rejected{0};  // the VSwitch refused its proxy addresses
    std::uint64_t tunnel_keys_refused{0};     // set_tunnel_key / set_tunnel_peer the Tunnel refused
    // GroupPolicy frames (task 13), counted like map_updates.
    std::uint64_t group_applied{0};
    std::uint64_t group_redelivered{0};
    std::uint64_t group_undecodable{0};
    std::uint64_t group_wrong_server{0};
    std::uint64_t group_bad_signature{0};
    std::uint64_t group_stale{0};        // older than the version applied for the VNI
    std::uint64_t group_rejected{0};     // the VSwitch refused the policy
    std::uint64_t usage_unknown_vni{0};  // a meter whose NIC helm never prepared here: skipped
    // GroupMembers frames (task 14), counted like map_updates.
    std::uint64_t members_applied{0};
    std::uint64_t members_redelivered{0};
    std::uint64_t members_undecodable{0};
    std::uint64_t members_wrong_server{0};
    std::uint64_t members_bad_signature{0};
    std::uint64_t members_stale{0};
    std::uint64_t members_rejected{0};  // the VSwitch refused the lists
};

// The identity a function carries between attachments: never in any
// mapping, never connected to the VSwitch.
[[nodiscard]] auto placeholder_identity(helm::oar::FunctionNumber fn, std::uint16_t mtu)
    -> NicIdentity;

class NetRole final : public helm::OarHandler {
public:
    // One function per transport, numbered from 0 in order. `sender` is the
    // underlay (a UdpEndpoint in ak-oar-net); `observer` may be null. Every
    // transport, `sender` and `observer` must outlive the role. `verifier`
    // checks the controller's map_update and tunnel_peers signatures.
    [[nodiscard]] static auto create(NetRoleConfig config,
                                     const std::vector<NetTransport*>& transports,
                                     MapVerifier verifier, DatagramSender& sender,
                                     PeerObserver* observer)
        -> std::expected<std::unique_ptr<NetRole>, std::string>;

    NetRole(const NetRole&) = delete;
    auto operator=(const NetRole&) -> NetRole& = delete;
    NetRole(NetRole&&) = delete;
    auto operator=(NetRole&&) -> NetRole& = delete;
    ~NetRole() override;

    // helm::OarHandler
    auto function_inventory() -> std::expected<helm::oar::Inventory, helm::oar::Status> override;
    auto prepare_function(const helm::oar::PrepareFunction& request) -> helm::oar::Status override;
    auto clean_function(const helm::oar::CleanFunction& request) -> helm::oar::Status override;
    auto deliver_key(const helm::oar::DeliverKey& request) -> helm::oar::Status override;
    auto drop_key(const helm::oar::DropKey& request) -> helm::oar::Status override;
    auto map_update(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto vpc_config(std::span<const std::byte> frame) -> helm::oar::Status override;

    auto health() -> std::expected<helm::oar::Health, helm::oar::Status> override;
    auto set_tunnel_key(const helm::oar::SetTunnelKey& request) -> helm::oar::Status override;
    auto set_tunnel_peer(const helm::oar::SetTunnelPeer& request) -> helm::oar::Status override;
    auto remove_tunnel_peer(const helm::oar::RemoveTunnelPeer& request)
        -> helm::oar::Status override;
    auto tunnel_peers(std::span<const std::byte> frame) -> helm::oar::Status override;

    // One datagram from the underlay, from `outer_src` at `now`: through
    // the tunnel if there is one, then the Vtep and the VSwitch. True if a
    // data packet reached the VSwitch.
    auto receive(std::span<const std::byte> datagram, const Ipv6Address& outer_src,
                 VtepClock::time_point now) -> bool;
    // Reads up to `budget` datagrams from `endpoint` into the role, as
    // receive() does for each; returns how many were read.
    auto pump(UdpEndpoint& endpoint, std::span<std::byte> buffer, std::size_t budget,
              VtepClock::time_point now) -> std::size_t;
    auto group_policy(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto group_usage(std::uint16_t cursor)
        -> std::expected<helm::oar::UsagePage, helm::oar::Status> override;
    auto group_members(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto instance_metadata(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto group_membership(const helm::oar::MembershipRequest& request)
        -> std::expected<helm::oar::MembershipPage, helm::oar::Status> override;

    // Serves deferred transmit work on every function; true if any still
    // has work (call again soon).
    auto poll() -> bool;
    // Runs the Vtep's timers (keepalives, MTU probes, peer liveness) and
    // the tunnel's (handshake retries, session expiry); returns when it
    // next needs to run.
    auto tick(VtepClock::time_point now) -> VtepClock::time_point;

    [[nodiscard]] auto function_count() const noexcept -> std::size_t { return _slots.size(); }
    // The NIC ID function `fn` serves, if it is attached.
    [[nodiscard]] auto attached(helm::oar::FunctionNumber fn) const -> std::optional<geneve::NicId>;
    [[nodiscard]] auto function(helm::oar::FunctionNumber fn) -> VirtioNetFunction*;
    [[nodiscard]] auto mappings() -> MappingTable& { return _mappings; }
    [[nodiscard]] auto vswitch() -> VSwitch& { return *_vswitch; }
    [[nodiscard]] auto vtep() -> Vtep& { return *_vtep; }
    // Null without a tunnel.
    [[nodiscard]] auto tunnel() -> Tunnel* { return _tunnel.get(); }
    [[nodiscard]] auto peer_set() -> TunnelPeerSet* { return _peer_set.get(); }
    [[nodiscard]] auto counters() const noexcept -> const RoleCounters& { return _counters; }
    // The NICs' instance metadata records (one per function at most).
    [[nodiscard]] auto metadata() const noexcept -> const MetadataStore& { return *_metadata; }
    // The metadata service's parts; null without NetRoleConfig::metadata.
    [[nodiscard]] auto metadata_server() noexcept -> MetadataServer* { return _md_server.get(); }
    [[nodiscard]] auto metadata_tap() noexcept -> MetadataTap* { return _md_tap.get(); }
    [[nodiscard]] auto metadata_aliases() noexcept -> AliasTable* { return _aliases.get(); }
    // What the metadata service answers a NIC from (Requirement 13.4).
    [[nodiscard]] auto metadata_view(std::uint64_t nic_id) const -> MetadataView;
    // Appends the metadata service's descriptors, so the caller's poll
    // wakes for them; poll() then serves them.
    auto metadata_poll_fds(std::vector<pollfd>& out) const -> void;

private:
    struct Slot {
        std::unique_ptr<VirtioNetFunction> function;
        std::optional<geneve::NicId> nic;
    };

    NetRole(NetRoleConfig config, MapVerifier verifier);

    [[nodiscard]] auto slot(helm::oar::FunctionNumber fn) -> Slot*;
    // Disconnects the slot's NIC and puts its placeholder back.
    auto release(helm::oar::FunctionNumber fn, Slot& s) -> bool;
    auto start_metadata() -> std::expected<void, std::string>;
    // Notes which up peers still lack mtu_ok, and since when.
    auto track_mtu(VtepClock::time_point now) -> void;
    // The VSwitch's meters as group_usage entries (UsagePager's snapshot).
    auto usage_snapshot() -> helm::oar::UsagePager::Snapshot;

    NetRoleConfig _config;
    MapVerifier _verifier;
    MappingTable _mappings;
    std::unique_ptr<Tunnel> _tunnel;
    std::unique_ptr<TunnelPeerSet> _peer_set;
    std::unique_ptr<Vtep> _vtep;
    std::unique_ptr<VSwitch> _vswitch;
    std::map<std::uint32_t, std::uint64_t> _vpc_versions;  // applied config version, by VNI
    std::vector<Slot> _slots;
    NetRoleConfig::Clock::time_point _started;
    // Up peers without mtu_ok, with when tick() first saw them so, and the
    // last tick's time.
    std::map<Ipv6Address, VtepClock::time_point> _mtu_unproven;
    VtepClock::time_point _last_tick{};
    std::map<std::uint32_t, std::uint64_t> _group_versions;  // applied policy version, by VNI
    std::map<std::uint64_t, std::uint32_t> _nic_vnis;        // helm's VNI, by NIC ID
    helm::oar::UsagePager _usage;
    std::map<std::uint32_t, std::uint64_t> _members_versions;  // applied members version, by VNI
    helm::oar::MembershipPager _membership;
    std::unique_ptr<MetadataStore> _metadata;
    std::unique_ptr<AliasTable> _aliases;
    std::unique_ptr<MetadataServer> _md_server;
    std::unique_ptr<MetadataTap> _md_tap;
    RoleCounters _counters;
};

}  // namespace ak::oar::net
