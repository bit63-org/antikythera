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
//   health              ok, or degraded while any peer VTEP is down
//
// Keys and volumes are not the network role's: deliver_key, drop_key and
// the volume requests answer unsupported.
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
// Not thread-safe: the sideband, the transports and the underlay share one
// thread, as the VSwitch and Vtep require.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "helm/oar_link.hpp"
#include "oar/net/mapping_table.hpp"
#include "oar/net/mtu.hpp"
#include "oar/net/virtio_net.hpp"
#include "oar/net/vswitch.hpp"
#include "oar/net/vtep.hpp"

namespace ak::oar::net {

inline constexpr std::size_t map_signature_size = 64;

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
    // Empty: steady_clock::now (health's uptime).
    std::function<Clock::time_point()> clock;
};

struct RoleCounters {
    std::uint64_t map_applied{0};       // frames that changed the table
    std::uint64_t map_redelivered{0};   // the version already applied: ok, unchanged
    std::uint64_t map_undecodable{0};   // proto::decode_map_update refused it
    std::uint64_t map_wrong_server{0};  // for another server
    std::uint64_t map_bad_signature{0};
    std::uint64_t map_rejected{0};  // MappingTable refused it (stale version, bad entries)
    std::uint64_t map_neighbors_rejected{0};  // the VSwitch refused its proxy addresses
};

// The identity a function carries between attachments: never in any
// mapping, never connected to the VSwitch.
[[nodiscard]] auto placeholder_identity(helm::oar::FunctionNumber fn, std::uint16_t mtu)
    -> NicIdentity;

class NetRole final : public helm::OarHandler {
public:
    // One function per transport, numbered from 0 in order. `sender` is the
    // underlay (a UdpEndpoint in ak-oar-net); `observer` may be null. Every
    // transport, `sender` and `observer` must outlive the role.
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
    auto health() -> std::expected<helm::oar::Health, helm::oar::Status> override;

    // Serves deferred transmit work on every function; true if any still
    // has work (call again soon).
    auto poll() -> bool;
    // Runs the Vtep's timers (keepalives, MTU probes, peer liveness);
    // returns when it next needs to run.
    auto tick(VtepClock::time_point now) -> VtepClock::time_point;

    [[nodiscard]] auto function_count() const noexcept -> std::size_t { return _slots.size(); }
    // The NIC ID function `fn` serves, if it is attached.
    [[nodiscard]] auto attached(helm::oar::FunctionNumber fn) const -> std::optional<geneve::NicId>;
    [[nodiscard]] auto function(helm::oar::FunctionNumber fn) -> VirtioNetFunction*;
    [[nodiscard]] auto mappings() -> MappingTable& { return _mappings; }
    [[nodiscard]] auto vswitch() -> VSwitch& { return *_vswitch; }
    [[nodiscard]] auto vtep() -> Vtep& { return *_vtep; }
    [[nodiscard]] auto counters() const noexcept -> const RoleCounters& { return _counters; }

private:
    struct Slot {
        std::unique_ptr<VirtioNetFunction> function;
        std::optional<geneve::NicId> nic;
    };

    NetRole(NetRoleConfig config, MapVerifier verifier);

    [[nodiscard]] auto slot(helm::oar::FunctionNumber fn) -> Slot*;
    // Disconnects the slot's NIC and puts its placeholder back.
    auto release(helm::oar::FunctionNumber fn, Slot& s) -> bool;

    NetRoleConfig _config;
    MapVerifier _verifier;
    MappingTable _mappings;
    std::unique_ptr<Vtep> _vtep;
    std::unique_ptr<VSwitch> _vswitch;
    std::vector<Slot> _slots;
    NetRoleConfig::Clock::time_point _started;
    RoleCounters _counters;
};

}  // namespace ak::oar::net
