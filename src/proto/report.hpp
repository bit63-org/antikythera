// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Report: what a server's helm tells the controller about itself
// (.kiro/specs/controller-interface/ Requirement 3, design "Inventory and
// status reports").
//
// Reports travel helm -> controller over the mTLS ControllerLink. They are
// not signed: mTLS authenticates helm, and the controller treats a server
// as authoritative only for state that server reported (Requirement 3.3).
//
// Header (little-endian, 0x20 bytes):
//   0x00  magic       u32  'AKRP'
//   0x04  version     u16  report format version (2)
//   0x06  kind        u16  ReportKind
//   0x08  server_id   u64  reporting server; non-zero
//   0x10  report_seq  u64  non-zero, strictly increasing within one helm boot
//   0x18  body_len    u32  exact length of the body that follows
//   0x1C  reserved    u32  zero
//   0x20  body
//
// Bodies (every reserved byte zero, every enum a known value):
//
//   inventory  -- a full snapshot, sent first on every connection
//     0x00 boot_id u64 (non-zero, fresh per helm boot)
//     0x08 last_command_seq u64 (highest sequence hull accepted; 0 = none)
//     0x10 cores_total u16 | cores_free u16 | health u8 | vtep_count u8 | rsvd u16
//     0x18 pages_1g_total u32 | pages_1g_free u32
//     0x20 function_count u16 | vm_count u16 | volume_count u16 | network_count u16
//     0x28 vteps      vtep_count x 48:
//                       address [16] (IPv6 underlay) | tunnel_modes u8 | rsvd [7]
//                       tunnel_key [32]
//          functions  function_count x 16:
//                       slot u8 | type u8 | function u16 | state u8 | rsvd [3] | owner_vm u64
//          vms        vm_count x 16: vm_id u64 | vcpus u16 | rsvd u16 | memory_mib u32
//          volumes    volume_count x 24:
//                       volume_id u64 | owner_vm u64 | size_gib u32 | rsvd u32
//          networks   network_count x 16: vni u32 | rsvd u32 | map_version u64
//   command_outcome  -- hull's response to one command
//     in_reply_to u64 | command u16 | status u16 | payload_len u8 | rsvd [3] | payload
//   pool_state  -- a device-pool transition
//     slot u8 | type u8 | function u16 | from u8 | to u8 | rsvd u16 | owner_vm u64
//   vm_exited  -- a VM exit hull did not cause
//     vm_id u64 | exit_status u32 | reason u8 | rsvd [3]
//   map_applied  -- oar-net swapped in a mapping version
//     vni u32 | rsvd u32 | map_version u64
//   host_fault
//     code u16 | slot u8 | rsvd [5] | detail u64
//   group_usage  -- cumulative per-NIC group meters (controller-interface
//                   Requirement 7.5, design "Multicast policy and usage")
//     count u16 | rsvd [6]
//     entries  count x 96:
//       nic_id u64 | vni u32 | flags u8 (bit 0: detached) | slot u8 | rsvd u16
//       attachment u64
//       frames u64 | bytes u64
//       replicas_remote u64 | replica_bytes_remote u64   (billable)
//       replicas_local u64 | replica_bytes_local u64
//       drop_policy u64 | drop_rate u64 | drop_fanout u64
//
// Network volume reports (.kiro/specs/block-volume-service/ design
// "Reports"), from a hold role or oar-blk (the initiator) through helm.
// `slot` is the reporting role's data-plane slot.
//   replica_status  -- a snapshot of replicas a hold role keeps
//     count u16 | rsvd [6]
//     entries  count x 128, strictly increasing (slot, volume_id, replica_gen):
//       volume_id u64 | epoch u64 (applied)
//       replica_gen u32 | slot u8 | role u8 | state u8 | rsvd u8
//       last_seq u64 | commit_seq u64 (<= last_seq)
//       synced_bytes u64 | total_bytes u64 | hydrated_bytes u64 (both <= total)
//       lease_remaining_ms u32 (0 unless primary) | rsvd u32
//       checksum_errors u64 | checksum_repairs u64
//       reads u64 | writes u64 | read_bytes u64 | write_bytes u64 | throttled_us u64
//   volume_fault  -- what a role saw go wrong with a volume
//     volume_id u64 | epoch u64 | suspect u64 (server ID; 0 = none)
//     kind u8 | reporter u8 | slot u8 | rsvd [5]
//   attachment_status  -- an initiator attachment's state change
//     attachment_id u64 | volume_id u64 | generation u32 | state u8 | slot u8
//     rsvd u16 | in_flight u32 | rsvd u32
//   demotion_confirmed  -- a leaving primary drained and stopped serving
//     volume_id u64 | epoch u64 | last_seq u64 | slot u8 | rsvd [7]
//   op_outcome  -- a hold role finished (or refused) a VolumeOp
//     volume_id u64 | op_id u64 | epoch u64 | detail u64
//     kind u8 (VolumeOpKind) | status u8 | slot u8 | rsvd [5]
//     detail: the cut sequence for snapshot_prepare, else 0
//   snapshot_progress  -- an uploader's progress on one cut
//     volume_id u64 | cut_id u64 | chunks_done u64 | chunks_total u64
//     bytes_uploaded u64 | state u8 | slot u8 | rsvd [6]
//     manifest_name [32] (non-zero exactly when completed)
//
// Enrollment (block-volume-service task 12, design "Keys and crypto-erase"
// and "hold wire protocol"):
//   enrollment  -- helm's secure-element transport key, sent after the
//                  inventory on every connection
//     kem u16 (HPKE KEM ID; 0x0020, DHKEM(X25519, HKDF-SHA256)) | rsvd [6]
//     transport_key [32] (never all zero)
//   cert_request  -- a storage role asks for its storage certificate
//     slot u8 | role u8 (StorageRole) | csr_len u16 | rsvd u32
//     csr [csr_len] (a DER PKCS#10 request, 1..max_csr_size bytes)
//
// The controller seals every VolumeKey for this server to the newest
// transport key it holds. A cert_request's CSR is the role's own key pair
// (the private key never leaves the role); its outer framing is checked
// here (der.hpp) and the rest is the controller's to parse. The controller
// signs a request only with names it vouches for: exactly one URI SAN, the
// reporting server's (server_identity.hpp), plus for a hold role the IP
// SANs of that server's storage endpoints, and answers with a
// role_certificate record (link.hpp) for the same slot.
//
// group_usage entries are in strictly increasing (slot, nic_id, attachment)
// order, at most max_group_usage_entries per report. Counters are
// cumulative for one attachment: the controller bills the difference
// between successive readings of a series keyed by (server, boot_id, slot,
// nic_id, attachment). A detached entry is that series' final reading.
//
// Every inventory list is in strictly increasing key order (functions by
// (slot, function), the others by ID), so the encoding is canonical and
// carries no duplicates. A function has an owner VM exactly when it is
// assigned or releasing. map_version 0 in `networks` means the network
// exists but no mapping has been applied yet.
//
// A VTEP's tunnel_modes is the set of tunnel modes it supports
// (tunnel_peers.hpp, TunnelMode bits: wireguard, psp), from which the
// controller picks one per pair of VTEPs; tunnel_key is the X25519 public
// key of its WireGuard key pair, all zero until helm has one for it, and
// non-zero only with the wireguard bit set. The controller sends the key
// to the VTEP's peers. Format 2 added both; format 1 had 16-byte VTEP
// entries.
//
// Enum values are shared with helm (FunctionType, FunctionState) and the
// mailbox (Status, ExitReason, FaultCode); tests/proto_report_test.cpp
// pins them together, since this header must not depend on helm.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/der.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"
#include "proto/volume_op.hpp"
#include "proto/tunnel_peers.hpp"

namespace ak::proto {

inline constexpr std::uint32_t report_magic = 0x5052'4B41;  // "AKRP" as little-endian bytes
inline constexpr std::uint16_t report_version = 2;
inline constexpr std::size_t report_header_size = 0x20;

// Inventory bounds. They keep the largest report under 128 KiB; a server
// that outgrows one needs a new format version.
inline constexpr std::size_t max_vteps = 8;
inline constexpr std::size_t max_functions = 1024;
inline constexpr std::size_t max_vms = 512;
inline constexpr std::size_t max_volumes = 1024;
inline constexpr std::size_t max_networks = 4096;

inline constexpr std::size_t inventory_fixed_size = 0x28;
inline constexpr std::size_t inventory_vtep_size = vtep_address_size + 8 + tunnel_key_size;  // 56
inline constexpr std::size_t inventory_function_size = 16;
inline constexpr std::size_t inventory_vm_size = 16;
inline constexpr std::size_t inventory_volume_size = 24;
inline constexpr std::size_t inventory_network_size = 16;
inline constexpr std::size_t command_outcome_fixed_size = 16;
// The mailbox response payload limit (helm/mailbox.hpp max_response_payload).
inline constexpr std::size_t max_outcome_payload = 148;
inline constexpr std::size_t fixed_event_size = 16;

inline constexpr std::size_t max_inventory_size =
    inventory_fixed_size + (max_vteps * inventory_vtep_size) +
    (max_functions * inventory_function_size) + (max_vms * inventory_vm_size) +
    (max_volumes * inventory_volume_size) + (max_networks * inventory_network_size);
inline constexpr std::size_t group_usage_fixed_size = 8;
inline constexpr std::size_t group_usage_entry_size = 96;
inline constexpr std::size_t max_group_usage_entries = 1024;
inline constexpr std::size_t max_group_usage_size =
    group_usage_fixed_size + (max_group_usage_entries * group_usage_entry_size);
inline constexpr std::uint8_t group_usage_detached = 0x01;

inline constexpr std::size_t replica_status_fixed_size = 8;
inline constexpr std::size_t replica_status_entry_size = 128;
inline constexpr std::size_t max_replica_status_entries = 512;  // more replicas: several reports
inline constexpr std::size_t max_replica_status_size =
    replica_status_fixed_size + (max_replica_status_entries * replica_status_entry_size);
inline constexpr std::size_t volume_fault_size = 32;
inline constexpr std::size_t attachment_status_size = 32;
inline constexpr std::size_t demotion_confirmed_size = 32;
inline constexpr std::size_t op_outcome_size = 40;
inline constexpr std::size_t snapshot_progress_size = 80;
inline constexpr std::uint16_t hpke_kem_x25519 = 0x0020;
inline constexpr std::size_t transport_key_size = 32;
inline constexpr std::size_t enrollment_size = 8 + transport_key_size;
inline constexpr std::size_t cert_request_fixed_size = 8;
inline constexpr std::size_t max_csr_size = 4096;

inline constexpr std::size_t max_report_size =
    report_header_size +
    std::max({max_inventory_size, max_group_usage_size, max_replica_status_size});

// Values are part of the wire protocol: never renumber.
enum class ReportKind : std::uint16_t {
    inventory = 1,
    command_outcome = 2,
    pool_state = 3,
    vm_exited = 4,
    map_applied = 5,
    host_fault = 6,
    group_usage = 7,
    replica_status = 8,
    volume_fault = 9,
    attachment_status = 10,
    demotion_confirmed = 11,
    op_outcome = 12,
    snapshot_progress = 13,
    enrollment = 14,
    cert_request = 15,
};

// Which storage role a certificate is for.
enum class StorageRole : std::uint8_t {
    hold = 1,
    initiator = 2,  // oar-blk
};

enum class ReplicaState : std::uint8_t {
    in_sync = 1,
    joining = 2,  // being rebuilt
    stale = 3,    // missed writes; waits for resync or rebuild
};

enum class VolumeFaultKind : std::uint8_t {
    member_timeout = 1,   // a member did not acknowledge REPL_WRITE; suspect is that member
    primary_timeout = 2,  // the primary did not answer; suspect is the primary
    stale_epoch = 3,      // a peer or initiator spoke an epoch older than the reporter's
    checksum_unrepairable = 4,
    media_error = 5,
    lease_lost = 6,  // the primary's lease ran out before an acknowledgement came back
};

enum class FaultReporter : std::uint8_t {
    hold = 1,
    initiator = 2,  // oar-blk's NetworkVolumeBackend
};

enum class AttachmentState : std::uint8_t {
    attached = 1,
    eject_requested = 2,  // cooperative detach asked the guest to let go
    released = 3,         // the guest let go; hull may hot-unplug
    fenced = 4,           // the primary refused this generation
    busy = 5,             // the guest did not let go within the detach timeout
};

enum class OpStatus : std::uint8_t {
    ok = 0,
    stale_epoch = 1,
    unknown_volume = 2,
    unknown_cut = 3,
    io_error = 4,
    no_space = 5,
    timed_out = 6,
    unsupported = 7,
};

enum class SnapshotState : std::uint8_t {
    frozen = 1,
    uploading = 2,
    completed = 3,
    failed = 4,
};

enum class Health : std::uint8_t {
    ok = 0,
    degraded = 1,  // running, but a role or function is faulted
    faulted = 2,   // the host cannot take new work
};

// helm::FunctionType.
enum class FunctionType : std::uint8_t {
    nic_vf = 1,
    blk_fn = 2,
    gpu_whole = 3,
    gpu_vf = 4,
};

// helm::FunctionState.
enum class FunctionState : std::uint8_t {
    free = 0,
    assigned = 1,
    releasing = 2,
    cleaning = 3,
    faulted = 4,
};

// helm::mailbox::Status.
enum class CommandStatus : std::uint16_t {
    ok = 0,
    accepted = 1,
    bad_signature = 2,
    stale_sequence = 3,
    malformed = 4,
    unknown_vm = 5,
    unknown_device = 6,
    unknown_volume = 7,
    insufficient_resources = 8,
    conflict = 9,
    timed_out = 10,
    internal_error = 11,
    unsupported = 12,
    wrong_server = 13,
    busy = 14,  // a cooperative detach the guest has not released (helm, not hull)
};

// helm::mailbox::ExitReason.
enum class ExitReason : std::uint8_t {
    guest_shutdown = 1,
    guest_fault = 2,
    vmm_failure = 3,
};

// helm::mailbox::FaultCode.
enum class FaultCode : std::uint16_t {
    iommu_fault = 1,
    machine_check = 2,
    agent_restarted = 3,
    device_lost = 4,
    resources_exhausted = 5,
};

struct InventoryFunction {
    std::uint8_t slot{0};
    FunctionType type{FunctionType::nic_vf};
    std::uint16_t function{0};
    FunctionState state{FunctionState::free};
    std::uint64_t owner_vm{0};  // non-zero exactly when assigned or releasing
    friend auto operator==(const InventoryFunction&, const InventoryFunction&) -> bool = default;
};

struct InventoryVm {
    std::uint64_t vm_id{0};
    std::uint16_t vcpus{0};
    std::uint32_t memory_mib{0};
    friend auto operator==(const InventoryVm&, const InventoryVm&) -> bool = default;
};

struct InventoryVolume {
    std::uint64_t volume_id{0};
    std::uint64_t owner_vm{0};
    std::uint32_t size_gib{0};
    friend auto operator==(const InventoryVolume&, const InventoryVolume&) -> bool = default;
};

struct InventoryNetwork {
    std::uint32_t vni{0};
    std::uint64_t map_version{0};  // 0: created, no mapping applied yet
    friend auto operator==(const InventoryNetwork&, const InventoryNetwork&) -> bool = default;
};

// A VTEP's tunnel capabilities: the modes it supports and its WireGuard
// public key (all zero until it has one).
struct VtepTunnel {
    TunnelModes modes{0};
    TunnelPublicKey public_key{};
    friend auto operator==(const VtepTunnel&, const VtepTunnel&) -> bool = default;
};

struct Inventory {
    std::uint64_t boot_id{0};
    std::uint64_t last_command_seq{0};
    std::uint16_t cores_total{0};
    std::uint16_t cores_free{0};
    Health health{Health::ok};
    std::uint32_t pages_1g_total{0};
    std::uint32_t pages_1g_free{0};
    std::vector<VtepAddress> vteps;
    // The VTEPs' tunnel modes and keys (encoded with `vteps`): empty, or
    // one per entry of `vteps` in the same order. Decoding gives empty when
    // every entry is all zero, so the encoding stays canonical.
    std::vector<VtepTunnel> tunnels;
    std::vector<InventoryFunction> functions;
    std::vector<InventoryVm> vms;
    std::vector<InventoryVolume> volumes;
    std::vector<InventoryNetwork> networks;
    friend auto operator==(const Inventory&, const Inventory&) -> bool = default;
};

struct CommandOutcome {
    std::uint64_t in_reply_to{0};  // the command's sequence number
    std::uint16_t command{0};      // the command's mailbox type
    CommandStatus status{CommandStatus::ok};
    std::vector<std::byte> payload;  // at most max_outcome_payload bytes
    friend auto operator==(const CommandOutcome&, const CommandOutcome&) -> bool = default;
};

struct PoolStateChange {
    std::uint8_t slot{0};
    FunctionType type{FunctionType::nic_vf};
    std::uint16_t function{0};
    FunctionState from{FunctionState::free};
    FunctionState to{FunctionState::free};
    std::uint64_t owner_vm{0};  // the VM involved, if any
    friend auto operator==(const PoolStateChange&, const PoolStateChange&) -> bool = default;
};

struct VmExitedReport {
    std::uint64_t vm_id{0};
    std::uint32_t exit_status{0};
    ExitReason reason{ExitReason::guest_shutdown};
    friend auto operator==(const VmExitedReport&, const VmExitedReport&) -> bool = default;
};

struct MapApplied {
    std::uint32_t vni{0};
    std::uint64_t map_version{0};
    friend auto operator==(const MapApplied&, const MapApplied&) -> bool = default;
};

struct HostFaultReport {
    FaultCode code{FaultCode::iommu_fault};
    std::uint8_t slot{0xFF};  // 0xFF: no slot involved
    std::uint64_t detail{0};
    friend auto operator==(const HostFaultReport&, const HostFaultReport&) -> bool = default;
};

// One NIC attachment's group meter (oar-net VSwitch GroupMeter), with the
// slot of the network role that keeps it.
struct GroupUsageEntry {
    std::uint8_t slot{0};
    std::uint64_t nic_id{0};
    std::uint32_t vni{0};
    bool detached{false};
    std::uint64_t attachment{0};
    std::uint64_t frames{0};
    std::uint64_t bytes{0};
    std::uint64_t replicas_remote{0};
    std::uint64_t replica_bytes_remote{0};
    std::uint64_t replicas_local{0};
    std::uint64_t replica_bytes_local{0};
    std::uint64_t drop_policy{0};
    std::uint64_t drop_rate{0};
    std::uint64_t drop_fanout{0};
    friend auto operator==(const GroupUsageEntry&, const GroupUsageEntry&) -> bool = default;
};

struct GroupUsage {
    std::vector<GroupUsageEntry> entries;
    friend auto operator==(const GroupUsage&, const GroupUsage&) -> bool = default;
};

struct ReplicaStatusEntry {
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint32_t replica_gen{0};
    std::uint8_t slot{0};
    ReplicaRole role{ReplicaRole::secondary};
    ReplicaState state{ReplicaState::in_sync};
    std::uint64_t last_seq{0};
    std::uint64_t commit_seq{0};
    std::uint64_t synced_bytes{0};
    std::uint64_t total_bytes{0};
    std::uint64_t hydrated_bytes{0};
    std::uint32_t lease_remaining_ms{0};
    std::uint64_t checksum_errors{0};
    std::uint64_t checksum_repairs{0};
    std::uint64_t reads{0};
    std::uint64_t writes{0};
    std::uint64_t read_bytes{0};
    std::uint64_t write_bytes{0};
    std::uint64_t throttled_us{0};
    friend auto operator==(const ReplicaStatusEntry&, const ReplicaStatusEntry&) -> bool = default;
};

struct ReplicaStatus {
    std::vector<ReplicaStatusEntry> entries;
    friend auto operator==(const ReplicaStatus&, const ReplicaStatus&) -> bool = default;
};

struct VolumeFault {
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t suspect{0};  // server ID; required for the two timeouts
    VolumeFaultKind kind{VolumeFaultKind::member_timeout};
    FaultReporter reporter{FaultReporter::hold};
    std::uint8_t slot{0};
    friend auto operator==(const VolumeFault&, const VolumeFault&) -> bool = default;
};

struct AttachmentStatus {
    std::uint64_t attachment_id{0};
    std::uint64_t volume_id{0};
    std::uint32_t generation{0};
    AttachmentState state{AttachmentState::attached};
    std::uint8_t slot{0};
    std::uint32_t in_flight{0};
    friend auto operator==(const AttachmentStatus&, const AttachmentStatus&) -> bool = default;
};

struct DemotionConfirmed {
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    std::uint64_t last_seq{0};
    std::uint8_t slot{0};
    friend auto operator==(const DemotionConfirmed&, const DemotionConfirmed&) -> bool = default;
};

struct OpOutcome {
    std::uint64_t volume_id{0};
    std::uint64_t op_id{0};
    std::uint64_t epoch{0};
    std::uint64_t detail{0};
    VolumeOpKind kind{VolumeOpKind::snapshot_prepare};
    OpStatus status{OpStatus::ok};
    std::uint8_t slot{0};
    friend auto operator==(const OpOutcome&, const OpOutcome&) -> bool = default;
};

struct SnapshotProgress {
    std::uint64_t volume_id{0};
    std::uint64_t cut_id{0};
    std::uint64_t chunks_done{0};
    std::uint64_t chunks_total{0};
    std::uint64_t bytes_uploaded{0};
    SnapshotState state{SnapshotState::frozen};
    std::uint8_t slot{0};
    ManifestName manifest_name{};  // set exactly when completed
    friend auto operator==(const SnapshotProgress&, const SnapshotProgress&) -> bool = default;
};

using TransportKey = std::array<std::byte, transport_key_size>;

struct Enrollment {
    std::uint16_t kem{hpke_kem_x25519};
    TransportKey transport_key{};
    friend auto operator==(const Enrollment&, const Enrollment&) -> bool = default;
};

struct CertRequest {
    std::uint8_t slot{0};
    StorageRole role{StorageRole::hold};
    std::vector<std::byte> csr;  // DER PKCS#10
    friend auto operator==(const CertRequest&, const CertRequest&) -> bool = default;
};

using ReportBody =
    std::variant<Inventory, CommandOutcome, PoolStateChange, VmExitedReport, MapApplied,
                 HostFaultReport, GroupUsage, ReplicaStatus, VolumeFault, AttachmentStatus,
                 DemotionConfirmed, OpOutcome, SnapshotProgress, Enrollment, CertRequest>;

struct Report {
    std::uint64_t server_id{0};
    std::uint64_t report_seq{0};
    ReportBody body;
    friend auto operator==(const Report&, const Report&) -> bool = default;
};

// The variant's alternatives are in ReportKind order, starting at 1.
[[nodiscard]] inline auto report_kind(const ReportBody& body) noexcept -> ReportKind {
    return static_cast<ReportKind>(body.index() + 1);
}
static_assert(std::variant_size_v<ReportBody> ==
              static_cast<std::size_t>(ReportKind::cert_request));

namespace detail {

[[nodiscard]] constexpr auto known(Health h) noexcept -> bool {
    return h == Health::ok || h == Health::degraded || h == Health::faulted;
}
[[nodiscard]] constexpr auto known(FunctionType t) noexcept -> bool {
    return t >= FunctionType::nic_vf && t <= FunctionType::gpu_vf;
}
[[nodiscard]] constexpr auto known(FunctionState s) noexcept -> bool {
    return s <= FunctionState::faulted;
}
[[nodiscard]] constexpr auto known(CommandStatus s) noexcept -> bool {
    return s <= CommandStatus::busy;
}
[[nodiscard]] constexpr auto known(ExitReason r) noexcept -> bool {
    return r >= ExitReason::guest_shutdown && r <= ExitReason::vmm_failure;
}
[[nodiscard]] constexpr auto known(FaultCode c) noexcept -> bool {
    return c >= FaultCode::iommu_fault && c <= FaultCode::resources_exhausted;
}
[[nodiscard]] constexpr auto known(ReplicaState s) noexcept -> bool {
    return s >= ReplicaState::in_sync && s <= ReplicaState::stale;
}
[[nodiscard]] constexpr auto known(VolumeFaultKind k) noexcept -> bool {
    return k >= VolumeFaultKind::member_timeout && k <= VolumeFaultKind::lease_lost;
}
[[nodiscard]] constexpr auto known(FaultReporter r) noexcept -> bool {
    return r == FaultReporter::hold || r == FaultReporter::initiator;
}
[[nodiscard]] constexpr auto known(AttachmentState s) noexcept -> bool {
    return s >= AttachmentState::attached && s <= AttachmentState::busy;
}
[[nodiscard]] constexpr auto known(OpStatus s) noexcept -> bool {
    return s <= OpStatus::unsupported;
}
[[nodiscard]] constexpr auto known(SnapshotState s) noexcept -> bool {
    return s >= SnapshotState::frozen && s <= SnapshotState::failed;
}
[[nodiscard]] constexpr auto known(StorageRole r) noexcept -> bool {
    return r == StorageRole::hold || r == StorageRole::initiator;
}
[[nodiscard]] constexpr auto has_owner(FunctionState s) noexcept -> bool {
    return s == FunctionState::assigned || s == FunctionState::releasing;
}

[[nodiscard]] inline auto valid_vtep(const VtepAddress& a) noexcept -> bool {
    return !all_zero(a) && std::to_integer<std::uint8_t>(a[0]) != ipv6_multicast_prefix;
}

[[nodiscard]] inline auto check_inventory(const Inventory& inv) noexcept
    -> std::expected<void, DecodeError> {
    if (inv.boot_id == 0) {
        return std::unexpected(DecodeError::bad_boot_id);
    }
    if (!known(inv.health)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (inv.cores_free > inv.cores_total || inv.pages_1g_free > inv.pages_1g_total) {
        return std::unexpected(DecodeError::bad_capacity);
    }
    if (inv.vteps.size() > max_vteps || inv.functions.size() > max_functions ||
        inv.vms.size() > max_vms || inv.volumes.size() > max_volumes ||
        inv.networks.size() > max_networks) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& v : inv.vteps) {
        if (!valid_vtep(v)) {
            return std::unexpected(DecodeError::bad_vtep);
        }
    }
    if (std::ranges::adjacent_find(inv.vteps, std::ranges::greater_equal{}) != inv.vteps.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    if (!inv.tunnels.empty() && inv.tunnels.size() != inv.vteps.size()) {
        return std::unexpected(DecodeError::bad_public_key);
    }
    for (const auto& t : inv.tunnels) {
        if ((t.modes & ~known_tunnel_modes) != 0) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (!all_zero(t.public_key) && (t.modes & tunnel_mode_bit(TunnelMode::wireguard)) == 0) {
            return std::unexpected(DecodeError::bad_public_key);
        }
    }
    for (const auto& f : inv.functions) {
        if (!known(f.type) || !known(f.state)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if ((f.owner_vm != 0) != has_owner(f.state)) {
            return std::unexpected(DecodeError::bad_owner);
        }
    }
    const auto fn_key = [](const InventoryFunction& f) { return std::tuple{f.slot, f.function}; };
    if (std::ranges::adjacent_find(inv.functions, [&](const auto& a, const auto& b) {
            return fn_key(a) >= fn_key(b);
        }) != inv.functions.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& vm : inv.vms) {
        if (vm.vm_id == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
    }
    if (std::ranges::adjacent_find(inv.vms, std::ranges::greater_equal{}, &InventoryVm::vm_id) !=
        inv.vms.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& vol : inv.volumes) {
        if (vol.volume_id == 0 || vol.owner_vm == 0 || vol.size_gib == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
    }
    if (std::ranges::adjacent_find(inv.volumes, std::ranges::greater_equal{},
                                   &InventoryVolume::volume_id) != inv.volumes.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& n : inv.networks) {
        if (n.vni == 0 || n.vni > max_vni) {
            return std::unexpected(DecodeError::bad_vni);
        }
    }
    if (std::ranges::adjacent_find(inv.networks, std::ranges::greater_equal{},
                                   &InventoryNetwork::vni) != inv.networks.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const CommandOutcome& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.in_reply_to == 0 || c.command == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (!known(c.status)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (c.payload.size() > max_outcome_payload) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const PoolStateChange& p) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(p.type) || !known(p.from) || !known(p.to)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const VmExitedReport& v) noexcept
    -> std::expected<void, DecodeError> {
    if (v.vm_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (!known(v.reason)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const MapApplied& m) noexcept
    -> std::expected<void, DecodeError> {
    if (m.vni == 0 || m.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (m.map_version == 0) {
        return std::unexpected(DecodeError::bad_map_version);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const HostFaultReport& h) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(h.code)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const Inventory& inv) noexcept
    -> std::expected<void, DecodeError> {
    return check_inventory(inv);
}

[[nodiscard]] inline auto check_body(const GroupUsage& u) noexcept
    -> std::expected<void, DecodeError> {
    if (u.entries.size() > max_group_usage_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& e : u.entries) {
        if (e.nic_id == 0 || e.attachment == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (e.vni == 0 || e.vni > max_vni) {
            return std::unexpected(DecodeError::bad_vni);
        }
    }
    const auto key = [](const GroupUsageEntry& e) {
        return std::tuple{e.slot, e.nic_id, e.attachment};
    };
    if (std::ranges::adjacent_find(u.entries, [&](const auto& a, const auto& b) {
            return key(a) >= key(b);
        }) != u.entries.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const ReplicaStatus& s) noexcept
    -> std::expected<void, DecodeError> {
    if (s.entries.size() > max_replica_status_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& e : s.entries) {
        if (!known(e.role) || !known(e.state)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (e.volume_id == 0 || e.replica_gen == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (e.epoch == 0) {
            return std::unexpected(DecodeError::bad_epoch);
        }
        if (e.commit_seq > e.last_seq || e.synced_bytes > e.total_bytes ||
            e.hydrated_bytes > e.total_bytes) {
            return std::unexpected(DecodeError::bad_capacity);
        }
    }
    const auto key = [](const ReplicaStatusEntry& e) {
        return std::tuple{e.slot, e.volume_id, e.replica_gen};
    };
    if (std::ranges::adjacent_find(s.entries, [&](const auto& a, const auto& b) {
            return key(a) >= key(b);
        }) != s.entries.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const VolumeFault& f) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(f.kind) || !known(f.reporter)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (f.volume_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (f.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    if (f.suspect == 0 &&
        (f.kind == VolumeFaultKind::member_timeout || f.kind == VolumeFaultKind::primary_timeout)) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const AttachmentStatus& a) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(a.state)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (a.attachment_id == 0 || a.volume_id == 0 || a.generation == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const DemotionConfirmed& d) noexcept
    -> std::expected<void, DecodeError> {
    if (d.volume_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (d.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const OpOutcome& o) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(o.kind) || !known(o.status)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (o.volume_id == 0 || o.op_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (o.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const SnapshotProgress& p) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(p.state)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (p.volume_id == 0 || p.cut_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (p.chunks_done > p.chunks_total) {
        return std::unexpected(DecodeError::bad_capacity);
    }
    if (all_zero(p.manifest_name) == (p.state == SnapshotState::completed)) {
        return std::unexpected(DecodeError::bad_source);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const Enrollment& e) noexcept
    -> std::expected<void, DecodeError> {
    if (e.kem != hpke_kem_x25519) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (all_zero(e.transport_key)) {
        return std::unexpected(DecodeError::bad_public_key);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const CertRequest& c) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(c.role)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (c.csr.size() > max_csr_size) {
        return std::unexpected(DecodeError::bad_der);
    }
    if (auto n = der_sequences(c.csr, 1); !n) {
        return std::unexpected(n.error());
    }
    return {};
}

// A reader over a body whose length the header has already checked, so
// every field read below either succeeds or the frame is truncated.
struct BodyReader {
    wire::Reader r;
    bool ok{true};

    auto u8() -> std::uint8_t { return take(r.u8()); }
    auto le16() -> std::uint16_t { return take(r.le16()); }
    auto le32() -> std::uint32_t { return take(r.le32()); }
    auto le64() -> std::uint64_t { return take(r.le64()); }
    // Reads n bytes that must be zero.
    auto zeros(std::size_t n) -> bool {
        auto b = r.bytes(n);
        ok = ok && b.has_value();
        return b.has_value() && all_zero(*b);
    }
    auto bytes(std::span<std::byte> out) -> void {
        auto b = r.bytes(out.size());
        ok = ok && b.has_value();
        if (b) {
            std::ranges::copy(*b, out.begin());
        }
    }

private:
    template<typename T> auto take(std::expected<T, wire::WireError> v) -> T {
        ok = ok && v.has_value();
        return v.value_or(T{});
    }
};

[[nodiscard]] inline auto inventory_size(std::size_t vteps, std::size_t functions, std::size_t vms,
                                         std::size_t volumes, std::size_t networks) noexcept
    -> std::size_t {
    return inventory_fixed_size + (vteps * inventory_vtep_size) +
           (functions * inventory_function_size) + (vms * inventory_vm_size) +
           (volumes * inventory_volume_size) + (networks * inventory_network_size);
}

[[nodiscard]] inline auto decode_inventory(std::span<const std::byte> body)
    -> std::expected<Inventory, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    Inventory inv;
    inv.boot_id = in.le64();
    inv.last_command_seq = in.le64();
    inv.cores_total = in.le16();
    inv.cores_free = in.le16();
    inv.health = static_cast<Health>(in.u8());
    const std::size_t vtep_count = in.u8();
    bool zero = in.zeros(2);
    inv.pages_1g_total = in.le32();
    inv.pages_1g_free = in.le32();
    const std::size_t function_count = in.le16();
    const std::size_t vm_count = in.le16();
    const std::size_t volume_count = in.le16();
    const std::size_t network_count = in.le16();
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (vtep_count > max_vteps || function_count > max_functions || vm_count > max_vms ||
        volume_count > max_volumes || network_count > max_networks) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    // The exact length is known before anything is allocated.
    const auto want =
        inventory_size(vtep_count, function_count, vm_count, volume_count, network_count);
    if (body.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    inv.vteps.resize(vtep_count);
    inv.tunnels.resize(vtep_count);
    for (std::size_t i = 0; i < vtep_count; ++i) {
        in.bytes(inv.vteps[i]);
        inv.tunnels[i].modes = in.u8();
        zero = in.zeros(7) && zero;
        in.bytes(inv.tunnels[i].public_key);
    }
    if (std::ranges::all_of(inv.tunnels, [](const VtepTunnel& t) { return t == VtepTunnel{}; })) {
        inv.tunnels.clear();
    }
    inv.functions.resize(function_count);
    for (auto& f : inv.functions) {
        f.slot = in.u8();
        f.type = static_cast<FunctionType>(in.u8());
        f.function = in.le16();
        f.state = static_cast<FunctionState>(in.u8());
        zero = in.zeros(3) && zero;
        f.owner_vm = in.le64();
    }
    inv.vms.resize(vm_count);
    for (auto& vm : inv.vms) {
        vm.vm_id = in.le64();
        vm.vcpus = in.le16();
        zero = in.zeros(2) && zero;
        vm.memory_mib = in.le32();
    }
    inv.volumes.resize(volume_count);
    for (auto& vol : inv.volumes) {
        vol.volume_id = in.le64();
        vol.owner_vm = in.le64();
        vol.size_gib = in.le32();
        zero = in.zeros(4) && zero;
    }
    inv.networks.resize(network_count);
    for (auto& n : inv.networks) {
        n.vni = in.le32();
        zero = in.zeros(4) && zero;
        n.map_version = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_inventory(inv); !ok) {
        return std::unexpected(ok.error());
    }
    return inv;
}

inline auto write_inventory(wire::Writer& w, const Inventory& inv) -> void {
    w.le64(inv.boot_id);
    w.le64(inv.last_command_seq);
    w.le16(inv.cores_total);
    w.le16(inv.cores_free);
    w.u8(static_cast<std::uint8_t>(inv.health));
    w.u8(static_cast<std::uint8_t>(inv.vteps.size()));
    w.le16(0);
    w.le32(inv.pages_1g_total);
    w.le32(inv.pages_1g_free);
    w.le16(static_cast<std::uint16_t>(inv.functions.size()));
    w.le16(static_cast<std::uint16_t>(inv.vms.size()));
    w.le16(static_cast<std::uint16_t>(inv.volumes.size()));
    w.le16(static_cast<std::uint16_t>(inv.networks.size()));
    for (std::size_t i = 0; i < inv.vteps.size(); ++i) {
        constexpr std::array<std::byte, 7> rsvd{};
        const VtepTunnel t = inv.tunnels.empty() ? VtepTunnel{} : inv.tunnels[i];
        w.bytes(inv.vteps[i]);
        w.u8(t.modes);
        w.bytes(rsvd);
        w.bytes(t.public_key);
    }
    for (const auto& f : inv.functions) {
        w.u8(f.slot);
        w.u8(static_cast<std::uint8_t>(f.type));
        w.le16(f.function);
        w.u8(static_cast<std::uint8_t>(f.state));
        w.u8(0);
        w.le16(0);
        w.le64(f.owner_vm);
    }
    for (const auto& vm : inv.vms) {
        w.le64(vm.vm_id);
        w.le16(vm.vcpus);
        w.le16(0);
        w.le32(vm.memory_mib);
    }
    for (const auto& vol : inv.volumes) {
        w.le64(vol.volume_id);
        w.le64(vol.owner_vm);
        w.le32(vol.size_gib);
        w.le32(0);
    }
    for (const auto& n : inv.networks) {
        w.le32(n.vni);
        w.le32(0);
        w.le64(n.map_version);
    }
}

[[nodiscard]] inline auto decode_outcome(std::span<const std::byte> body)
    -> std::expected<CommandOutcome, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    CommandOutcome c;
    c.in_reply_to = in.le64();
    c.command = in.le16();
    c.status = static_cast<CommandStatus>(in.le16());
    const std::size_t payload_len = in.u8();
    const bool zero = in.zeros(3);
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (payload_len > max_outcome_payload) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    if (in.r.remaining() < payload_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (in.r.remaining() > payload_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    c.payload.resize(payload_len);
    in.bytes(c.payload);
    if (auto ok = check_body(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

// Decodes one of the fixed 16-byte event bodies.
template<typename T>
[[nodiscard]] auto decode_fixed(std::span<const std::byte> body) -> std::expected<T, DecodeError> {
    if (body.size() < fixed_event_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > fixed_event_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    T out{};
    bool zero = true;
    if constexpr (std::is_same_v<T, PoolStateChange>) {
        out.slot = in.u8();
        out.type = static_cast<FunctionType>(in.u8());
        out.function = in.le16();
        out.from = static_cast<FunctionState>(in.u8());
        out.to = static_cast<FunctionState>(in.u8());
        zero = in.zeros(2);
        out.owner_vm = in.le64();
    } else if constexpr (std::is_same_v<T, VmExitedReport>) {
        out.vm_id = in.le64();
        out.exit_status = in.le32();
        out.reason = static_cast<ExitReason>(in.u8());
        zero = in.zeros(3);
    } else if constexpr (std::is_same_v<T, MapApplied>) {
        out.vni = in.le32();
        zero = in.zeros(4);
        out.map_version = in.le64();
    } else {
        static_assert(std::is_same_v<T, HostFaultReport>);
        out.code = static_cast<FaultCode>(in.le16());
        out.slot = in.u8();
        zero = in.zeros(5);
        out.detail = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

[[nodiscard]] inline auto decode_group_usage(std::span<const std::byte> body)
    -> std::expected<GroupUsage, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    const std::size_t count = in.le16();
    bool zero = in.zeros(group_usage_fixed_size - 2);
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (count > max_group_usage_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t want = group_usage_fixed_size + (count * group_usage_entry_size);
    if (body.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    GroupUsage u;
    u.entries.resize(count);
    for (auto& e : u.entries) {
        e.nic_id = in.le64();
        e.vni = in.le32();
        const std::uint8_t flags = in.u8();
        e.slot = in.u8();
        zero = in.zeros(2) && zero;
        if ((flags & ~group_usage_detached) != 0) {
            zero = false;
        }
        e.detached = (flags & group_usage_detached) != 0;
        e.attachment = in.le64();
        e.frames = in.le64();
        e.bytes = in.le64();
        e.replicas_remote = in.le64();
        e.replica_bytes_remote = in.le64();
        e.replicas_local = in.le64();
        e.replica_bytes_local = in.le64();
        e.drop_policy = in.le64();
        e.drop_rate = in.le64();
        e.drop_fanout = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(u); !ok) {
        return std::unexpected(ok.error());
    }
    return u;
}

inline auto write_group_usage(wire::Writer& w, const GroupUsage& u) -> void {
    w.le16(static_cast<std::uint16_t>(u.entries.size()));
    w.le16(0);
    w.le32(0);
    for (const auto& e : u.entries) {
        w.le64(e.nic_id);
        w.le32(e.vni);
        w.u8(e.detached ? group_usage_detached : std::uint8_t{0});
        w.u8(e.slot);
        w.le16(0);
        w.le64(e.attachment);
        w.le64(e.frames);
        w.le64(e.bytes);
        w.le64(e.replicas_remote);
        w.le64(e.replica_bytes_remote);
        w.le64(e.replicas_local);
        w.le64(e.replica_bytes_local);
        w.le64(e.drop_policy);
        w.le64(e.drop_rate);
        w.le64(e.drop_fanout);
    }
}

[[nodiscard]] inline auto decode_replica_status(std::span<const std::byte> body)
    -> std::expected<ReplicaStatus, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    const std::size_t count = in.le16();
    bool zero = in.zeros(replica_status_fixed_size - 2);
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (count > max_replica_status_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t want = replica_status_fixed_size + (count * replica_status_entry_size);
    if (body.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    ReplicaStatus s;
    s.entries.resize(count);
    for (auto& e : s.entries) {
        e.volume_id = in.le64();
        e.epoch = in.le64();
        e.replica_gen = in.le32();
        e.slot = in.u8();
        e.role = static_cast<ReplicaRole>(in.u8());
        e.state = static_cast<ReplicaState>(in.u8());
        zero = in.zeros(1) && zero;
        e.last_seq = in.le64();
        e.commit_seq = in.le64();
        e.synced_bytes = in.le64();
        e.total_bytes = in.le64();
        e.hydrated_bytes = in.le64();
        e.lease_remaining_ms = in.le32();
        zero = in.zeros(4) && zero;
        e.checksum_errors = in.le64();
        e.checksum_repairs = in.le64();
        e.reads = in.le64();
        e.writes = in.le64();
        e.read_bytes = in.le64();
        e.write_bytes = in.le64();
        e.throttled_us = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(s); !ok) {
        return std::unexpected(ok.error());
    }
    return s;
}

inline auto write_replica_status(wire::Writer& w, const ReplicaStatus& s) -> void {
    w.le16(static_cast<std::uint16_t>(s.entries.size()));
    w.le16(0);
    w.le32(0);
    for (const auto& e : s.entries) {
        w.le64(e.volume_id);
        w.le64(e.epoch);
        w.le32(e.replica_gen);
        w.u8(e.slot);
        w.u8(static_cast<std::uint8_t>(e.role));
        w.u8(static_cast<std::uint8_t>(e.state));
        w.u8(0);
        w.le64(e.last_seq);
        w.le64(e.commit_seq);
        w.le64(e.synced_bytes);
        w.le64(e.total_bytes);
        w.le64(e.hydrated_bytes);
        w.le32(e.lease_remaining_ms);
        w.le32(0);
        w.le64(e.checksum_errors);
        w.le64(e.checksum_repairs);
        w.le64(e.reads);
        w.le64(e.writes);
        w.le64(e.read_bytes);
        w.le64(e.write_bytes);
        w.le64(e.throttled_us);
    }
}

template<typename T> inline constexpr std::size_t volume_event_size = 0;
template<> inline constexpr std::size_t volume_event_size<VolumeFault> = volume_fault_size;
template<>
inline constexpr std::size_t volume_event_size<AttachmentStatus> = attachment_status_size;
template<>
inline constexpr std::size_t volume_event_size<DemotionConfirmed> = demotion_confirmed_size;
template<> inline constexpr std::size_t volume_event_size<OpOutcome> = op_outcome_size;
template<>
inline constexpr std::size_t volume_event_size<SnapshotProgress> = snapshot_progress_size;

// Decodes one of the fixed-size network volume event bodies.
template<typename T>
[[nodiscard]] auto decode_volume_event(std::span<const std::byte> body)
    -> std::expected<T, DecodeError> {
    if (body.size() < volume_event_size<T>) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > volume_event_size<T>) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    T out{};
    bool zero = true;
    if constexpr (std::is_same_v<T, VolumeFault>) {
        out.volume_id = in.le64();
        out.epoch = in.le64();
        out.suspect = in.le64();
        out.kind = static_cast<VolumeFaultKind>(in.u8());
        out.reporter = static_cast<FaultReporter>(in.u8());
        out.slot = in.u8();
        zero = in.zeros(5);
    } else if constexpr (std::is_same_v<T, AttachmentStatus>) {
        out.attachment_id = in.le64();
        out.volume_id = in.le64();
        out.generation = in.le32();
        out.state = static_cast<AttachmentState>(in.u8());
        out.slot = in.u8();
        zero = in.zeros(2);
        out.in_flight = in.le32();
        zero = in.zeros(4) && zero;
    } else if constexpr (std::is_same_v<T, DemotionConfirmed>) {
        out.volume_id = in.le64();
        out.epoch = in.le64();
        out.last_seq = in.le64();
        out.slot = in.u8();
        zero = in.zeros(7);
    } else if constexpr (std::is_same_v<T, OpOutcome>) {
        out.volume_id = in.le64();
        out.op_id = in.le64();
        out.epoch = in.le64();
        out.detail = in.le64();
        out.kind = static_cast<VolumeOpKind>(in.u8());
        out.status = static_cast<OpStatus>(in.u8());
        out.slot = in.u8();
        zero = in.zeros(5);
    } else {
        static_assert(std::is_same_v<T, SnapshotProgress>);
        out.volume_id = in.le64();
        out.cut_id = in.le64();
        out.chunks_done = in.le64();
        out.chunks_total = in.le64();
        out.bytes_uploaded = in.le64();
        out.state = static_cast<SnapshotState>(in.u8());
        out.slot = in.u8();
        zero = in.zeros(6);
        in.bytes(out.manifest_name);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

inline auto write_volume_event(wire::Writer& w, const VolumeFault& b) -> void {
    w.le64(b.volume_id);
    w.le64(b.epoch);
    w.le64(b.suspect);
    w.u8(static_cast<std::uint8_t>(b.kind));
    w.u8(static_cast<std::uint8_t>(b.reporter));
    w.u8(b.slot);
    w.bytes(std::array<std::byte, 5>{});
}

inline auto write_volume_event(wire::Writer& w, const AttachmentStatus& b) -> void {
    w.le64(b.attachment_id);
    w.le64(b.volume_id);
    w.le32(b.generation);
    w.u8(static_cast<std::uint8_t>(b.state));
    w.u8(b.slot);
    w.le16(0);
    w.le32(b.in_flight);
    w.le32(0);
}

inline auto write_volume_event(wire::Writer& w, const DemotionConfirmed& b) -> void {
    w.le64(b.volume_id);
    w.le64(b.epoch);
    w.le64(b.last_seq);
    w.u8(b.slot);
    w.bytes(std::array<std::byte, 7>{});
}

inline auto write_volume_event(wire::Writer& w, const OpOutcome& b) -> void {
    w.le64(b.volume_id);
    w.le64(b.op_id);
    w.le64(b.epoch);
    w.le64(b.detail);
    w.u8(static_cast<std::uint8_t>(b.kind));
    w.u8(static_cast<std::uint8_t>(b.status));
    w.u8(b.slot);
    w.bytes(std::array<std::byte, 5>{});
}

inline auto write_volume_event(wire::Writer& w, const SnapshotProgress& b) -> void {
    w.le64(b.volume_id);
    w.le64(b.cut_id);
    w.le64(b.chunks_done);
    w.le64(b.chunks_total);
    w.le64(b.bytes_uploaded);
    w.u8(static_cast<std::uint8_t>(b.state));
    w.u8(b.slot);
    w.bytes(std::array<std::byte, 6>{});
    w.bytes(b.manifest_name);
}

[[nodiscard]] inline auto decode_enrollment(std::span<const std::byte> body)
    -> std::expected<Enrollment, DecodeError> {
    if (body.size() < enrollment_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > enrollment_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    Enrollment out;
    out.kem = in.le16();
    const bool zero = in.zeros(6);
    in.bytes(out.transport_key);
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

[[nodiscard]] inline auto decode_cert_request(std::span<const std::byte> body)
    -> std::expected<CertRequest, DecodeError> {
    wire::Reader r{body};
    auto slot = r.u8();
    auto role = r.u8();
    auto csr_len = r.le16();
    auto reserved = r.le32();
    if (!slot || !role || !csr_len || !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (r.remaining() < *csr_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > *csr_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    const auto csr = r.rest();
    CertRequest out{
        .slot = *slot, .role = static_cast<StorageRole>(*role), .csr = {csr.begin(), csr.end()}};
    if (auto ok = check_body(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

inline auto write_body(wire::Writer& w, const ReportBody& body) -> void {
    std::visit(
        [&w]<typename T>(const T& b) {
            if constexpr (std::is_same_v<T, Inventory>) {
                write_inventory(w, b);
            } else if constexpr (std::is_same_v<T, CommandOutcome>) {
                w.le64(b.in_reply_to);
                w.le16(b.command);
                w.le16(static_cast<std::uint16_t>(b.status));
                w.u8(static_cast<std::uint8_t>(b.payload.size()));
                w.u8(0);
                w.le16(0);
                w.bytes(b.payload);
            } else if constexpr (std::is_same_v<T, PoolStateChange>) {
                w.u8(b.slot);
                w.u8(static_cast<std::uint8_t>(b.type));
                w.le16(b.function);
                w.u8(static_cast<std::uint8_t>(b.from));
                w.u8(static_cast<std::uint8_t>(b.to));
                w.le16(0);
                w.le64(b.owner_vm);
            } else if constexpr (std::is_same_v<T, VmExitedReport>) {
                w.le64(b.vm_id);
                w.le32(b.exit_status);
                w.u8(static_cast<std::uint8_t>(b.reason));
                w.u8(0);
                w.le16(0);
            } else if constexpr (std::is_same_v<T, MapApplied>) {
                w.le32(b.vni);
                w.le32(0);
                w.le64(b.map_version);
            } else if constexpr (std::is_same_v<T, GroupUsage>) {
                write_group_usage(w, b);
            } else if constexpr (std::is_same_v<T, ReplicaStatus>) {
                write_replica_status(w, b);
            } else if constexpr (volume_event_size<T> != 0) {
                write_volume_event(w, b);
            } else if constexpr (std::is_same_v<T, Enrollment>) {
                w.le16(b.kem);
                w.bytes(std::array<std::byte, 6>{});
                w.bytes(b.transport_key);
            } else if constexpr (std::is_same_v<T, CertRequest>) {
                w.u8(b.slot);
                w.u8(static_cast<std::uint8_t>(b.role));
                w.le16(static_cast<std::uint16_t>(b.csr.size()));
                w.le32(0);
                w.bytes(b.csr);
            } else {
                static_assert(std::is_same_v<T, HostFaultReport>);
                w.le16(static_cast<std::uint16_t>(b.code));
                w.u8(b.slot);
                w.u8(0);
                w.le32(0);
                w.le64(b.detail);
            }
        },
        body);
}

}  // namespace detail

// Strict decode: exactly one report, known magic, version and kind, a
// non-zero server ID and sequence number, body_len equal to the body that
// follows, and a body that passes every rule in the header comment.
[[nodiscard]] inline auto decode_report(std::span<const std::byte> bytes)
    -> std::expected<Report, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto kind = r.le16();
    auto server_id = r.le64();
    auto report_seq = r.le64();
    auto body_len = r.le32();
    auto reserved = r.le32();
    if (!magic || !version || !kind || !server_id || !report_seq || !body_len || !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != report_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != report_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (*report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    if (r.remaining() < *body_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > *body_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    const auto body = r.rest();
    auto wrap = [&](auto decoded) -> std::expected<Report, DecodeError> {
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        return Report{
            .server_id = *server_id, .report_seq = *report_seq, .body = std::move(*decoded)};
    };
    switch (static_cast<ReportKind>(*kind)) {
        case ReportKind::inventory:
            return wrap(detail::decode_inventory(body));
        case ReportKind::command_outcome:
            return wrap(detail::decode_outcome(body));
        case ReportKind::pool_state:
            return wrap(detail::decode_fixed<PoolStateChange>(body));
        case ReportKind::vm_exited:
            return wrap(detail::decode_fixed<VmExitedReport>(body));
        case ReportKind::map_applied:
            return wrap(detail::decode_fixed<MapApplied>(body));
        case ReportKind::host_fault:
            return wrap(detail::decode_fixed<HostFaultReport>(body));
        case ReportKind::group_usage:
            return wrap(detail::decode_group_usage(body));
        case ReportKind::replica_status:
            return wrap(detail::decode_replica_status(body));
        case ReportKind::volume_fault:
            return wrap(detail::decode_volume_event<VolumeFault>(body));
        case ReportKind::attachment_status:
            return wrap(detail::decode_volume_event<AttachmentStatus>(body));
        case ReportKind::demotion_confirmed:
            return wrap(detail::decode_volume_event<DemotionConfirmed>(body));
        case ReportKind::op_outcome:
            return wrap(detail::decode_volume_event<OpOutcome>(body));
        case ReportKind::snapshot_progress:
            return wrap(detail::decode_volume_event<SnapshotProgress>(body));
        case ReportKind::enrollment:
            return wrap(detail::decode_enrollment(body));
        case ReportKind::cert_request:
            return wrap(detail::decode_cert_request(body));
    }
    return std::unexpected(DecodeError::unknown_value);
}

// Encodes a report, enforcing every rule decode_report checks.
[[nodiscard]] inline auto encode_report(const Report& report)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (report.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (report.report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    if (auto ok = std::visit([](const auto& b) { return detail::check_body(b); }, report.body);
        !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> body;
    wire::Writer bw{body};
    detail::write_body(bw, report.body);

    std::vector<std::byte> out;
    out.reserve(report_header_size + body.size());
    wire::Writer w{out};
    w.le32(report_magic);
    w.le16(report_version);
    w.le16(static_cast<std::uint16_t>(report_kind(report.body)));
    w.le64(report.server_id);
    w.le64(report.report_seq);
    w.le32(static_cast<std::uint32_t>(body.size()));
    w.le32(0);
    w.bytes(body);
    return out;
}

}  // namespace ak::proto
