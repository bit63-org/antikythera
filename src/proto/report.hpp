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
//   group_membership  -- one network role's snooped multicast joins, whole
//                        (controller-interface Requirement 7.9, oar-net
//                        Requirement 10.5)
//     slot u8 | rsvd u8 | count u16 | rsvd u32
//     entries  count x 32, strictly increasing (nic_id, family, group):
//       nic_id u64 | vni u32 | family u8 (4 or 6) | rsvd [3]
//       group [16] (IPv4 in the first 4 bytes, the rest zero)
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
// khold reports (kythira .kiro/specs/khold-block-service/ design "Running
// on antikythera", Requirements 4.6, 7.3, 9 and 12), from a khold role
// through helm. `slot` is the reporting role's data-plane slot.
//   group_status  -- a snapshot of the stripe group members a khold role keeps
//     slot u8 | rsvd u8 | count u16 | rsvd u32
//     entries  count x 64, strictly increasing (volume_id, group_id):
//       volume_id u64 | group_id u64 | epoch u64 (applied layout epoch)
//       term u64 | commit_index u64 | applied_index u64 (<= commit_index)
//       kind u8 (MemberKind) | state u8 (GroupMemberState) | lagging u8
//       (members the group has recorded as lagging) | drive u8 | rsvd u32
//       allocated_bytes u64 (0 for a witness)
//   capacity  -- the role's drives and link, whole (Requirements 4.6, 12.1)
//     slot u8 | rsvd u8 | count u16 | link_mbps u32
//     entries  count x 56, strictly increasing drive:
//       drive u8 | state u8 (DriveState) | rsvd [6]
//       capacity_bytes u64 | allocated_bytes u64 (<= capacity) | reserved_bytes u64
//       read_iops u32 | write_iops u32 | read_mib_per_s u32 | write_mib_per_s u32
//       replicas u32 | rsvd u32
//   group_fault  -- what a khold member saw go wrong in one stripe group
//     volume_id u64 | group_id u64 | epoch u64 | term u64
//     suspect u64 (server ID; required except for no_space)
//     kind u8 (GroupFaultKind) | slot u8 | drive u8 | rsvd [5]
//
// Local <-> network conversion (block-volume-service Requirement 8.6,
// task 23.2), from helm, which runs the copy on a storage role (`slot`):
//   conversion_progress  -- one CONVERT_VOLUME's copy, while it runs and
//                           once when it ends
//     local_volume_id u64 | network_volume_id u64
//     total_bytes u64 | done_bytes u64 | written_bytes u64 (both <= total)
//     direction u8 (ConversionDirection) | state u8 (ConversionState)
//     failure u8 (ConversionFailure; non-zero exactly when failed) | slot u8
//     rsvd u32
//
// AZ cold start (.kiro/specs/cold-start/ Requirement 8), from helm:
//   cold_start  -- kind 27, once, on the first link after helm's own power
//                  returned
//     power_return_time u64 (helm's RTC, Unix seconds) | time_floor u64
//     waited_ms u32 (the power-on hold helm applied)
//     boot_source u8 (BootSource) | flags u8 (bit 0: store rollback
//     detected; bit 1: RTC read below the time floor) | count u16
//     store_faults u32 (sealed-store objects discarded) | rsvd u32
//     entries  count x 16, strictly increasing vm_id, at most
//              max_standing_instances:
//       vm_id u64 | result u8 (StandingResult) | rsvd u8 | attempts u16 | rsvd u32
//   boot_cache  -- kind 28, after every inventory
//     lkg_image [32] | previous_image [32] (SHA-256 of the hull UKIs; all
//     zero = none, and no previous without an LKG)
//     standing_generation u64 | policy_version u64 (0 = none stored)
//     store_free_bytes u64 | store_total_bytes u64 (free <= total)
//   Kinds 21-24 and 29-31 belong to other specs still being built, so the
//   known kinds are not one contiguous range: report_kind() maps each body
//   to its kind.
//
// Server provisioning (.kiro/specs/server-provisioning/ Requirements 5 and
// 6), from helm. Text fields are printable ASCII (0x20-0x7E) padded with
// zero bytes, with no zero byte before a printable one.
//   hardware_identity  -- kind 25, at registration and whenever any of it
//                         changes
//     ek_hash [32] (SHA-256 of the secure element's endorsement key; never
//     all zero) | board_serial [32] (text, non-empty)
//     firmware [32] (helm's firmware version, text)
//     memory_bytes u64 | cpu_count u32 (both 0 while helm cannot read them)
//     flags u8 (bit 0: Secure Boot on; bit 1: IOMMU on; bit 2: hull
//     reported bits 0-1, which are zero without it) | slot_count u8
//     drive_count u16
//     slots   slot_count x 72, strictly increasing slot, at most
//             max_identity_slots:
//       slot u8 | kind u8 (SlotKind) | rsvd [6] | serial [32] (text,
//       non-empty) | firmware [32] (text)
//     drives  drive_count x 48, strictly increasing (slot, serial), at most
//             max_identity_drives, each in a listed storage slot:
//       slot u8 | rsvd [7] | size_bytes u64 (non-zero) | serial [32] (text,
//       non-empty)
//   decommission_progress  -- kind 26, after each step of a decommission
//     step u8 (DecommissionStep) | result u8 (SanitizeResult; non-zero
//     exactly when step is media) | slot u8 (media only, else 0) | rsvd [5]
//     drive_serial [32] (text; non-empty exactly when step is media)
//   One media report is sent per drive, failures included, so the
//   controller can list by serial every drive that must be destroyed.
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
// A group_membership report replaces everything the controller holds for
// that (server, slot): helm sends one whenever a role's joins change, and
// an empty one when a role goes away, so a lost or reordered report is
// healed by the next. Groups follow GroupMembers' rules (group_members.hpp).
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
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/der.hpp"
#include "proto/group_members.hpp"
#include "proto/map_update.hpp"
#include "proto/replica_config.hpp"
#include "proto/standing_set.hpp"
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
inline constexpr std::size_t group_membership_fixed_size = 8;
inline constexpr std::size_t group_membership_entry_size = 32;
inline constexpr std::size_t max_group_membership_entries = 1024;  // per network role
inline constexpr std::size_t max_group_membership_size =
    group_membership_fixed_size + (max_group_membership_entries * group_membership_entry_size);
inline constexpr std::size_t max_csr_size = 4096;
inline constexpr std::size_t group_status_fixed_size = 8;
inline constexpr std::size_t group_status_entry_size = 64;
inline constexpr std::size_t max_group_status_entries = 1024;  // more members: several reports
inline constexpr std::size_t max_group_status_size =
    group_status_fixed_size + (max_group_status_entries * group_status_entry_size);
inline constexpr std::size_t capacity_fixed_size = 8;
inline constexpr std::size_t capacity_entry_size = 56;
inline constexpr std::size_t max_capacity_drives = 64;
inline constexpr std::size_t group_fault_size = 48;
inline constexpr std::size_t conversion_progress_size = 48;
inline constexpr std::size_t cold_start_fixed_size = 0x20;
inline constexpr std::size_t cold_start_entry_size = 16;
inline constexpr std::size_t boot_cache_size = (2 * image_digest_size) + 32;
inline constexpr std::uint8_t cold_start_rollback = 0x01;
inline constexpr std::uint8_t cold_start_rtc_below_floor = 0x02;
inline constexpr std::uint8_t known_cold_start_flags =
    cold_start_rollback | cold_start_rtc_below_floor;
inline constexpr std::size_t identity_text_size = 32;
inline constexpr std::size_t hardware_identity_fixed_size = (3 * identity_text_size) + 16;
inline constexpr std::size_t identity_slot_size = 8 + (2 * identity_text_size);
inline constexpr std::size_t identity_drive_size = 16 + identity_text_size;
inline constexpr std::size_t max_identity_slots = 16;
inline constexpr std::size_t max_identity_drives = 64;
inline constexpr std::size_t max_hardware_identity_size =
    hardware_identity_fixed_size + (max_identity_slots * identity_slot_size) +
    (max_identity_drives * identity_drive_size);
inline constexpr std::size_t decommission_progress_size = 8 + identity_text_size;
inline constexpr std::uint8_t identity_secure_boot = 0x01;
inline constexpr std::uint8_t identity_iommu = 0x02;
inline constexpr std::uint8_t identity_host_reported = 0x04;
inline constexpr std::uint8_t known_identity_flags =
    identity_secure_boot | identity_iommu | identity_host_reported;

inline constexpr std::size_t max_report_size =
    report_header_size +
    std::max({max_inventory_size, max_group_usage_size, max_replica_status_size,
              max_group_status_size, max_hardware_identity_size});

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
    group_membership = 16,
    group_status = 17,
    capacity = 18,
    group_fault = 19,
    conversion_progress = 20,
    hardware_identity = 25,
    decommission_progress = 26,
    cold_start = 27,
    boot_cache = 28,
};

// What a data-plane slot holds (hardware_identity).
enum class SlotKind : std::uint8_t {
    network = 1,  // oar-net
    storage = 2,  // a storage role with drives (hold, khold, instance store)
    blk = 3,      // oar-blk with no drives of its own
    gpu = 4,      // oar-gpu
    control = 5,  // the control slot (helm's own board)
};

// One step of a decommission (decommission_progress), in the order helm
// runs them.
enum class DecommissionStep : std::uint8_t {
    keys_destroyed = 1,    // every VM key and the master key are gone
    media = 2,             // one drive's sanitize finished or failed
    identity_cleared = 3,  // attestation and TLS keys and the server ID next
};

// How one drive's sanitize ended (decommission_progress, step media).
enum class SanitizeResult : std::uint8_t {
    sanitized_crypto = 1,  // NVMe Sanitize with crypto erase
    sanitized_block = 2,   // block erase (crypto erase not supported)
    failed = 3,            // neither worked: destroy the drive
};

// Where helm booted hull from after power returned (cold_start).
enum class BootSource : std::uint8_t {
    lkg = 1,       // the last-known-good image in the sealed store
    previous = 2,  // the image before it, after the LKG failed to start
    netboot = 3,   // an assigned image fetched from the metal boot layer
};

// The latest outcome of one standing start (cold_start).
enum class StandingResult : std::uint8_t {
    started = 1,         // hull started the instance
    image_missing = 2,   // its root volume or image could not be read
    volume_refused = 3,  // a storage role refused a standing attachment
    device_missing = 4,  // a NIC or device function was not available
    refused = 5,         // hull refused the standing start
    failed = 6,          // any other failure
};

// Which way a conversion copies (mailbox CONVERT_VOLUME's direction).
enum class ConversionDirection : std::uint8_t {
    to_network = 1,
    to_local = 2,
};

enum class ConversionState : std::uint8_t {
    copying = 1,
    completed = 2,  // every block copied and the target flushed
    failed = 3,
};

enum class ConversionFailure : std::uint8_t {
    none = 0,
    source_io = 1,
    target_io = 2,
    not_hydrated = 3,  // the network source still awaits hydration
    out_of_range = 4,
    crypto = 5,
    start = 6,  // the copy could not start (keys, the storage role)
    lost = 7,   // the storage role no longer knew the copy
};

// Which storage role a certificate is for.
enum class StorageRole : std::uint8_t {
    hold = 1,
    initiator = 2,  // oar-blk
    khold = 3,      // a khold node (kythira khold-block-service)
};

// A khold member's state in its stripe group (group_status).
enum class GroupMemberState : std::uint8_t {
    leader = 1,
    follower = 2,      // in sync
    lagging = 3,       // recorded lagging by a committed entry; catching up
    learner = 4,       // being rebuilt
    store_failed = 5,  // its block store failed; refusing requests
    unavailable = 6,   // the group cannot commit (no up-to-date data replica)
};

// A khold drive's state (capacity).
enum class DriveState : std::uint8_t {
    ok = 1,
    warning = 2,  // physical use above the warning watermark
    full = 3,     // above the refusal watermark: place nothing new here
    failed = 4,
};

enum class GroupFaultKind : std::uint8_t {
    lagging = 1,      // the leader recorded `suspect` lagging (missed the member deadline)
    caught_up = 2,    // the leader recorded `suspect` in sync again
    media_error = 3,  // `suspect`'s block store failed (EIO on a write, metadata, fsync or log)
    fail_slow = 4,    // `suspect` stayed slow against its peers for the slow window
    no_space = 5,     // a write needed space an overcommitted drive lacks
    checksum_unrepairable = 6,
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
    lease_lost = 6,         // the primary's lease ran out before an acknowledgement came back
    checksum_mismatch = 7,  // initiator: a block read back failed its CRC32C (retried once)
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

// One NIC's join of one group, as a network role snooped it.
struct GroupMembershipEntry {
    std::uint64_t nic_id{0};
    std::uint32_t vni{0};
    RouteFamily family{RouteFamily::ipv4};
    Ipv6Address group{};  // IPv4 in the first four bytes, the rest zero
    friend auto operator==(const GroupMembershipEntry&, const GroupMembershipEntry&)
        -> bool = default;
};

struct GroupMembership {
    std::uint8_t slot{0};
    std::vector<GroupMembershipEntry> entries;  // strictly ascending (nic_id, family, group)
    friend auto operator==(const GroupMembership&, const GroupMembership&) -> bool = default;
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

struct ConversionProgress {
    std::uint64_t local_volume_id{0};
    std::uint64_t network_volume_id{0};
    std::uint64_t total_bytes{0};
    std::uint64_t done_bytes{0};
    std::uint64_t written_bytes{0};
    ConversionDirection direction{ConversionDirection::to_network};
    ConversionState state{ConversionState::copying};
    ConversionFailure failure{ConversionFailure::none};
    std::uint8_t slot{0};
    friend auto operator==(const ConversionProgress&, const ConversionProgress&) -> bool = default;
};

struct GroupStatusEntry {
    std::uint64_t volume_id{0};
    std::uint64_t group_id{0};
    std::uint64_t epoch{0};
    std::uint64_t term{0};
    std::uint64_t commit_index{0};
    std::uint64_t applied_index{0};
    std::uint8_t kind{1};  // volume_layout.hpp MemberKind
    GroupMemberState state{GroupMemberState::follower};
    std::uint8_t lagging{0};
    std::uint8_t drive{0};
    std::uint64_t allocated_bytes{0};
    friend auto operator==(const GroupStatusEntry&, const GroupStatusEntry&) -> bool = default;
};

struct GroupStatus {
    std::uint8_t slot{0};
    std::vector<GroupStatusEntry> entries;
    friend auto operator==(const GroupStatus&, const GroupStatus&) -> bool = default;
};

struct DriveCapacity {
    std::uint8_t drive{0};
    DriveState state{DriveState::ok};
    std::uint64_t capacity_bytes{0};
    std::uint64_t allocated_bytes{0};
    std::uint64_t reserved_bytes{0};
    std::uint32_t read_iops{0};
    std::uint32_t write_iops{0};
    std::uint32_t read_mib_per_s{0};
    std::uint32_t write_mib_per_s{0};
    std::uint32_t replicas{0};
    friend auto operator==(const DriveCapacity&, const DriveCapacity&) -> bool = default;
};

struct Capacity {
    std::uint8_t slot{0};
    std::uint32_t link_mbps{0};
    std::vector<DriveCapacity> drives;  // strictly increasing drive
    friend auto operator==(const Capacity&, const Capacity&) -> bool = default;
};

struct GroupFault {
    std::uint64_t volume_id{0};
    std::uint64_t group_id{0};
    std::uint64_t epoch{0};
    std::uint64_t term{0};
    std::uint64_t suspect{0};
    GroupFaultKind kind{GroupFaultKind::lagging};
    std::uint8_t slot{0};
    std::uint8_t drive{0};
    friend auto operator==(const GroupFault&, const GroupFault&) -> bool = default;
};

using TransportKey = std::array<std::byte, transport_key_size>;

struct Enrollment {
    std::uint16_t kem{hpke_kem_x25519};
    TransportKey transport_key{};
    friend auto operator==(const Enrollment&, const Enrollment&) -> bool = default;
};

struct StandingStartResult {
    std::uint64_t vm_id{0};
    StandingResult result{StandingResult::started};
    std::uint16_t attempts{0};
    friend auto operator==(const StandingStartResult&, const StandingStartResult&)
        -> bool = default;
};

struct ColdStart {
    std::uint64_t power_return_time{0};
    std::uint64_t time_floor{0};
    std::uint32_t waited_ms{0};
    BootSource boot_source{BootSource::lkg};
    std::uint8_t flags{0};  // cold_start_* bits
    std::uint32_t store_faults{0};
    std::vector<StandingStartResult> standing;  // strictly increasing vm_id
    friend auto operator==(const ColdStart&, const ColdStart&) -> bool = default;
};

struct BootCache {
    ImageDigest lkg_image{};
    ImageDigest previous_image{};
    std::uint64_t standing_generation{0};
    std::uint64_t policy_version{0};
    std::uint64_t store_free_bytes{0};
    std::uint64_t store_total_bytes{0};
    friend auto operator==(const BootCache&, const BootCache&) -> bool = default;
};

// A fixed text field: printable ASCII padded with zero bytes.
using IdentityText = std::array<char, identity_text_size>;

// Makes an IdentityText from at most identity_text_size characters; longer
// text is cut. Characters outside 0x20-0x7E make the field invalid, which
// encode_report() refuses.
[[nodiscard]] inline auto identity_text(std::string_view text) noexcept -> IdentityText {
    IdentityText t{};
    std::ranges::copy(text.substr(0, identity_text_size), t.begin());
    return t;
}

// The text in a field, without its padding.
[[nodiscard]] inline auto identity_text_view(const IdentityText& t) noexcept -> std::string_view {
    const auto length = static_cast<std::size_t>(std::ranges::find(t, '\0') - t.begin());
    return {t.data(), length};
}

struct IdentitySlot {
    std::uint8_t slot{0};
    SlotKind kind{SlotKind::network};
    IdentityText serial{};
    IdentityText firmware{};
    friend auto operator==(const IdentitySlot&, const IdentitySlot&) -> bool = default;
};

struct IdentityDrive {
    std::uint8_t slot{0};
    std::uint64_t size_bytes{0};
    IdentityText serial{};
    friend auto operator==(const IdentityDrive&, const IdentityDrive&) -> bool = default;
};

struct HardwareIdentity {
    ImageDigest ek_hash{};
    IdentityText board_serial{};
    IdentityText firmware{};
    std::uint64_t memory_bytes{0};
    std::uint32_t cpu_count{0};
    std::uint8_t flags{0};              // identity_* bits
    std::vector<IdentitySlot> slots;    // strictly increasing slot
    std::vector<IdentityDrive> drives;  // strictly increasing (slot, serial)
    friend auto operator==(const HardwareIdentity&, const HardwareIdentity&) -> bool = default;
};

struct DecommissionProgress {
    DecommissionStep step{DecommissionStep::keys_destroyed};
    std::optional<SanitizeResult> result;  // exactly when step is media
    std::uint8_t slot{0};                  // media only
    IdentityText drive_serial{};           // non-empty exactly when step is media
    friend auto operator==(const DecommissionProgress&, const DecommissionProgress&)
        -> bool = default;
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
                 DemotionConfirmed, OpOutcome, SnapshotProgress, Enrollment, CertRequest,
                 GroupMembership, GroupStatus, Capacity, GroupFault, ConversionProgress, ColdStart,
                 BootCache, HardwareIdentity, DecommissionProgress>;

struct Report {
    std::uint64_t server_id{0};
    std::uint64_t report_seq{0};
    ReportBody body;
    friend auto operator==(const Report&, const Report&) -> bool = default;
};

// Kinds 1-20 are the variant's alternatives 0-19; the later alternatives
// have the kinds in this table, in the variant's order (which is the order
// they were added, not their kind numbers).
inline constexpr std::array report_kinds_after_contiguous{
    ReportKind::cold_start, ReportKind::boot_cache, ReportKind::hardware_identity,
    ReportKind::decommission_progress};
[[nodiscard]] inline auto report_kind(const ReportBody& body) noexcept -> ReportKind {
    constexpr auto contiguous = static_cast<std::size_t>(ReportKind::conversion_progress);
    if (body.index() < contiguous) {
        return static_cast<ReportKind>(body.index() + 1);
    }
    return report_kinds_after_contiguous.at(body.index() - contiguous);
}
static_assert(std::variant_size_v<ReportBody> ==
              static_cast<std::size_t>(ReportKind::conversion_progress) +
                  report_kinds_after_contiguous.size());

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
    return k >= VolumeFaultKind::member_timeout && k <= VolumeFaultKind::checksum_mismatch;
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
    return r >= StorageRole::hold && r <= StorageRole::khold;
}
[[nodiscard]] constexpr auto known(GroupMemberState s) noexcept -> bool {
    return s >= GroupMemberState::leader && s <= GroupMemberState::unavailable;
}
[[nodiscard]] constexpr auto known(DriveState s) noexcept -> bool {
    return s >= DriveState::ok && s <= DriveState::failed;
}
[[nodiscard]] constexpr auto known(GroupFaultKind k) noexcept -> bool {
    return k >= GroupFaultKind::lagging && k <= GroupFaultKind::checksum_unrepairable;
}
[[nodiscard]] constexpr auto known(ConversionDirection d) noexcept -> bool {
    return d == ConversionDirection::to_network || d == ConversionDirection::to_local;
}
[[nodiscard]] constexpr auto known(ConversionState s) noexcept -> bool {
    return s >= ConversionState::copying && s <= ConversionState::failed;
}
[[nodiscard]] constexpr auto known(ConversionFailure f) noexcept -> bool {
    return f <= ConversionFailure::lost;
}
[[nodiscard]] constexpr auto known_member_kind(std::uint8_t k) noexcept -> bool {
    // volume_layout.hpp's MemberKind (data 1, witness 2, learner 3); the
    // report stays independent of the layout header.
    return k >= 1 && k <= 3;
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

[[nodiscard]] inline auto check_body(const GroupMembership& m) noexcept
    -> std::expected<void, DecodeError> {
    if (m.entries.size() > max_group_membership_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& e : m.entries) {
        if (e.nic_id == 0) {
            return std::unexpected(DecodeError::bad_nic_id);
        }
        if (e.vni == 0 || e.vni > max_vni) {
            return std::unexpected(DecodeError::bad_vni);
        }
        if (e.family != RouteFamily::ipv4 && e.family != RouteFamily::ipv6) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (!valid_member_group(e.family, e.group)) {
            return std::unexpected(DecodeError::bad_group);
        }
    }
    const auto key = [](const GroupMembershipEntry& e) {
        return std::tuple{e.nic_id, e.family, e.group};
    };
    if (std::ranges::adjacent_find(m.entries, [&](const auto& a, const auto& b) {
            return key(a) >= key(b);
        }) != m.entries.end()) {
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

[[nodiscard]] inline auto check_body(const ConversionProgress& p) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(p.direction) || !known(p.state) || !known(p.failure) ||
        ((p.failure != ConversionFailure::none) != (p.state == ConversionState::failed))) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (p.local_volume_id == 0 || p.network_volume_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (p.done_bytes > p.total_bytes || p.written_bytes > p.total_bytes) {
        return std::unexpected(DecodeError::bad_capacity);
    }
    return {};
}

[[nodiscard]] constexpr auto known(BootSource b) noexcept -> bool {
    return b >= BootSource::lkg && b <= BootSource::netboot;
}
[[nodiscard]] constexpr auto known(StandingResult r) noexcept -> bool {
    return r >= StandingResult::started && r <= StandingResult::failed;
}

[[nodiscard]] inline auto check_body(const ColdStart& c) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(c.boot_source) || (c.flags & ~known_cold_start_flags) != 0) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (c.standing.size() > max_standing_instances) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < c.standing.size(); ++i) {
        const auto& e = c.standing[i];
        if (e.vm_id == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (!known(e.result)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (i > 0 && c.standing[i - 1].vm_id >= e.vm_id) {
            return std::unexpected(DecodeError::not_ascending);
        }
    }
    return {};
}

[[nodiscard]] inline auto check_body(const BootCache& b) noexcept
    -> std::expected<void, DecodeError> {
    if (all_zero(b.lkg_image) && !all_zero(b.previous_image)) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (b.store_free_bytes > b.store_total_bytes) {
        return std::unexpected(DecodeError::bad_capacity);
    }
    return {};
}

[[nodiscard]] constexpr auto known(SlotKind k) noexcept -> bool {
    return k >= SlotKind::network && k <= SlotKind::control;
}
[[nodiscard]] constexpr auto known(DecommissionStep s) noexcept -> bool {
    return s >= DecommissionStep::keys_destroyed && s <= DecommissionStep::identity_cleared;
}
[[nodiscard]] constexpr auto known(SanitizeResult r) noexcept -> bool {
    return r >= SanitizeResult::sanitized_crypto && r <= SanitizeResult::failed;
}

// Printable ASCII, then only zero bytes.
[[nodiscard]] inline auto valid_text(const IdentityText& t) noexcept -> bool {
    bool padding = false;
    for (const char c : t) {
        if (c == '\0') {
            padding = true;
        } else if (padding || c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}
[[nodiscard]] inline auto empty_text(const IdentityText& t) noexcept -> bool {
    return t[0] == '\0';
}

[[nodiscard]] inline auto check_body(const HardwareIdentity& h) noexcept
    -> std::expected<void, DecodeError> {
    if (all_zero(h.ek_hash)) {
        return std::unexpected(DecodeError::bad_public_key);
    }
    if (!valid_text(h.board_serial) || empty_text(h.board_serial) || !valid_text(h.firmware)) {
        return std::unexpected(DecodeError::bad_text);
    }
    if ((h.flags & ~known_identity_flags) != 0 ||
        ((h.flags & identity_host_reported) == 0 &&
         (h.flags & (identity_secure_boot | identity_iommu)) != 0)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (h.slots.size() > max_identity_slots || h.drives.size() > max_identity_drives) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (std::size_t i = 0; i < h.slots.size(); ++i) {
        const auto& s = h.slots[i];
        if (!known(s.kind)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (!valid_text(s.serial) || empty_text(s.serial) || !valid_text(s.firmware)) {
            return std::unexpected(DecodeError::bad_text);
        }
        if (i > 0 && h.slots[i - 1].slot >= s.slot) {
            return std::unexpected(DecodeError::not_ascending);
        }
    }
    for (std::size_t i = 0; i < h.drives.size(); ++i) {
        const auto& d = h.drives[i];
        if (d.size_bytes == 0) {
            return std::unexpected(DecodeError::bad_capacity);
        }
        if (!valid_text(d.serial) || empty_text(d.serial)) {
            return std::unexpected(DecodeError::bad_text);
        }
        if (i > 0 &&
            std::tie(h.drives[i - 1].slot, h.drives[i - 1].serial) >= std::tie(d.slot, d.serial)) {
            return std::unexpected(DecodeError::not_ascending);
        }
        const auto slot = std::ranges::find(h.slots, d.slot, &IdentitySlot::slot);
        if (slot == h.slots.end() || slot->kind != SlotKind::storage) {
            return std::unexpected(DecodeError::bad_id);
        }
    }
    return {};
}

[[nodiscard]] inline auto check_body(const DecommissionProgress& p) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(p.step) || (p.result && !known(*p.result))) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (!valid_text(p.drive_serial)) {
        return std::unexpected(DecodeError::bad_text);
    }
    const bool media = p.step == DecommissionStep::media;
    if (p.result.has_value() != media || empty_text(p.drive_serial) == media ||
        (!media && p.slot != 0)) {
        return std::unexpected(DecodeError::unknown_value);
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

[[nodiscard]] inline auto check_body(const GroupStatus& s) noexcept
    -> std::expected<void, DecodeError> {
    if (s.entries.size() > max_group_status_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& e : s.entries) {
        if (!known_member_kind(e.kind) || !known(e.state)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (e.volume_id == 0 || e.group_id == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
        if (e.epoch == 0) {
            return std::unexpected(DecodeError::bad_epoch);
        }
        if (e.applied_index > e.commit_index) {
            return std::unexpected(DecodeError::bad_capacity);
        }
    }
    const auto key = [](const GroupStatusEntry& e) { return std::tuple{e.volume_id, e.group_id}; };
    if (std::ranges::adjacent_find(s.entries, [&](const auto& a, const auto& b) {
            return key(a) >= key(b);
        }) != s.entries.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const Capacity& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.drives.size() > max_capacity_drives) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& d : c.drives) {
        if (!known(d.state)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if (d.allocated_bytes > d.capacity_bytes) {
            return std::unexpected(DecodeError::bad_capacity);
        }
    }
    if (std::ranges::adjacent_find(c.drives, std::ranges::greater_equal{}, &DriveCapacity::drive) !=
        c.drives.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const GroupFault& f) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(f.kind)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (f.volume_id == 0 || f.group_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (f.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    if (f.suspect == 0 && f.kind != GroupFaultKind::no_space) {
        return std::unexpected(DecodeError::bad_server_id);
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
template<>
inline constexpr std::size_t volume_event_size<ConversionProgress> = conversion_progress_size;

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
    } else if constexpr (std::is_same_v<T, ConversionProgress>) {
        out.local_volume_id = in.le64();
        out.network_volume_id = in.le64();
        out.total_bytes = in.le64();
        out.done_bytes = in.le64();
        out.written_bytes = in.le64();
        out.direction = static_cast<ConversionDirection>(in.u8());
        out.state = static_cast<ConversionState>(in.u8());
        out.failure = static_cast<ConversionFailure>(in.u8());
        out.slot = in.u8();
        zero = in.zeros(4);
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

inline auto write_volume_event(wire::Writer& w, const ConversionProgress& b) -> void {
    w.le64(b.local_volume_id);
    w.le64(b.network_volume_id);
    w.le64(b.total_bytes);
    w.le64(b.done_bytes);
    w.le64(b.written_bytes);
    w.u8(static_cast<std::uint8_t>(b.direction));
    w.u8(static_cast<std::uint8_t>(b.state));
    w.u8(static_cast<std::uint8_t>(b.failure));
    w.u8(b.slot);
    w.le32(0);
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

[[nodiscard]] inline auto decode_group_membership(std::span<const std::byte> body)
    -> std::expected<GroupMembership, DecodeError> {
    wire::Reader r{body};
    auto slot = r.u8();
    auto reserved1 = r.u8();
    auto count = r.le16();
    auto reserved2 = r.le32();
    if (!slot || !reserved1 || !count || !reserved2) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*reserved1 != 0 || *reserved2 != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*count > max_group_membership_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t want = std::size_t{*count} * group_membership_entry_size;
    if (r.remaining() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    GroupMembership out{.slot = *slot, .entries = {}};
    out.entries.reserve(*count);
    for (std::uint16_t i = 0; i < *count; ++i) {
        auto nic = r.le64();
        auto vni = r.le32();
        auto family = r.u8();
        auto pad = r.bytes(3);
        auto group = r.bytes(ipv6_address_size);
        if (!nic || !vni || !family || !pad || !group) {
            return std::unexpected(DecodeError::truncated);
        }
        if (!all_zero(*pad)) {
            return std::unexpected(DecodeError::reserved_not_zero);
        }
        auto& e = out.entries.emplace_back();
        e.nic_id = *nic;
        e.vni = *vni;
        e.family = static_cast<RouteFamily>(*family);
        std::ranges::copy(*group, e.group.begin());
    }
    if (auto ok = check_body(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

[[nodiscard]] inline auto decode_group_status(std::span<const std::byte> body)
    -> std::expected<GroupStatus, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    GroupStatus s{.slot = in.u8(), .entries = {}};
    bool zero = in.zeros(1);
    const std::size_t count = in.le16();
    zero = in.zeros(4) && zero;
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (count > max_group_status_entries) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t want = group_status_fixed_size + (count * group_status_entry_size);
    if (body.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    s.entries.resize(count);
    for (auto& e : s.entries) {
        e.volume_id = in.le64();
        e.group_id = in.le64();
        e.epoch = in.le64();
        e.term = in.le64();
        e.commit_index = in.le64();
        e.applied_index = in.le64();
        e.kind = in.u8();
        e.state = static_cast<GroupMemberState>(in.u8());
        e.lagging = in.u8();
        e.drive = in.u8();
        zero = in.zeros(4) && zero;
        e.allocated_bytes = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(s); !ok) {
        return std::unexpected(ok.error());
    }
    return s;
}

[[nodiscard]] inline auto decode_capacity(std::span<const std::byte> body)
    -> std::expected<Capacity, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    Capacity c{.slot = in.u8(), .link_mbps = 0, .drives = {}};
    bool zero = in.zeros(1);
    const std::size_t count = in.le16();
    c.link_mbps = in.le32();
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (count > max_capacity_drives) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const std::size_t want = capacity_fixed_size + (count * capacity_entry_size);
    if (body.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    c.drives.resize(count);
    for (auto& d : c.drives) {
        d.drive = in.u8();
        d.state = static_cast<DriveState>(in.u8());
        zero = in.zeros(6) && zero;
        d.capacity_bytes = in.le64();
        d.allocated_bytes = in.le64();
        d.reserved_bytes = in.le64();
        d.read_iops = in.le32();
        d.write_iops = in.le32();
        d.read_mib_per_s = in.le32();
        d.write_mib_per_s = in.le32();
        d.replicas = in.le32();
        zero = in.zeros(4) && zero;
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

[[nodiscard]] inline auto decode_group_fault(std::span<const std::byte> body)
    -> std::expected<GroupFault, DecodeError> {
    if (body.size() < group_fault_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > group_fault_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    GroupFault f{};
    f.volume_id = in.le64();
    f.group_id = in.le64();
    f.epoch = in.le64();
    f.term = in.le64();
    f.suspect = in.le64();
    f.kind = static_cast<GroupFaultKind>(in.u8());
    f.slot = in.u8();
    f.drive = in.u8();
    if (!in.zeros(5)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(f); !ok) {
        return std::unexpected(ok.error());
    }
    return f;
}

[[nodiscard]] inline auto decode_cold_start(std::span<const std::byte> body)
    -> std::expected<ColdStart, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    ColdStart c{};
    c.power_return_time = in.le64();
    c.time_floor = in.le64();
    c.waited_ms = in.le32();
    c.boot_source = static_cast<BootSource>(in.u8());
    c.flags = in.u8();
    const auto count = in.le16();
    c.store_faults = in.le32();
    bool zero = in.zeros(4);
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (count > max_standing_instances) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    if (body.size() < cold_start_fixed_size + (count * cold_start_entry_size)) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > cold_start_fixed_size + (count * cold_start_entry_size)) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    c.standing.reserve(count);
    for (std::uint16_t i = 0; i < count; ++i) {
        StandingStartResult& e = c.standing.emplace_back();
        e.vm_id = in.le64();
        e.result = static_cast<StandingResult>(in.u8());
        zero = in.zeros(1) && zero;
        e.attempts = in.le16();
        zero = in.zeros(4) && zero;
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

[[nodiscard]] inline auto decode_boot_cache(std::span<const std::byte> body)
    -> std::expected<BootCache, DecodeError> {
    if (body.size() < boot_cache_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > boot_cache_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    BootCache b{};
    in.bytes(b.lkg_image);
    in.bytes(b.previous_image);
    b.standing_generation = in.le64();
    b.policy_version = in.le64();
    b.store_free_bytes = in.le64();
    b.store_total_bytes = in.le64();
    if (auto ok = check_body(b); !ok) {
        return std::unexpected(ok.error());
    }
    return b;
}

inline auto write_cold_start_body(wire::Writer& w, const ColdStart& c) -> void {
    w.le64(c.power_return_time);
    w.le64(c.time_floor);
    w.le32(c.waited_ms);
    w.u8(static_cast<std::uint8_t>(c.boot_source));
    w.u8(c.flags);
    w.le16(static_cast<std::uint16_t>(c.standing.size()));
    w.le32(c.store_faults);
    w.le32(0);
    for (const auto& e : c.standing) {
        w.le64(e.vm_id);
        w.u8(static_cast<std::uint8_t>(e.result));
        w.u8(0);
        w.le16(e.attempts);
        w.le32(0);
    }
}

inline auto write_cold_start_body(wire::Writer& w, const BootCache& b) -> void {
    w.bytes(b.lkg_image);
    w.bytes(b.previous_image);
    w.le64(b.standing_generation);
    w.le64(b.policy_version);
    w.le64(b.store_free_bytes);
    w.le64(b.store_total_bytes);
}

inline auto read_text(BodyReader& in, IdentityText& t) -> void {
    in.bytes(std::as_writable_bytes(std::span{t}));
}
inline auto write_text(wire::Writer& w, const IdentityText& t) -> void {
    w.bytes(std::as_bytes(std::span{t}));
}

[[nodiscard]] inline auto decode_hardware_identity(std::span<const std::byte> body)
    -> std::expected<HardwareIdentity, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    HardwareIdentity h{};
    in.bytes(h.ek_hash);
    read_text(in, h.board_serial);
    read_text(in, h.firmware);
    h.memory_bytes = in.le64();
    h.cpu_count = in.le32();
    h.flags = in.u8();
    const std::size_t slots = in.u8();
    const std::size_t drives = in.le16();
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (slots > max_identity_slots || drives > max_identity_drives) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    const auto size = hardware_identity_fixed_size + (slots * identity_slot_size) +
                      (drives * identity_drive_size);
    if (body.size() < size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    bool zero = true;
    h.slots.reserve(slots);
    for (std::size_t i = 0; i < slots; ++i) {
        IdentitySlot& s = h.slots.emplace_back();
        s.slot = in.u8();
        s.kind = static_cast<SlotKind>(in.u8());
        zero = in.zeros(6) && zero;
        read_text(in, s.serial);
        read_text(in, s.firmware);
    }
    h.drives.reserve(drives);
    for (std::size_t i = 0; i < drives; ++i) {
        IdentityDrive& d = h.drives.emplace_back();
        d.slot = in.u8();
        zero = in.zeros(7) && zero;
        d.size_bytes = in.le64();
        read_text(in, d.serial);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(h); !ok) {
        return std::unexpected(ok.error());
    }
    return h;
}

[[nodiscard]] inline auto decode_decommission_progress(std::span<const std::byte> body)
    -> std::expected<DecommissionProgress, DecodeError> {
    if (body.size() < decommission_progress_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > decommission_progress_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    DecommissionProgress p{};
    p.step = static_cast<DecommissionStep>(in.u8());
    if (const auto result = in.u8(); result != 0) {
        p.result = static_cast<SanitizeResult>(result);
    }
    p.slot = in.u8();
    const bool zero = in.zeros(5);
    read_text(in, p.drive_serial);
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(p); !ok) {
        return std::unexpected(ok.error());
    }
    return p;
}

inline auto write_provisioning_body(wire::Writer& w, const HardwareIdentity& h) -> void {
    w.bytes(h.ek_hash);
    write_text(w, h.board_serial);
    write_text(w, h.firmware);
    w.le64(h.memory_bytes);
    w.le32(h.cpu_count);
    w.u8(h.flags);
    w.u8(static_cast<std::uint8_t>(h.slots.size()));
    w.le16(static_cast<std::uint16_t>(h.drives.size()));
    for (const auto& s : h.slots) {
        w.u8(s.slot);
        w.u8(static_cast<std::uint8_t>(s.kind));
        w.bytes(std::array<std::byte, 6>{});
        write_text(w, s.serial);
        write_text(w, s.firmware);
    }
    for (const auto& d : h.drives) {
        w.u8(d.slot);
        w.bytes(std::array<std::byte, 7>{});
        w.le64(d.size_bytes);
        write_text(w, d.serial);
    }
}

inline auto write_provisioning_body(wire::Writer& w, const DecommissionProgress& p) -> void {
    w.u8(static_cast<std::uint8_t>(p.step));
    w.u8(p.result ? static_cast<std::uint8_t>(*p.result) : 0);
    w.u8(p.slot);
    w.bytes(std::array<std::byte, 5>{});
    write_text(w, p.drive_serial);
}

inline auto write_khold_body(wire::Writer& w, const GroupStatus& s) -> void {
    w.u8(s.slot);
    w.u8(0);
    w.le16(static_cast<std::uint16_t>(s.entries.size()));
    w.le32(0);
    for (const auto& e : s.entries) {
        w.le64(e.volume_id);
        w.le64(e.group_id);
        w.le64(e.epoch);
        w.le64(e.term);
        w.le64(e.commit_index);
        w.le64(e.applied_index);
        w.u8(e.kind);
        w.u8(static_cast<std::uint8_t>(e.state));
        w.u8(e.lagging);
        w.u8(e.drive);
        w.le32(0);
        w.le64(e.allocated_bytes);
    }
}

inline auto write_khold_body(wire::Writer& w, const Capacity& c) -> void {
    w.u8(c.slot);
    w.u8(0);
    w.le16(static_cast<std::uint16_t>(c.drives.size()));
    w.le32(c.link_mbps);
    for (const auto& d : c.drives) {
        w.u8(d.drive);
        w.u8(static_cast<std::uint8_t>(d.state));
        w.bytes(std::array<std::byte, 6>{});
        w.le64(d.capacity_bytes);
        w.le64(d.allocated_bytes);
        w.le64(d.reserved_bytes);
        w.le32(d.read_iops);
        w.le32(d.write_iops);
        w.le32(d.read_mib_per_s);
        w.le32(d.write_mib_per_s);
        w.le32(d.replicas);
        w.le32(0);
    }
}

inline auto write_khold_body(wire::Writer& w, const GroupFault& f) -> void {
    w.le64(f.volume_id);
    w.le64(f.group_id);
    w.le64(f.epoch);
    w.le64(f.term);
    w.le64(f.suspect);
    w.u8(static_cast<std::uint8_t>(f.kind));
    w.u8(f.slot);
    w.u8(f.drive);
    w.bytes(std::array<std::byte, 5>{});
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
            } else if constexpr (std::is_same_v<T, GroupMembership>) {
                w.u8(b.slot);
                w.u8(0);
                w.le16(static_cast<std::uint16_t>(b.entries.size()));
                w.le32(0);
                for (const auto& e : b.entries) {
                    w.le64(e.nic_id);
                    w.le32(e.vni);
                    w.u8(static_cast<std::uint8_t>(e.family));
                    w.bytes(std::array<std::byte, 3>{});
                    w.bytes(e.group);
                }
            } else if constexpr (std::is_same_v<T, ReplicaStatus>) {
                write_replica_status(w, b);
            } else if constexpr (std::is_same_v<T, GroupStatus> || std::is_same_v<T, Capacity> ||
                                 std::is_same_v<T, GroupFault>) {
                write_khold_body(w, b);
            } else if constexpr (std::is_same_v<T, ColdStart> || std::is_same_v<T, BootCache>) {
                write_cold_start_body(w, b);
            } else if constexpr (std::is_same_v<T, HardwareIdentity> ||
                                 std::is_same_v<T, DecommissionProgress>) {
                write_provisioning_body(w, b);
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
        case ReportKind::group_membership:
            return wrap(detail::decode_group_membership(body));
        case ReportKind::group_status:
            return wrap(detail::decode_group_status(body));
        case ReportKind::capacity:
            return wrap(detail::decode_capacity(body));
        case ReportKind::group_fault:
            return wrap(detail::decode_group_fault(body));
        case ReportKind::conversion_progress:
            return wrap(detail::decode_volume_event<ConversionProgress>(body));
        case ReportKind::cold_start:
            return wrap(detail::decode_cold_start(body));
        case ReportKind::boot_cache:
            return wrap(detail::decode_boot_cache(body));
        case ReportKind::hardware_identity:
            return wrap(detail::decode_hardware_identity(body));
        case ReportKind::decommission_progress:
            return wrap(detail::decode_decommission_progress(body));
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
