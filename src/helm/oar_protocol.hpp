// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Message bodies of the helm <-> oar sideband protocol (OarLink,
// .kiro/specs/helm-control-plane/ Requirements 5 and 7, design "OarLink").
//
// Each operation is one ak vendor-defined MCTP message (helm/mctp.hpp,
// VendorType) sent by helm as a request and answered by the data-plane role
// with a response of the same VendorType and the response flag set. This
// header defines only the bodies, which follow the 7-byte vendor header.
// Integers are little-endian, like the mailbox and src/proto/.
//
// Requests (helm -> oar):
//
//   function_inventory  (empty)
//   prepare_function    0  fn u16 | 2  type u8 | 3  reserved u8 | 4  reserved u32
//                       8  vm_id u64 | 16 per-type config:
//                         nic_vf: nic_id u64 | vni u32 | mac [6] | reserved u16  (20 bytes)
//                         blk_fn: volume_id u64 | attachment_id u64 | generation u32
//                                 | reserved u32                               (24 bytes)
//                                 (attachment_id and generation zero for a local or
//                                 image volume; both non-zero for a network volume,
//                                 whose ReplicaConfig the role already has)
//                         gpu_whole, gpu_vf: nothing
//   clean_function      0  fn u16 | 2  action u8 (CleaningAction) | 3  reserved u8
//   deliver_key         0  fn u16 | 2  reserved u16 | 4  reserved u32 | 8  volume_id u64
//                       16 key [64] (AES-256-XTS volume key, oar-blk Requirement 2)
//                       80 image_key [64], only for an encrypted image volume
//   drop_key            0  fn u16 | 2  reserved u16 | 4  reserved u32 | 8  volume_id u64
//   map_update          0  total u32 | 4  offset u32 | 8  chunk (1..max_map_chunk bytes)
//   health              (empty)
//   group_policy        0  total u32 | 4  offset u32 | 8  chunk (as map_update): one
//                          controller proto::GroupPolicy (signed; version 1 is
//                          group_policy_frame_size bytes, version 2
//                          min_group_policy_v2_frame to max_group_policy_frame)
//   group_usage         0  cursor u16 | 2  reserved u16
//   create_volume       0  volume_id u64 | 8  owner_vm u64 | 16 capacity_sectors u64
//                       24 block_size u32 | 28 key_len u16 | 30 image_store u16
//                       32 image_name [32], only when image_store != 0
//                       wrapped_key [key_len]
//   delete_volume       0  volume_id u64
//   rewrap_volume       0  volume_id u64 | 8  owner_vm u64 | 16 key_len u16
//                       18 reserved u16 | 20 reserved u32 | 24 wrapped_key [key_len]
//   set_tunnel_key      0  private_key [32]
//                       32 grace_s u32 | 36 reserved u32, only for a rotation
//   set_tunnel_peer     0  vtep [16] | 16 public_key [32] | 48 psk [32]
//   remove_tunnel_peer  0  vtep [16]
//   tunnel_peers        0  total u32 | 4  offset u32 | 8  chunk (as map_update)
//   replica_config      0  frame (proto::ReplicaConfig, signed; min_replica_config_frame
//                          to max_replica_config_frame bytes)
//   volume_op           0  frame [volume_op_frame_size] (proto::VolumeOp, signed)
//   lease_grant         0  volume_id u64 | 8  epoch u64
//   hold_reports        0  ack u64 | 8  offset u32 | 12 reserved u32
//   cert_request        (empty)
//   role_certificate    0  total u32 | 4  offset u32 | 8  chunk (as map_update)
//   eject               0  fn u16 | 2  op u8 (EjectOp) | 3  reserved u8
//   vpc_config          0  total u32 | 4  offset u32 | 8  chunk (as map_update): one
//                          controller proto::VpcConfigFrame (signed;
//                          min_vpc_config_frame to max_vpc_config_frame bytes)
//   group_members       0  total u32 | 4  offset u32 | 8  chunk (as map_update)
//   instance_metadata   0  total u32 | 4  offset u32 | 8  chunk (as map_update)
//   volume_layout       0  total u32 | 4  offset u32 | 8  chunk (as map_update): one
//                          controller proto::VolumeLayout (signed; at most
//                          max_volume_layout_frame bytes), for a blk role
//                          attaching khold volumes (kythira khold-block-service
//                          Requirement 11.5) or a khold role serving them
//   self_test           (empty)
//   vtep_credential     0  total u32 | 4  offset u32 | 8  chunk (as map_update): one
//                          controller proto::VtepCredential (signed,
//                          vtep_credential_frame bytes) for this role's VTEP
//   credential_revocations 0  total u32 | 4  offset u32 | 8  chunk (as map_update):
//                          one controller proto::CredentialRevocations (signed;
//                          at most max_credential_revocations_frame bytes)
//   frame_notice        0  one proto::FrameNotice (frame_notice_body bytes, unsigned):
//                          a frame to fetch over the bulk channel
//                          (fleet-scale-networking task 11); a single
//                          message, never chunked, so it is control traffic
//   group_membership    0  cursor u16 | 2  flags u16 (bit 0: `since` is set)
//                       4  since u32 (the generation helm last read whole)
//   copy_volume         0  op u8 (CopyOp) | 1  direction u8 (CopyDirection) | 2  reserved u16
//                       4  mib_per_s u32 (0: unpaced) | 8  local_volume_id u64
//                       16 network_volume_id u64 | 24 attachment_id u64 | 32 generation u32
//                       36 reserved u32
//                       40 local_key [64] | 104 network_key [64], only for start
//
// The tunnel requests deliver the network role's WireGuard keys (oar-net
// Requirement 5.2): its own static X25519 private key, and for each peer
// VTEP that peer's public key and the pre-shared key for the pair (all
// zero for none, as in WireGuard). A 40-byte set_tunnel_key is a key
// rotation (fleet-scale-networking Requirement 1.3): the role keeps its old
// key for grace_s seconds (1 or more) for the sessions made under it and
// for handshakes still addressed to it; the 32-byte form replaces the key
// at once and drops every session. set_tunnel_peer adds the peer or
// replaces its keys. Private and public keys and VTEP addresses are never
// all zero. Only the network role implements them. The bodies carry
// secrets, so both ends wipe every buffer that held one, as for
// deliver_key.
//
// The volume requests are the storage role's half of CREATE_VOLUME,
// DELETE_VOLUME and REWRAP_VOLUME (oar-blk Requirement 3): the role keeps
// the wrapped volume key with the volume's metadata on the media and
// releases the space on delete. The wrapped key is helm's KeyStore blob,
// opaque to the role (helm authenticates it on unwrap); key_len is 1 to
// max_wrapped_volume_key. capacity_sectors counts 512-byte sectors, is
// non-zero and a whole number of logical blocks; block_size is 512 or 4096.
// A non-zero image_store makes it an image volume (oar-blk Requirement 8,
// task 13): the image named image_name (the SHA-256 of its manifest, never
// all zero) in the object store the role knows by that ID, under a
// throwaway overlay. Such a volume needs no volume key; key_len is 0 for a
// plain image, or carries the wrapped image key of an encrypted one. Its
// attachment key is the ephemeral one helm delivers with deliver_key.
//
// map_update forwards one controller MapUpdate frame (src/proto/map_update.hpp)
// unmodified, signature included, so the role can check it itself. A full
// frame (up to 131 KiB) is larger than an MCTP message may be here
// (mctp::max_message_size), so it travels as consecutive chunks: offset 0
// starts a transfer, each later chunk continues exactly where the last one
// ended, and the chunk that reaches `total` completes it. Every chunk is
// acknowledged; the last acknowledgement carries the result of applying it.
//
// group_policy forwards one controller GroupPolicy frame
// (src/proto/group_policy.hpp) unmodified, in map_update's chunks: a
// version 2 frame, one entry per opted-in subnet, is up to 8,096 bytes
// (.kiro/specs/vpc-subnets-routing/ task 12). group_usage reads the role's per-NIC group meters
// (oar-net Requirement 10.6) a page at a time: cursor 0 takes a new snapshot, later cursors page
// through it. A snapshot's final readings of detached NICs are carried into the next snapshot until
// a read reaches its last page, so an interrupted read loses nothing (UsagePager).
//
// vpc_config forwards one controller VpcConfig frame
// (src/proto/vpc_config.hpp: a VPC's blocks, subnets, route tables, gateway
// and DHCP settings) unmodified, in map_update's chunks: a version 2 frame
// is up to 136 KiB (.kiro/specs/vpc-subnets-routing/ task 3). Only the
// network role implements it (oar-net task 20).
//
// tunnel_peers forwards one controller TunnelPeers frame
// (src/proto/tunnel_peers.hpp: the signed public keys of one VTEP's
// WireGuard peers) the same way, in the same chunk format, up to
// max_tunnel_peers_frame. The role verifies it and replaces its
// controller-managed peers with the frame's (oar-net Requirement 5.2). A
// transfer of one type is abandoned by a chunk of the other.
//
// The block volume requests go to the hold role only
// (.kiro/specs/block-volume-service/ task 12). replica_config and
// volume_op forward one controller frame unmodified, like group_policy;
// the role verifies it. lease_grant passes down the controller's
// acknowledgement of the role's lease request as primary of the volume at
// that epoch (non-zero both). hold_reports takes what the role reports
// (proto::Report frames, numbered by the role from a random start so a
// restarted role's numbers do not repeat its predecessor's): the role
// answers with a chunk of the oldest report it still holds, from `offset`.
// `ack` names the last report helm read whole: the role first drops its
// oldest report if that is the one, so a lost response costs a resend,
// never a report. A role with nothing to report answers total 0.
//
// The khold requests (kythira khold-block-service task 17) go to the
// khold role: volume_layout as above, hold_reports as for a hold role
// (group_status, capacity, group_fault and volume_fault reports), and
// self_test, which starts the role's storage self-test (drive capacity,
// random 4 KiB IOPS, sequential throughput, link speed) and answers at
// once; the measurements arrive as the role's next capacity report. A
// self_test while one runs answers ok and starts nothing.
//
// Enrollment (block-volume-service task 12), to a storage role (blk,
// hold or khold) or a network role (fleet-scale-networking task 10):
// cert_request asks the role whether it wants a certificate, and
// the role answers with its PKCS#10 request (DER), or csr_len 0 while the
// certificate it holds is good. helm reports a request to the controller
// (proto::CertRequest) and passes the controller's answer down with
// role_certificate: the DER chain, leaf first, in map_update's chunk
// format, up to max_cert_chain bytes. The role checks the chain against
// its storage CA, its server ID and its own key before it uses or keeps
// it, so neither body needs more than its framing checked here.
//
// Cooperative detach (block-volume-service task 13), to the storage role
// (blk): eject asks the guest to release a function (request), withdraws
// that (cancel) or only looks (query), and every answer says where the
// function stands: no request, requested, or released (the driver reset
// the device and left it alone long enough, with no request still in the
// backend). request and cancel are idempotent.
//
// Local <-> network conversion (block-volume-service Requirement 8.6,
// task 23.2), to the storage role (blk): copy_volume copies one detached
// volume into another on this server, decrypting with the source's key
// and encrypting with the target's (oar/blk/volume_copier.hpp). The pair
// is a local volume (the role's volume file) and a network volume, opened
// through `attachment_id` at `generation`, an attachment for this server
// in the volume's newest ReplicaConfig (a utility attachment: no VM).
// to_network copies the local volume into the network one, to_local the
// other way; the target must be new. start carries both keys (helm's
// unwrapped local key and the network volume's attachment key) and
// begins the copy; query reports it; release stops it if it is still
// running and forgets it. A copy stays queryable until released, so helm
// reads its outcome however late it polls. Every answer is the copy's
// state and progress; query and release of a pair with no copy answer
// state none. The body carries secrets on start, so both ends wipe it,
// as for deliver_key.
//
// Responses (oar -> helm) start with a 2-byte head:
//
//   0  status u8 (Status) | 1  reserved u8
//
// A response with any status other than ok ends there. An ok response to
// function_inventory or health carries a body after the head:
//
//   function_inventory  2  role u8 (Role) | 3  reserved u8 | 4  count u16
//                       6  vtep [16] (IPv6; the role's VTEP for net, zero otherwise)
//                       22 count x { fn u16 | type u8 (FunctionType) | reserved u8 }
//   health              2  state u8 (HealthState) | 3  reserved u8 | 4  fault_code u16
//                       6  uptime_seconds u32
//   hold_reports        2  report_seq u64 | 10 total u32 | 14 offset u32 | 18 chunk
//                       (total 0: nothing to report, and the rest zero and empty)
//   cert_request        2  role u8 (Role: blk, hold, khold or net) | 3  reserved u8
//                       4  csr_len u16
//                       6  csr [csr_len] (0..max_csr bytes)
//   eject               2  state u8 (EjectState) | 3  reserved u8
//   copy_volume         2  state u8 (CopyVolumeState) | 3  failure u8 (CopyVolumeFailure)
//                       4  reserved [6] | 10 total_bytes u64 | 18 done_bytes u64
//                       26 written_bytes u64 (done, written <= total)
//   group_usage         2  total u16 | 4  count u16 | 6  reserved u32
//                       10 count x 96 (the proto group_usage report entry, slot 0):
//                          nic_id u64 | vni u32 | flags u8 | reserved [3] | attachment u64
//                          frames, bytes, replicas_remote, replica_bytes_remote,
//                          replicas_local, replica_bytes_local, drop_policy,
//                          drop_rate, drop_fanout: u64 each
//                       entries [cursor, cursor + count) of the snapshot, which
//                       is in strictly increasing (nic_id, attachment) order
//   group_membership    2  generation u32 | 6  total u16 | 8  count u16
//                       10 flags u8 (bit 0: unchanged) | 11 reserved [3]
//                       14 count x 32 (the proto group_membership report entry):
//                          nic_id u64 | vni u32 | family u8 (4, 6) | reserved [3]
//                          | group [16] (IPv4 in the first four bytes)
//                       entries [cursor, cursor + count) of the snapshot, in
//                       strictly increasing (nic_id, family, group) order;
//                       an unchanged answer has total and count zero
//
// Every decoder here is strict (exact length, zero reserved bytes, known
// enum values, non-zero identifiers) and every encoder enforces the same
// rules, so neither side can emit a body the other would refuse. The
// sideband is unauthenticated in the first release (Requirement 5.3), so
// helm parses responses with the same suspicion as the oar parses requests.

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include "helm/device_pool.hpp"
#include "helm/mctp.hpp"
#include "helm/scoped_key.hpp"
#include "helm/secure_element.hpp"

namespace ak::helm::oar {

// A function's number within its slot (helm-control-plane design, data
// models: FunctionId { slot, fn }).
using FunctionNumber = std::uint16_t;
using NicId = std::uint64_t;

inline constexpr std::size_t mac_size = 6;
inline constexpr std::size_t vtep_size = 16;
using Mac = std::array<std::byte, mac_size>;
using Vtep = std::array<std::byte, vtep_size>;

inline constexpr std::uint32_t max_vni = 0x00FF'FFFF;  // 24-bit Geneve VNI

// Largest body a message can carry (mctp::max_message_size less the vendor header).
inline constexpr std::size_t max_body_size = mctp::max_message_size - mctp::vendor_header_size;

inline constexpr std::size_t prepare_head_size = 16;
inline constexpr std::size_t nic_config_size = 20;
inline constexpr std::size_t blk_config_size = 24;
inline constexpr std::size_t clean_function_size = 4;
inline constexpr std::size_t deliver_key_size = 16 + volume_key_size;
inline constexpr std::size_t deliver_keys_size = deliver_key_size + volume_key_size;
inline constexpr std::size_t drop_key_size = 16;
inline constexpr std::size_t map_chunk_head_size = 8;
inline constexpr std::size_t create_volume_head_size = 32;
inline constexpr std::size_t delete_volume_size = 8;
inline constexpr std::size_t rewrap_volume_head_size = 24;
inline constexpr std::size_t tunnel_key_size = 32;  // X25519 keys and the WireGuard PSK
inline constexpr std::size_t set_tunnel_key_size = tunnel_key_size;
inline constexpr std::size_t rotate_tunnel_key_size = tunnel_key_size + 8;
inline constexpr std::size_t set_tunnel_peer_size = vtep_size + (2 * tunnel_key_size);
inline constexpr std::size_t remove_tunnel_peer_size = vtep_size;
// Room for a later wrapped-key format; helm's format 1 is 95 bytes. Equal
// to oar-blk's max_wrapped_key_size (the field in its volume header).
inline constexpr std::size_t max_wrapped_volume_key = 256;
inline constexpr std::size_t image_name_size = 32;  // SHA-256 of an image manifest
using ImageName = std::array<std::byte, image_name_size>;
inline constexpr std::uint32_t sector_size = 512;
// Largest volume a request may describe: its byte size still fits an off_t
// with room for the role's metadata.
inline constexpr std::uint64_t max_capacity_sectors = std::uint64_t{1} << 53U;
inline constexpr std::size_t max_map_chunk = max_body_size - map_chunk_head_size;
// Largest MapUpdate frame (proto::max_map_update_size, format v4: 40-byte
// header, 4096 entries of 40 bytes, 8192 guest IPv4 addresses of 16 bytes
// and 8192 IPv6 of 24, 64-byte signature). Mirrored so this header does not
// depend on ak::proto; tests/oar_protocol_test.cpp pins the two.
inline constexpr std::size_t max_map_frame =
    0x28 + (4096 * 0x28) + (8192 * 0x10) + (8192 * 0x18) + 64;
// Largest TunnelPeers frame (proto::max_tunnel_peers_size: 48-byte header,
// 2048 peers of 56 bytes, 64-byte signature), pinned the same way.
inline constexpr std::size_t max_tunnel_peers_frame = 0x30 + (2048 * 0x38) + 64;
// A VtepCredential (proto::vtep_credential_size) and the largest
// CredentialRevocations (proto::max_credential_revocations_size: 32-byte
// header, 16,384 entries of 16 bytes, signature), mirrored like the above
// (fleet-scale-networking task 2).
inline constexpr std::size_t vtep_credential_frame = 160;
// A FrameNotice (proto::frame_notice_size), mirrored the same way.
inline constexpr std::size_t frame_notice_body = 56;
inline constexpr std::size_t max_credential_revocations_frame = 0x20 + (16384 * 0x10) + 64;
static_assert(max_tunnel_peers_frame <= max_map_frame);

inline constexpr std::size_t response_head_size = 2;
inline constexpr std::size_t inventory_head_size = 20;
inline constexpr std::size_t inventory_entry_size = 4;
// Bounded so an inventory response fits one message with room to spare.
inline constexpr std::size_t max_inventory_entries = 1000;
inline constexpr std::size_t health_body_size = 8;
// proto::group_policy_size (version 1) and the version 2 bounds (no
// entries; 200 of 0x28 bytes), mirrored; tests/oar_protocol_test.cpp pins
// them.
inline constexpr std::size_t group_policy_frame_size = 0x80;
inline constexpr std::size_t min_group_policy_v2_frame = 0x20 + 64;
inline constexpr std::size_t max_group_policy_frame = 0x20 + (200 * 0x28) + 64;
inline constexpr std::size_t usage_request_size = 4;
inline constexpr std::size_t usage_head_size = 8;
inline constexpr std::size_t usage_entry_size = 96;
inline constexpr std::size_t max_usage_page = 40;  // 3848 bytes: one message
// proto::max_group_usage_entries, mirrored: one role never meters more.
inline constexpr std::size_t max_usage_entries = 1024;
inline constexpr std::uint8_t usage_detached = 0x01;
// proto::ReplicaConfig frames, mirrored (one member and no attachment, five
// members and sixteen attachments); tests/oar_protocol_test.cpp pins them.
inline constexpr std::size_t min_replica_config_frame = 0x88 + 0x20 + 64;
inline constexpr std::size_t max_replica_config_frame = 0x88 + (5 * 0x20) + (16 * 0x18) + 64;
// proto::VpcConfigFrame version 2 sizes, mirrored (one block, subnet,
// table and local route; five blocks, four DNS servers per family, 200
// subnets, 200 tables, 4,096 routes and a 253-byte domain);
// tests/oar_protocol_test.cpp pins them.
inline constexpr std::size_t min_vpc_config_frame = 0x48 + 0x08 + 0x20 + 0x08 + 0x20 + 64;
inline constexpr std::size_t max_vpc_config_frame =
    0x48 + (5 * 0x08) + (4 * 4) + (4 * 16) + (200 * 0x20) + (200 * 0x08) + (4096 * 0x20) + 253 + 64;
static_assert(max_vpc_config_frame <= max_map_frame);
// Largest GroupMembers frame (proto::max_group_members_size: 32-byte
// header, 512 groups of 24 bytes, 4096 VTEPs of 16, 64-byte signature),
// pinned the same way.
inline constexpr std::size_t max_group_members_frame = 0x20 + (512 * 0x18) + (4096 * 0x10) + 64;
static_assert(max_group_members_frame <= max_map_frame);
// Largest InstanceMetadata frame (proto::max_instance_metadata_size: a
// 56-byte header, nine strings of up to 255 bytes with their sizes, 16 KiB
// of user data, a 64-byte signature), pinned the same way.
inline constexpr std::size_t max_instance_metadata_frame = 0x38 + (9 * 256) + 16384 + 64;
// Largest VolumeLayout frame (proto::max_volume_layout_size: the header, 64
// stripe groups of five members, 16 gateways, 16 attachments and the
// signature).
inline constexpr std::size_t max_volume_layout_frame =
    0x78 + (64 * (16 + (5 * 32))) + (16 * 32) + (16 * 24) + 64;
inline constexpr std::size_t membership_request_size = 8;
inline constexpr std::size_t membership_head_size = 12;
inline constexpr std::size_t membership_entry_size = 32;
inline constexpr std::size_t max_membership_page = 120;  // 3854 bytes: one message
// oar-net's max_role_memberships and proto::max_group_membership_entries,
// mirrored: one role never reports more joins.
inline constexpr std::size_t max_memberships = 1024;
inline constexpr std::uint16_t membership_since = 0x0001;
inline constexpr std::uint8_t membership_unchanged = 0x01;
inline constexpr std::size_t volume_op_frame_size = 0x30 + 0x30 + 64;  // proto::volume_op_size
inline constexpr std::size_t lease_grant_size = 16;
inline constexpr std::size_t report_request_size = 16;
inline constexpr std::size_t report_chunk_head_size = 16;
inline constexpr std::size_t max_report_chunk =
    max_body_size - response_head_size - report_chunk_head_size;
// Largest report a role may send (at least proto::max_report_size, pinned).
inline constexpr std::size_t max_role_report = std::size_t{1} << 17U;
inline constexpr std::size_t cert_answer_head_size = 4;
inline constexpr std::size_t eject_request_size = 4;
inline constexpr std::size_t eject_answer_size = 2;
inline constexpr std::size_t copy_volume_head_size = 40;
inline constexpr std::size_t copy_volume_start_size = copy_volume_head_size + 2 * volume_key_size;
inline constexpr std::size_t copy_volume_answer_size = 32;
// Largest certificate request that fits one cert_request answer (below
// proto::max_csr_size; a P-256 request is a few hundred bytes).
inline constexpr std::size_t max_csr = max_body_size - response_head_size - cert_answer_head_size;
// proto::max_cert_chain_size, mirrored; tests/oar_protocol_test.cpp pins it.
inline constexpr std::size_t max_cert_chain = 16384;
static_assert(max_cert_chain <= max_map_frame);

// Result of a request. Values are part of the wire protocol: never renumber.
enum class Status : std::uint8_t {
    ok = 0,
    unknown_function = 1,  // no such function on this role
    wrong_type = 2,        // the function is not of the type the request names
    bad_request = 3,       // the request body did not decode
    busy = 4,              // the function is in a state that cannot take the request
    failed = 5,            // the role tried and failed (cleaning error, bad map frame)
    unsupported = 6,       // this role does not implement the operation
};

// Which data-plane role answers on a slot. Values are wire protocol.
enum class Role : std::uint8_t {
    net = 1,
    blk = 2,
    gpu = 3,
    hold = 4,   // block volume replicas: no functions
    khold = 5,  // khold stripe group members (kythira khold-block-service): no functions
};

// Values are wire protocol.
enum class HealthState : std::uint8_t {
    ok = 0,
    degraded = 1,
    faulted = 2,
};

// What an eject request does. Values are wire protocol.
enum class EjectOp : std::uint8_t {
    request = 1,
    cancel = 2,
    query = 3,
};

// Where a function stands in a cooperative detach. Values are wire protocol.
enum class EjectState : std::uint8_t {
    none = 0,       // no eject requested
    requested = 1,  // requested; the guest still holds the device
    released = 2,   // the guest let go
};

// What a copy_volume request does. Values are wire protocol.
enum class CopyOp : std::uint8_t {
    start = 1,
    query = 2,
    release = 3,
};

// Which way a copy_volume goes. Values are wire protocol.
enum class CopyDirection : std::uint8_t {
    to_network = 1,  // the local volume into the network volume
    to_local = 2,    // the network volume into the local volume
};

// Where a copy stands. Values are wire protocol.
enum class CopyVolumeState : std::uint8_t {
    none = 0,  // no copy of this pair (never started, or released)
    copying = 1,
    completed = 2,  // every block copied and the target flushed
    failed = 3,
};

// Why a copy failed. Values are wire protocol.
enum class CopyVolumeFailure : std::uint8_t {
    none = 0,
    source_io = 1,
    target_io = 2,
    not_hydrated = 3,  // the network source still awaits hydration
    out_of_range = 4,
    crypto = 5,
};

[[nodiscard]] auto to_string(Status s) noexcept -> const char*;
[[nodiscard]] auto to_string(Role r) noexcept -> const char*;
// Whether a role takes part in enrollment: the storage roles (blk, hold,
// khold) and the network role, whose bulk channel (fleet-scale-networking
// Requirement 6.1) authenticates with its role certificate.
[[nodiscard]] constexpr auto enrolls(Role r) noexcept -> bool {
    return r == Role::blk || r == Role::hold || r == Role::khold || r == Role::net;
}
[[nodiscard]] auto to_string(HealthState h) noexcept -> const char*;

// Whether a role may report functions of `type`.
[[nodiscard]] auto role_serves(Role role, FunctionType type) noexcept -> bool;

enum class BodyError : std::uint8_t {
    truncated,          // shorter than the body's fixed size
    trailing_bytes,     // longer than the body's size
    reserved_not_zero,  // a reserved byte is set
    unknown_enum,       // function type, cleaning action, status, role or state out of range
    zero_id,            // vm_id, nic_id or volume_id is zero (ids are never zero)
    bad_vni,            // zero, or wider than 24 bits
    bad_mac,            // not a locally administered unicast MAC
    bad_vtep,           // zero for the net role, non-zero for any other
    type_mismatch,      // config does not match the function type, or role cannot serve it
    not_increasing,     // inventory entries not in strictly increasing fn order
    too_many_entries,   // inventory larger than max_inventory_entries
    bad_chunk,          // map_update total, offset or chunk length out of range
    status_with_body,   // a non-ok response carries bytes after its head
    bad_geometry,       // block size not 512/4096, or capacity zero, ragged or too large
    bad_key_length,     // wrapped key empty, too long, or not the length the body says
    zero_key,           // a tunnel private or public key is all zero
    bad_image,          // an image volume's image name is all zero
    bad_csr,            // a certificate request longer than max_csr
    bad_group,          // a membership's family is not 4 or 6, or an IPv4 group has a tail
};

[[nodiscard]] auto to_string(BodyError e) noexcept -> const char*;

// ---- Requests -------------------------------------------------------------

struct NicConfig {
    NicId nic_id{0};
    std::uint32_t vni{0};
    Mac mac{};

    friend auto operator==(const NicConfig&, const NicConfig&) -> bool = default;
};

struct BlkConfig {
    VolumeId volume_id{0};
    // A network volume's attachment (block-volume-service task 12): both
    // zero for a volume on the role's own media.
    std::uint64_t attachment_id{0};
    std::uint32_t generation{0};

    [[nodiscard]] auto network() const noexcept -> bool { return attachment_id != 0; }

    friend auto operator==(const BlkConfig&, const BlkConfig&) -> bool = default;
};

// monostate for GPU functions, which take no configuration.
using FunctionConfig = std::variant<std::monostate, NicConfig, BlkConfig>;

struct PrepareFunction {
    FunctionNumber fn{0};
    FunctionType type{FunctionType::nic_vf};
    VmId vm_id{0};
    FunctionConfig config;

    friend auto operator==(const PrepareFunction&, const PrepareFunction&) -> bool = default;
};

struct CleanFunction {
    FunctionNumber fn{0};
    CleaningAction action{CleaningAction::reset_nic_vf};

    friend auto operator==(const CleanFunction&, const CleanFunction&) -> bool = default;
};

// The key is a view: into the caller's ScopedKey when encoding, into the
// received message when decoding. The receiver copies it into its key slot
// and wipes the message (OarEndpoint does).
//
// An encrypted image volume (oar-blk Requirement 8.8, task 15) gets its
// image key K_img in the same request, after the attachment's ephemeral
// key: a 144-byte body instead of 80. A role that predates it refuses the
// longer body as the wrong size, so an encrypted image never attaches
// without its key.
struct DeliverKey {
    FunctionNumber fn{0};
    VolumeId volume_id{0};
    std::span<const std::byte, volume_key_size> key;
    std::optional<std::span<const std::byte, volume_key_size>> image_key;
};

struct DropKey {
    FunctionNumber fn{0};
    VolumeId volume_id{0};

    friend auto operator==(const DropKey&, const DropKey&) -> bool = default;
};

// The storage role's half of CREATE_VOLUME. `wrapped_key` views into the
// caller's blob when encoding, into the message when decoding.
struct CreateVolume {
    VolumeId volume_id{0};
    VmId owner_vm{0};
    std::uint64_t capacity_sectors{0};
    std::uint32_t block_size{sector_size};
    std::span<const std::byte> wrapped_key;
    std::uint16_t image_store{0};  // non-zero: an image volume
    ImageName image_name{};        // set exactly when image_store is
};

struct DeleteVolume {
    VolumeId volume_id{0};

    friend auto operator==(const DeleteVolume&, const DeleteVolume&) -> bool = default;
};

// REWRAP_VOLUME: the new owner and the key helm re-wrapped for it.
struct RewrapVolume {
    VolumeId volume_id{0};
    VmId owner_vm{0};
    std::span<const std::byte> wrapped_key;
};

// The network role's WireGuard keys. The key spans view into the caller's
// buffers when encoding, into the message when decoding; the receiver
// copies them during the call (OarEndpoint wipes the message after).
struct SetTunnelKey {
    std::span<const std::byte, tunnel_key_size> private_key;
    std::uint32_t grace_seconds{0};  // non-zero: a rotation keeping the old key this long
};

struct SetTunnelPeer {
    Vtep vtep{};
    std::span<const std::byte, tunnel_key_size> public_key;
    std::span<const std::byte, tunnel_key_size> psk;
};

struct RemoveTunnelPeer {
    Vtep vtep{};

    friend auto operator==(const RemoveTunnelPeer&, const RemoveTunnelPeer&) -> bool = default;
};

struct LeaseGrant {
    VolumeId volume_id{0};
    std::uint64_t epoch{0};

    friend auto operator==(const LeaseGrant&, const LeaseGrant&) -> bool = default;
};

struct ReportRequest {
    std::uint64_t ack{0};  // the last report read whole, or 0
    std::uint32_t offset{0};

    friend auto operator==(const ReportRequest&, const ReportRequest&) -> bool = default;
};

// One chunk of the role's oldest report. `chunk` views into the role's
// queue when encoding, into the message when decoding.
struct ReportChunk {
    std::uint64_t report_seq{0};
    std::uint32_t total{0};  // 0: nothing to report
    std::uint32_t offset{0};
    std::span<const std::byte> chunk;
};

// A storage role's answer to cert_request. `csr` views into the role's
// storage when encoding, into the message when decoding; empty: the role
// wants no certificate now.
struct CertAnswer {
    Role role{Role::blk};
    std::span<const std::byte> csr;
};

struct Eject {
    FunctionNumber fn{0};
    EjectOp op{EjectOp::query};

    friend auto operator==(const Eject&, const Eject&) -> bool = default;
};

// copy_volume. The keys are set exactly for start; they view into the
// caller's buffers when encoding, into the message when decoding.
struct CopyVolume {
    CopyOp op{CopyOp::query};
    CopyDirection direction{CopyDirection::to_network};
    std::uint32_t mib_per_s{0};
    VolumeId local_volume_id{0};
    VolumeId network_volume_id{0};
    std::uint64_t attachment_id{0};
    std::uint32_t generation{0};
    std::optional<std::span<const std::byte, volume_key_size>> local_key;
    std::optional<std::span<const std::byte, volume_key_size>> network_key;
};

struct CopyAnswer {
    CopyVolumeState state{CopyVolumeState::none};
    CopyVolumeFailure failure{CopyVolumeFailure::none};  // none unless failed
    std::uint64_t total_bytes{0};
    std::uint64_t done_bytes{0};
    std::uint64_t written_bytes{0};

    friend auto operator==(const CopyAnswer&, const CopyAnswer&) -> bool = default;
};

// One chunk of a MapUpdate frame. `chunk` views into the message.
struct MapChunk {
    std::uint32_t total{0};
    std::uint32_t offset{0};
    std::span<const std::byte> chunk;
};

[[nodiscard]] auto encode_prepare_function(const PrepareFunction& p)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_prepare_function(std::span<const std::byte> body) noexcept
    -> std::expected<PrepareFunction, BodyError>;

[[nodiscard]] auto encode_clean_function(const CleanFunction& c)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_clean_function(std::span<const std::byte> body) noexcept
    -> std::expected<CleanFunction, BodyError>;

// The returned buffer holds the key: the caller wipes it with secure_zero.
[[nodiscard]] auto encode_deliver_key(const DeliverKey& d)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_deliver_key(std::span<const std::byte> body) noexcept
    -> std::expected<DeliverKey, BodyError>;

[[nodiscard]] auto encode_drop_key(const DropKey& d)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_drop_key(std::span<const std::byte> body) noexcept
    -> std::expected<DropKey, BodyError>;

[[nodiscard]] auto encode_map_chunk(const MapChunk& m)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_map_chunk(std::span<const std::byte> body) noexcept
    -> std::expected<MapChunk, BodyError>;

[[nodiscard]] auto encode_create_volume(const CreateVolume& c)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_create_volume(std::span<const std::byte> body) noexcept
    -> std::expected<CreateVolume, BodyError>;

[[nodiscard]] auto encode_delete_volume(const DeleteVolume& d)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_delete_volume(std::span<const std::byte> body) noexcept
    -> std::expected<DeleteVolume, BodyError>;

[[nodiscard]] auto encode_rewrap_volume(const RewrapVolume& v)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_rewrap_volume(std::span<const std::byte> body) noexcept
    -> std::expected<RewrapVolume, BodyError>;

// The returned buffers of the first two hold keys: the caller wipes them.
[[nodiscard]] auto encode_set_tunnel_key(const SetTunnelKey& k)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_set_tunnel_key(std::span<const std::byte> body) noexcept
    -> std::expected<SetTunnelKey, BodyError>;

[[nodiscard]] auto encode_set_tunnel_peer(const SetTunnelPeer& p)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_set_tunnel_peer(std::span<const std::byte> body) noexcept
    -> std::expected<SetTunnelPeer, BodyError>;

[[nodiscard]] auto encode_remove_tunnel_peer(const RemoveTunnelPeer& r)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_remove_tunnel_peer(std::span<const std::byte> body) noexcept
    -> std::expected<RemoveTunnelPeer, BodyError>;

// replica_config and volume_op bodies: the frame itself, a view into the
// body. Only its size is checked here; the role decodes and verifies it.
[[nodiscard]] auto encode_replica_config_frame(std::span<const std::byte> frame)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_replica_config_frame(std::span<const std::byte> body) noexcept
    -> std::expected<std::span<const std::byte>, BodyError>;
// vpc_config bodies, the same way.
[[nodiscard]] auto encode_volume_op_frame(std::span<const std::byte> frame)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_volume_op_frame(std::span<const std::byte> body) noexcept
    -> std::expected<std::span<const std::byte>, BodyError>;

[[nodiscard]] auto encode_lease_grant(const LeaseGrant& g)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_lease_grant(std::span<const std::byte> body) noexcept
    -> std::expected<LeaseGrant, BodyError>;

[[nodiscard]] auto encode_report_request(const ReportRequest& r)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_report_request(std::span<const std::byte> body) noexcept
    -> std::expected<ReportRequest, BodyError>;

[[nodiscard]] auto encode_usage_request(std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_usage_request(std::span<const std::byte> body) noexcept
    -> std::expected<std::uint16_t, BodyError>;

// function_inventory and health requests have empty bodies.
[[nodiscard]] auto decode_empty(std::span<const std::byte> body) noexcept
    -> std::expected<void, BodyError>;

// ---- Responses ------------------------------------------------------------

struct InventoryEntry {
    FunctionNumber fn{0};
    FunctionType type{FunctionType::nic_vf};

    friend auto operator==(const InventoryEntry&, const InventoryEntry&) -> bool = default;
};

struct Inventory {
    Role role{Role::net};
    Vtep vtep{};
    std::vector<InventoryEntry> functions;  // strictly increasing fn

    friend auto operator==(const Inventory&, const Inventory&) -> bool = default;
};

struct Health {
    HealthState state{HealthState::ok};
    std::uint16_t fault_code{0};
    std::uint32_t uptime_seconds{0};

    friend auto operator==(const Health&, const Health&) -> bool = default;
};

// One NIC attachment's cumulative group meter, as a network role keeps it
// (oar-net VSwitch GroupUsage).
struct UsageEntry {
    NicId nic_id{0};
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

    friend auto operator==(const UsageEntry&, const UsageEntry&) -> bool = default;
};

struct UsagePage {
    std::uint16_t total{0};  // entries in the whole snapshot
    std::vector<UsageEntry> entries;

    friend auto operator==(const UsagePage&, const UsagePage&) -> bool = default;
};

// The role's side of group_usage paging. `snapshot` is called on cursor 0
// and returns every meter (attached NICs, then final readings of NICs
// detached since its last call, which it forgets). Final readings of a
// snapshot whose last page was never read are carried into the next one.
class UsagePager {
public:
    using Snapshot = std::vector<UsageEntry>;

    template<typename F>
    auto page(std::uint16_t cursor, F&& snapshot) -> std::expected<UsagePage, Status> {
        if (cursor == 0) {
            take(std::forward<F>(snapshot)());
        }
        return serve(cursor);
    }

private:
    auto take(Snapshot fresh) -> void;
    auto serve(std::uint16_t cursor) -> std::expected<UsagePage, Status>;

    Snapshot _snapshot;
    bool _open{false};  // a snapshot whose last page has not been served
};

// One NIC's snooped join of one multicast group (oar-net VSwitch
// Membership), as group_membership lists it.
struct MembershipEntry {
    NicId nic_id{0};
    std::uint32_t vni{0};
    bool ipv6{false};
    std::array<std::byte, 16> group{};  // IPv4 in the first four bytes, the rest zero

    friend auto operator==(const MembershipEntry&, const MembershipEntry&) -> bool = default;
};

struct MembershipRequest {
    std::uint16_t cursor{0};
    // The generation helm last read whole; cursor 0 with a matching
    // generation is answered "unchanged" without a snapshot.
    std::optional<std::uint32_t> since;

    friend auto operator==(const MembershipRequest&, const MembershipRequest&) -> bool = default;
};

struct MembershipPage {
    std::uint32_t generation{0};  // of the snapshot the page is from
    bool unchanged{false};        // only on cursor 0: total and entries are empty
    std::uint16_t total{0};
    std::vector<MembershipEntry> entries;

    friend auto operator==(const MembershipPage&, const MembershipPage&) -> bool = default;
};

// The role's side of group_membership paging. `generation` names the
// role's current join list (it changes whenever the list does); cursor 0
// answers unchanged when it equals the request's `since`, and otherwise
// takes a fresh snapshot from `snapshot`, which later pages are served
// from. A snapshot larger than max_memberships is cut to it.
class MembershipPager {
public:
    using Snapshot = std::vector<MembershipEntry>;

    template<typename F>
    auto page(const MembershipRequest& request, std::uint32_t generation, F&& snapshot)
        -> std::expected<MembershipPage, Status> {
        if (request.cursor == 0) {
            if (request.since == generation) {
                return MembershipPage{
                    .generation = generation, .unchanged = true, .total = 0, .entries = {}};
            }
            take(generation, std::forward<F>(snapshot)());
        }
        return serve(request.cursor);
    }

private:
    auto take(std::uint32_t generation, Snapshot fresh) -> void;
    auto serve(std::uint16_t cursor) -> std::expected<MembershipPage, Status>;

    std::uint32_t _generation{0};
    Snapshot _snapshot;
    bool _open{false};
};

// The role's side of hold_reports: the reports it has not yet seen helm
// read whole, oldest first, at most `limit` (older ones are dropped and
// counted: a status report supersedes them, and faults repeat).
class ReportQueue {
public:
    explicit ReportQueue(std::size_t limit = 1024) : _limit{limit} {}

    // `report` is an encoded proto::Report numbered `seq` (non-zero, never
    // repeated); empty or larger than max_role_report is refused.
    auto push(std::uint64_t seq, std::vector<std::byte> report) -> bool;
    // Drops the oldest report if it is `request.ack`, then answers with a
    // chunk of the oldest left (valid until the next call).
    auto serve(const ReportRequest& request) -> std::expected<ReportChunk, Status>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _reports.size(); }
    [[nodiscard]] auto dropped() const noexcept -> std::uint64_t { return _dropped; }

private:
    struct Entry {
        std::uint64_t seq{0};
        std::vector<std::byte> bytes;
    };
    std::size_t _limit;
    std::deque<Entry> _reports;
    std::uint64_t _dropped{0};
};

// A decoded response head. `body` is what follows it, empty unless status is ok.
struct ResponseView {
    Status status{Status::ok};
    std::span<const std::byte> body;
};

// A response with the given status and (only for ok) body.
[[nodiscard]] auto encode_response(Status status, std::span<const std::byte> body = {})
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_response(std::span<const std::byte> response) noexcept
    -> std::expected<ResponseView, BodyError>;

// Inventory and health bodies, as carried after an ok head.
[[nodiscard]] auto encode_inventory(const Inventory& inv)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_inventory(std::span<const std::byte> body)
    -> std::expected<Inventory, BodyError>;

// group_usage page bodies. decode checks the page against the cursor
// it answers.
[[nodiscard]] auto encode_usage_page(const UsagePage& page, std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_usage_page(std::span<const std::byte> body, std::uint16_t cursor)
    -> std::expected<UsagePage, BodyError>;
// group_membership bodies. decode_membership_page checks the page against
// the cursor that asked for it.
[[nodiscard]] auto encode_membership_request(const MembershipRequest& request)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_membership_request(std::span<const std::byte> body) noexcept
    -> std::expected<MembershipRequest, BodyError>;
[[nodiscard]] auto encode_membership_page(const MembershipPage& page, std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_membership_page(std::span<const std::byte> body, std::uint16_t cursor)
    -> std::expected<MembershipPage, BodyError>;
// group_members chunks use the map_update chunk format (MapChunk).

// hold_reports chunk bodies.
[[nodiscard]] auto encode_report_chunk(const ReportChunk& c)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_report_chunk(std::span<const std::byte> body) noexcept
    -> std::expected<ReportChunk, BodyError>;

// eject requests and answers.
[[nodiscard]] auto encode_eject(const Eject& e) -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_eject(std::span<const std::byte> body) noexcept
    -> std::expected<Eject, BodyError>;
[[nodiscard]] auto encode_eject_answer(EjectState s)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_eject_answer(std::span<const std::byte> body) noexcept
    -> std::expected<EjectState, BodyError>;

// copy_volume requests and answers. A start needs both keys and non-zero
// IDs, attachment and generation; query and release take no keys. An
// answer's failure is none unless its state is failed, and its done and
// written bytes never pass its total.
[[nodiscard]] auto encode_copy_volume(const CopyVolume& c)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_copy_volume(std::span<const std::byte> body) noexcept
    -> std::expected<CopyVolume, BodyError>;
[[nodiscard]] auto encode_copy_answer(const CopyAnswer& a)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_copy_answer(std::span<const std::byte> body) noexcept
    -> std::expected<CopyAnswer, BodyError>;

// cert_request answer bodies.
[[nodiscard]] auto encode_cert_answer(const CertAnswer& a)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_cert_answer(std::span<const std::byte> body) noexcept
    -> std::expected<CertAnswer, BodyError>;

[[nodiscard]] auto encode_health(const Health& h)
    -> std::expected<std::vector<std::byte>, BodyError>;
[[nodiscard]] auto decode_health(std::span<const std::byte> body) noexcept
    -> std::expected<Health, BodyError>;

}  // namespace ak::helm::oar
