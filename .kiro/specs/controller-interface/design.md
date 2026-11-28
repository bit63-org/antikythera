# Design Document — Controller interface and the kythira EC2 integration

## Overview

```
 AWS CLI / SDK ──EC2 Query API──► kythira EC2 module (Raft, IAM, KMS/HSM)
                                     │ placement, ID allocation, signing
                                     │ mTLS management link
                                     ▼
                     helm (server 1) … helm (server N)
                         │ mailbox (signed slots)   │ sideband
                         ▼                          ▼
                        hull                       oars
```

## Envelope

```
Envelope {
  server_id    u64
  key_id       u16          // which controller key signed it
  slot         [256]byte    // exact mailbox slot image, signature included
}
MapUpdate {
  server_id u64, key_id u16, vni u32, map_version u64,
  entries [] { nic_id u64, mac [6], flags u8, owner_vtep [16] },
                            // flags bit 0: no source/destination check (v3)
  ipv4 [] { nic_id u64, address [4] },     // guest addresses (format v2)
  ipv6 [] { nic_id u64, address [16] },
  signature [64]            // Ed25519 over everything above
}
```

The byte layouts are in `src/proto/envelope.hpp` and
`src/proto/map_update.hpp` (little-endian, a magic and a format version
first). Both decoders are strict: exact length, non-zero server and key
IDs, zero reserved bytes. Encoders enforce the same rules, so the
controller cannot emit a frame helm would refuse. The codecs never sign or
verify; `src/proto/test_vectors.hpp` pins the exact bytes and signatures a
controller must produce under the RFC 8032 test keys.

A MapUpdate carries its own `key_id` (rotation, Requirement 1.3) and
`server_id`, both inside the signed bytes, since no slot header covers
them. It is a full snapshot of the VPC's mapping, not a delta, so applying
one is idempotent and a server that missed versions catches up from the
newest alone. Entries are in strictly increasing NIC ID order (a canonical
encoding with no duplicates), MACs must be locally administered unicast
(Requirement 4.2), owner VTEPs must be unicast IPv6 (IPv4-mapped allowed),
and a frame holds at most 4096 entries; a larger VPC needs a new format
version.

Format version 2 added the guest addresses oar-net's ARP/ND proxy answers
for: per address family, a list of `{nic_id, address}` in strictly
increasing address order (so each address belongs to one NIC and the
encoding stays canonical), each naming a NIC in the same frame's
entries, at most 8192 per family. Addresses must be unicast (IPv4 not
0.0.0.0 and below 224.0.0.0, IPv6 neither unspecified nor multicast). The
addresses ride in the mapping frame rather than a separate message so the
proxy can never answer for a NIC under a stale mapping, and one version
number covers both.

`key_id` and `server_id` are carried in the slot header as well, inside
the signed range `[0x00, 0xC0)`, so hull picks the verification key and
knows the command is meant for it without trusting the envelope wrapper.
Mailbox protocol version 2 put `key_id` in two of version 1's six
reserved header bytes (a little-endian u16 at slot offset 0x12). Version 3
grew the header from 24 to 32 bytes for a little-endian u64 `server_id`
at 0x18, after four reserved zero bytes, shrinking the body limit from
168 to 160 bytes. Commands must carry a non-zero `key_id` and
`server_id` (0 means "unsigned" and "never allocated"); responses and
events, which are not signed, must carry 0 in both. A slot that breaks
either rule fails `mailbox::decode`. The envelope's `key_id` and
`server_id` must equal the slot's, which `decode_envelope` checks, but
hull trusts only the slot.

hull checks the slot's `server_id` against its own provisioned identity
right after decoding, before the signature: a command signed for another
server is refused as `wrong_server` (a distinct outcome status) without
any crypto and without consuming a sequence number. Before version 3 the
envelope's `server_id` was not signed, so a command signed for one server
verified on any other whose sequence floor was lower, and only mTLS to
the right helm prevented replaying it there. A server ID in the slot was
chosen over per-server signing keys because it keeps one key table per
region and costs eight bytes of body.

Version 3 also gave `ATTACH_DEVICE` for a NIC VF the VPC (VNI), the
region-unique NIC ID and the guest MAC (32-byte body), which helm passes
to oar-net to prepare the VF; before, helm had to be configured with them
out of band. A GPU attach carries zeros there.

## Inventory and status reports

helm reports to the controller with `Report` frames
(`src/proto/report.hpp`): a 32-byte header (magic, format version, kind,
`server_id`, `report_seq`, `body_len`) and one body per kind.

| Kind | Body | Requirement |
|---|---|---|
| `inventory` | full snapshot: boot ID, last command sequence hull accepted, cores and 1 GiB pages (total, free), health, VTEPs with their tunnel public keys, every function with type/state/owner, VMs, local volumes, networks with applied mapping version | 3.1, placement inputs |
| `command_outcome` | hull's response: command sequence and type, status, optional payload | 3.2 |
| `pool_state` | one device-pool transition (function, from, to, VM) | 3.2 |
| `vm_exited` | a VM exit hull did not cause | 3.2 |
| `map_applied` | VNI and mapping version oar-net swapped in | 3.2, 5.3 |
| `host_fault` | hull's fault code, slot and detail | 3.2 |
| `group_usage` | cumulative per-NIC group meters (see "Multicast policy and usage") | 7.5 |
| `group_membership` | one network role's snooped multicast joins, whole (kind 16) | 7.9 |

Reports are not signed. mTLS authenticates helm, and the controller only
trusts a server about that server (Requirement 3.3). The inventory is a
snapshot rather than a delta, for the same reason MapUpdate is: after a
reconnect or a helm reboot the controller replaces what it knew about the
server with the newest inventory, with nothing to replay. `boot_id` is fresh
on every helm boot, so the controller can tell a reconnect (same boot ID:
report sequence numbers continue) from a reboot (new boot ID: they restart).
`last_command_seq` tells the controller where its per-server command
sequence resumes (Requirement 2.3).

Every list in an inventory is in strictly increasing key order and bounded
(8 VTEPs, 1024 functions, 512 VMs, 1024 volumes, 4096 networks), so the
encoding is canonical and the largest report is under 128 KiB. A function
names an owner VM exactly when it is `assigned` or `releasing`. Enum values
are helm's (`FunctionType`, `FunctionState`) and the mailbox's (`Status`,
`ExitReason`, `FaultCode`), pinned by `tests/proto_report_test.cpp`.

Report format 2 made each inventory VTEP entry 56 bytes: the address, the
VTEP's supported tunnel modes (a bit set: WireGuard, PSP), a
`tunnel_flags` byte, six reserved bytes, and its WireGuard public key
(all zero until helm has a key pair for it; see "TunnelPeers"). Format 1
frames are refused. `tunnel_flags` bit 0, `certified`, says the role
holds an unexpired controller credential for that public key
(fleet-scale-networking Requirement 3.5): the controller may stop
listing the VTEP's peers once every VTEP of a VNI sets it. The byte was
reserved and zero, so older helms send it clear.

## Multicast policy and usage

Requirement 7 and oar-net Requirement 10; the decision and its reasoning
are in `docs/vpc-gap-analysis.md` ("Broadcast and multicast").

```
GroupPolicy {                 // controller -> helm -> oar-net, signed;
                              // src/proto/group_policy.hpp, 0x80 bytes LE
  0x00 magic 'AKGP' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 server_id u64, 0x10 vni u32,
  0x14 mode u8 (0 drop, 1 multicast), 0x15 reserved [3],
  0x18 policy_version u64,    // per VNI, starts at 1, strictly increasing
  0x20 rate_frames u32, 0x24 burst_frames u32,
  0x28 rate_bytes u64, 0x30 burst_bytes u64,
  0x38 max_remote_vteps u32, 0x3C max_groups_per_nic u16, 0x3E reserved u16,
  0x40 signature [64]         // Ed25519 over bytes 0x00-0x3F
}```

Like MapUpdate it is a full per-VNI snapshot carrying its own server and
key IDs inside the signed bytes, so applying it is idempotent and a server
that missed versions catches up from the newest. A `drop` policy has
every limit zero; a `multicast` policy has every limit non-zero
(`max_groups_per_nic` may be zero, refusing every join) and within the
oar-net bounds. Per-subnet policies are version 2 (vpc-subnets-routing
design "GroupPolicy version 2"): one entry per opted-in subnet, each
with a `multicast` policy's limits, every other subnet in `drop`, under
the same `policy_version` sequence; the sideband op is chunked for it.

Snooping (Requirement 7.9) closes the loop. helm sends a
`group_membership` report with one network role's whole join list
(`slot`, then `(nic_id, vni, family, group)` entries, at most 1024,
ascending) whenever it changes, and an empty one when the role goes away,
so the controller can replace what it holds for that slot and a lost
report is healed by the next. The controller answers with a signed
`GroupMembers` frame per VPC, link record type 15:

```
GroupMembers {                // controller -> helm -> oar-net, signed;
                              // src/proto/group_members.hpp, LE
  0x00 magic 'AKGM' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 server_id u64, 0x10 vni u32, 0x14 group_count u16 (<= 512),
  0x16 reserved u16, 0x18 members_version u64,
  0x20 groups, ascending by (family, group):
       family u8 (4|6) | vtep_count u8 (1..64) | reserved [6] | group [16]
       vteps: vtep_count x [16], ascending
  then signature [64]         // Ed25519 over every byte before it
}```

At most 4,096 VTEP entries in all (77,920 bytes). Groups are IPv4
224.0.0.0/4 or IPv6 multicast other than solicited-node; VTEPs are
unicast. Like GroupPolicy it is a full per-VNI snapshot. A group not
listed is unknown and flooded to the whole VPC, so a frame never waits
for the controller.

The `group_usage` report body is `count u16 | rsvd [6]` then `count`
(at most 1024) entries of 96 bytes, in strictly increasing `(slot, nic_id,
attachment)` order. `slot` names the network role that holds the meter,
because NIC IDs are unique only per role:

```
nic_id u64 | vni u32 | flags u8 (bit 0: detached, final) | slot u8 | rsvd u16
attachment u64          // per oar-net run; with boot_id and slot, unique
frames u64 | bytes u64
replicas_remote u64 | replica_bytes_remote u64   // billable
replicas_local u64 | replica_bytes_local u64
drop_policy u64 | drop_rate u64 | drop_fanout u64
```

Billing keys a series by `(server_id, boot_id, slot, nic_id,
attachment)`. Counters only grow within a series, so the controller bills
`reading − previous reading` and a lost or replayed report only delays or
repeats a reading, never double-counts it. A new series (re-attach, oar-net
restart, helm reboot) starts from zero. Nothing is billed for a NIC whose
VNI was never opted in, though drops are still reported for visibility.
Enablement hours come from the controller's own record of when each
subnet's policy was in force.

## VpcConfig

Requirement 10 and oar-net Requirements 11.10 and 12. One frame per VPC
per server, like `GroupPolicy`. The current format is version 2, specified
in `.kiro/specs/vpc-subnets-routing/` design "VpcConfig version 2"
(`src/proto/vpc_config.hpp`, built by that spec's task 2): the VPC's CIDR
blocks, its subnets (ID, IPv4 prefix whose base + 1 is the gateway,
optional IPv6 /64, route table) and its route tables (`local` routes, one
per block, and NIC routes), with the per-VPC gateway MAC, DNS servers,
domain and lease time. Version 1, one VPC-wide prefix, gateway and route
list, is no longer accepted; nothing outside this repository spoke it.

Routes name NICs, not addresses or VTEPs. Only a NIC whose
source/destination check is off (oar-net Requirement 11.10, a per-NIC flag
in the mapping) can usefully receive traffic not addressed to it, and
each receiver resolves the NIC through its own signed mapping, so a frame
cannot point traffic at a server. A target missing from the receiver's
mapping matches nothing there instead of refusing the frame (Requirement
10.5): the controller sends `VpcConfig` and `MapUpdate` independently and
they may arrive in either order. Until the network role applies subnets
and route tables (vpc-subnets-routing tasks 4 and 5) it refuses a frame
with more than one subnet or table, or any route but `local`, whole
rather than half-apply it.

The largest frame is 139,581 bytes, so helm forwards it over OarLink in
chunks, like `GroupMembers` (vpc-subnets-routing task 3). The link record
is type 14; type 13 is `image_key` (oar-blk task 15). Clearing a VPC's
configuration is not a frame: a VPC keeps one from its first NIC's attach
until it is deleted, and a server that no longer hosts the VPC drops it
with the VNI's mapping.

## InstanceMetadata

Requirement 11 and oar-net Requirement 13. One frame per attached NIC,
sent to the server hosting it. The record holds only what the server
cannot derive: the NIC's MAC and addresses come from its signed mapping
entry and the subnet's prefix from `VpcConfig`, so the metadata service
answers them from the same frames the data plane enforces.

```
InstanceMetadata {            // controller -> helm -> oar-net, signed;
                              // src/proto/instance_metadata.hpp, LE
  0x00 magic 'AKIM' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 server_id u64, 0x10 nic_id u64, 0x18 metadata_version u64,
  0x20 vni u32, 0x24 http_endpoint u8 (0 disabled, 1 enabled),
  0x25 http_tokens u8 (0 optional, 1 required),
  0x26 put_hop_limit u8 (1..64), 0x27 device_index u8,
  0x28 launch_index u32, 0x2C user_data_size u16 (<= 16384),
  0x2E reserved u16, 0x30 pending_time u64 (Unix seconds),
  0x38 strings: instance_id, image_id, instance_type, account_id,
       local_hostname, availability_zone, region, interface_id, vpc_id,
       each { size u8 | bytes },
       user_data [user_data_size],
       signature [64]         // Ed25519 over every byte before it
}
```

Strings are 1 to 255 printable ASCII bytes without spaces, except that
`local_hostname` follows RFC 1123 host name syntax. The IDs keep EC2's
prefixes (`i-`, `ami-`, `eni-`, `vpc-`) because guests parse them. User
data is opaque bytes, served verbatim. The largest frame is 18,808 bytes
(nine 255-byte strings and 16 KiB of user data), so helm forwards it as
consecutive chunks like `MapUpdate`. The link record is type 16 (15 is
`group_members`).

A NIC keeps a record from before its attach until its detach, and a
server drops the NIC's record when the NIC is cleaned, so there is no
delete frame. An interface moved to another instance gets a new record
with a higher version before it is attached there; the server where it
was attached has dropped the old one at detach.

## TunnelPeers

oar-net carries VTEP-to-VTEP traffic inside WireGuard (oar-net
Requirement 5), and WireGuard needs each peer's public key. The keys are
distributed through the controller (Requirement 8):

1. helm derives an X25519 key pair for each VTEP when its network role
   attaches (`src/helm/tunnel_keyring.*`), from its secure element, the
   server ID, the role's slot and the slot's key epoch
   (fleet-scale-networking Requirement 1), hands the private key to that
   role (`set_tunnel_key`), and reports the public key in the inventory.
   Only the epochs are persisted (helm's `key-epochs` state file), so a
   helm reboot reports the same keys and the controller re-signs nothing.
   The controller changes a key with a `rotate_vtep_key` link record
   (number 35: `server_id u64 | slot u8 | rsvd [3] | key_epoch u32`,
   unsigned, on the authenticated link; an epoch at or below the one held
   is ignored). helm saves the new epoch, derives the new key, delivers it
   with a grace period (the 40-byte `set_tunnel_key`, default 10 minutes)
   in which the role keeps sessions made under the old key and answers
   handshakes still addressed to it, and reports the new public key, after
   which the controller sends the VTEP's peers new peer sets.

   The controller also certifies each key (fleet-scale-networking
   Requirement 2): helm reports a `credential_request` (report kind 31:
   slot, key epoch, VTEP, public key) whenever a network role holds no
   credential for its current key or the one it holds has a third of its
   life left, and the controller answers with a signed `vtep_credential`
   (link record 30, `src/proto/vtep_credential.hpp`, 160 bytes) binding
   the key to the server, slot, epoch, VTEP and cell for a validity
   window. `credential_revocations` (link record 31) is the cell's signed
   list of credentials revoked before they expire, a full snapshot by
   `list_version`. helm forwards both unmodified; the role verifies them.
   Peers exchange credentials before a handshake (task 3), so peer sets
   become optional at fleet scale.
2. The controller keeps every VTEP's public key and, for each VTEP, the set
   of VTEPs it shares a VNI with. Whenever that set or a key in it changes
   (a NIC attach that adds a VTEP to a VPC, a key rotation), it sends the
   VTEP a `TunnelPeers` frame (`src/proto/tunnel_peers.hpp`):

   ```
   0x00 magic 'AKTP' u32 | 0x04 version u16 (1) | 0x06 key_id u16
   0x08 server_id u64 | 0x10 vtep [16] | 0x20 peers_version u64
   0x28 peer_count u16 | 0x2A reserved [6]
   0x30 peers: peer_count x { vtep [16] | mode u8 | reserved [3] | spi u32 | key [32] },
        VTEPs ascending
   then Ed25519 signature [64] over every byte before it
   ```

   It is a full snapshot at `peers_version` (per server and VTEP, from 1),
   like a MapUpdate: idempotent, and a role that missed versions catches up
   from the newest alone. `key_id`, `server_id` and the target VTEP are
   signed, so a set cannot be replayed elsewhere. No peer is the target
   VTEP, no key is zero, no two WireGuard peers share a key, and at most
   2048 peers fit (112 KiB). Pre-shared keys are not distributed: peers
   installed this way have none.

   Each peer names its tunnel mode (Requirement 8.5). For `wireguard`,
   `key` is the peer's X25519 public key and `spi` is 0. `psp` is room for
   a later move to PSP NIC offload: `spi` would be the peer's receive SPI
   and `key` the AES-256-GCM key derived for this sender. The controller
   picks a mode per pair from what both VTEPs advertise, so a fleet moves
   to PSP one pair at a time and falls back to WireGuard where either end
   lacks it; a pair would switch with PSP keys pushed while WireGuard stays
   up, then a new peer set flipping its mode. The guest MTU is already
   budgeted for the larger PSP overhead (oar-net Requirement 6.3), so that
   switch never changes a guest's MTU. Nothing implements PSP today: VTEPs
   advertise only WireGuard, and a role refuses a peer set with a PSP peer.
   PSP keys are secrets, so the frames carrying them will need wiping
   wherever they are held.
3. helm checks the frame's shape and server (ControllerSession), keeps the
   newest frame per VTEP, and forwards it unmodified over the sideband
   (`tunnel_peers`, chunked like `map_update`). It re-sends the key and the
   newest frame whenever the role restarts. It verifies nothing; a frame
   with the same version but other bytes replaces the one held, so a
   refused frame never shadows the real one.
4. The role (`src/oar/net/tunnel_peers.*`, `TunnelPeerSet`) decodes the
   frame, checks it names its server and VTEP, verifies the signature with
   the controller keys it also uses for MapUpdates, ignores a re-delivery
   of the version it applied, refuses an older one, and replaces the peers
   it installed from earlier frames with the frame's. Unchanged peers keep
   their WireGuard sessions.

## Link framing

The mTLS stream carries records (`src/proto/link.hpp`): `length u32 | type
u16 | reserved u16 | payload`. Controller to helm: `envelope`, `map_update`, `group_policy`,
`report_ack` (`server_id u64 | report_seq u64`, acknowledging every report
up to that sequence), `tunnel_peers` (type 7, a TunnelPeers frame), and the
block volume records `replica_config`, `volume_op`, `volume_key`, `lease_grant` and
`role_certificate` (types 8 to 12, `.kiro/specs/block-volume-service/`),
`image_key` (type 13, an encrypted image's key for the image volume a
CREATE_VOLUME is about to create, `.kiro/specs/oar-blk-data-plane/` task 15),
`vpc_config` (type 14, a VpcConfig frame), `group_members` (type 15,
a GroupMembers frame), `instance_metadata` (type 16, an
InstanceMetadata frame), and from fleet-scale-networking `vtep_credential`
(type 30), `credential_revocations` (type 31), `frame_notice` (type 33:
`server_id u64` then a 56-byte FrameNotice, `src/proto/frame_notice.hpp`,
unsigned since the fetched frame is checked against its digest and its own
signature) and `rotate_vtep_key` (type 35); 19-29, 32 and 34 are reserved
by other specs and refused until built. Helm to controller: `hello` (`server_id u64 |
boot_id u64`, the first record on every connection) and `report`. Report sequence
numbers restart when helm reboots, so the controller keys them by the
connection's boot ID and drops any `(boot_id, report_seq)` it has already
processed; that makes helm's replay after a reconnect idempotent. The framing only
delimits; each payload goes to its own strict decoder, and a record in the
wrong direction is a protocol error. A record header announcing more than
the largest frame (a full MapUpdate, about 128 KiB) ends the connection
before any payload is buffered.

## ControllerLink

helm's side of the link is `src/helm/controller_link.{hpp,cpp}`, in two
layers. `ControllerSession` is the protocol with no I/O, tested byte by
byte. `ControllerLink` drives a session over `ak::tls` (`src/tls/`): TLS 1.3
only, both sides present certificates, helm trusts only kythira's CA and
checks the controller's DNS or IP name, the controller trusts only the CA
that issues server certificates and may pin a server's name. No session
resumption, so every connection re-authenticates both sides.

On every connection helm sends `hello`, then every report the controller
has not acknowledged (original order and sequence numbers), then a fresh
inventory with the newest sequence number. An unacknowledged older
inventory is dropped rather than replayed: the new one supersedes it. The
controller processes reports in order, drops `(boot_id, report_seq)` pairs
it has seen, and acknowledges the highest it processed; helm then forgets
everything up to it. Unacknowledged reports are capped at 4096; past that
the oldest are dropped and counted, and the next inventory restates the
state they described.

helm checks each envelope, MapUpdate and TunnelPeers frame strictly and
that it names this server, then passes it on unmodified (the slot to the
mailbox, the exact MapUpdate and TunnelPeers bytes to the network roles
that verify them). It verifies no signatures. Any
protocol violation (malformed record, a record type only helm sends, a
frame for another server, an ack for a report never sent) closes the
connection; helm reconnects with capped exponential backoff (1 s to 60 s,
up to 25% jitter) and re-registers. Losing the link touches nothing on the
host: only controller envelopes reach the mailbox (Requirement 2.3).

The process ignores SIGPIPE, since OpenSSL writes to the socket with
`write(2)`.

## Placement inputs

From inventory: free whole cores, free 1 GiB pages, free functions by type,
local volumes. Local volumes pin the server; network volumes do not
(Requirement 6.2), so an instance with only network volumes goes to the
server with most free cores and a free blk function per attachment.
Replica placement for network volumes is block-volume-service's
(failure domains, reference model `ak_hold_master`), independent of where
the instance runs.

## Sequencing RunInstances

```
controller                       helm                hull
  CREATE_VOLUME (root)  ───────►  oar-blk prepares
  CREATE_VM             ───────►  ───────────────────► start VMM (paused)
  ATTACH_VOLUME         ───────►  deliver key ───────► hot-plug blk fn
  InstanceMetadata      ───────►  to the NIC's network role
  ATTACH_DEVICE (NIC)   ───────►  set VPC/MAC/NIC ID ► hot-plug VF
  MAP_UPDATE (VPC peers)
  start                  ───────────────────────────► resume VM
```

Each step is acknowledged before the next; failure triggers the
controller's compensation (destroy in reverse order).

For an `Ebs` root volume, `CREATE_VOLUME` is not a mailbox command: the
controller places the replica set and publishes its ReplicaConfig, waits
for every member's `replica_status`, then sends the instance's server
the ReplicaConfig and `VolumeKey` before `ATTACH_VOLUME`. The AMI's root
is restored as a foreign-key image hydrated by oar-blk, so the VM can
boot before hydration finishes.

## Network volumes in EC2

Requirement 9 in tables. Names in `code` on the right are
block-volume-service's (`src/proto/replica_config.hpp`,
`src/proto/report.hpp`).

### Parameters

| EC2 parameter | Network volume |
|---|---|
| `VolumeType` `gp2`, `gp3` | class `general`: 2 replicas; gp3 defaults 3000 IOPS and 125 MiB/s; gp2's size-derived IOPS become fixed QoS numbers |
| `VolumeType` `io1`, `io2` | class `provisioned`: 3 replicas; `Iops` required |
| `VolumeType` `st1`, `sc1`, `standard` | `UnsupportedOperation` |
| `Size` (GiB) | `capacity_blocks = Size × 2³⁰ / block_size`, `block_size` 512 (what EBS presents) |
| `Iops`, `Throughput` | `qos.iops`, `qos.mib_per_s`; bursts from class policy; values beyond the class maximum: `InvalidParameterValue` |
| `SnapshotId` | `source {snapshot}`; same lineage, or a new lineage with oar-blk hydration when `KmsKeyId` differs |
| `VolumeInitializationRate` | `source.hydrate_mib_per_s` (else the controller default) |
| `MultiAttachEnabled` | flag `multi_attach`; `provisioned` only |
| `Encrypted`, `KmsKeyId` | always encrypted, per-lineage KMS key optionally protected by `KmsKeyId` (Requirement 6.3) |
| `AvailabilityZone` | the region's one zone; any other is `InvalidParameterValue` |
| `OutpostArn` | `UnsupportedOperation` |
| `Device` (`AttachVolume`) | recorded and reported; the guest sees virtio-blk devices in attach order, as Nitro guests see NVMe, so the name is a label |

### Volume states

| EC2 `State` | Controller condition |
|---|---|
| `creating` | placed, epoch 1 published, not every member has reported `replica_status`; with fast restore, until hydration completes |
| `available` | every member reported, no attachment |
| `in-use` | at least one attachment in any state but `detached` |
| `deleting` | `delete_replica` sent, not every `op_outcome` back |
| `deleted` | every member reported `delete_replica` done; the record is kept for `DescribeVolumes` for an hour |
| `error` | placement found no failure-domain-diverse members, a member failed to create its replica, or KMS refused the key |

### Attachment states

| EC2 attachment `State` | Condition |
|---|---|
| `attaching` | attachment in the published ReplicaConfig, `ATTACH_VOLUME` not yet answered |
| `attached` | hull answered `ok`; `attachment_status` `attached` |
| `detaching` | `DETACH_VOLUME` (`wait`) relayed or the forced path's fencing epoch published; `eject_requested`, or `fenced` before the unplug |
| `busy` | `DETACH_VOLUME` answered `busy` / `attachment_status` `busy`: the guest still holds the disk; it stays attached and serving |
| `detached` | hull answered `ok` to the unplug and the controller published the epoch that retires the generation |

### Status checks

| `VolumeStatus` | Condition |
|---|---|
| `ok` | a primary with a current lease and at least the class's replication factor in sync |
| `warning` | serving, but fewer in-sync replicas than the class's factor (rebuild queued or running), or hydration still running on a non-fast-restored volume |
| `impaired` | `io_suspended` or `impaired` in the newest ReplicaConfig; event `potential-data-inconsistency`, action `enable-volume-io` unless `AutoEnableIO` already ran it |
| `insufficient-data` | `creating`, or no report from the primary's server within the 10 s report timeout |

`DescribeVolumeStatus` also reports the `io-enabled` and
`io-performance` details: `io-performance` is `degraded` while the
primary reports time throttled below the provisioned rate (Requirement
10.5 counters) for a sustained minute.

### Operations

| EC2 action | Steps |
|---|---|
| `ModifyVolume` | new epoch with new `capacity_blocks` (members extend first, then initiators raise the config change) and QoS; replica-count change = add `joining` members or retire members as a move; modification `modifying` → `optimizing` (rebuilds) → `completed` |
| `EnableVolumeIO` | promote the most up-to-date surviving replica at a new epoch, clear `io_suspended`, record a possible-loss event |
| `CreateSnapshot` | `VolumeOp` `snapshot_prepare` / `snapshot_commit` / `snapshot_upload` on one volume; snapshot ID ↔ manifest name kept by the controller |
| `CreateSnapshots` | multi-volume cut over the instance's network volumes; one snapshot per volume, same cut |
| `DeleteSnapshot` | delete the manifest, mark-and-sweep the lineage's chunks |
| `EnableFastSnapshotRestores` | flag per (snapshot, zone): `enabling` → `enabled` at once, since fast restore is a creation-time behaviour here; a creation-credit bucket per snapshot bounds the hydration load it can cause |
| `CopyVolumes` | `VolumeOp` `clone` on every member after a cut; new volume ID, same lineage; size or QoS changes applied as a `ModifyVolume` after |
| `TerminateInstances` | `DESTROY_VM`; retire every attachment's generation; `DeleteVolume` for those with `DeleteOnTermination` |
| `StopInstances` / `StartInstances` | `DESTROY_VM {persist_volumes = true}` and retire the generations / place anywhere, new generations, `VolumeKey` per attachment, `ATTACH_VOLUME` each |

The mailbox sees only `ATTACH_VOLUME`, `DETACH_VOLUME` (with
`DetachPolicy` `wait = 3`), `WITHDRAW_DETACH`, `CONVERT_VOLUME` and the
VM commands;
everything else is ReplicaConfig, VolumeOp, VolumeKey and reports on the
controller link. `WITHDRAW_DETACH` cancels a `busy` detach's request to
the guest and returns the attachment to `attached`. EC2 has no action
for that (a `busy` attachment stays so until the guest lets go or a
forced detach), so the EC2 mapping never sends it; it is there for
controllers and tools that let a caller abandon a detach, and for
reconciliation after a controller decides not to detach after all.

`CONVERT_VOLUME` (type `0x0026`, 32 bytes: `local_volume_id u64 |
owner_vm u64 | network_volume_id u64 | direction u8 (1 to_network, 2
to_local) | rsvd u8 | rsvd u16 | mib_per_s u32`) moves a volume between
local and network storage (block-volume-service Requirement 8.6). The
controller creates the target first (`CREATE_VOLUME`, or a network
volume with a utility attachment for the local volume's server and its
`VolumeKey`), and for a restored network source waits until
`hydrated_bytes` equals `total_bytes`. The command's outcome says only
that the copy was accepted; its progress and end arrive as
`conversion_progress` reports (kind 20: both volume IDs, `total_bytes`,
`done_bytes`, `written_bytes`, direction, state `copying` / `completed` /
`failed`, failure, slot). After `completed` the controller switches the
instance's records to the new volume and deletes the old one; after
`failed` it deletes the target. Either way it retires the utility
attachment.

## Where the code lives

| Piece | Repository |
|---|---|
| Envelope and MapUpdate codecs, signing test vectors | antikythera `src/proto/` (header-only, consumable by kythira; done) |
| helm's ControllerLink | antikythera |
| EC2 API, placement, Raft state | kythira `services/ec2/` |
