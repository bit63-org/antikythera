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
  entries [] { nic_id u64, mac [6], owner_vtep [16] },
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
VTEP's supported tunnel modes (a bit set: WireGuard, PSP), seven reserved
bytes, and its WireGuard public key (all zero until helm has a key pair
for it; see "TunnelPeers"). Format 1 frames are refused.

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
(`max_groups_per_nic` may be zero until snooping is built) and within the
oar-net bounds. Per-subnet policies come with subnets: a later version
carries one entry per subnet. Phase 2 adds a `GroupMembers` frame (VNI,
version, per-group VTEP lists) built from snooped joins.

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

## TunnelPeers

oar-net carries VTEP-to-VTEP traffic inside WireGuard (oar-net
Requirement 5), and WireGuard needs each peer's public key. The keys are
distributed through the controller (Requirement 8):

1. helm generates an X25519 key pair for each VTEP when its network role
   attaches (`src/helm/tunnel_keyring.*`), hands the private key to that
   role (`set_tunnel_key`), and reports the public key in the inventory.
   Key pairs live as long as the helm process; nothing secret is
   persisted, and a new helm boot reports new keys.
2. The controller keeps every VTEP's public key and, for each VTEP, the set
   of VTEPs it shares a VNI with. Whenever that set or a key in it changes
   (a NIC attach that adds a VTEP to a VPC, a helm reboot), it sends the
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
up to that sequence), `tunnel_peers` (type 7, a TunnelPeers frame). Helm to controller: `hello` (`server_id u64 | boot_id
u64`, the first record on every connection) and `report`. Report sequence
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
local volumes. The first placement policy: volumes pin the server; otherwise
most free cores.

## Sequencing RunInstances

```
controller                       helm                hull
  CREATE_VOLUME (root)  ───────►  oar-blk prepares
  CREATE_VM             ───────►  ───────────────────► start VMM (paused)
  ATTACH_VOLUME         ───────►  deliver key ───────► hot-plug blk fn
  ATTACH_DEVICE (NIC)   ───────►  set VPC/MAC/NIC ID ► hot-plug VF
  MAP_UPDATE (VPC peers)
  start                  ───────────────────────────► resume VM
```

Each step is acknowledged before the next; failure triggers the
controller's compensation (destroy in reverse order).

## Where the code lives

| Piece | Repository |
|---|---|
| Envelope and MapUpdate codecs, signing test vectors | antikythera `src/proto/` (header-only, consumable by kythira; done) |
| helm's ControllerLink | antikythera |
| EC2 API, placement, Raft state | kythira `services/ec2/` |
