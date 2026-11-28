# Design Document — Network control at fleet scale

## Overview

```
                     kythira EC2 controller (ec2-controller-scale)
       signs once per VPC change ──► VpcStream deltas / snapshots ──► frame store
       signs once per VTEP/day   ──► VtepCredential, revocation list      (fleet tier,
                                                                          content-addressed)
             │ controller link: credentials, notices, small frames          ▲
             ▼                                                              │ HTTPS GET by digest
           helm ── OarLink (SMBus): keys, commands, notices, small frames   │ (mTLS, dial-out only)
             │                                                              │
             ▼                                                              │
       network role ────────────── bulk channel (control address on the ───┘
         StreamApplier → per-VNI persistent tables → VSwitch, router, SGs
         Tunnel: list peers + certified peers (credential exchange, cache)
         lookups for `lookup` VNIs
```

Three ideas carry the spec:

1. **Prove identity in the handshake instead of distributing peer lists.**
   A VTEP's key is certified once a day by the controller; peers exchange
   credentials on first contact. Peer lists, and their 2,048 cap, become
   optional.
2. **Describe a VPC once, as a stream.** One signature per change, one
   small delta per change, applied atomically; snapshots only to start or
   recover.
3. **Move bytes on Ethernet, decisions on SMBus.** helm keeps the
   sideband for keys, commands and notices; the role pulls signed bulk
   frames itself.

## Decisions

- **Keep WireGuard's handshake and add a credential message beside it**,
  rather than replacing it with IKEv2 or a new Noise pattern. WireGuard's
  initiator must know the responder's static key before it can send an
  initiation, and the responder learns the initiator's key only from the
  initiation, so both sides need each other's key first. A credential
  exchange gives them that, signed, and leaves the four WireGuard message
  types and the Linux interop test untouched. The cost is one extra round
  trip on first contact with a peer, after which credentials are cached
  for their lifetime.
- **Credentials are compact controller-signed records, not X.509.** They
  are verified with the same Ed25519 controller keys as every other
  frame, fit in one packet (160 bytes), and need no ASN.1 parser in the
  data path. A cell scope in the record lets `fleet-cells` delegate
  signing per cell without a format change.
- **Authorization stays in the mapping.** A certified peer is only "a
  VTEP of this fleet". Whether it may send a frame for VNI V from NIC N
  is still `check_ingress` against the signed mapping's `owner_vtep`, so
  certification adds no authority. This is why a peer list is not needed
  for safety: it never was the authorization.
- **Streams reuse the edge table's container.** `vpc-internet-gateways`
  already defined snapshot parts, ordered deltas, holds and gaps for the
  edge table; VPC streams use the same rules with typed records, so the
  sequence logic is written and fuzzed once.
- **Persistent tables, not copies.** Applying a delta must look atomic
  to forwarding, but copying a 1 M-entry table per delta is too slow. Each
  VNI's tables are persistent (structure-sharing) maps; a delta builds a
  new root and the data-plane thread swaps one pointer between packet
  batches, as `MappingTable` swaps snapshots today.
- **Reused VNIs carry an incarnation.** Reuse is safe only if a role can
  never merge state from the VNI's previous VPC. The incarnation is in
  the signed bytes of every stream frame; a newer incarnation wipes the
  VNI's state first.

## Stable VTEP keys

`TunnelKeyring` derives each VTEP's private key instead of generating it:

```
seed = SE.derive("antikythera vtep key v1" | server_id u64 | slot u8 | key_epoch u32)
priv = X25519 clamp(seed[0..32])
```

The secure element (or software secure element) does the derivation from
its master key, as it already derives the transport key. `key_epoch`
starts at 1 and is raised only by a controller `rotate_vtep_key` op (a
small link record, below); helm keeps the epoch in its state file
(`key-epochs`, one `vtep-key-epoch SLOT EPOCH` line per rotated slot). An
epoch is 1 to 65,535 so it fits the credential's 16-bit field. During
a rotation the role holds both keys: new handshakes use the new key once
its credential is installed, sessions on the old key run until their
WireGuard rekey or the grace period (10 minutes) ends, whichever is
first. A re-provisioned server has a new master key and therefore new
keys at every epoch.

Built in task 1: `SecureElement::derive_vtep_key`, `KeyEpochs` and
`TunnelKeyring::rotate` in helm; the `rotate_vtep_key` record (35:
`server_id u64 | slot u8 | rsvd [3] | key_epoch u32`, unsigned like
`self_test`, since it carries no key and only moves an epoch forward);
the 40-byte `set_tunnel_key` (`private_key [32] | grace_s u32 | rsvd
u32`) rather than a new vendor type, so a role that predates it answers
`bad_request` and helm falls back to the plain key; and
`Tunnel::rotate_private_key` in the role. The role abandons its own
in-flight initiations at a rotation (their responses would be keyed to
the old static key) and answers initiations whose mac1 names the old key
until the grace ends, when every session made under the old key is
dropped (`retired_sessions`). Until task 3 installs credentials, new
handshakes use the new key at once.

## VTEP credentials

```
VtepCredential {              // controller -> helm -> network role, signed;
                              // src/proto/vtep_credential.hpp, 160 bytes LE
  0x00 magic 'AKVC' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 server_id u64, 0x10 cell_id u32 (0: no cells), 0x14 modes u8
  (bit 0 WireGuard, bit 1 PSP), 0x15 slot u8, 0x16 key_epoch u16,
  0x18 vtep [16], 0x28 public_key [32],
  0x48 not_before u64, 0x50 not_after u64 (Unix seconds),
  0x58 serial u64,            // per cell, increasing; revocations name it
  0x60 signature [64]         // Ed25519 over bytes 0x00-0x5F
}
CredentialRevocations {       // per cell, signed, full list (it is small)
  0x00 magic 'AKCR', version (1), key_id, 0x08 cell_id u32, rsvd u32,
  0x10 list_version u64, 0x18 count u32 (<= 65,536), rsvd u32,
  0x20 entries x count { serial u64 | not_after u64 }, ascending by serial,
  signature [64]
}
```

helm asks for a credential with a `credential_request` report (kind 31:
`slot u8 | rsvd [3] | key_epoch u32 | public_key [32]`), on every
connection, at key rotation, and when the current credential has less
than a third of its life left. The controller answers with link record
30 (`vtep_credential`) and keeps the cell's revocation list current with
link record 31 (`credential_revocations`); helm forwards both to the role
(vendor types 0x31 and 0x32). An entry leaves the list once its
`not_after` has passed, so with 24-hour credentials the list holds at most
a day of revocations.

## Certified handshake

Tunnel messages keep WireGuard's framing (`type u8 | reserved [3]`). One
type is added in the range WireGuard leaves unused:

```
credential (type 0x10): flags u8 (bit 0: send me yours) | reserved [2]
                        | VtepCredential [160]
```

```
initiator I                                   responder R
  no credential of R cached:
  credential{flags=1, cred_I}  ─────────────►  verify cred_I (rate limit,
                                               cache), names the outer source?
                               ◄─────────────  credential{flags=0, cred_R}
  verify cred_R, names R's address?
  handshake initiation (WireGuard) ─────────►  decrypt static key; cached
                                               credential for that key, valid,
                                               not revoked, address matches?
                               ◄─────────────  handshake response
  transport data ...
```

- **Verification** checks magic, version, key ID among the controller
  keys, signature, the validity window against the role's clock with a
  configured skew allowance (default 5 minutes), the revocation list, and
  that `vtep` equals the outer source address the message came from.
  Results go into a `CredentialCache` keyed by public key (65,536
  entries, LRU), so a credential is verified once per cache lifetime.
- **Cost bounds.** Unknown-credential verifies are rate limited per
  source address (default 16/s) and per role (default 2,000/s, about a
  tenth of a core); past the role limit, credentials from sources with no
  existing session are dropped and counted. Handshake initiations keep
  WireGuard's mac1/mac2 and cookie reply, which now apply after the
  credential exchange since the initiator knows R's key.
- **Peer state** (`Tunnel` peer record, sessions, counters) is created at
  the first accepted handshake and reclaimed 5 minutes after its last
  session expires, so memory follows active peers.
- **Coexistence.** `TunnelPeerSet` and `set_tunnel_peer` peers are looked
  up first; a key found there is accepted without a credential, as today.
  A key with neither a list entry nor a valid credential is refused
  (`handshake_drop_uncertified`). The inventory VTEP entry gains mode bit
  2, `certified`, in one of its reserved bytes; the controller moves a
  VNI's VTEPs off `TunnelPeers` only when all of them set it, and back by
  sending `TunnelPeers` again.
- **Expiry and revocation.** On credential expiry or revocation the role
  drops the peer's sessions and cache entry; the peer must present a new
  credential. Renewal with the same key keeps sessions.

PSP, when it comes, uses the same credential: the receiver derives a
per-SPI key from a device key, and the credential exchange is where the
sender learns the SPI and derived key over the authenticated session.

## VPC streams

```
VpcStream {                   // controller -> frame store / helm -> role, signed;
                              // src/proto/vpc_stream.hpp, LE
  0x00 magic 'AKVS' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 vpc_id u64, 0x10 vni u32, 0x14 incarnation u32,
  0x18 cell_scope u32 (0: every cell), 0x1C kind u8 (1 snapshot part, 2 delta),
  0x1D flags u8 (bit 0: lookup VNI), 0x1E part u16, 0x20 part_count u16,
  0x22 reserved [6], 0x28 snapshot_id u64, 0x30 from_sequence u64,
  0x38 to_sequence u64, 0x40 record_count u32, 0x44 records_len u32,
  0x48 records: { type u8 | op u8 (1 put, 2 remove) | len u16 | body [len] }
  signature [64]              // Ed25519 over every byte before it
}
```

Sequence rules are the edge table's: a snapshot is `part_count` parts
with one non-zero `snapshot_id`, consistent at `to_sequence`; a delta
covers `from_sequence ..= to_sequence`. A part is at most 295,032 bytes
(`proto::max_record_payload`), so a 4,096-part snapshot holds well over a
million NICs.

| Type | Record | Key | Body (bytes) |
|---|---|---|---|
| 1 | NIC binding | nic_id | nic_id, mac, flags, subnet_id, owner_vtep (40) |
| 2 | IPv4 address | address | address, nic_id (12) |
| 3 | IPv6 address | address | address, nic_id (24) |
| 4 | VPC settings | — | gateway MAC, blocks, DNS, domain, lease (VpcConfig v3 header fields) |
| 5 | subnet | subnet_id | as VpcConfig v3 subnet |
| 6 | route table | table_id | table header |
| 7 | route | table, prefix | as VpcConfig v3 route (incl. `igw`/`eigw`/NAT kinds) |
| 8 | gateway | gateway_id | as VpcConfig v3 gateway |
| 9 | NAT port block | gateway, server_id, port | owner server and first port |
| 10 | security group | group_id | group header |
| 11 | SG rule | group, direction, rule bytes | as SecurityPolicy rule |
| 12 | membership | nic_id | up to 16 group IDs |
| 13 | tracking setting | nic_id | as SecurityPolicy tracking entry |
| 14 | group policy | subnet_id | as GroupPolicy v2 entry |
| 15 | group member list | family, group | VTEP list |
| 16 | lookup interest | nic_id | marks a NIC the role must hold in a `lookup` VNI |

Records in a snapshot part are in ascending (type, key) order; records in
a delta are in change order. A remove carries only the key.

`StreamApplier` (`src/oar/net/stream_applier.*`) owns, per VNI, the
incarnation, the applied sequence, at most 64 held deltas and a timer.
On a gap held for 5 s it raises `need_snapshot` in `stream_status`; the
controller (or helm, holding the newest snapshot) re-sends one. Applying
a delta validates every record against the post-delta state (an address
naming a missing NIC, two NICs with one MAC, a route to an unknown table,
a budget exceeded) and refuses the whole delta if any fails, leaving the
VNI at its old sequence with `stream_refused` counted: the controller has
a bug, and half-applying would be worse.

### Persistent tables

`VniState` holds HAMT-style persistent maps (32-way, path copying) for
NIC bindings, addresses and memberships, and compiles route tables and
rules per subnet as today. A delta of k records copies O(k log n) nodes;
the new `VniState` root is published to the data-plane thread through the
existing snapshot pointer. Route tries and rule buckets are rebuilt only
for the subnets a delta touches.

### Snapshot frames and streams side by side

A VNI is in one of two modes in the role: `frames` (today's
`MapUpdate`, `VpcConfig`, `SecurityPolicy`, `GroupPolicy`,
`GroupMembers`) or `stream`. The first complete stream snapshot moves it
to `stream` and discards frame state; a snapshot frame whose version is
higher than the last applied frame version moves it back. The controller
chooses per VNI, so a fleet moves VPC by VPC and can move back.

### Reused VNIs and MACs

- VPC ID and VNI are separate fields everywhere a stream frame names a
  VPC. `InstanceMetadata` already carries `vpc_id` as a string; nothing
  else changes.
- A stream frame with incarnation greater than the held one wipes the
  VNI (NICs detached from it are already gone: the controller frees a VNI
  only after every server reported not holding it) and starts over.
- MACs are checked unique per VNI in `StreamApplier`. `VSwitch` was
  already per VNI, so nothing in forwarding assumed region-wide MACs. The
  gateway MAC is a VPC settings field and must differ from every NIC MAC
  in the VNI.

## Bulk channel

```
FrameNotice {                 // controller link record 33 / vendor type 0x33
  kind u8 (1 vpc_stream, 2 edge_mapping, 3 security_policy, ...)
  rsvd [3] | vni_or_scope u32 | sequence_or_version u64
  size u32 | rsvd u32 | sha256 [32]
}
```

- **Address.** The network role gets a control address on its underlay
  port (from the role's configuration, like the VTEP address) and
  marks bulk traffic CS6. It dials only frame-store addresses helm passes
  it with the notice batch; it listens on nothing for this.
- **Identity.** The role enrolls for a role certificate with the existing
  `cert_request` flow, role kind `net` added to `StorageRole`'s
  neighbour enum (block-volume-service design "Enrollment"), naming its
  server and control address.
- **Fetch.** `BulkFetcher` (`src/oar/net/bulk_fetch.*`) runs HTTP/1.1 over
  TLS 1.3 (`ak::tls`), `GET /v1/frames/<sha256-hex>`, response body
  exactly `size` bytes, digest checked before decode, then the frame's
  own decoder and signature check. Retries with backoff across the
  listed endpoints; after a configured failure count it asks helm to
  fall back to OarLink chunks for that notice.
- **OarLink scheduling.** helm's per-link queue gets three classes:
  control (keys, commands, credentials, revocations, lease traffic,
  notices), status polls, and bulk chunks. A bulk transfer sends one
  chunk per turn and always lets a waiting control message go first, so
  one 128 KiB frame never holds a lease renewal for seconds. Frames above
  16 KiB go by notice whenever the role reports the bulk channel up.

## Lookups for very large VPCs

A VNI flagged `lookup` holds its local NICs, the NICs named by
`lookup interest` records (the controller's choice: same subnet, SG
peers, recent talkers), and the VPC settings, subnets, routes and SG
rules (small). For any other destination the role asks the frame store:

```
GET /v1/lookup/<vni>/<incarnation>/<ipv4|ipv6|mac>/<address>
MapEntry {                    // signed record, src/proto/map_entry.hpp
  magic 'AKME', version (1), key_id, vni u32, incarnation u32,
  sequence u64,               // stream sequence it is current at
  not_after u64,              // cache bound (default now + 60 s)
  binding (record type 1 body) | addresses (types 2, 3) | membership (type 12)
  signature [64]
}
```

A negative answer is a signed `MapEntry` with no binding. Cached entries
are dropped when a delta removes or changes their NIC (deltas still
carry every NIC change of the VNI, which costs one small record per
change, so invalidation is exact). Unknown destinations queue up to 4
packets per destination and 1,024 per role for at most 100 ms, then drop
(`lookup_queue_drop`). The receiving VTEP looks up the source NIC the
same way before `check_ingress` and `rx_drop_route_mismatch` checks, so
receive never trusts what it cannot verify.

## Edge groups

```
EdgeGroup {                   // controller link record 34, per cell, signed
  magic 'AKEG', version (1), key_id, cell_id u32, group_id u32,
  group_version u64, role_count u16 (<= 1024), prefix_count u16 (<= 4096),
  roles: role_count x { vtep [16] | flags u8 | rsvd [7] }
  prefixes: prefix_count x { family u8 | length u8 | rsvd [6] | prefix [16] }
  signature [64]
}
```

- Hosts receive their group's `EdgeGroup` and pick an edge role per flow
  by rendezvous hashing among the listed roles their tunnel reports up,
  replacing the `edge` flag in `TunnelPeers` v2.
- `EdgeMapping` (vpc-internet-gateways) gains `edge_group_id` in its
  signed header's reserved bytes, and the controller builds one table
  slice per group: addresses and gateways in the group's prefixes, NAT
  blocks of the group's hosts, and `forward` entries (kind 6: public
  address → owning group) for addresses whose instance is served
  elsewhere.
- **Forward mode**: an edge role receiving inbound traffic for a
  `forward` address wraps the packet (VNI 0, a Geneve option `transit`
  carrying the public destination) to an edge role of the owning group,
  chosen by rendezvous; that role translates and delivers. Outbound
  traffic from the instance leaves through its own group, so the path is
  asymmetric, which a stateless edge allows.
- **Re-home mode** (routed pools with an upstream that takes host routes):
  the controller moves the address's slice entry to the new group and
  the operator's routing announces the /32 there. Static routing gets
  forward mode only.
- Moving hosts or prefixes between groups is an edge-table change like
  any other: put in the new group, wait for `edge_applied`, update the
  hosts' `EdgeGroup`, then remove from the old group.

## Observability

`stream_status` (report kind 30, paged like `group_usage`): per network
role `slot`, budgets and use (NIC entries, certified peers, cached
credentials, lookup cache entries, held deltas), bulk channel state and
counters; then per VNI `vni u32 | incarnation u32 | sequence u64 | flags
(gap, need_snapshot, lookup, mode) | oldest_hold_ms u32`. helm polls it
every second and reports changes, coalesced to at most one report per
second per role.

## Number reservations

Checked against `main` and the open drafts on 2026-11-27, leaving gaps
for numbers the drafts are still settling (security groups claim link
19; internet gateways link 20, vendor 0x21-0x24, report kinds 22-24;
server provisioning 21-22 and 25-26; AZ cold start link 23-24 and
report kinds 27-28):

| Space | Numbers |
|---|---|
| Link records | 30 `vtep_credential`, 31 `credential_revocations`, 32 `vpc_stream`, 33 `frame_notice`, 34 `edge_group`, 35 `rotate_vtep_key` |
| Report kinds | 30 `stream_status`, 31 `credential_request` |
| OarLink vendor types | 0x30 `vpc_stream`, 0x31 `vtep_credential`, 0x32 `credential_revocations`, 0x33 `frame_notice`, 0x34 `stream_status`, 0x35 `edge_group` |
| Tunnel message types | 0x10 `credential` |

The first task to land re-checks them against `main`.

## Testing strategy

- Codecs: pinned vectors under the RFC 8032 keys, strict decoders, a fuzz
  target each with re-encode round trips; `fuzz_stream_applier` against a
  naive applier that rebuilds full state from the record list after every
  delta and must agree with the persistent tables on every lookup.
- Tunnel: certified handshake against a reference model (credential
  states, expiry, revocation, rate limits); WireGuard interop unchanged
  for list peers; a fuzz target for the credential message.
- Network namespaces (`vpc_netns.sh` style): each migration in
  Requirement 10.3 on a live three-role VPC with traffic and counters
  checked before, during and after.
- Scale: `tests/stream_scale_bench` (1,048,576 NIC entries, deltas per
  second and memory), `tests/certified_peer_bench` (50,000 peers,
  handshakes per second, memory), an edge slice of 1 M entries over the
  bulk channel; results go in this section, as the router benchmark does
  in vpc-subnets-routing.
- Harbor (tikhov, Clark's go): the migrations on nested boards.

## Benchmarks

(Filled in by task 16.)
