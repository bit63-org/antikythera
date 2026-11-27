# Requirements Document — Network control at fleet scale

## Introduction

The network data plane already scales well per packet: every forwarding
decision is local to the VTEP, frames are signed snapshots that heal
themselves, and a host keeps forwarding on the frames it holds when the
controller is away. What does not scale is how those frames and tunnel
keys reach the hosts. The 2026-11-27 analysis
(`/mnt/project-files/audits/antikythera-scaling-limits-2026-11-27.md`,
"AntiKythera at a million hosts per AZ") ranked the walls; the network
ones, in the order they hit, are:

1. **Edge peering at ~2,000 hosts.** Inbound internet traffic can land on
   any edge role (`vpc-internet-gateways`), so every edge role must be a
   WireGuard peer of every host, and a `TunnelPeers` frame holds at most
   2,048 peers.
2. **One large VPC.** A `MapUpdate` holds at most 4,096 NICs, a VTEP at
   most 2,048 peers, a `SecurityPolicy` 4,096 members. Under those caps a
   NIC change still costs one full-snapshot frame per server hosting the
   VPC: a 4,000-NIC autoscaling VPC alone produces ~20k signatures and
   ~4 GB/s of controller writes.
3. **Never-reused 24-bit handles.** VNIs and MACs are never reused, which
   limits *creations*, not live objects: a 24-bit MAC counter runs out in
   under a day of launches at a million hosts, the VNI space after
   16.7 M VPCs have ever existed.
4. **Every frame crosses helm's SMBus sideband.** At tens of KB/s a
   1 M-entry edge table takes ~20 minutes to reload, and one busy VPC
   saturates a host's link.
5. **helm reboots change every tunnel key,** so each reboot re-signs and
   re-sends peer sets to every peer.

This spec removes those walls in the network role, helm and the frame
formats. Its kythira counterparts are `ec2-controller-scale` (how the
controller produces and signs what this spec defines) and `fleet-cells`
(the cell split that bounds every regional table). It changes the
contracts in `controller-interface` (Requirements 4, 5, 8, 10),
`oar-net-data-plane` (Requirement 5), `helm-control-plane` (OarLink),
`vpc-security-groups` (the `SecurityPolicy` frame) and
`vpc-internet-gateways` (edge peers and the edge table); each task
updates the owning spec's text.

Every change keeps the current mechanism working beside the new one, and
moving either way is tested (the independent-layers rule Clark set for
Kythira services, applied here to protocol generations).

### What this spec does not cover

- The controller's signing, debouncing and storage of frames:
  kythira `ec2-controller-scale`.
- Cells, delegated cell keys and certificate hierarchies:
  kythira `fleet-cells`. This spec only requires that keys and
  credentials can be scoped to a cell.
- PSP NIC offload. The certified handshake here is designed so a later
  PSP mode needs no new control plane.
- BGP. Edge-group inbound uses static routes first, as
  `vpc-internet-gateways` does.

## Glossary

- **VTEP credential** — a small controller-signed record binding a VTEP's
  static X25519 public key to its server ID, VTEP address, cell and a
  validity window.
- **Certified peer** — a tunnel peer accepted because it presented a
  valid VTEP credential, not because a peer list named it.
- **VPC stream** — the ordered sequence of changes to one VPC's network
  state (mapping, addresses, subnets and routes, security groups,
  multicast policy and members), delivered as snapshot parts and deltas
  under one sequence number.
- **Incarnation** — a counter that distinguishes successive VPCs that
  were given the same reused VNI.
- **Bulk channel** — a network role's own path over Ethernet to fetch
  signed frames, as opposed to helm's OarLink sideband.
- **Frame store** — a read-only, content-addressed endpoint on the
  controller's fleet tier that serves signed frames by digest.
- **Edge group** — a set of edge roles that serve one set of hosts and
  hold one set of public prefixes.

## Requirements

### Requirement 1: Stable VTEP keys

**User Story:** As an operator, I want a server's tunnel keys to survive a
helm restart, so that a routine reboot does not re-key every peer of
every VTEP on the server.

#### Acceptance Criteria

1. helm SHALL derive each VTEP's static X25519 key pair from its secure
   element (or the software secure element) and the VTEP's slot, so the
   same server and slot get the same key after a helm or board restart.
2. The key SHALL change only when the controller asks for a rotation, or
   when the server is re-provisioned and its master key replaced.
3. A rotation SHALL overlap old and new keys: the new public key is
   reported and certified first, and the old key keeps working for
   existing sessions until a configured grace period ends (default
   10 minutes).
4. The private key SHALL never leave helm and the network role, as today
   (controller-interface Requirement 8).

### Requirement 2: VTEP credentials

**User Story:** As the controller, I want to certify each VTEP's key once,
so that no host needs to be told about every other host before talking to
it.

#### Acceptance Criteria

1. The controller SHALL issue each VTEP a `VtepCredential`: server ID,
   VTEP address, cell ID, supported tunnel modes, the static public key,
   `not_before`, `not_after` and the signing `key_id`, signed with Ed25519
   by a controller key the network role trusts.
2. A credential's lifetime SHALL default to 24 hours; helm SHALL ask for a
   new one when less than a third remains, with the same rules as storage
   role certificates (block-volume-service design, "Enrollment").
3. The controller SHALL be able to revoke credentials before they expire
   through a signed, versioned revocation list per cell; entries SHALL
   expire with the credentials they revoke, so the list holds at most a
   day of revocations.
4. A network role SHALL hold its own credentials and present them; it
   SHALL refuse one that does not name its server, VTEP and current key.

### Requirement 3: Certified tunnel handshakes

**User Story:** As a network role, I want to accept a tunnel peer that
proves who it is, so that peer sets need not be distributed and their size
stops mattering.

#### Acceptance Criteria

1. Before a WireGuard handshake initiation to a peer that has not seen its
   credential, a role SHALL send a `credential` message carrying its VTEP
   credential; the handshake messages themselves SHALL stay WireGuard's.
2. A responder SHALL accept an initiation whose decrypted static key has
   a credential that verifies, is within its validity window, is not
   revoked, names the source VTEP address the packet came from, and
   advertises the mode in use. Otherwise it SHALL drop the initiation and
   count the reason.
3. Credential verification SHALL be bounded: a per-source rate limit, a
   cache of verified credentials keyed by public key (default 65,536
   entries, least recently used evicted), and WireGuard's cookie reply
   under load before any signature is checked.
4. Accepting a certified peer SHALL NOT authorize any traffic by itself:
   a decapsulated packet SHALL still pass `check_ingress` against the
   signed mapping, so a peer can only send for NICs the controller says it
   owns.
5. Peers from `TunnelPeers` frames and peers set by hand SHALL keep
   working beside certified peers. The inventory SHALL advertise a
   `certified` tunnel mode bit, and the controller SHALL stop sending
   `TunnelPeers` to a VTEP only when the VTEP and every VTEP it shares a
   VNI with advertise it.
6. Sessions to certified peers SHALL be torn down when the peer's
   credential expires or is revoked; established sessions to peers whose
   credential is merely renewed SHALL be kept.
7. Per-peer state SHALL be created only for peers with traffic and SHALL
   be reclaimed after an idle period (default 5 minutes after the last
   session expired), so a role's memory grows with active peers, not
   with fleet size.

### Requirement 4: VPC-scoped frames and reused VNIs

**User Story:** As the controller, I want to sign a VPC's network state
once per change rather than once per server, so that the cost of a change
does not grow with the number of servers hosting the VPC.

#### Acceptance Criteria

1. The VPC stream frames (Requirement 5) SHALL be signed over the VNI, the
   VPC's incarnation, the cell scope and the content, and SHALL NOT name a
   target server.
2. A network role SHALL apply a VPC stream frame only for a VNI that has,
   or is about to have, a local NIC (an `ATTACH_DEVICE` it accepted), and
   SHALL ignore frames for other VNIs.
3. VNIs SHALL become reusable wire handles: the controller SHALL free a
   VNI only after every server has reported no longer holding it and a
   quarantine (default 24 hours) has passed. VPC IDs stay 64-bit and
   never reused, and SHALL be carried separately from the VNI wherever
   a frame names the VPC.
4. Each VPC stream frame SHALL carry the VPC's incarnation. A role
   holding state for an older incarnation of a VNI SHALL discard it
   before applying a newer one, and SHALL refuse frames of an older
   incarnation.
5. MAC addresses SHALL be unique within a VNI (NICs and the VPC's gateway
   MAC), allocated per VPC from the whole locally administered space, and
   reusable once freed. A role SHALL refuse a VPC stream that gives two
   NICs of one VNI the same MAC.
6. Per-server frames (`InstanceMetadata`, `VtepCredential`,
   `VolumeLayout`, mailbox envelopes) SHALL keep their `server_id`.

### Requirement 5: VPC streams with deltas

**User Story:** As an operator, I want a NIC change to cost a few dozen
bytes on each server rather than a full snapshot, so that large and busy
VPCs stay cheap.

#### Acceptance Criteria

1. A VPC's mapping entries, guest addresses, subnets and route tables,
   gateway settings, security groups and memberships, group policies and
   multicast members SHALL be deliverable as one VPC stream: snapshot
   parts and ordered deltas under one per-VNI sequence number, in the
   container format the edge table already uses (`vpc-internet-gateways`
   design "EdgeMapping").
2. A role at sequence S SHALL apply a delta only when it starts at S + 1,
   ignore one ending at or below S, and hold one starting past S + 1 (at
   most 64 frames) while reporting the gap; a gap held longer than a
   configured time (default 5 s) SHALL make it ask for a snapshot.
3. Records SHALL be the entry types of today's frames (NIC binding,
   address, subnet, route table, route, gateway, security group, rule,
   membership, tracking setting, group policy, group member list), each
   with put and remove, keyed as in those frames.
4. A role SHALL apply a delta atomically with respect to forwarding: the
   ARP/ND proxy, the source check, routing and security groups SHALL see
   either all of a delta or none of it, as they see one frame today.
5. The per-frame caps (4,096 NICs, 8,192 addresses per family, 4,096
   security-group members, 4,096 multicast VTEP entries) SHALL be
   replaced by role-wide budgets reported in the inventory (default
   1,048,576 NIC entries across all VNIs on a role); exceeding a budget
   SHALL refuse the change that would exceed it and report it.
6. Snapshot frames (`MapUpdate`, `VpcConfig`, `SecurityPolicy`,
   `GroupPolicy`, `GroupMembers`) SHALL keep working; a role SHALL move a
   VNI from snapshot frames to a stream at the stream's first snapshot,
   and back when the controller sends a snapshot frame with a higher
   version.

### Requirement 6: Bulk frames over Ethernet

**User Story:** As an operator, I want large signed frames to reach a
network role at Ethernet speed, so that a board restart or a large table
does not wait on an SMBus link.

#### Acceptance Criteria

1. A network role SHALL be able to fetch signed frames from a frame store
   over its own Ethernet port (a control address on the underlay port, in
   the control traffic class), authenticated with mutual TLS using its
   role certificate.
2. helm SHALL tell the role what to fetch with a short `frame_notice`
   over OarLink: the frame kind, its VNI or scope, sequence or version,
   size and SHA-256 digest. The role SHALL verify the digest and then the
   frame's own signature, so neither the frame store nor the path needs
   to be trusted.
3. Frames up to a configured size (default 16 KiB), and every frame while
   the bulk channel is unavailable, SHALL still travel over OarLink in
   chunks as today.
4. On OarLink, keys, commands, credentials, leases and notices SHALL be
   sent ahead of bulk chunks, and a bulk transfer SHALL yield between
   chunks so none of them waits behind it.
5. The bulk channel SHALL accept connections from nothing: the role only
   dials out, to frame-store addresses helm gives it. The addresses need
   no signature, because every fetched frame is checked against the
   notice's digest and its own signature.
6. The role SHALL report bulk fetches (bytes, time, failures) in its
   `stream_status`.

### Requirement 7: Mapping lookups for very large VPCs

**User Story:** As a tenant with a very large VPC, I want my instances to
reach any address in it without every host holding the whole VPC.

#### Acceptance Criteria

1. The controller MAY mark a VNI as `lookup` in its stream. In a `lookup`
   VNI a role SHALL hold the entries the stream gives it (its own NICs and
   the controller's chosen interest set) and SHALL ask the frame store for
   any other destination on first use.
2. A looked-up entry SHALL be a signed record with the VNI, incarnation,
   the stream sequence it is current at, and the binding; the role SHALL
   cache it for a bounded time (default 60 s) and SHALL drop it when a
   later delta removes or changes it.
3. A packet to an unknown destination in a `lookup` VNI SHALL be queued
   briefly (bounded per NIC and per role) or dropped and counted, never
   flooded.
4. The receiving VTEP's checks SHALL use the same lookups, so a packet is
   never accepted on a mapping the receiver cannot verify.

### Requirement 8: Edge groups

**User Story:** As an operator, I want each edge role to serve a bounded
set of hosts and prefixes, so that the internet edge grows with the fleet
instead of every edge role holding the whole region.

#### Acceptance Criteria

1. Every edge role SHALL belong to one edge group, and every host SHALL be
   assigned to one edge group for outbound traffic, so a host's edge
   peers are only its group's edge roles.
2. Public pools SHALL be assigned to edge groups by prefix; upstream SHALL
   route each prefix only to its group's edge roles, so inbound traffic
   for a prefix lands only where its hosts are reachable.
3. An edge role SHALL hold only its group's slice of the edge table: its
   prefixes' addresses and gateways, and the NAT port blocks of its hosts.
4. An Elastic IP SHALL be allocated by default from the edge group of the
   instance it is first associated with. Associating it with an instance
   served by another group SHALL either re-home it (a host route announced
   from the new group, where the upstream allows) or forward its traffic
   between the two groups' edge roles over the underlay, chosen by the
   operator per pool.
5. Edge roles SHALL use certified peers (Requirement 3), so an edge group
   is limited by active peers and packet rate, not by a peer list.
6. One edge group per region SHALL remain a valid configuration, and
   moving hosts and prefixes between groups SHALL work while traffic
   flows, dropping no established flow longer than one rendezvous-hash
   failover.

### Requirement 9: Observability and budgets

**User Story:** As an operator, I want to see how far behind each role is
and how close it is to its budgets, so that fan-out problems are visible
before they drop traffic.

#### Acceptance Criteria

1. helm SHALL report a `stream_status` per network role: per VNI the
   incarnation, applied sequence, gap flag and age of the oldest held
   delta; and the role's budgets and use (NIC entries, certified peers,
   cached credentials, lookup cache).
2. The role SHALL count every refusal this spec adds (credential reasons,
   stream gaps, budget refusals, lookup misses and queue drops).
3. The controller SHALL be able to tell when a change is live on every
   server hosting a VPC from the reported sequences alone.

### Requirement 10: Testing and migration

**User Story:** As a developer, I want each mechanism tested alone, side
by side with the old one, and in both migration directions.

#### Acceptance Criteria

1. Every new codec (`VtepCredential`, revocation list, `VpcStream`,
   `FrameNotice`, looked-up record) SHALL have pinned vectors, unit tests
   and a fuzz target with a re-encode round trip.
2. The certified handshake SHALL be tested against a naive reference and
   still interoperate with Linux WireGuard for peers set from lists.
3. Network-namespace tests SHALL cover: list peers to certified peers and
   back on a live VPC; snapshot frames to streams and back; SMBus-only to
   the bulk channel and back; one edge group to two and back.
4. Scale tests SHALL record, in the design's benchmark section: a role
   holding 1,048,576 NIC entries (memory, apply time per delta); 50,000
   certified peers on one edge role (memory, handshakes per second); an
   edge-table slice of 1 M entries loaded over the bulk channel.
5. Harbor (tikhov, Clark's go) SHALL run the migrations on real boards in
   nested KVM with traffic flowing.
