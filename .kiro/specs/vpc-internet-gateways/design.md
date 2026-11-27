# Design Document — VPC internet gateways, public addresses and NAT

## Overview

```
                      upstream router (static ECMP routes, or a LAN)
                         │ public pools            ▲
          ┌──────────────┴───────┐  ...  ┌──────────┴───────────┐
          │ edge role e1         │       │ edge role eN          │   edge servers,
          │  outside port        │       │  outside port         │   each zone
          │  EdgeTable (regional)│       │  EdgeTable (regional) │
          │  1:1 translate, wrap │       │  1:1 translate, wrap  │
          └──────────┬───────────┘       └──────────┬────────────┘
                     │ Geneve in WireGuard (underlay), any edge ↔ any host
          ┌──────────┴──────────────────────────────┴───────────┐
          │ host network role (VSwitch)                          │
          │  router: igw / eigw / nat targets                    │
          │  security groups (egress, ingress)                   │
          │  NatEngine: SNAT to NAT gw address + owned port block │
          │  eigw: outbound-only gateway flows                   │
          └──────────────────────────────────────────────────────┘

 controller ── VpcConfig v3 (per VPC per server: gateways, routes, port blocks)
            ── TunnelPeers v2 (edge flag)
            ── EdgeMapping (regional: pools, gateways, addresses, port blocks)
               snapshot parts + ordered deltas, to every edge server
```

Outbound, a NIC's packet is routed and filtered at its own VTEP as
today; a gateway route sends it, untranslated (or source-NATed for a NAT
gateway), to one edge role, which checks the sender owns the source,
swaps the private source for the public address and sends it out.
Inbound, any edge role looks up the destination, swaps it for the
private address and sends the packet to the VTEP that hosts the NIC (or,
for a NAT gateway, the VTEP that owns the destination port's block),
where the reverse route, the NAT flow and the security groups decide.

## Decisions

- **Stateless edge, 1:1 only.** AWS's edge fleet does the Elastic IP
  translation while it wraps and unwraps packets, and stays horizontally
  scalable because 1:1 translation needs no per-flow state. The edge has
  to hold the public → (VPC, private, host) mapping anyway to know where
  an inbound packet goes, so translating there adds nothing. Clark chose
  this on 2026-11-27 over translating at the host.
- **NAT gateways translate at the source VTEP, in port blocks.** Clark
  chose this ("A") over a stateful NAT fleet like AWS's Hyperplane. The
  host already keeps per-flow state for security groups, so the NAT flow
  lives next to it and costs no new failure domain. The edge still does
  only 1:1 work: the host translates to the NAT gateway's *private*
  address and an owned port, and the edge maps that private address to
  the Elastic IP like any association. Return traffic is routed by
  destination port to the block's owner. The cost is that a NIC that
  moves or a role that restarts loses its NAT flows (Requirement 5.8),
  which EC2's NAT gateway avoids; new connections work at once.
- **No anycast VTEP.** An anycast underlay address for the edge would let
  hosts send to "the edge" without choosing, but WireGuard keeps a
  session per peer key, so packets for one address landing on different
  edge roles would fail to decrypt. Each edge role is an ordinary tunnel
  peer instead, flagged in `TunnelPeers`, and each host chooses one per
  flow by rendezvous hashing over the healthy ones. Inbound, the upstream
  router's ECMP spreads packets over the edge roles' outside addresses,
  which carry no tunnel state.
- **Gateway IDs stand in the NIC-pair option.** Gateway IDs and NIC IDs
  share the controller's never-reused ID space, so a gateway ID in the
  Geneve option's source or destination is unambiguous. The receiving
  host recognises it from `VpcConfig` version 3; no Geneve change.
- **Hosts check inbound with a reverse route lookup.** EC2 makes a
  subnet public by giving it a route to the internet gateway; an
  instance with an Elastic IP in a subnet without one is unreachable. The
  host looks the inner source up in the destination subnet's table and
  delivers only when it leads to `igw` (or `eigw` with a flow), which
  also gives egress-only behaviour per subnet with no extra state.
- **The edge table is regional and delta-coded.** Elastic IPs are
  regional and move between zones, so every edge role holds the region's
  whole table. Shipping a full snapshot for every association would be
  too heavy at a million entries; ordered deltas with a periodic snapshot
  keep updates small, and the sequence number gives the controller one
  number to wait on ("live on every edge").
- **Edge servers are ordinary servers.** An edge server runs helm and
  network roles in edge mode, on the same boards and code as host
  servers, with each board's second port facing outside. The controller
  keeps guests off it. This keeps one data-plane codebase and one
  management path.

## VpcConfig version 3

Replaces version 2 (`vpc-subnets-routing` design); decoders accept
version 3 only, as before. The header's reserved bytes at 0x32 become
`gateway_count u8 (<= 18)` and `reserved [5]`; routes gain three kinds
whose `target` is a gateway ID; a gateways section follows the routes:

```
  routes ... { target u64 (NIC ID, gateway ID, or 0 for local) |
               kind u8 (1 local, 2 nic, 3 igw, 4 nat, 5 eigw) | ... }
  gateways x gateway_count, gateway_id ascending {          // 24 bytes
    gateway_id u64 | kind u8 (1 igw, 2 eigw, 3 nat) |
    address_count u8 (nat: 1..8; else 0) | block_count u8 (nat: 0..16; else 0) |
    reserved u8 | subnet_id u64 (nat: its subnet; else 0) | reserved u32 }
    addresses [4] x address_count     // nat: private IPv4, primary first
    blocks x block_count {            // nat: blocks this server owns, ascending
      address_index u8 | block u8 (0..62: ports 1024 + 1024 x block ...) }
  domain ..., signature [64]
```

Rules: at most one `igw` and one `eigw`, at most 16 `nat`; an `igw` route
names the listed internet gateway, an `eigw` route has family 6 and names
the egress-only gateway, a `nat` route has family 4 and names a listed
NAT gateway. NAT addresses lie inside their subnet's IPv4 prefix, are
distinct, and are not the subnet's reserved addresses. Blocks refer to a
listed address. The frame is per server (it is already signed for one
`server_id`), so each server sees only its own blocks.

Largest frame: version 2's 139,581 bytes plus an internet gateway, an
egress-only gateway and 16 NAT gateways with eight addresses and sixteen
blocks each, 141,037 bytes.

## TunnelPeers version 2

Version 1's per-peer `reserved [3]` becomes `flags u8 | reserved [2]`,
bit 0 = edge. Decoders accept version 2 only. The controller sets the
flag for edge VTEPs. A host role keeps the healthy edge peers (those the
tunnel does not report down) as its edge set. Edge roles on one LAN are
listed in each other's peer sets for on-link failover.

## EdgeMapping frame

Link record type 20 (`edge_mapping`), OarLink vendor type 0x21, chunked
like `group_members`.

```
EdgeMapping {                 // controller -> helm (edge server) -> edge role,
                              // signed; src/proto/edge_mapping.hpp, LE
  0x00 magic 'AKEM' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 server_id u64,
  0x10 kind u8 (1 snapshot part, 2 delta), 0x11 reserved u8,
  0x12 part u16, 0x14 part_count u16 (snapshot 1..4096; delta 1), 0x16 reserved u16,
  0x18 snapshot_id u64        // snapshot: non-zero, same in every part; delta: 0
  0x20 from_sequence u64      // delta: first sequence covered; snapshot: 0
  0x28 to_sequence u64        // snapshot: consistent at; delta: last covered
  0x30 entry_count u32 (<= 4096), 0x34 reserved u32
  0x38 entries x entry_count, 72 bytes {
    op u8 (1 put, 2 remove; snapshots put only) |
    kind u8 (1 pool, 2 internet gateway, 3 egress-only gateway,
             4 address, 5 nat_block) |
    family u8 (4, 6) | length u8 (pool: prefix length; else 32 or 128) |
    vni u32 | public [16] | private [16] |
    id u64 (gateway, NIC or NAT gateway ID; pool 0) |
    owner_vtep [16] (address of a NIC, nat_block: the owner; else zero) |
    port u16 (nat_block: first port; else 0) | reserved [6] }
  signature [64]              // Ed25519 over every byte before it
}
```

Keys: a pool by `(family, public, length)`, a gateway by `(kind, vni)`,
an address by `public`, a block by `(public, port)`. A put replaces the
entry with the same key; a remove names the key and zeroes the rest.
Address entries: IPv4 public → private for a NIC (`owner_vtep` set) or a
NAT gateway address (`owner_vtep` zero, `id` the NAT gateway); IPv6 with
`public == private`. Blocks start at 1,024 + 1,024·n for n in 0..62.

A part is at most 295,032 bytes, under `proto::max_record_payload`. A
snapshot of 4,096 parts holds 16.7 M entries.

Deltas: the controller commits edge-table changes in a regional sequence
(one number per change). A delta covers `from_sequence ..=
to_sequence`, one or more changes in order. An edge role at sequence S
applies a delta only with `from_sequence == S + 1`; one ending at or
below S is ignored (a replay); one starting past S + 1 is held (at most
64 frames, then dropped) and the gap is reported.

## The edge role

`src/oar/net/edge/`, run by `ak-oar-net --edge CONFIG`. It reuses the
Vtep, the WireGuard tunnel and TunnelPeerSet, the packet parser and its
checksum helpers.

- **`EdgeTable`.** Hash maps keyed by public address (both families),
  by `(vni, private IPv4)`, by `(public, block)` for blocks, by VNI for
  gateways, and a prefix set for pools. A snapshot is built on the
  control thread and swapped in by pointer; deltas are queued to the
  data-plane thread and applied between packet batches, at most 4,096
  entries per poll, so a large delta cannot stall forwarding.
- **`OutsidePort`.** An interface like `Underlay`: `send(frame)` and a
  poll for received frames. First implementation: `PacketSocketPort`,
  AF_PACKET on a netdev with TPACKET_V3 memory-mapped rings (batched
  receive and transmit, no system call per frame) and PACKET_FANOUT to
  spread flows over one ring per data-plane thread. It runs on veth and
  TAP, so network namespaces, harbor and CI use the production code.
  `XdpPort` (AF_XDP) follows as the production path (see "Packet I/O").
- **Next hop.** Routed mode resolves the configured upstream next hop
  with ARP/ND on the outside port and sends everything to it. On-link
  mode resolves destinations on the outside LAN directly and anything
  else through the next hop.
- **On-link responder.** Answers ARP and NS on the outside port for
  allocated public addresses whose rendezvous winner, among the edge
  roles on the LAN that the tunnel reports up, is this role. On a change
  in that set it sends gratuitous ARP and unsolicited NA for the
  addresses it gained.
- **`EdgeConfig`** (local operator file): outside interface, outside
  addresses, mode, upstream next hop, outside MTU, the LAN's edge VTEPs
  (on-link), bogon prefixes, per-address inbound rate defaults.

### Outbound (from a host)

1. Vtep decode and tunnel authentication as today; the peer must not be
   flagged edge. The destination in the NIC-pair option is a gateway ID
   that the edge table lists for the frame's VNI, else
   `edge_drop_gateway`.
2. Parse the inner IP packet. IPv4: look up `(vni, source)`. A NIC entry
   needs `id ==` the frame's source NIC and `owner_vtep ==` the tunnel
   peer. A NAT gateway entry needs `id ==` the source and the block
   holding the source port owned by the tunnel peer. Otherwise
   `edge_drop_owner`; no entry, `edge_drop_no_public`. IPv6: look up the
   source address with the same checks, no translation.
3. Rewrite the IPv4 source, incrementally fix the IP and L4 checksums
   (RFC 1624), and for ICMP errors rewrite the quoted packet's
   destination and its checksums too.
4. Destination in a pool: hairpin to step 2 of "Inbound" with the
   translated packet. Otherwise MTU (Requirement 9.2), then out the
   outside port to the next hop.

### Inbound (from outside)

1. Drop spoofed sources (Requirement 8.4), packets to the role's own
   addresses other than echo and ARP/ND (Requirement 9.4), and packets
   over the per-address rate limit.
2. Look up the destination. NIC entry: VTEP = `owner_vtep`, destination
   ID = the NIC. NAT gateway entry: block by destination port; no owner,
   `edge_drop_no_block`; VTEP = the owner, destination ID = the NAT
   gateway. No entry: `edge_drop_no_entry`.
3. IPv4: rewrite the destination to the private address, fix checksums
   and quoted packets. Lower TTL (time-exceeded at zero, Requirement
   9.3).
4. Source ID: the VPC's internet gateway, or for IPv6 its egress-only
   gateway when it has no internet gateway. Send to the VTEP through the
   tunnel with inner MACs set to the VPC's gateway MAC.

## Packet I/O

Compared on 2026-11-27, with rough per-core figures from published
benchmarks (task 11 replaces them with our own):

| | AF_PACKET, TPACKET_V3 (first build) | AF_XDP | DPDK |
|---|---|---|---|
| Small packets per core | about 1-3 Mpps | 2-5 Mpps copy mode, 10-25 Mpps zero-copy | 20-40 Mpps |
| NIC ownership | kernel | kernel; an XDP program redirects our frames, passes the rest | taken from the kernel (vfio-pci) |
| veth/TAP (netns, harbor, CI) | yes | copy mode | emulation drivers only |
| Driver support | any | zero-copy: ice, i40e, mlx5, ixgbe and similar | a DPDK poll-mode driver |
| Cost | none beyond the socket | libbpf/libxdp, an XDP program, umem rings, CAP_NET_ADMIN and BPF | large dependency, hugepages, busy-polling cores |

Decisions:

- **AF_PACKET with TPACKET_V3 and fanout first.** It needs nothing new,
  and the same code runs in every test environment. At 25GbE with
  ordinary packet sizes (about 2 Mpps at 1,500 bytes) the edge's
  underlay side (the kernel UDP socket of `UdpEndpoint` and WireGuard's
  ChaCha20-Poly1305 at a few Gbps per core) binds before the outside
  port does; small-packet floods (about 37 Mpps at 64 bytes on 25G) are
  where the port method matters.
- **AF_XDP is the production path, for both sides.** `XdpPort` for the
  outside port and an `XdpEndpoint` underlay (raw UDP over IPv6 framed by
  the role, beside `UdpEndpoint`) share the umem and ring code. Zero-copy
  where the driver has it, copy mode elsewhere, so the same build still
  runs on veth. The kernel keeps the NIC: management traffic, ARP for the
  board's own addresses and tools like `ethtool` keep working through
  `XDP_PASS`. libbpf/libxdp join as a QUIET optional dependency
  (`AK_HAS_XDP`), listed in `DEPENDENCIES.md`; without it the role uses
  the AF_PACKET port and `UdpEndpoint`. Host network roles can use
  `XdpEndpoint` for their underlay too.
- **DPDK only on evidence.** It is considered only if task 11's numbers
  on the target NIC show AF_XDP zero-copy short of 25G line rate at the
  packet sizes we care about, or if PSP or crypto offload changes where
  the cost is. It would take the NIC away from the kernel and add the
  heaviest dependency in the stack.

## The host role

### Transmit

Route step 2 of `vpc-subnets-routing` gains three targets. In each case
the sender's security groups (`egress`) run first, then the TTL is
lowered, then:

- **`igw`:** pick the edge peer by rendezvous hash of `(vni, protocol,
  source, destination, ports)` over the edge set (none:
  `tx_drop_no_edge`), and send with `{vni, src = sender NIC, dst = igw}`
  through a new `Vtep::send_to(peer, …)`, since the destination is not a
  mapped NIC. Counted `tx_gateway`.
- **`eigw`:** record or refresh a gateway flow for the sender in the flow
  table (key as a security-group flow, kind `eigw`), then send as for
  `igw` with `dst = eigw`.
- **`nat`:** `NatEngine::outbound` (below), then send with `{vni, src =
  NAT gateway, dst = igw}`. The VPC has an internet gateway whenever it
  has a NAT gateway (Requirement 5.1); without one in the frame,
  `tx_drop_no_igw`.

### Receive from an edge

For a frame whose NIC-pair source is a gateway ID, in order (counters as
Requirement 3.5): peer flagged edge; the gateway is the VPC's internet
or egress-only gateway; inner source outside the VPC's blocks. Then:

- destination ID is a NAT gateway: `NatEngine::inbound` finds the flow
  and restores the NIC's address and port (`rx_drop_nat_no_flow`);
- destination ID is a NIC: it must be local and own the inner
  destination in its subnet.

Then the reverse lookup: the destination NIC's subnet table for the
inner source must give `igw`, or `eigw` with a gateway flow (NAT
returns match their flow and skip this, since the NAT flow proves the
NIC sent first through a `nat` route). Then `ingress` for an enforced
NIC, and delivery with the gateway MAC as source.

### NatEngine

`src/oar/net/nat_engine.*`, owned by the VSwitch, sharing the
security-group `FlowTable` (its budget, per-NIC limits, timer wheel and
fragment cache).

- **Flow.** A NAT flow has two keys: forward `(nic, protocol, private
  source, source port, remote, remote port)` and reverse `(NAT address,
  NAT port, protocol, remote, remote port)`. ICMP echo uses the
  identifier as the port.
- **Port choice.** From the blocks this server owns for the gateway,
  across its addresses: up to 32 random probes for a port whose reverse
  key is free, then a scan of the owned ports; none free,
  `drop_nat_ports` and a pressure mark for the next `nat_usage` read.
- **Timeouts.** TCP 350 s idle once established (EC2's NAT gateway),
  the security-group TCP states otherwise; UDP and ICMP 60 s.
- **Blocks taken away.** A `VpcConfig` that drops a block flushes that
  block's flows; the controller only does that after ten minutes with no
  NIC routing to the gateway here, so it normally flushes nothing.
- **Per destination, not per server.** Endpoint-dependent mapping makes
  each owned block worth 1,024 concurrent flows *per destination*, so a
  server rarely needs more than one block; pressure comes from many
  flows to one destination (a package mirror, say).

## Port block lifecycle

```
 grant:   controller picks a free block ─► EdgeMapping delta (put nat_block)
          ─► every in-service edge reports edge_applied >= that sequence
          ─► VpcConfig v3 to the server lists the block ─► server uses it
 revoke:  no NIC routing to the gateway on the server for 10 min
          ─► VpcConfig without the block ─► nat_usage shows it not held
          ─► EdgeMapping delta (remove nat_block)
```

The controller grants a further block when a `nat_usage` reading shows
the busiest destination above 75% of the server's ports for that
gateway, or `drop_nat_ports` grew, up to 16 blocks per server and
gateway. A gateway with no free block left grants nothing and the drops
show up as EC2's `ErrorPortAllocation`.

Associations follow the same order: put to the edge, wait for every
edge's `edge_applied`, then report the association done; a
disassociation is removed from every edge before the address is free to
associate again.

## helm on an edge server

- Forwards `edge_mapping` link records to the edge role over OarLink
  (0x21, chunked). Keeps the newest complete snapshot and the deltas
  after it (at most 64 MiB of deltas; past that it drops them and flags
  `need_snapshot`), and replays them in order when a role restarts.
- Polls each edge role's `edge_status` (vendor type 0x24: snapshot ID,
  applied sequence, entries in use, capacity, gap flag) every second and
  reports changes as report kind 22 `edge_applied`.
- Reads `edge_usage` (vendor type 0x22, paged like `group_usage`) every
  minute and on demand, reported as report kind 23 `edge_usage`.

On host servers helm reads `nat_usage` (vendor type 0x23, paged) every
10 seconds from roles with NAT blocks and reports it as report kind 24
`nat_usage`. Record and number reservations: link record 20; vendor
types 0x21-0x24; report kinds 22-24 (security groups hold record 19,
vendor types 0x1F-0x20 and report kind 21).

## InstanceMetadata version 2

Adds, per NIC, `association_count u8 (<= 64)` and that many `{ private
[4] | public [4] }` pairs after the existing fields. `metadata_http`
serves `public-ipv4` (the primary address's association), and under
`network/interfaces/macs/<mac>/` `public-ipv4s` and
`ipv4-associations/<public-ip>`. `public-hostname` stays absent until
there is DNS.

## Counters

Host `VSwitchCounters`: `tx_gateway`, `tx_drop_no_edge`,
`tx_drop_no_igw`, `rx_gateway`, `rx_drop_not_edge`,
`rx_drop_edge_gateway`, `rx_drop_edge_src_inside`,
`rx_drop_edge_no_route`, `rx_drop_eigw_unsolicited`,
`rx_drop_nat_no_flow`; NAT meters `drop_nat_ports`, `drop_nat_protocol`.
Edge `EdgeCounters`: `edge_drop_gateway`, `edge_drop_owner`,
`edge_drop_no_public`, `edge_drop_no_entry`, `edge_drop_no_block`,
`edge_drop_spoofed`, `edge_drop_rate`, `edge_drop_ttl`, `edge_frag`,
`edge_ptb_sent`, `edge_hairpin`, plus per-entry meters.

## Test controller and harbor

`ak-test-controller vpc-config` gains `gateway=ID,igw|eigw` and
`gateway=ID,nat,SUBNET,ADDR[,ADDR…][,blocks=I:B,…]` and route targets
`igw:ID`, `eigw:ID`, `nat:ID`; `tunnel-peers` takes `edge` per peer; a
new `edge-mapping snapshot|delta …` sends EdgeMapping frames.

harbor scenarios (on tikhov): hosts s1 and s2, edge VMs e1 and e2 on an
outside bridge with an "internet" VM (web server, `iperf3`) behind an
upstream router VM.

- **Routed mode.** The router has ECMP static routes for
  `203.0.113.0/24` (TEST-NET-3) via e1 and e2. A guest with an Elastic
  IP serves HTTP to the internet VM; a guest in a private subnet fetches
  from it through a NAT gateway; a dual-stack guest behind the
  egress-only gateway reaches out over IPv6 and is not reachable
  inbound; hairpin from one guest to another's Elastic IP; PMTU
  discovery from the internet VM with its 1,500 MTU.
- **On-link mode.** The pool is the outside LAN's `192.168.77.0/24`; the
  internet VM reaches Elastic IPs on the LAN directly.
- **Failover.** Killing e1 mid-transfer leaves TCP streams working
  through e2 in both modes (in on-link mode after its gratuitous ARP).
- **Hostile roles.** A harbor-only flag lets s1 send frames with s2's NIC
  as source and with ports outside its blocks; the edges count
  `edge_drop_owner`. Another lets e1 send inbound frames with a VPC
  source address; s2 counts `rx_drop_edge_src_inside`.

## Testing strategy

- Codecs: unit tests, signing vectors in `src/proto/test_vectors.hpp`,
  `fuzz_vpc_config`, `fuzz_tunnel_peers`, `fuzz_instance_metadata`
  updated, new `fuzz_edge_mapping`, all with re-encode round trips.
- `EdgeTable`: snapshot assembly, delta ordering, holds and gaps against
  a naive map; `fuzz_edge_table`.
- Edge path: unit tests per counter and per checksum case (TCP, UDP,
  ICMP, ICMP errors quoting each); `fuzz_edge` feeds hostile host frames
  and outside packets and checks that nothing leaves without a matching
  owner and nothing spoofed gets in.
- `NatEngine`: unit tests on a fake clock for port choice, reuse per
  destination, exhaustion, timeouts, fragments and block removal;
  `fuzz_nat` checks no two live flows share a reverse key.
- In-process: `net_role_test` with two hosts and two edge roles over the
  tunnel and loopback UDP, outside ports as fake ports.
- Network namespaces: `tests/vpc_netns.sh` gains edge namespaces (a
  `tests/vpc_netns_edge` program, as `vpc_netns_role` is for hosts) and
  an internet namespace, in both modes, with real `curl`, `ping`,
  `tracepath` and `nc`.
- Benchmark: `tests/edge_bench` measures outbound, inbound and NAT
  return paths with 1,048,576 entries, and records the table's memory
  for Requirement 11.1. A second mode drives real ports (AF_PACKET now,
  AF_XDP after task 16) over a veth pair, and on hardware the target NIC,
  at 64, 512 and 1,500 bytes, recording per-core packet rates and where
  the time goes (port, crypto, table).

## Later

- **BGP and BFD.** The edge server announces the pools to upstream and
  withdraws when its roles are unhealthy; static routes need upstream
  health checks to fail over in routed mode.
- **Edge groups.** Past 2,047 hosts per edge (the `TunnelPeers` cap),
  hosts are split over edge groups for outbound, and inbound needs
  either peer sets past the cap or a second hop.
- **Sharding by public prefix,** if the regional table outgrows one
  board: each edge group announces and holds only its prefixes.
- **DPDK,** only if AF_XDP falls short (see "Packet I/O"), and
  per-address DDoS limits beyond the token bucket.
