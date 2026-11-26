# Design Document — VPC subnets and the implicit router

## Overview

```
 controller (kythira EC2)                       VPC 10.0.0.0/16, gateway MAC G
   CreateSubnet / CreateRouteTable ...           subnet A 10.0.1.0/24  table 1 (main)
        │ signed VpcConfig v2 (per VPC)          subnet B 10.0.2.0/24  table 2
        │ signed MapUpdate v4 (NIC → subnet)
        ▼
 helm ──OarLink, chunked──► network role (one per VTEP)
                              VSwitch
                               ├─ subnet of each NIC (MapUpdate v4)
                               ├─ per-subnet gateway: ARP/ND, DHCP, RA
                               ├─ router: route table of the sender's subnet,
                               │   longest prefix, local → owner NIC,
                               │   NIC route → appliance
                               └─ rewrite dst MAC → target, src MAC → G,
                                  TTL − 1, then local port or Geneve
                                                    │
 receiving VTEP: check_ingress (src MAC = NIC's or G) ◄┘
                 routed? redo the lookup in the source subnet's table,
                 deliver only to the same target
```

The router is not a component on the fabric. Every network role is the
router for the NICs it hosts, the way AWS's Nitro card is the VPC router
for its instance: the decision is made once, at the source VTEP, and the
packet travels one hop to the target's VTEP. The receiving VTEP repeats
the decision against its own signed copy of the configuration, so it
never trusts the sender's.

## Decisions

- **One frame for subnets and route tables.** The gap analysis sketched
  a separate `RouteTable` frame. Routing needs the subnet of the sender,
  the table associated with it and the table's routes together, and two
  frames would need an ordering rule between them on every change. One
  `VpcConfig` version 2 frame per VPC carries all three, so each server
  switches atomically. The cost is that a DNS or lease change resends the
  route tables, which change rarely and fit easily (at most about
  140 KB, see "VpcConfig version 2").
- **The NIC's subnet is explicit in the mapping.** Deriving it from the
  NIC's addresses would need no format change, but a NIC with no address
  in a family, or one whose addresses a buggy controller split across
  subnets, would have an ambiguous subnet, and the subnet decides which
  route table applies. MapUpdate version 4 carries a subnet ID per entry,
  and the role treats addresses outside that subnet as not the NIC's
  (Requirement 2.6), so the controller's two records cannot be read two
  ways.
- **Routed frames carry the gateway MAC as source, on the wire too.**
  oar-net's step-3 routing (oar-net design "Routing") kept the sender's
  source MAC so the Geneve ingress policy, which ties an inner source MAC
  to its source NIC, needed no change. With subnets the receiver must
  tell a routed frame from a frame sent straight to another subnet's MAC,
  because only the first is allowed (Requirement 6.4). The source MAC is
  that signal, and it is also what a guest expects to see from its
  router. `check_ingress` therefore also accepts the VPC's gateway MAC as
  the inner source, which grants nothing: the source NIC is still
  authenticated by the tunnel peer and the mapping, and the receiver
  re-runs the route lookup before delivering. The step-3 routes change to
  this rule too.
- **One gateway MAC per VPC.** Each subnet's gateway has its own IPv4
  address (base + 1) but they share the VPC's gateway MAC and link-local
  address, which are per link anyway. This keeps the frame and the
  receiver's routed-frame test simple (one MAC per VNI) and matches what
  a guest can observe in EC2.
- **TTL is lowered by one,** as step-3 routing already does and as
  RFC 1812 asks of a router. A one-hop `traceroute` between subnets is
  the visible result.
- **Same-subnet traffic never reaches the router.** EC2 applies routes
  more specific than `local` only to traffic that reaches the VPC router,
  which traffic within a subnet does not. We match that (Requirement
  6.6), so a middlebox route cannot break a subnet's own L2 traffic.

## VpcConfig version 2

Replaces version 1 (controller-interface design "VpcConfig"). Nothing
outside this repository spoke version 1, so decoders accept version 2
only, as MapUpdate did for versions 1 and 2. Same magic, link record type
14 and OarLink vendor type 0x18; the OarLink transfer becomes chunked.

```
VpcConfig {                   // controller -> helm -> oar-net, signed;
                              // src/proto/vpc_config.hpp, LE
  0x00 magic 'AKVC' u32, 0x04 version u16 (2), 0x06 key_id u16,
  0x08 server_id u64, 0x10 vni u32,
  0x14 ipv4_block_count u8 (1..5), 0x15 flags u8 (bit 0: ipv6_block present),
  0x16 dns4_count u8 (<= 4), 0x17 dns6_count u8 (<= 4),
  0x18 config_version u64,    // per VNI, starts at 1, strictly increasing
  0x20 gateway_mac [6], 0x26 domain_size u8 (<= 253), 0x27 reserved u8,
  0x28 lease_seconds u32 (60 .. 2^31-1),
  0x2C subnet_count u16 (1..200), 0x2E table_count u16 (1..200),
  0x30 route_count u16 (<= 4096, every table's routes, local ones included),
  0x32 reserved [6],
  0x38 ipv6_block [16]        // a /56; all zero without the flag
  0x48 ipv4_blocks x ipv4_block_count { prefix [4] | length u8 (16..28)
                                        | reserved [3] }     // primary first
       dns4 [4] x dns4_count, dns6 [16] x dns6_count,
       subnets x subnet_count {                             // 32 bytes
         subnet_id u64 | table u16 | flags u8 (bit 0: ipv6) |
         ipv4_length u8 (16..28) | ipv4_prefix [4] | ipv6_prefix [16] }
       tables x table_count {                               // 8 bytes
         table u16 | flags u8 (bit 0: main) | reserved u8 |
         route_count u16 | reserved u16 }
       routes x route_count, table by table in table order { // 32 bytes
         target_nic u64 (0 for local) | kind u8 (1 local, 2 nic) |
         family u8 (4, 6) | length u8 | reserved [5] | prefix [16] }
       domain [domain_size],
       signature [64]         // Ed25519 over every byte before it
}
```

Rules, all checked by the decoder and again by `VSwitch::set_vpc_config`:

- IPv4 blocks: /16 to /28, no host bits, not overlapping, the primary
  first and the secondaries ascending after it. The IPv6 block is a /56
  inside `2000::/3` or `fc00::/7`, no host bits.
- Subnets: strictly ascending by `subnet_id`, non-zero IDs. The IPv4
  prefix is inside one IPv4 block; the IPv6 prefix, when the flag is
  set, is a /64 inside the IPv6 block; no two subnets overlap in either
  family. The gateway is not carried: it is the prefix's base + 1
  (Requirement 2.2). `table` names a listed table.
- Tables: strictly ascending by number, exactly one with the main flag,
  and every listed table's `route_count` adds up to `route_count`. A
  subnet names its associated table, or the main table when it has no
  association; the controller resolves that, so the role never has to.
- Routes, per table: strictly ascending by `(family, prefix, length)`,
  no bits past the length. Exactly one `local` route per VPC block, with
  the block as its prefix and target 0. NIC routes have a real NIC ID
  (not 0 or the broadcast ID), at most 1,000 per table, and never a
  `local` route's prefix and length. Any other `kind` refuses the frame:
  new targets come with a new version and a role that advertises them.

The largest frame (five IPv4 blocks, four DNS servers of each family,
200 subnets, 200 tables, 4,096 routes, a 253-byte domain) is 139,581
bytes: under the largest MapUpdate, so `proto::max_record_payload` does
not grow. helm sends it over OarLink in chunks, like `group_members`.

The decoded form is `VpcConfigFrame` with `std::vector<Ipv4Block>`,
`std::optional<Ipv6Block>`, `std::vector<Subnet>` and
`std::vector<RouteTable>` (each with its routes); version 1's
`ipv4_prefix`, `ipv4_gateway`, `ipv6_prefix` and `routes` go away.

## MapUpdate version 4

Replaces version 3 (`src/proto/map_update.hpp`); decoders accept
version 4 only. Each entry grows from 32 to 40 bytes:

```
  entries  entry_count x 40 bytes, NIC IDs strictly ascending:
    +0x00 nic_id u64 (non-zero) | +0x08 mac [6] | +0x0E flags u8 | +0x0F reserved u8
    +0x10 owner_vtep [16]
    +0x20 subnet_id u64       // 0: no subnet (a VNI used without VpcConfig)
  flags: bit 0 source/destination check off (version 3),
         bit 1 security groups enforced (vpc-security-groups Requirement 6)
```

The largest frame grows by 32 KiB. Subnet IDs are not checked against
anything in the frame: the role matches them against its `VpcConfig`
(Requirement 2.6), since the two frames arrive independently.

## The network role's VPC state

`NetRole` already applies `map_update` and `vpc_config` separately and
hands the VSwitch the mapping, the neighbor tables and the config. With
subnets both feed one derived structure, rebuilt whenever either changes
and swapped into the VSwitch atomically per VNI:

```
struct VpcState {                       // immutable, shared_ptr per VNI
    VpcConfig config;                   // per-VPC fields, gateway MAC
    std::vector<SubnetState> subnets;   // sorted by subnet_id
    std::vector<RouteTrie> tables;      // compiled, per table and family
    flat_map<NicId, std::uint16_t> nic_subnet;  // index into subnets; absent = none
    NeighborTables neighbors;           // only addresses inside the NIC's subnet
    flat_map<std::uint16_t, VtepSet> subnet_vteps;  // flood lists per subnet
};
```

- `nic_subnet` comes from the MapUpdate entries whose subnet is in the
  config. A NIC whose subnet is missing is left out, and the VSwitch
  treats it as having no IP (Requirement 2.6, counter
  `tx_drop_no_subnet` / `rx_drop_no_subnet`).
- `neighbors` is the MapUpdate's address list filtered to addresses
  inside the owning NIC's subnet prefix of the same family. Each
  address left out increments `map_addr_outside_subnet` once per
  rebuild. The ARP/ND proxy, the source check, DHCP and the router all
  read this one table, so they cannot disagree (as today).
- `RouteTrie` is a binary trie per family over at most 1,006 prefixes,
  built at apply time; a lookup walks at most 32 or 128 bits. Each leaf
  holds `local` or a NIC ID.
- `subnet_vteps` is the distinct remote VTEPs owning a NIC in each
  subnet, for group replication (Requirement 6.7).

As built (task 4), the VSwitch does not precompute `nic_subnet`: each
frame looks the NIC's subnet up from the snapshot's binding (the
MapUpdate entry's subnet ID) and the VNI's config, a binary search over
at most 200 subnets. That keeps the MappingTable, which other threads
publish, and the config, which the data-plane thread owns, independent,
and makes "applied in either order" hold by construction. `NetRole`
filters the neighbor table whenever either input changes
(`refresh_neighbors`), which is the one derived structure the design
above keeps. Task 5 compiles the route tables into the VSwitch's
per-VNI state when the config is applied (a `RouteTrie` per table and
family, `src/oar/net/route_trie.hpp`); the local route's target is found
in the neighbor table at lookup time, so it too needs no rebuild when
only the mapping changes. `subnet_vteps` arrives with task 12, where it
is needed.

A VNI with a mapping but no config keeps today's behaviour (one L2
segment, no gateway), which harbor's fabric tests and the unit tests
rely on. A VNI with a config and a mapping whose entries all have subnet
0 carries no IP: the controller always names subnets once it sends
version 2.

## Transmit

The transmit order of oar-net design "IP awareness" stays; steps change
as follows.

1-4. Unchanged, except that the source check (step 3) uses the filtered
     neighbor table, and a NIC with no subnet in a VNI with a config is
     `tx_drop_no_subnet` before parsing.
5.   Local responders answer from the NIC's subnet: ARP and NS for its
     own subnet's gateway only (another subnet's gateway address goes
     unanswered and is `tx_drop_arp_other_subnet`); the ARP/ND proxy
     answers only for owners in the same subnet; DHCPv4 uses the subnet
     prefix, mask and gateway; RAs and DHCPv6 use the subnet's /64. The
     IGMP/MLD querier's source is the subnet's gateway.
6.   Unchanged.
7.   Destination MAC is the gateway MAC: **route** (below).
8.   Group frame: replicated only within the sender's subnet (below).
9.   Unicast to a NIC's MAC: the destination NIC must be in the sender's
     subnet, else `tx_drop_cross_subnet`; then today's address check and
     delivery.

### Route

For a unicast IP packet at the gateway MAC that is not metadata:

1. Table: the sender's subnet's table. Lookup: longest prefix in the
   family's trie. No match: `tx_drop_no_route`.
2. Target:
   - `local`: the NIC owning the destination in `neighbors` (any subnet
     of the VPC). None: `tx_drop_no_neighbor`.
   - NIC: that NIC, under oar-net Requirement 12.7 (unmapped here
     `tx_drop_route_target`, the sender itself `tx_drop_hairpin`, a
     target that keeps its check and does not own the destination
     `tx_drop_ip_dst`).
3. TTL or hop limit one or less: `tx_drop_ttl`. Otherwise lower it by
   one and patch the IPv4 checksum (RFC 1624).
4. Rewrite the destination MAC to the target's and the source MAC to the
   gateway MAC, then deliver to the local port or hand to the Vtep with
   `{vni, src = sender NIC, dst = target NIC}`. Counted as `tx_routed`
   and as `tx_local` or `tx_remote`.

Security groups (`vpc-security-groups`) hook in after step 2, once the
target is known and before the rewrite.

### Group frames

`replicate()` takes the flood list from `subnet_vteps` for the sender's
subnet instead of every peer VTEP of the VNI, and delivers local copies
only to NICs in that subnet. A `GroupMembers` list for a group is
intersected with the subnet's VTEPs. The flood-list cap is compared with
the subnet's list, so a tenant spreading one subnet wide still hits it,
and a VPC with many small subnets is not penalised for its total spread.

## Receive

After `check_ingress` and the inner EtherType and parse steps:

- **Routed frame** (inner source MAC equals this VTEP's gateway MAC for
  the VNI). Without a config for the VNI the packet already failed
  `check_ingress` (`PolicyError::src_mac_mismatch`, now meaning "neither
  the NIC's MAC nor this VNI's gateway MAC"). The VSwitch looks the
  destination up in the source NIC's subnet's table, as the sender did,
  and the resulting target must be the destination NIC; otherwise
  `rx_drop_route_mismatch`. The source address check uses the source
  NIC's addresses as today (or skips it when the source's check is off),
  and the destination check is the routed-hop rule of oar-net design
  "Routing". The TTL is not lowered again.
- **Switched frame** (inner source MAC is the source NIC's). Source and
  destination NIC must share a subnet, else `rx_drop_cross_subnet`.
- **Replicated frame.** Delivered only to local NICs in the source NIC's
  subnet that the group policy and `GroupMembers` admit.

`MappingView` gains `gateway_mac(vni)` (from the config, absent without
one) so `check_ingress` can apply the new source rule without reaching
into the VSwitch.

## helm

`HelmDaemon` keeps the newest `VpcConfig` per VNI and forwards it as
today; only the transfer changes: `OarLink::send_vpc_config` uses
`send_chunked(VendorType::vpc_config, …)` and the role reassembles with
the shared chunk receiver that `group_members` uses, bounded by
`max_vpc_config_size`. helm-control-plane's text for VpcConfig forwarding
gains "in chunks".

## Metadata

`metadata_http`'s `NicView` takes the NIC's subnet (ID, IPv4 prefix,
IPv6 /64) and the VPC's blocks from `VpcState`. New paths under
`network/interfaces/macs/<mac>/`: `subnet-id` (`subnet-` plus the
controller's rendering of the 64-bit ID, the same reversible encoding
kythira uses for `eni-` and `vpc-`), `subnet-ipv4-cidr-block`,
`subnet-ipv6-cidr-blocks`, `vpc-ipv4-cidr-block` (the primary),
`vpc-ipv4-cidr-blocks` and `vpc-ipv6-cidr-blocks`. The rendering function
lives in `src/proto/` next to the other EC2 ID checks so both repos share
one definition (ported to kythira by task 10).

## Counters

New `VSwitchCounters`: `tx_drop_no_subnet`, `tx_drop_cross_subnet`,
`tx_drop_no_neighbor`, `tx_drop_arp_other_subnet`, `rx_drop_no_subnet`,
`rx_drop_cross_subnet`, `rx_drop_route_mismatch`; role-level
`map_addr_outside_subnet`. Existing routing counters keep their meaning.

## Test controller and harbor

`ak-test-controller vpc-config` gains a version 2 syntax:

```
vpc-config VNI VERSION gateway=MAC block=10.0.0.0/16 [block=...] [block6=2001:db8:1200::/56]
           subnet=ID,10.0.1.0/24[,2001:db8:1200:1::/64],TABLE ...
           table=N[,main] route=TABLE,PREFIX,local|NIC ...
           [dns=...] [domain=...] [lease=...]
```

and `map-update` takes `subnet=ID` per entry. The harbor multi-server
scenarios (task 9) are scripts for it, run by harbor's phase-5 driver
(harbor task 8) on the multi-server topology (harbor task 7):

- **Topology.** Three servers: s1 and s2 in combined placement, s3 in
  split placement with two oar-net boards. VPC A: `10.0.0.0/16` and
  `2001:db8:a::/56`; subnets A1 `10.0.1.0/24` (NICs on s1 and s2), A2
  `10.0.2.0/24` (s2 and s3), A3 `10.0.3.0/24` (s3, holding the
  appliance). VPC B: `10.0.0.0/16` again, one subnet `10.0.1.0/24`, on s1
  and s3, so addresses overlap A's.
- **Guests.** A stock Ubuntu cloud image (cloud-init, DHCP and RA) in
  each subnet. Scripted checks run inside the guests over the serial
  console with the image's own `ping`, `nc`, `curl` and `traceroute`
  (`tracepath` where that is all the image has).
- **Checks.** Each guest's address, mask, router and IPv6 prefix come
  from its subnet; ping and TCP in both families between every pair of
  subnets, on one server and across servers; `traceroute` shows one hop
  between subnets and none within one; ARP for another subnet's address
  gets no answer; VPC B's `10.0.1.x` never hears VPC A's; a route
  `10.0.2.0/24 → appliance` in A1's table sends A1 → A2 through the
  appliance on s3 (seen in its counters and a capture inside it) while
  A2 → A2 stays direct; detaching the appliance blackholes that traffic
  (`tx_drop_route_target`) and re-attaching restores it; full-size
  frames cross subnets at the planned MTU, and a guest's PMTU discovery
  works.
- **Hostile VTEP.** A harbor-only build flag lets one role send forged
  routed frames (gateway source MAC, a destination its source subnet's
  table does not lead to, and a cross-subnet frame with the NIC's own
  MAC); the receivers count `rx_drop_route_mismatch` and
  `rx_drop_cross_subnet` and the guests see nothing.

## Testing strategy

- Codecs: unit tests, RFC 8032 signing vectors in
  `src/proto/test_vectors.hpp`, `fuzz_vpc_config` and `fuzz_map_update`
  updated for the new versions, including a re-encode round trip.
- `RouteTrie`: unit tests against a naive longest-prefix scan, and a fuzz
  target that compares the two on random tables and addresses.
- VSwitch: unit tests per counter above; `fuzz_vswitch` gives one VNI
  three subnets, two tables and a NIC route, and checks the invariants
  of Requirement 8.1.
- In-process end to end: `net_role_test` cases with two and three roles
  over the WireGuard tunnel and loopback UDP (skipped without IPv6), as
  `guests_talk_through_the_wireguard_tunnel` does today.
- Network namespaces: `tests/vpc_netns.sh` (root, so CI's sudo job
  only) runs two `ak-oar-net` roles in two namespaces joined by an IPv6
  veth underlay, each with TAP-backed NICs moved into guest namespaces;
  real `dhclient`/`networkd`, `ping`, `nc` and `traceroute` run in those.
  The TAP mode is a test seam: `ak-oar-net --tap NAME=NIC_ID,MAC`
  (repeatable) gives the role TAP-backed ports instead of virtio
  functions.
- harbor: as above (tikhov), then the AWS CLI run (task 11).
