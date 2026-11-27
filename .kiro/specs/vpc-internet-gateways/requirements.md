# Requirements Document — VPC internet gateways, public addresses and NAT

## Introduction

A VPC today has no way in or out: oar-net switches and routes only
between NICs of one VPC, and the controller refuses Elastic IPs and
gateways (`docs/vpc-gap-analysis.md`, "No way in or out"). This spec is
the first half of build-order step 7: the internet gateway, Elastic IPs
and auto-assigned public IPv4 addresses, the NAT gateway, and the IPv6
egress-only internet gateway.

The shape follows the decisions Clark made on 2026-11-27:

- **A horizontally scalable, stateless edge fleet**, as AWS's edge
  works: identical **edge roles** with an outside interface wrap and
  unwrap the VPC encapsulation and do the 1:1 translation between public
  and private addresses. Nothing they hold is per flow, so any edge role
  can take any packet in either direction, capacity grows by adding edge
  roles, and losing one moves its traffic to the rest without resetting
  connections.
- **Host VTEPs never see public addresses.** A route to an internet
  gateway sends the packet to an edge role; the edge translates.
- **NAT gateways are distributed.** Many-to-one translation needs
  per-flow state, so it runs at the network role hosting the sending
  NIC, next to the security-group connection tracking. The controller
  gives each server **port blocks** of the NAT gateway's address, so the
  edge routes return traffic to the right server from the destination
  port alone and stays stateless.
- **IPv6 is routed, not translated.** VPC IPv6 prefixes come from a
  public pool; the egress-only gateway is outbound-only connection
  tracking at the sending NIC's network role.
- **Public pools are operator-defined prefixes**, any prefix at all. A
  region with no public address space (one dynamic IPv4 address at home)
  runs with a LAN prefix as its "public" pool and the home router
  forwarding to it; buying or leasing a /24 later is a configuration
  change.
- **The edge table is regional.** Every edge role holds every public
  address of the region, since an Elastic IP can move to any instance in
  any zone. Edge roles are deployed in each zone. Sharding by public
  prefix is left for later; hosts keep their per-VPC frames.

### What this spec does not cover

- BGP and BFD toward upstream routers. The first build uses static
  routes (routed mode) or answers ARP/ND on a LAN (on-link mode); BGP is
  a follow-up task here once the edge works.
- Bring-your-own-IP API calls (`ProvisionByoipCidr` and the rest). The
  operator configures pools directly.
- Private NAT gateways (`ConnectivityType=private`), NAT64/DNS64, VPC
  peering, transit gateways, VPN, endpoints, load balancers and the
  `.2` DNS resolver, including public DNS hostnames. Each comes with its
  own spec.
- Network ACLs. Security groups (`vpc-security-groups`) apply to traffic
  through the gateways like any other traffic.
- The kythira EC2 module's implementation. This spec states what the
  controller must keep and send; the module's spec
  (`ec2-compatible-api` in the kythira repository) is amended alongside
  it.

## Glossary

- **Edge role** — a network role in edge mode: an underlay port on the
  encrypted fabric like any VTEP, plus an **outside port** toward the
  upstream network. It hosts no NICs.
- **Edge server** — a server in the controller's inventory with the edge
  class: helm and one or more edge roles, no guests.
- **Public pool** — an operator-configured IPv4 or IPv6 prefix that
  public addresses are allocated from. "Public" means "reachable from
  outside the VPCs", not necessarily globally routable.
- **Elastic IP (EIP)** — a public IPv4 address allocated to an account
  and associated with one private IPv4 address of a NIC, or used by a
  NAT gateway. An **auto-assigned public IP** behaves the same but lives
  only as long as the instance runs.
- **Gateway ID** — the 64-bit controller ID of an internet gateway,
  egress-only internet gateway or NAT gateway. It comes from the same
  never-reused, region-unique space as NIC IDs, so on the wire it stands
  in the Geneve NIC-pair option where a NIC ID would.
- **Port block** — 1,024 consecutive ports of one NAT gateway address
  (ports 1,024 to 65,535 make 63 blocks), owned by one server.
- **Edge table** — the regional mapping every edge role holds: public
  address to (VNI, private address, NIC or gateway, owning VTEP), NAT
  port blocks to their servers, and the pools.

## Requirements

### Requirement 1: Edge fleet

**User Story:** As the operator, I want internet traffic to pass through
a fleet I can grow by adding identical members, so that capacity and
availability come from count rather than from failover pairs.

#### Acceptance Criteria

1. Edge roles SHALL keep no per-flow state: every forwarding decision
   SHALL depend only on the packet, the edge table and the set of
   healthy tunnel peers, so any edge role can forward any packet of any
   connection in either direction.
2. Each edge role SHALL be a VTEP on the encrypted underlay with its own
   WireGuard key, distributed like every other VTEP's
   (controller-interface Requirement 8). The controller SHALL list every
   edge VTEP in the `TunnelPeers` of every server hosting a NIC in a VPC
   with a gateway, and every such server in each edge VTEP's, marked
   with the edge flag (Requirement 7.4).
3. A host network role SHALL spread gateway-bound packets over the
   healthy edge peers by rendezvous hashing of the VNI and the inner
   5-tuple, so one flow keeps one edge role while it is healthy and only
   the flows of a failed edge role move. An edge peer the tunnel reports
   down SHALL leave the set within the tunnel's liveness timeout.
4. Return traffic MAY take a different edge role from the outbound
   traffic of the same connection; nothing SHALL depend on symmetry.
5. An edge role's outside port SHALL run in one of two modes, set per
   role by the operator:
   - **routed**: upstream routes the public pools to the edge roles'
     outside addresses (static routes with several next hops, BGP
     later), and the edge forwards outbound packets to a configured
     upstream next hop;
   - **on-link**: the pools are on the outside LAN, and the edge role
     answers ARP and ND for allocated public addresses. Each address SHALL
     be answered by one healthy edge role, chosen by rendezvous hashing of
     the address over the edge roles on that LAN; when one fails, the
     others SHALL take its addresses and announce them with gratuitous
     ARP and unsolicited neighbor advertisements.
6. Edge servers SHALL be deployed in each zone, and a region SHALL keep
   working with any one edge role, or every edge role in one zone, down.

### Requirement 2: Public pools

**User Story:** As the operator, I want to say which prefixes are public,
so that the same software runs with a bought /24, an ISP's delegated
IPv6 prefix, or a home LAN.

#### Acceptance Criteria

1. The controller SHALL keep a region's public pools as operator
   configuration: any number of IPv4 prefixes and IPv6 prefixes, none
   overlapping one another or any VPC block the region has allocated.
   RFC 1918 and ULA prefixes SHALL be accepted.
2. Elastic IPs, auto-assigned public IPs and NAT gateway addresses SHALL
   be allocated from the IPv4 pools; VPC IPv6 /56 blocks SHALL be
   allocated from the IPv6 pools.
3. The pools SHALL reach every edge role in the edge table, so the edge
   knows which outside addresses are its own (Requirements 4.6, 8.4,
   9.4).
4. A region with no IPv4 pool SHALL refuse `AllocateAddress`, public IPs
   on launch and NAT gateways with EC2's address-limit error, and keep
   working otherwise.

### Requirement 3: Internet gateway and route targets

**User Story:** As a tenant, I want to attach an internet gateway and
route to it, so that instances with public addresses reach the internet
and are reached from it.

#### Acceptance Criteria

1. The controller SHALL keep internet gateways (at most one attached per
   VPC) and egress-only internet gateways (at most one per VPC), and
   SHALL send them to the network role in `VpcConfig` version 3
   (design "VpcConfig version 3") with their gateway IDs.
2. Route tables SHALL accept three new targets: an attached internet
   gateway (`igw`), the VPC's egress-only gateway (`eigw`, IPv6
   destinations only), and a NAT gateway of the VPC (`nat`, IPv4
   destinations only). A route to a gateway the frame does not list
   SHALL refuse the frame whole.
3. When the router's lookup for a packet sent by a NIC ends at `igw`,
   the source role SHALL apply the sender's security groups, lower the
   TTL as for any routed packet, and send the packet unchanged to an
   edge peer with the internet gateway's ID as the destination in the
   NIC-pair option. With no healthy edge peer it SHALL drop and count
   (`tx_drop_no_edge`).
4. The source role SHALL NOT translate addresses for `igw` routes and
   SHALL NOT need to know whether the source address has a public
   mapping; the edge decides (Requirement 4.3).
5. A frame from an edge peer (`rx` with a gateway ID as the source) SHALL
   be delivered to a local NIC only when:
   - the tunnel peer is marked edge (else `rx_drop_not_edge`);
   - the source gateway is an internet gateway attached to the frame's
     VPC (else `rx_drop_edge_gateway`);
   - the inner source address lies outside every block of the VPC (else
     `rx_drop_edge_src_inside`), so the edge can never pose as a NIC of
     the VPC and slip past security-group references;
   - the inner destination is an address of the destination NIC in the
     mapping, in the NIC's subnet;
   - the route the destination NIC's subnet table gives for the inner
     *source* address is `igw` (accept), or `eigw` with a matching
     outbound flow (Requirement 6.3); anything else is
     `rx_drop_edge_no_route`. A subnet with no route to the gateway is
     therefore unreachable from outside, as on EC2.
   The NIC's security groups SHALL then apply as for any inbound packet.
6. The TTL SHALL be lowered once per direction: by the source role on
   the way out, by the edge role on the way in.

### Requirement 4: Elastic IPs and public IPv4 addresses

**User Story:** As a tenant, I want an address the internet can reach
that I can move between instances, so that my service survives instance
replacement.

#### Acceptance Criteria

1. The controller SHALL allocate Elastic IPs from the IPv4 pools to an
   account, associate one with one private IPv4 address of a NIC in a
   VPC with an attached internet gateway, move it, disassociate and
   release it; and SHALL give a NIC an auto-assigned public IP when its
   subnet or launch asks for one, released when the instance stops or
   terminates.
2. Each association SHALL be one edge table entry: public address,
   VNI, private address, NIC ID and the VTEP hosting the NIC. Moving the
   NIC to another server (a stop and start, or a live migration) SHALL
   update the entry's VTEP.
3. Outbound, an edge role SHALL look the packet up by (VNI, inner source
   address), check that the entry's NIC is the frame's source NIC and its
   VTEP the frame's tunnel peer (else `edge_drop_owner`), rewrite the
   source to the public address, fix the IP and L4 checksums, and send
   it out. A packet with no entry SHALL be dropped and counted
   (`edge_drop_no_public`), as EC2 drops traffic from an instance with
   no public address at the internet gateway.
4. Inbound, an edge role SHALL look the packet up by destination
   address, rewrite the destination to the private address, lower the
   TTL, and send it to the entry's VTEP with the internet gateway's ID as
   the source and the NIC as the destination in the NIC-pair option.
5. Translation SHALL be 1:1 and port-preserving, and SHALL rewrite the
   addresses quoted inside ICMP errors, so path MTU discovery and
   traceroute work through it.
6. A packet from a NIC to a public address in the region's own pools
   SHALL be turned around inside the edge role (hairpin): translated out
   and then handled as inbound without leaving the outside port.

### Requirement 5: NAT gateway

**User Story:** As a tenant, I want instances without public addresses
to reach the internet through a NAT gateway, so that they can fetch
updates without being reachable from outside.

#### Acceptance Criteria

1. The controller SHALL keep NAT gateways per VPC (public connectivity
   only), each with a gateway ID, a primary private address in a subnet,
   an Elastic IP, and up to seven secondary address pairs, as EC2 does.
   The VPC SHALL have an attached internet gateway.
2. A NAT gateway's ports SHALL be split into port blocks. The controller
   SHALL give a server a block of a NAT gateway when the server hosts a
   NIC in a subnet that routes to it, more blocks when the server reports
   pressure (Requirement 5.7), up to 16 blocks per server and gateway,
   and SHALL take back blocks from a server that has hosted no such NIC
   for ten minutes.
3. Every block SHALL be in the edge table before the server that owns it
   is told, and a server SHALL stop using a block before the edge table
   drops it (design "Port block lifecycle").
4. When the router's lookup ends at `nat`, the source role SHALL apply
   the sender's security groups, then translate the source address and
   port to one of the NAT gateway's private addresses and a port from a
   block this server owns, keep that mapping in a NAT flow, and send the
   packet to an edge peer with the NAT gateway's ID as the source and the
   internet gateway's ID as the destination. The edge SHALL then
   translate the NAT gateway's private address to its Elastic IP like any
   other association.
5. Mappings SHALL be endpoint-dependent: a NAT address and port SHALL be
   reused for different (protocol, destination address, destination
   port), never for two flows to the same one, so each block gives 1,024
   concurrent flows per destination. TCP, UDP and ICMP echo (by its
   identifier) SHALL be translated; other protocols SHALL be dropped and
   counted (`drop_nat_protocol`). Non-first fragments SHALL follow their
   first fragment's mapping through the security-group fragment cache.
6. Inbound, an edge role SHALL find the NAT gateway by destination
   address, the block by destination port, check the block has an owner,
   translate the destination to the NAT gateway's private address, and
   send the frame to the block's server with the NAT gateway's ID as the
   destination. That server SHALL find the NAT flow, restore the original
   destination address and port, and deliver to the NIC through its
   security groups; with no flow it SHALL drop and count
   (`rx_drop_nat_no_flow`).
7. NAT flows SHALL time out after 350 seconds idle for TCP, as EC2's NAT
   gateway does, and 60 seconds for UDP and ICMP; they SHALL count
   against the network role's flow budget (vpc-security-groups
   Requirement 4) and per-NIC limits. A role that finds no free port for
   a destination SHALL drop and count it (`drop_nat_ports`, EC2's
   `ErrorPortAllocation`) and report pressure.
8. A NIC moving to another server SHALL lose its NAT flows, and so SHALL
   a role restart; new connections then work at once.

### Requirement 6: IPv6 and the egress-only internet gateway

**User Story:** As a tenant, I want routed IPv6 with the choice of
inbound or outbound-only reachability, so that IPv6 works as it does on
EC2.

#### Acceptance Criteria

1. VPC IPv6 /56 blocks SHALL come from the IPv6 pools, so NIC IPv6
   addresses are public addresses and SHALL NOT be translated. Every
   IPv6 address of a NIC in a VPC with a gateway SHALL be an edge table
   entry (VNI, address, NIC, VTEP).
2. `igw` routes SHALL carry IPv6 both ways, checked as in Requirements
   3.5 and 4.3 without translation.
3. When the router's lookup ends at `eigw`, the source role SHALL record
   an outbound gateway flow for the sending NIC (in the flow table of
   `vpc-security-groups`, whether or not the NIC's security groups are
   enforced) and send the packet to an edge peer as for `igw`. Inbound
   frames whose source route is `eigw` SHALL be delivered only when they
   match such a flow (else `rx_drop_eigw_unsolicited`), with ICMPv6
   errors matched through their quoted packet.

### Requirement 7: Edge table distribution

**User Story:** As the operator, I want every edge role to hold the same
regional table, updated quickly and in order, so that an association
works within seconds and never points at the wrong instance.

#### Acceptance Criteria

1. The controller SHALL send the edge table to every edge server as
   signed `EdgeMapping` frames (design "EdgeMapping frame"): a snapshot in
   parts, consistent at one regional sequence number, and deltas, each
   covering the next contiguous range of sequence numbers.
2. An edge role SHALL build a snapshot off to the side and switch to it
   atomically once every part has arrived, then apply deltas strictly in
   sequence; a delta that does not follow its sequence SHALL be held or
   dropped, never applied out of order, and a gap SHALL be reported so
   the controller sends a new snapshot.
3. Each edge role SHALL report the sequence it has applied
   (`edge_applied`), and the controller SHALL treat an entry as live only
   once every edge role in service has applied it (Requirements 5.3,
   7.5).
4. `TunnelPeers` version 2 SHALL carry a flags byte per peer with bit 0
   marking an edge VTEP. A host role SHALL send gateway traffic only to
   peers so marked, and accept gateway-sourced frames only from them.
5. An association change SHALL update the edge table before the
   controller reports it complete; a disassociation SHALL be removed from
   the edge table before the address can be associated elsewhere.
6. helm on an edge server SHALL keep the newest complete snapshot and the
   deltas after it, and replay them in order when an edge role restarts.

### Requirement 8: Trust and validation

**User Story:** As the operator, I want a compromised host or edge role
to be unable to use another tenant's public address or reach into a VPC
past its security groups.

#### Acceptance Criteria

1. Edge roles SHALL be data-plane roles under the threat model: untrusted
   and contained. Every frame they act on SHALL be authenticated by the
   tunnel and checked against the signed edge table.
2. An edge role SHALL forward a frame from a host only if its source NIC
   or NAT gateway owns the inner source address (and, for NAT, the port's
   block) and the tunnel peer is that entry's VTEP (Requirement 4.3,
   5.6).
3. A host role SHALL apply Requirement 3.5 to every frame from an edge
   peer.
4. On its outside port an edge role SHALL drop packets whose source lies
   in a public pool of the region, is unspecified, loopback, multicast or
   link-local, or falls in an operator-configured bogon list
   (`edge_drop_spoofed`). It SHALL NOT drop private (RFC 1918) sources by
   default, so a LAN pool in on-link mode works.
5. Edge roles SHALL keep per-public-address packet and byte counters and
   MAY rate-limit inbound traffic per address with operator-configured
   limits (`edge_drop_rate`).

### Requirement 9: MTU, ICMP and TTL

**User Story:** As a tenant, I want large packets and path MTU discovery
to work between my 8,858-byte VPC MTU and the 1,500-byte internet.

#### Acceptance Criteria

1. Each edge role's outside MTU SHALL be configured (default 1,500).
2. An outbound packet larger than the outside MTU SHALL be fragmented by
   the edge if it is IPv4 without DF; otherwise the edge SHALL answer it
   with ICMP "fragmentation needed" or ICMPv6 "packet too big" (rate
   limited per source NIC) from its own outside address, sent back to
   the source NIC through the tunnel like any inbound packet.
3. A packet whose TTL or hop limit would reach zero at the edge SHALL be
   dropped with an ICMP time-exceeded reply, rate limited.
4. Packets addressed to an edge role's own outside addresses SHALL be
   answered only for ICMP echo and ARP/ND, rate limited, and otherwise
   dropped.

### Requirement 10: Metering and billing

**User Story:** As the operator, I want to charge for public addresses,
NAT gateways and data out, as EC2 does.

#### Acceptance Criteria

1. Edge roles SHALL keep cumulative per-entry meters: packets and bytes
   out and in, and drops by cause, read by helm with a paged OarLink read
   (`edge_usage`) and reported as report kind `edge_usage`, keyed by
   `(server_id, boot_id, slot, public address)`.
2. Host roles SHALL keep cumulative per-NAT-gateway meters: blocks held,
   flows in use, the busiest destination's ports in use per block, and
   `drop_nat_ports`, read with `nat_usage` and reported as report kind
   `nat_usage`.
3. The controller SHALL turn readings into per-account hourly deltas:
   data out and in per public address, bytes processed per NAT gateway,
   and from its own state the hours each public address is allocated and
   each NAT gateway exists. A reading below the previous one in its
   series SHALL be recorded as a fault and billed as zero.

### Requirement 11: Limits

#### Acceptance Criteria

1. An edge role SHALL hold at least 1,048,576 edge table entries; the
   measured figure for the board class SHALL be recorded and the
   controller SHALL refuse allocations past it.
2. `TunnelPeers` holds at most 2,048 peers, so one edge role SHALL serve
   at most 2,047 host servers in this version; a larger region needs edge
   groups (left for later and recorded in the design).
3. A VPC SHALL have at most 16 NAT gateways, and `VpcConfig` version 3
   SHALL stay under `proto::max_record_payload`.
4. The first outside port SHALL use AF_PACKET with memory-mapped
   TPACKET_V3 rings and PACKET_FANOUT, never one system call per frame.
   An AF_XDP outside port and underlay endpoint SHALL follow, zero-copy
   where the driver supports it and copy mode elsewhere, built only when
   its optional dependency is present. DPDK SHALL be adopted only if
   measurement on the target NIC shows AF_XDP zero-copy short of line
   rate (design "Packet I/O").

### Requirement 12: Controller and EC2 API

#### Acceptance Criteria

1. The kythira EC2 module SHALL serve `CreateInternetGateway`,
   `DeleteInternetGateway`, `AttachInternetGateway`,
   `DetachInternetGateway`, `DescribeInternetGateways`,
   `CreateEgressOnlyInternetGateway`, `DeleteEgressOnlyInternetGateway`,
   `DescribeEgressOnlyInternetGateways`, `AllocateAddress` (domain
   `vpc`), `AssociateAddress`, `DisassociateAddress`, `ReleaseAddress`,
   `DescribeAddresses`, `CreateNatGateway`, `DeleteNatGateway`,
   `DescribeNatGateways`, routes with `GatewayId` (`igw-`, `eigw-`) and
   `NatGatewayId`, `MapPublicIpOnLaunch` and `AssociatePublicIpAddress`,
   and public addresses in `DescribeInstances` and
   `DescribeNetworkInterfaces`, with EC2's errors and dependency rules.
2. Instance metadata SHALL serve `public-ipv4` and the per-interface
   `public-ipv4s` and `ipv4-associations/<public-ip>` paths, carried in
   `InstanceMetadata` version 2.
3. The controller SHALL keep edge servers in its inventory with their
   zone and outside mode, and refuse to place guests on them.

### Requirement 13: Testing

#### Acceptance Criteria

1. Codecs (`VpcConfig` version 3, `TunnelPeers` version 2, `EdgeMapping`,
   `InstanceMetadata` version 2, the usage reports) SHALL have unit tests,
   signing vectors and fuzz targets with re-encode round trips.
2. The edge table, the edge forwarding path and the NAT engine SHALL
   have unit tests on a fake clock and fuzz targets driving hostile
   packets, checking Requirements 4.3, 5.5, 8.2 and 8.4.
3. In-process tests SHALL run host roles and two edge roles over the
   WireGuard tunnel: EIP in and out, NAT out and back, egress-only, an
   edge role killed mid-stream with traffic continuing through the other,
   and a hostile host using another NIC's public address.
4. The network-namespace harness SHALL add an "internet" namespace
   behind the edge roles, in routed and on-link modes, with real
   `curl`, `ping`, `tracepath` and `nc`.
5. harbor SHALL run the same on tikhov, then the AWS CLI end to end:
   `create-internet-gateway`, `allocate-address`, `associate-address`,
   `create-nat-gateway` and routes, an instance reached from outside and
   another reaching outside through the NAT gateway.
