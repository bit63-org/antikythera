# Requirements Document — VPC subnets and the implicit router

## Introduction

A VPC today is one flat L2 segment per VNI: every NIC can reach every
other NIC in the VPC, oar-net answers DHCP, router advertisements and the
gateway's addresses from one per-VPC `VpcConfig`, and routes in that
config can send traffic to an appliance NIC (oar-net Requirements 11 to
13, built in VPC build-order steps 1 to 3). AWS tenants expect more: a
VPC has CIDR blocks, is cut into subnets, each subnet has its own gateway
at its `.1` address and its own route table, and traffic between subnets
is routed by an implicit VPC router that no tenant has to run.

This spec is build-order step 4 of `docs/vpc-gap-analysis.md`. It adds:

- **VPC CIDR blocks and subnets** in the controller model and in the
  signed frames the network role receives, with every NIC in exactly one
  subnet.
- **The implicit router**, distributed: the network role hosting the
  sending NIC answers that NIC's subnet gateway, looks up the subnet's
  route table and forwards the packet straight to the destination NIC's
  VTEP. There is no router box and no extra hop on the fabric, as in AWS.
- **Route tables** per subnet with the `local` target (one route per VPC
  CIDR block, which cannot be removed) and the NIC targets oar-net
  already routes to (oar-net Requirement 12.7), including routes more
  specific than `local` for middlebox appliances.

Step 5 (security groups, `vpc-security-groups`) builds on the subnet
model and the router's forwarding decision; steps 6 onwards (NACLs, the
gateway role, peering) add route targets and per-subnet rules to the same
frames.

### What this spec does not cover

- Route targets other than `local` and a NIC: internet, NAT and
  egress-only gateways, peering, transit gateways, endpoints and VPN
  gateways come with their own specs and a new frame version.
- Network ACLs (build-order step 6) and security groups (step 5).
- The DNS resolver at the VPC's `.2` address. The address is reserved
  here so it never goes to a NIC.
- The kythira EC2 module's implementation. This spec states what the
  controller must keep and send; the module's spec
  (`ec2-compatible-api` in the kythira repository) is amended by task 10.
- Per-subnet multicast opt-in is task 12, after the rest; until then the
  VPC-wide `GroupPolicy` applies to every subnet, with replication
  confined to the sender's subnet.

## Glossary

- **VPC CIDR block** — an IPv4 prefix (a primary and up to four
  secondaries) or an IPv6 /56 assigned to a VPC. Every subnet and every
  guest address in the VPC lies inside one.
- **Subnet** — a controller object inside a VPC with an IPv4 prefix, an
  optional IPv6 /64, a gateway address and a route table. Identified on
  the wire by its 64-bit **subnet ID**, allocated by the controller,
  unique in the region and never reused (kythira renders it as
  `subnet-…`).
- **Gateway MAC** — the VPC router's MAC, one per VPC (oar-net
  Requirement 12.1). Every subnet's gateway answers with it.
- **Route table** — an ordered set of routes, numbered within the VPC.
  One is the VPC's **main** route table; a subnet uses the table it is
  associated with, else the main one.
- **Source VTEP** — the VTEP hosting the NIC that sent a packet; the
  router runs there.
- **Routed frame** — a frame the router forwarded: its destination MAC
  is the target NIC's and its source MAC is the gateway MAC.

## Requirements

### Requirement 1: VPC CIDR blocks

**User Story:** As a tenant, I want my VPC to own the address ranges I
gave it, so that subnets and instances can only use addresses inside
them.

#### Acceptance Criteria

1. The controller SHALL keep, per VPC, a primary IPv4 CIDR block from
   /16 to /28 and up to four secondary IPv4 blocks, none overlapping,
   and at most one IPv6 /56, as EC2 does (`CreateVpc`,
   `AssociateVpcCidrBlock`, `DisassociateVpcCidrBlock`).
2. The blocks SHALL be carried in the VPC's signed configuration frame
   (Requirement 4), so every network role hosting the VPC holds the same
   set.
3. A secondary block SHALL NOT be disassociated while a subnet uses it;
   the controller SHALL refuse with EC2's error.

### Requirement 2: Subnets

**User Story:** As a tenant, I want to cut my VPC into subnets, each with
its own prefix and gateway, and put each network interface in one of
them, as on EC2.

#### Acceptance Criteria

1. A subnet SHALL have an IPv4 prefix from /16 to /28 inside one of the
   VPC's IPv4 blocks and MAY have one IPv6 /64 inside the VPC's /56.
   Subnets of one VPC SHALL NOT overlap in either family.
2. In each subnet the controller SHALL reserve, as EC2 does, the network
   address, the next three (the gateway at base + 1, the DNS resolver at
   base + 2, and base + 3), and the IPv4 broadcast address, and SHALL
   never assign them to a NIC. The subnet's IPv4 gateway SHALL be base
   + 1.
3. A VPC SHALL have at most 200 subnets (EC2's default quota).
4. Every NIC SHALL belong to exactly one subnet, named by subnet ID in
   the NIC's entry of the signed mapping (Requirement 5), and every guest
   address of the NIC SHALL lie inside that subnet's prefix of the same
   family.
5. A subnet SHALL NOT be deleted while it holds a NIC; the controller
   SHALL refuse with `DependencyViolation`.
6. A network role SHALL treat a guest address of a NIC that lies outside
   the NIC's subnet, as it holds it, as not owned by the NIC: the source
   check refuses it, the ARP/ND proxy and DHCP ignore it, and the role
   counts it per mapping it applies. A NIC whose subnet is not in the
   role's configuration for the VPC SHALL send and receive no IP traffic
   (counted), so a mapping that arrives before its configuration fails
   closed.

### Requirement 3: Per-subnet gateway and address configuration

**User Story:** As a tenant, I want a stock image in any subnet to get
the right address, mask, router and IPv6 prefix by DHCP and router
advertisements, as it would on EC2.

#### Acceptance Criteria

1. oar-net SHALL answer, for a NIC, ARP for its own subnet's IPv4
   gateway address and neighbor solicitations for the gateway's
   link-local address, with the VPC's gateway MAC (oar-net Requirement
   12.2, now per subnet). ARP for another subnet's gateway SHALL go
   unanswered.
2. The ARP/ND proxy SHALL answer a NIC only for addresses owned by NICs
   in the same subnet. Addresses in other subnets SHALL go unanswered,
   since a guest reaches them through its gateway.
3. DHCPv4 (oar-net Requirement 12.3) SHALL hand a NIC its lowest IPv4
   guest address inside its subnet's prefix, the subnet mask, and the
   subnet's gateway as router and server identifier.
4. Router advertisements and DHCPv6 (oar-net Requirements 12.4 and 12.5)
   SHALL use the NIC's subnet's /64; a subnet without one gets neither,
   and its NICs' IPv6 traffic is dropped and counted.
5. The metadata service (oar-net Requirement 13) SHALL answer
   `subnet-id`, `subnet-ipv4-cidr-block`, `subnet-ipv6-cidr-blocks`,
   `vpc-ipv4-cidr-block`, `vpc-ipv4-cidr-blocks` and
   `vpc-ipv6-cidr-blocks` under `network/interfaces/macs/<mac>/` from the
   NIC's subnet and the VPC's blocks.
6. DNS servers, domain name and lease time stay per VPC (EC2's DHCP
   option sets are per VPC).

### Requirement 4: Route tables

**User Story:** As a tenant, I want each subnet to follow a route table I
control, with the VPC's own ranges always reachable, and with the option
of sending some of them through an appliance I run.

#### Acceptance Criteria

1. A VPC SHALL have one main route table and MAY have more, at most 200
   in all (EC2's default quota). Each subnet SHALL be associated with at
   most one table; a subnet with none uses the main table.
2. Every route table SHALL contain exactly one `local` route for each of
   the VPC's CIDR blocks, with that block as its destination. `local`
   routes SHALL NOT be removed or have their targets changed while the
   block is associated.
3. A route table MAY also hold routes whose target is a NIC in the VPC
   (oar-net Requirement 12.7), at most 1,000 per table, with any
   destination prefix including a default route, and including prefixes
   inside a VPC block that are longer than its `local` route (EC2's
   middlebox routing). A NIC route with exactly a `local` route's prefix
   SHALL be refused by the controller.
4. Route tables, their routes and subnet associations SHALL be carried
   with the subnets in the VPC's signed configuration frame, so a change
   to any of them takes effect atomically on each server.
5. A route whose target NIC is not in the receiving server's mapping for
   the VPC SHALL match nothing there (its traffic is dropped and counted,
   EC2's `blackhole` state), rather than refuse the frame.

### Requirement 5: Mapping and configuration frames

**User Story:** As the operator, I want subnets, route tables and the
subnet of each NIC to reach every server as signed, versioned frames,
like the mapping and VPC configuration already do.

#### Acceptance Criteria

1. The `VpcConfig` frame SHALL gain a version 2 that carries the VPC's
   CIDR blocks, its subnets (subnet ID, IPv4 prefix and gateway, optional
   IPv6 /64, route table), and its route tables (number, main flag,
   routes with a target kind of `local` or NIC), alongside the per-VPC
   fields of version 1. Version 1's VPC-wide prefix, gateway and routes
   are replaced by these. Version 2 SHALL be a full per-VPC snapshot,
   signed, naming its target server and key, with a per-VPC version
   that strictly increases.
2. Version 2 frames SHALL be delivered to every server hosting a NIC in
   the VPC before the first NIC there is attached and again on every
   change (controller-interface Requirement 10.3, unchanged).
3. The `MapUpdate` frame SHALL gain a version 4 that carries each NIC's
   subnet ID. Its flags byte SHALL also define bit 1, "security groups
   enforced", for `vpc-security-groups` Requirement 6.
4. Each frame SHALL be a canonical encoding: lists strictly ascending,
   reserved bytes zero, every bound checked, so re-signing is
   reproducible and duplicates are impossible. Decoders SHALL return
   `std::expected`, use `ak::wire`, and have unit tests, signing vectors
   and a fuzz target.
5. helm SHALL forward version 2 `VpcConfig` frames unmodified, in chunks
   over OarLink since they exceed one message, keep the newest per VPC,
   and resend it to a network role whose sideband reopens before any NIC
   is prepared there (controller-interface Requirement 10.4, now
   chunked).
6. A network role SHALL apply a frame whole or not at all, and SHALL
   accept the mapping and configuration in either order (Requirement
   2.6, 4.5).

### Requirement 6: Distributed routing at the source VTEP

**User Story:** As a tenant, I want traffic between my subnets to take
one hop on the fabric, at line rate, with no router I have to run or
scale.

#### Acceptance Criteria

1. WHEN a NIC sends a unicast IP packet to the gateway MAC that no local
   responder consumes THEN its network role SHALL look the destination
   up in the route table of the NIC's subnet, longest prefix first, per
   family, and forward it to the target that the route names.
2. For a `local` route the target SHALL be the NIC in the VPC that owns
   the destination address in the role's mapping; a destination no NIC
   owns SHALL be dropped and counted. For a NIC route the target SHALL be
   that NIC, under oar-net Requirement 12.7's rules.
3. Forwarding SHALL rewrite the destination MAC to the target's and the
   source MAC to the gateway MAC, lower the TTL or hop limit by one
   (updating the IPv4 header checksum incrementally), and send the frame
   to the target's port or VTEP directly. A packet whose TTL or hop limit
   is one or less SHALL be dropped and counted.
4. Unicast frames addressed straight to the MAC of a NIC in another
   subnet SHALL be dropped and counted on transmit and on receive: the
   only way between subnets is through the router, so a route through an
   appliance cannot be bypassed at L2.
5. A receiving VTEP SHALL accept a routed frame (inner source MAC equal
   to the VPC's gateway MAC) only if it holds a configuration for the VNI
   with that gateway MAC, and only if its own lookup in the source NIC's
   subnet's route table picks the same target NIC; otherwise it SHALL
   drop and count it. A compromised sending VTEP therefore cannot skip a
   middlebox route or reach a NIC the route table does not lead to.
6. Packets between NICs of one subnet SHALL keep today's path: switched
   at L2, never through the router, whatever the route table says (as in
   EC2, where more-specific routes apply only to traffic that reaches
   the router).
7. Group frames SHALL be replicated only to NICs in the sender's subnet,
   locally and on remote VTEPs; the flood list and its cap (oar-net
   Requirement 10.4) count only VTEPs hosting a NIC in that subnet, and
   a receiving VTEP SHALL deliver a replicated frame only to its local
   NICs in the source NIC's subnet.
8. Each drop cause SHALL have its own counter, and routing changes SHALL
   take effect for the next frame after a frame is applied.

### Requirement 7: Controller and EC2 API

**User Story:** As a kythira user, I want the EC2 subnet and route table
calls to work, and the ones that need later features to be refused
clearly.

#### Acceptance Criteria

1. The EC2 module SHALL implement `CreateSubnet`, `DeleteSubnet`,
   `DescribeSubnets`, `ModifySubnetAttribute` (the attributes this spec
   backs), `AssociateVpcCidrBlock`, `DisassociateVpcCidrBlock`,
   `AssociateSubnetCidrBlock` and `DisassociateSubnetCidrBlock` (IPv6),
   `CreateRouteTable`, `DeleteRouteTable`, `DescribeRouteTables`,
   `AssociateRouteTable`, `DisassociateRouteTable`,
   `ReplaceRouteTableAssociation` (including the main table), and
   `CreateRoute`, `ReplaceRoute` and `DeleteRoute` with
   `NetworkInterfaceId` or `InstanceId` targets.
2. Routes to targets this spec does not back (`GatewayId`,
   `NatGatewayId`, `VpcPeeringConnectionId`, `TransitGatewayId`,
   `VpcEndpointId`, `EgressOnlyInternetGatewayId`, and the rest) SHALL be
   refused with `UnsupportedOperation`. Controller-interface Requirement
   6.4's refusal of subnets beyond one per VPC is lifted.
3. `RunInstances`, `CreateNetworkInterface` and their describe calls
   SHALL place each interface in its subnet and allocate its addresses
   from the subnet's prefixes, outside the reserved ones.
4. A route table SHALL report a NIC route as `blackhole` while its
   target is detached or deleted, as EC2 does.

### Requirement 8: Testing

**User Story:** As the operator, I want each path proven end to end:
inside one role, between roles over the encrypted underlay, with real
Linux network stacks, and on multi-server harbor with stock guests.

#### Acceptance Criteria

1. The new codecs, the route lookup and the VSwitch's subnet and routing
   paths SHALL have unit tests and fuzz targets; `fuzz_vswitch` SHALL
   check that no frame crosses subnets except through the router, that
   every routed frame carries the gateway MAC as source and a lowered
   TTL, and that no routed frame reaches a NIC other than the one the
   source subnet's route table names.
2. In-process tests SHALL run two and three network roles over the
   WireGuard tunnel: routing between subnets on one server and across
   servers, a middlebox route through an appliance NIC on a third
   server, a target that disappears (blackhole), frames arriving in
   either order, and a hostile sending VTEP that forges routed frames.
3. A network-namespace test (CI, under sudo, like
   `tests/geneve_interop.sh`) SHALL drive real Linux stacks on
   TAP-backed NICs of two network roles in two subnets: DHCP, ping and
   TCP across subnets in both families, a one-hop `traceroute`, no ARP
   answer for another subnet's address, and path MTU.
4. harbor SHALL verify, on three servers in both placements, stock cloud
   images in three subnets of one VPC configuring themselves by DHCP and
   RA, reachability between subnets on one server and across servers,
   isolation between two VPCs with overlapping CIDRs, a middlebox
   appliance on another server, an appliance that goes away, and MTU.
5. An AWS CLI run against kythira SHALL create a VPC, two subnets and a
   route table, launch instances in each subnet on harbor, and reach one
   from the other (controller-interface task 7 extended).
