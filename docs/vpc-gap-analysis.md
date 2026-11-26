# AWS VPC gap analysis

_Status as of 2026-11-26, against `main`. The fabric stack (#41 Vtep,
#42 mailbox v3, #43 MapUpdate v2, #45 MTU, #46 NetRole, #47 WireGuard,
#48 VTEP key distribution, wired together in #93), the first L3 pieces
(#56 group policy, #61 source/destination check, #62 DHCPv4 and gateway
ARP/ND, #63 RA, DHCPv6 and the metadata intercept) and the build-order
steps 2 and 3 that followed (#97 signed group policy and usage, #104/#105
signed `VpcConfig`, #107 source/destination check opt-out, #108/#112
IGMP/MLD snooping, #111-#116 metadata service) are all merged; no
networking PRs are open._

## Goal

Antikythera's networking goal is AWS VPC-like capability: a tenant using
the EC2 API through kythira should get the VPC features they expect, with
isolation enforced outside both the host and the guest, the way Nitro
enforces it in AWS.

This document maps each AWS VPC feature to where our design stands and
what it would take to close the gap. It is a planning document, not a
spec: each gap that we decide to build becomes requirements, design and
tasks in the spec that owns it (`oar-net-data-plane`,
`controller-interface`, `helm-control-plane`, or a new spec).

## What we have: the fabric

The parts that make the system a VPC at all are built:

- **Isolation by VNI.** Each VPC is a 24-bit Geneve VNI, so overlapping
  tenant address ranges never meet. A NIC's VNI, MAC and NIC ID come only
  from signed controller commands (mailbox v3, #42, signs them in
  `ATTACH_DEVICE`).
- **Mapping service.** The controller sends a signed, versioned, full
  per-VPC `MapUpdate` (NIC ID → MAC, owner VTEP; v2 in #43 adds guest IPv4
  and IPv6 addresses). This is the equivalent of AWS's mapping service.
- **Enforcement in the data plane.** The VSwitch forwards only on
  controller mappings, never learns from traffic, drops unknown unicast and
  spoofed source MACs, answers ARP/ND by proxy, and puts unassigned NICs in
  the dead VPC. The receiving VTEP checks every packet's NIC pair against
  the same mapping (`check_ingress`).
- **Encrypted, authenticated underlay.** WireGuard between VTEPs (#47),
  with per-VTEP keys distributed by the controller (#48). One tunnel per
  VTEP pair carries every VPC's traffic. Since #93 they run together:
  `NetRole`/`ak-oar-net` send every Geneve payload through the `Tunnel`
  and take peers from the controller's signed frame (`TunnelPeerSet`),
  and helm's daemon holds the `TunnelKeyring`, keys each network role and
  forwards its peer sets. Not yet exercised across servers in harbor
  (oar-net task 11).

What the fabric gives a tenant today is one flat L2 segment per VPC: every
NIC can reach every other NIC in the VPC, nothing outside it can reach in,
and there is no way out. Almost everything AWS sells on top of that is
missing, and it is mostly control plane plus one new data-plane capability
in oar-net: **L3 awareness** (routing between subnets, stateful
filtering, address checks). That capability is the common prerequisite for
most rows below. Its first layer has landed: the L3/L4 parser, IP
source/destination checks, and DHCPv4, DHCPv6, RA and the metadata
intercept answered from a per-VNI `VpcConfig` (oar-net tasks 15-19).

## Gap table

Status: **done** (merged), **in review** (open PR), **partial** (some of
it exists), **specced** (in a spec, not built), **missing** (not in any
spec).

| AWS feature | Status | What we have | What is needed |
|---|---|---|---|
| VPC (`CreateVpc`, CIDR block) | partial | VNI allocation, `CREATE_NETWORK`/`DELETE_NETWORK` mailbox commands; EC2 mapping in controller Req 6 | A VPC CIDR (IPv4, plus an IPv6 /56) recorded by the controller and enforced: guest addresses must fall inside it. The EC2 module itself (controller task 6, kythira repo) |
| Subnets | specced | One flat L2 segment per VPC. Controller Req 6.4 refuses subnets beyond one with `UnsupportedOperation`. Spec: `vpc-subnets-routing` (VpcConfig v2, MapUpdate v4). Built: MapUpdate v4 with each NIC's subnet ID (task 1); VpcConfig v2 codec, refused by the role beyond one subnet until tasks 4-5 (task 2), and chunked over OarLink (task 3) | Subnet CIDRs per VPC, each NIC in one subnet. oar-net becomes the implicit VPC router: it answers ARP/ND for each subnet's gateway address (`.1`) with a virtual router MAC and forwards between subnets by rewriting MACs and decrementing TTL, all local to the source VTEP (AWS-style distributed routing, no hop to a router box). Subnet and router config ride in the MapUpdate (format v3) or a new signed frame |
| Route tables | specced | NIC-target routes in the per-VPC `VpcConfig` (oar-net 22, #107). Spec: per-subnet tables with `local` and NIC targets in `vpc-subnets-routing`; the frame is VpcConfig v2, not a separate `RouteTable` frame | Per-subnet route tables (destination prefix → target: local, IGW, NAT GW, peering, TGW, VPN, a NIC for appliances), longest-prefix match in oar-net. A new signed `RouteTable` frame per VPC, versioned like MapUpdate, applied atomically with the mapping |
| Security groups | specced | Refused by controller Req 6.4. Spec: `vpc-security-groups` (per-NIC conntrack and rules at the NIC's own VTEP, `SecurityPolicy` frame; SG references resolved by oar-net from the mapping rather than expanded by the controller) | The single most important gap. Stateful per-NIC allow rules (protocol, port range, CIDR or another SG as source/destination) enforced in oar-net, so neither host nor guest can bypass them. Needs connection tracking per function (TCP/UDP/ICMP state, timeouts, a per-NIC table limit), rule evaluation on egress at the source VTEP and on ingress at the destination VTEP, and SG-to-SG references expanded by the controller into address sets. Distributed as a signed per-VPC `SecurityPolicy` frame. Fuzz target over hostile flows |
| Network ACLs | missing | None | Stateless, ordered, per-subnet allow/deny rules, evaluated at subnet boundaries. Simpler than SGs once the L3 parser and rule distribution exist; can share the `SecurityPolicy` frame |
| Source/destination check | done | Source MAC must be the NIC's mapped MAC; ARP sender and NA target checked; IP source and destination checked against the NIC's mapped addresses on transmit and receive, with an EtherType allowlist and per-cause counters (oar-net 16, #61); per-NIC opt-out (AWS `SourceDestCheck=false`) with NIC route targets (oar-net 22, #107) | Route tables themselves (see "Route tables") |
| Internet gateway | missing | oar-net spec explicitly has no uplink ("no uplink by default") | A gateway role: a VTEP with an external interface that terminates Geneve for VPCs with an IGW attached, does 1:1 NAT between public and private addresses, and advertises public prefixes upstream (BGP). Needs its own spec (placement, HA pairs, capacity) and route-table targets |
| Elastic IPs / public IPs | missing | Refused by controller Req 6.4 | Public address pool in the controller, allocation and association with a NIC's private address, programmed into the gateway role's NAT table. Depends on the IGW |
| NAT gateway | missing | None | Source NAT (many private → one EIP) with port allocation and connection tracking in the gateway role. Reuses the SG conntrack code |
| Egress-only IGW (IPv6) | missing | None | Stateful IPv6 outbound-only gateway in the gateway role; small once the IGW and conntrack exist |
| VPC peering | missing | VNIs are fully isolated; no cross-VNI forwarding | Route-table target that forwards from one VNI to another at the source VTEP (re-encapsulate with the peer VNI), with the controller enforcing non-overlapping CIDRs and both sides' consent. The mapping for the peer VPC's addresses must reach the source VTEP, so MapUpdate distribution has to follow peering, not just NIC placement |
| Transit gateway | missing | None | A hub that routes between many VPCs, VPNs and on-premises links with its own route tables. Best built as a gateway-role function after peering and the IGW; not needed early |
| VPC endpoints (gateway type) | missing | None | Route-table targets that send traffic for a kythira service (S3- or DynamoDB-compatible API) to that service without an IGW. Needs the gateway role plus a service-side ingress |
| PrivateLink (interface endpoints) | missing | None | A NIC in the consumer VPC whose traffic is NATed to a provider's load balancer in another VPC. Needs NAT in the gateway role and a load-balancer service; late |
| DHCP options / address assignment | partial | oar-net answers DHCPv4, stateless DHCPv6 and RAs from the mapping and a per-VNI `VpcConfig` (gateway, prefixes, DNS, MTU) (oar-net 17-18, #62, #63), delivered as a signed `VpcConfig` frame through helm (oar-net 20, #104, #105) | DHCP option sets as a controller object |
| DNS (Route 53 Resolver, `.2`) | missing | None | A resolver reachable at the VPC's `.2` (or `169.254.169.253`), answering instance private names from controller state and forwarding the rest. Either a resolver service reached through the gateway role or an in-oar-net stub that forwards to it. Private hosted zones later |
| Instance metadata (IMDS, `169.254.169.254`) | partial | oar-net intercepts `169.254.169.254` and `fd00:ec2::254` at the gateway MAC and hands packets to a `MetadataEndpoint` keyed by source NIC, rate-limited per NIC (oar-net 19, #63); the network role answers it over HTTP with IMDSv2 tokens from controller-signed per-NIC `InstanceMetadata` records that helm forwards only to the hosting role (oar-net 21, #111-#116) | Credentials and the rest of the controller's metadata content (kythira side); a harbor run with a stock cloud-init guest |
| ENIs / multiple NICs | partial | Each ENI is a NIC VF with its own NIC ID and MAC; `ATTACH_DEVICE` per ENI in the RunInstances sequence; EC2 mapping lists `Create/Attach/DetachNetworkInterface` | Secondary private IPs per ENI (MapUpdate v2 already allows several addresses per NIC; the EC2 API and DHCP need to expose them), moving an ENI between instances while keeping its NIC ID, and NICs in different subnets of one VPC (needs subnets) |
| IPv6 | partial | IPv6 underlay; ND proxy; MapUpdate v2 carries guest IPv6 addresses; RA and stateless DHCPv6 from the per-VNI prefix (oar-net 18) | VPC and subnet IPv6 prefixes in the controller model, IPv6 in SGs, NACLs and route tables, and the egress-only IGW |
| Flow logs | missing | Per-reason drop counters in the VSwitch and Vtep | Per-flow accept/reject records from the SG/NACL conntrack, batched by oar-net, carried to the controller as a new helm report kind (or a separate bulk channel, since volume can be high), and stored by kythira. Comes almost free with conntrack |
| Traffic mirroring | missing | None | Copy a NIC's frames to a target NIC or VTEP, encapsulated. Low priority |
| Site-to-site VPN | missing | None | A VPN gateway in the gateway role speaking IPsec/IKEv2 with BGP, since that is what customer routers speak. WireGuard does not fit here |
| Client VPN | missing | None | Lower priority; can be a tenant-run appliance once source/destination check opt-out and NIC route targets exist |
| Encryption in transit | done | WireGuard between VTEPs (#47), keys via controller (#48), run by `NetRole` and keyed by helm's daemon (#93); IPsec ESP kept as an option in oar-net Req 5 | The harbor multi-server run (oar-net 11) to show it across real servers. No per-tenant keys by design; tenants needing their own keys encrypt in the guest. PSP or inline crypto offload later for line rate |
| Jumbo frames / MTU | partial | MTU plan and probes (#45, merged): 8858 for guests on a 9000 underlay, reserving room for WireGuard or PSP; advertised through `VIRTIO_NET_F_MTU`; a path that fails the full-size probes degrades the role's health and helm's inventory (#93) | The harbor multi-server tests (oar-net 11) |
| Broadcast / multicast | done | VSwitch drops group frames by default; opt-in per-VNI multicast with per-NIC token buckets, the flood-list cap and cumulative usage meters (oar-net 12, #56); the signed `GroupPolicy` frame applied by `NetRole` and `group_usage` over OarLink (oar-net 13, helm 13, #97); IGMP/MLD snooping with per-group VTEP lists and `group_membership` reports (oar-net 14, #108, #112) | **Decision (2026-11-19): drop by default, like AWS; opt-in, metered and billable multicast per subnet.** ARP/ND stay answered by the proxy and DHCP will be answered locally, so nothing a stock guest needs crosses the fabric as broadcast. A VPC that opts in gets IP multicast (never broadcast) replicated by head-end replication over the encrypted tunnels, with IGMP/MLD snooping and controller-pushed per-group server lists, hard per-NIC rate limits, a per-NIC group cap and a flood-list cap. Every replica sent to the fabric is metered per NIC and reported through helm, so the controller can bill usage, plus an hourly charge per opted-in subnet. Spec: oar-net Requirement 10, controller-interface Requirement 7, helm Requirement 11. See "Broadcast and multicast" below |
| Scale limits | partial | MapUpdate holds at most 4096 NICs and 8192 addresses per family per VPC, as a full snapshot | Fine for early tenants. Large VPCs need a new format (sharded or delta updates), and peering/TGW make the set of mappings a VTEP needs larger than "VPCs with a NIC here" |

## Biggest gaps

1. **No stateful L3 in the data plane.** oar-net switches L2 frames by
   MAC. It now parses IP (a fuzzed L3/L4 parser) and uses it for IP
   anti-spoofing, DHCP, RA and the IMDS intercept, but subnets, route
   tables, security groups, NACLs and flow logs also need routing and
   per-flow state. The conntrack table (fuzzed like the parser) is the
   piece that unlocks most of the rest of the table.
2. **No security groups.** They are the feature tenants rely on most, and
   the one where enforcing in oar-net (outside host and guest) is our
   strongest selling point.
3. **No way in or out.** There is no gateway role, so no IGW, Elastic IP,
   NAT gateway, VPN, endpoints or DNS forwarding. This is a new component
   with its own spec, placement and HA design.
4. **Guest bring-up is unproven end to end.** oar-net answers DHCP, RA
   and IMDS from signed controller frames, but there is no DNS resolver,
   the controller does not yet produce those frames (kythira EC2 work),
   and no stock EC2 image has booted through it in harbor.
5. **No VPC object model beyond the VNI.** CIDRs, subnets, route tables,
   SGs and option sets need controller state, EC2 API actions and new
   signed frames to carry them to oar-net.

## Suggested build order

1. **Land the fabric.** The stack is merged and wired together (#42,
   #45, #46, #47, #48, #93). Still to do: run harbor's multi-server
   reachability, isolation and MTU tests on tikhov. Everything below builds on it.
2. **Group policy.** Drop group traffic by default in oar-net, with the
   opt-in multicast mode, rate limits and usage meters, then the signed
   `GroupPolicy` frame and the `group_usage` report (small; see
   "Broadcast and multicast"). IGMP/MLD snooping follows the L3 parser.
   Done (oar-net 12-14, helm 13).
3. **L3 foundation and guest bring-up.** VPC and subnet CIDRs in the
   controller model and a signed per-VPC config frame; an L3/L4 parser in
   oar-net; IP source/destination check; DHCPv4/DHCPv6/RA answered from the
   mapping; the IMDS intercept. After this a stock image boots with an
   address and metadata. Done in antikythera (oar-net 15-22); the
   controller model that produces the frames lands in kythira.
4. **Subnets and the implicit router.** Per-subnet gateway addresses,
   distributed routing between subnets at the source VTEP, and route tables
   with the `local` target (plus the NIC targets step 3 built). Specced in
   `.kiro/specs/vpc-subnets-routing/`.
5. **Security groups,** with conntrack in oar-net and the `SecurityPolicy`
   frame. Specced in `.kiro/specs/vpc-security-groups/`. Flow logs right
   after, since they read the same conntrack.
6. **NACLs,** reusing the parser and rule distribution.
7. **Gateway role spec and build:** IGW with Elastic IPs, then NAT gateway
   and the egress-only IGW, then the DNS resolver behind it. Route-table
   targets for each.
8. **VPC peering,** then gateway endpoints for kythira services.
9. **Site-to-site VPN** (IPsec/IKEv2 + BGP) and **transit gateway.**
10. **PrivateLink, traffic mirroring, client VPN** as demand appears.

IPv6 is not a separate step: each step above should handle both families
as it goes, since the underlay and ND proxy are already IPv6.

## Broadcast and multicast

Decided 2026-11-19: match AWS by default, and sell multicast as an opt-in
feature the way AWS sells Transit Gateway multicast.

**Default: drop.** oar-net drops every group-addressed frame the ARP/ND
proxy does not consume. ARP and ND for mapped addresses are answered
locally, DHCP will be answered locally (build order step 2), and DAD
probes and ARP for unknown addresses go unanswered, as in AWS. This
removes head-end replication, and with it the amplification risk, from
every VPC that has not asked for it.

**Opt-in: multicast per subnet.** Until subnets exist a VPC has one
subnet, so the first build is per VPC. An opted-in subnet carries IPv4
and IPv6 multicast, never broadcast, and never IPv6 solicited-node groups
(those are ND and stay with the proxy). The sending VTEP replicates each
frame once to every other VTEP hosting the subnet, as unicast Geneve
inside WireGuard (head-end replication), so the physical network needs
no multicast. First build: every multicast frame goes to every VTEP in
the subnet. Second build: oar-net snoops guest IGMP/MLD joins, reports
them through helm, and the controller pushes per-group VTEP lists, so a
frame goes only where a member is; unknown groups still go to the whole
subnet.

**Abuse limits.** Isolation between tenants is unaffected, since
replication never leaves the VNI. The risks are within a tenant and on
the fabric, and each has a hard limit enforced in oar-net, outside host
and guest:

| Risk | Limit |
|---|---|
| Amplification (one sender, N copies) | Per-NIC frame and byte token bucket on replicated traffic; a flood-list cap per subnet (the controller refuses to opt in, or to grow, a subnet past it, and oar-net drops frames for a larger one) |
| Noisy neighbor on the server uplink | The same per-NIC buckets; replication counted apart from unicast |
| Join floods | A per-NIC group cap on snooped joins |
| Rogue DHCP, gratuitous ARP spoofing | No broadcast at all, even when opted in; the ARP/ND proxy and source checks stay authoritative |
| A peer VTEP with a stale or hostile policy | The receiving VTEP applies its own policy too |

**Billing.** Two charges, both collected by the controller:

- *Enablement:* per opted-in subnet per hour, from controller state alone.
- *Usage:* replicas sent to the fabric. oar-net keeps cumulative per-NIC
  meters (frames and bytes accepted, replicas and replica bytes sent to
  other VTEPs and delivered locally, drops by cause). helm reads them
  periodically and on detach and reports them as a `group_usage` report;
  the controller turns successive readings into deltas per NIC and bills
  the NIC's account for remote replica bytes. Cumulative counters mean a
  lost report delays billing but never loses usage. Local copies and
  drops are reported for visibility and are not billed by default.

## Open questions

- Where does the gateway role run: on dedicated servers with a public
  uplink, or as a placement option of the existing oar-net boards?
- Which kythira services get gateway endpoints first?
- Is security-group state per NIC on the oar-net board small enough for
  the target hardware, and what is the per-NIC connection limit? The spec
  plans about 96 bytes per flow, a 262,144-flow role budget and 65,536
  flows per NIC by default, to be set by `vpc-security-groups` task 10's
  measurement.
