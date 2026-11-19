# AWS VPC gap analysis

_Status as of 2026-11-19, against `main` plus the open networking PRs
(#41 Vtep, #42 mailbox v3, #43 MapUpdate v2, #45 MTU, #46 NetRole, #47
WireGuard, #48 VTEP key distribution)._

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

The parts that make the system a VPC at all are built or in review:

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
  VTEP pair carries every VPC's traffic.

What the fabric gives a tenant today is one flat L2 segment per VPC: every
NIC can reach every other NIC in the VPC, nothing outside it can reach in,
and there is no way out. Almost everything AWS sells on top of that is
missing, and it is mostly control plane plus one new data-plane capability
in oar-net: **L3 awareness** (routing between subnets, stateful
filtering, address checks). That capability is the common prerequisite for
most rows below.

## Gap table

Status: **done** (merged), **in review** (open PR), **partial** (some of
it exists), **specced** (in a spec, not built), **missing** (not in any
spec).

| AWS feature | Status | What we have | What is needed |
|---|---|---|---|
| VPC (`CreateVpc`, CIDR block) | partial | VNI allocation, `CREATE_NETWORK`/`DELETE_NETWORK` mailbox commands; EC2 mapping in controller Req 6 | A VPC CIDR (IPv4, plus an IPv6 /56) recorded by the controller and enforced: guest addresses must fall inside it. The EC2 module itself (controller task 6, kythira repo) |
| Subnets | missing | One flat L2 segment per VPC. Controller Req 6.4 refuses subnets beyond one with `UnsupportedOperation` | Subnet CIDRs per VPC, each NIC in one subnet. oar-net becomes the implicit VPC router: it answers ARP/ND for each subnet's gateway address (`.1`) with a virtual router MAC and forwards between subnets by rewriting MACs and decrementing TTL, all local to the source VTEP (AWS-style distributed routing, no hop to a router box). Subnet and router config ride in the MapUpdate (format v3) or a new signed frame |
| Route tables | missing | None; only the implicit "local" reach within the VNI | Per-subnet route tables (destination prefix → target: local, IGW, NAT GW, peering, TGW, VPN, a NIC for appliances), longest-prefix match in oar-net. A new signed `RouteTable` frame per VPC, versioned like MapUpdate, applied atomically with the mapping |
| Security groups | missing | Refused by controller Req 6.4 | The single most important gap. Stateful per-NIC allow rules (protocol, port range, CIDR or another SG as source/destination) enforced in oar-net, so neither host nor guest can bypass them. Needs connection tracking per function (TCP/UDP/ICMP state, timeouts, a per-NIC table limit), rule evaluation on egress at the source VTEP and on ingress at the destination VTEP, and SG-to-SG references expanded by the controller into address sets. Distributed as a signed per-VPC `SecurityPolicy` frame. Fuzz target over hostile flows |
| Network ACLs | missing | None | Stateless, ordered, per-subnet allow/deny rules, evaluated at subnet boundaries. Simpler than SGs once the L3 parser and rule distribution exist; can share the `SecurityPolicy` frame |
| Source/destination check | partial | Source MAC must be the NIC's mapped MAC; ARP sender IP checked against the mapping | IP-level anti-spoofing: drop guest IP packets whose source address is not one of the NIC's mapped addresses, and deliver only to mapped destination addresses. Per-NIC opt-out (AWS `SourceDestCheck=false`) for NAT and firewall appliances, which also needs route-table targets that point at a NIC |
| Internet gateway | missing | oar-net spec explicitly has no uplink ("no uplink by default") | A gateway role: a VTEP with an external interface that terminates Geneve for VPCs with an IGW attached, does 1:1 NAT between public and private addresses, and advertises public prefixes upstream (BGP). Needs its own spec (placement, HA pairs, capacity) and route-table targets |
| Elastic IPs / public IPs | missing | Refused by controller Req 6.4 | Public address pool in the controller, allocation and association with a NIC's private address, programmed into the gateway role's NAT table. Depends on the IGW |
| NAT gateway | missing | None | Source NAT (many private → one EIP) with port allocation and connection tracking in the gateway role. Reuses the SG conntrack code |
| Egress-only IGW (IPv6) | missing | None | Stateful IPv6 outbound-only gateway in the gateway role; small once the IGW and conntrack exist |
| VPC peering | missing | VNIs are fully isolated; no cross-VNI forwarding | Route-table target that forwards from one VNI to another at the source VTEP (re-encapsulate with the peer VNI), with the controller enforcing non-overlapping CIDRs and both sides' consent. The mapping for the peer VPC's addresses must reach the source VTEP, so MapUpdate distribution has to follow peering, not just NIC placement |
| Transit gateway | missing | None | A hub that routes between many VPCs, VPNs and on-premises links with its own route tables. Best built as a gateway-role function after peering and the IGW; not needed early |
| VPC endpoints (gateway type) | missing | None | Route-table targets that send traffic for a kythira service (S3- or DynamoDB-compatible API) to that service without an IGW. Needs the gateway role plus a service-side ingress |
| PrivateLink (interface endpoints) | missing | None | A NIC in the consumer VPC whose traffic is NATed to a provider's load balancer in another VPC. Needs NAT in the gateway role and a load-balancer service; late |
| DHCP options / address assignment | missing | Guest addresses are known to the controller and, with #43, to oar-net. Nothing hands them to the guest | DHCPv4 and DHCPv6 (and IPv6 RA) answered by oar-net from the mapping, like the ARP/ND proxy: address, subnet mask, gateway, DNS servers, domain name, MTU (we already compute it). DHCP option sets as a controller object |
| DNS (Route 53 Resolver, `.2`) | missing | None | A resolver reachable at the VPC's `.2` (or `169.254.169.253`), answering instance private names from controller state and forwarding the rest. Either a resolver service reached through the gateway role or an in-oar-net stub that forwards to it. Private hosted zones later |
| Instance metadata (IMDS, `169.254.169.254`) | missing | None | Not a VPC feature, but every EC2 guest image needs it (cloud-init, credentials). oar-net intercepts the link-local address and proxies to a metadata service through helm or the gateway role, keyed by the trusted NIC ID (so a guest can only read its own metadata). IMDSv2 token semantics |
| ENIs / multiple NICs | partial | Each ENI is a NIC VF with its own NIC ID and MAC; `ATTACH_DEVICE` per ENI in the RunInstances sequence; EC2 mapping lists `Create/Attach/DetachNetworkInterface` | Secondary private IPs per ENI (MapUpdate v2 already allows several addresses per NIC; the EC2 API and DHCP need to expose them), moving an ENI between instances while keeping its NIC ID, and NICs in different subnets of one VPC (needs subnets) |
| IPv6 | partial | IPv6 underlay; ND proxy; MapUpdate v2 carries guest IPv6 addresses | VPC and subnet IPv6 prefixes, RA/DHCPv6 to configure guests, IPv6 in SGs, NACLs and route tables, and the egress-only IGW |
| Flow logs | missing | Per-reason drop counters in the VSwitch and Vtep | Per-flow accept/reject records from the SG/NACL conntrack, batched by oar-net, carried to the controller as a new helm report kind (or a separate bulk channel, since volume can be high), and stored by kythira. Comes almost free with conntrack |
| Traffic mirroring | missing | None | Copy a NIC's frames to a target NIC or VTEP, encapsulated. Low priority |
| Site-to-site VPN | missing | None | A VPN gateway in the gateway role speaking IPsec/IKEv2 with BGP, since that is what customer routers speak. WireGuard does not fit here |
| Client VPN | missing | None | Lower priority; can be a tenant-run appliance once source/destination check opt-out and NIC route targets exist |
| Encryption in transit | in review | WireGuard between VTEPs (#47), keys via controller (#48); IPsec ESP kept as an option in oar-net Req 5 | Land #41/#47/#48, wire the keyring into the helm daemon and the peer set into NetRole. No per-tenant keys by design; tenants needing their own keys encrypt in the guest. PSP or inline crypto offload later for line rate |
| Jumbo frames / MTU | in review | MTU plan and probes (#45): 8874 with a 9000 underlay and WireGuard | Land #45/#46 and the harbor multi-server tests |
| Broadcast / multicast | decided, specced | VSwitch floods group frames to local members and head-end replicates to remote VTEPs | **Decision (2026-11-19): drop by default, like AWS; opt-in, metered and billable multicast per subnet.** ARP/ND stay answered by the proxy and DHCP will be answered locally, so nothing a stock guest needs crosses the fabric as broadcast. A VPC that opts in gets IP multicast (never broadcast) replicated by head-end replication over the encrypted tunnels, with IGMP/MLD snooping and controller-pushed per-group server lists, hard per-NIC rate limits, a per-NIC group cap and a flood-list cap. Every replica sent to the fabric is metered per NIC and reported through helm, so the controller can bill usage, plus an hourly charge per opted-in subnet. Spec: oar-net Requirement 10, controller-interface Requirement 7, helm Requirement 11. See "Broadcast and multicast" below |
| Scale limits | partial | MapUpdate holds at most 4096 NICs and 8192 addresses per family per VPC, as a full snapshot | Fine for early tenants. Large VPCs need a new format (sharded or delta updates), and peering/TGW make the set of mappings a VTEP needs larger than "VPCs with a NIC here" |

## Biggest gaps

1. **No L3 in the data plane.** oar-net switches L2 frames by MAC. Subnets,
   route tables, security groups, NACLs, IP anti-spoofing, DHCP, IMDS and
   flow logs all need oar-net to parse IP and keep per-flow state. This is
   one piece of work (a bounds-checked L3/L4 parser and a conntrack table,
   both fuzzed) that unlocks most of the table.
2. **No security groups.** They are the feature tenants rely on most, and
   the one where enforcing in oar-net (outside host and guest) is our
   strongest selling point.
3. **No way in or out.** There is no gateway role, so no IGW, Elastic IP,
   NAT gateway, VPN, endpoints or DNS forwarding. This is a new component
   with its own spec, placement and HA design.
4. **Guests can't configure themselves.** No DHCP, DNS or metadata
   service, so a stock EC2 image will not boot into a working network.
5. **No VPC object model beyond the VNI.** CIDRs, subnets, route tables,
   SGs and option sets need controller state, EC2 API actions and new
   signed frames to carry them to oar-net.

## Suggested build order

1. **Land the fabric.** Merge the in-flight stack (#41, #45, #46, #47,
   #48, #42, #43), wire the keyring and peer set into the helm daemon and
   NetRole, and run harbor's multi-server reachability, isolation and MTU
   tests on tikhov. Everything below builds on it.
2. **Group policy.** Drop group traffic by default in oar-net, with the
   opt-in multicast mode, rate limits and usage meters, then the signed
   `GroupPolicy` frame and the `group_usage` report (small; see
   "Broadcast and multicast"). IGMP/MLD snooping follows the L3 parser.
3. **L3 foundation and guest bring-up.** VPC and subnet CIDRs in the
   controller model and a signed per-VPC config frame; an L3/L4 parser in
   oar-net; IP source/destination check; DHCPv4/DHCPv6/RA answered from the
   mapping; the IMDS intercept. After this a stock image boots with an
   address and metadata.
4. **Subnets and the implicit router.** Per-subnet gateway addresses,
   distributed routing between subnets at the source VTEP, and route tables
   with the `local` target only.
5. **Security groups,** with conntrack in oar-net and the `SecurityPolicy`
   frame. Flow logs right after, since they read the same conntrack.
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
  the target hardware, and what is the per-NIC connection limit?
