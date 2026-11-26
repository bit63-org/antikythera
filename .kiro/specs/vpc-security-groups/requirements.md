# Requirements Document — VPC security groups

## Introduction

Security groups are the feature AWS tenants rely on most: stateful,
allow-only firewalls attached to each network interface, whose rules
name protocols, ports, address ranges or other security groups. In
antikythera they are also where enforcing outside the host and the guest
pays off most: a guest that is compromised, or a host that is, cannot
switch its own filtering off, because the rules are applied by the
network role on the oar-net board, from frames the controller signs.

This spec is build-order step 5 of `docs/vpc-gap-analysis.md`. It builds
on the subnet model and router of `vpc-subnets-routing` and adds:

- **Connection tracking** per NIC in the network role: TCP, UDP, ICMP
  and other protocols, with timeouts, per-NIC limits and a role-wide
  budget, hardened against hostile flows.
- **Rule evaluation** for each NIC at its own VTEP, egress when the NIC
  sends and ingress when it receives, so a NIC's rules never depend on
  another server applying them.
- **A signed per-VPC `SecurityPolicy` frame** carrying each security
  group's rules and each NIC's group membership; security-group
  references are resolved by the network role from its signed mapping.

Flow logs read the same connection table and come right after this spec
(build-order step 5); network ACLs (step 6) reuse its parser work and
rule distribution.

### What this spec does not cover

- Network ACLs, flow logs, and traffic mirroring.
- Managed prefix lists as rule peers, and security-group references
  across peered VPCs. Both come with peering and the gateway role.
- Traffic to and from outside the VPC: it needs the gateway role, whose
  spec says where the internet side of a flow is tracked.
- TCP sequence-window validation. Within a VPC every packet has already
  passed the source/destination check at both ends, so only the real
  peer can send on a tracked flow; window tracking can come with the
  gateway role, whose traffic does not have that property.
- The kythira EC2 module's implementation. This spec states what the
  controller must keep and send; the module's spec is amended by task
  12.

## Glossary

- **Security group (SG)** — a set of inbound and outbound allow rules in
  one VPC, identified on the wire by its 64-bit **group ID**, allocated
  by the controller, unique in the region and never reused (kythira
  renders it as `sg-…`).
- **Rule** — direction (inbound or outbound), protocol (a number, or
  all), a port range or ICMP type and code, and one peer: an IPv4 or
  IPv6 prefix, or a security group.
- **Member** — a NIC attached to a security group; a NIC is a member of
  one to sixteen groups.
- **Flow** — a connection in a NIC's tracking table, keyed by protocol,
  the NIC's address and port, and the peer's address and port (ICMP
  echo: identifier).
- **Tracked / untracked** — a flow is tracked when the table records it;
  untracked when the NIC's rules allow it in both directions without
  condition (EC2's untracked connections), so recording it buys nothing.
- **Own VTEP** — the VTEP hosting a NIC; its security groups are
  enforced only there.

## Requirements

### Requirement 1: Rule semantics

**User Story:** As a tenant, I want security groups to behave exactly as
EC2's do, so that my existing templates and habits carry over.

#### Acceptance Criteria

1. Rules SHALL only allow. A packet SHALL be allowed outbound from a NIC
   when any outbound rule of any of the NIC's groups matches it, and
   allowed inbound to a NIC when any inbound rule matches; everything
   else SHALL be dropped and counted.
2. A rule SHALL match on protocol (TCP, UDP, ICMP, ICMPv6, any other IP
   protocol number, or all), on a destination port range for TCP and
   UDP, on ICMP type and code (each a value or any) for ICMP and ICMPv6,
   and on its peer: the packet's remote address inside the rule's
   prefix, or the remote address owned by a NIC that is a member of the
   rule's group.
3. A group peer SHALL match addresses of both families owned by its
   members in the receiving role's mapping (oar-net Requirement 11), so
   a group's address set follows NIC attach, detach and address changes
   without a new policy frame.
4. A NIC that is a member of no group, or whose membership the role does
   not hold, SHALL send and receive nothing that rules govern (fail
   closed), while its NIC entry says security groups are enforced
   (Requirement 6.2).
5. Rules SHALL govern only traffic that crosses the VPC: the gateway's
   local responders (DHCP, router solicitations and advertisements,
   ARP and neighbor discovery, the instance metadata service) SHALL be
   answered regardless of rules, as EC2's are.
6. Group frames admitted by the group policy SHALL be checked against
   the sender's outbound rules and each receiver's inbound rules, without
   tracking.

### Requirement 2: Stateful connection tracking

**User Story:** As a tenant, I want replies to connections I opened to
come back without an inbound rule for them, and replies to connections
I accepted to leave without an outbound rule.

#### Acceptance Criteria

1. WHEN a packet is allowed by rules in one direction THEN the NIC's own
   VTEP SHALL record its flow, unless it is untracked, and SHALL allow
   the flow's packets in both directions while the flow lives, whatever
   the rules then say.
2. TCP flows SHALL follow the handshake and teardown (SYN, SYN-ACK,
   established, FIN in each direction, RST) with a timeout per state.
   A TCP packet other than a SYN that rules allow SHALL start a flow in
   the established state (loose pickup), so connections survive a
   network-role restart once either side sends again.
3. UDP flows SHALL be unreplied until a packet comes back, then a
   stream; other protocols SHALL be tracked by address pair and protocol
   like UDP. ICMP and ICMPv6 echo SHALL be tracked by identifier.
4. Timeouts SHALL default to EC2's: TCP established 432,000 seconds, UDP
   stream 180 seconds, UDP unreplied 30 seconds, and SHALL be settable
   per NIC within EC2's ranges (TCP established 60 to 432,000, UDP
   stream 60 to 180, UDP 30 to 60), as EC2's
   `ConnectionTrackingSpecification` does. Embryonic and closing TCP
   states SHALL have short fixed timeouts.
5. ICMP and ICMPv6 errors (destination unreachable, packet too big,
   time exceeded, parameter problem) SHALL be allowed when the packet
   they quote belongs to a tracked flow of the receiving NIC, so path MTU
   discovery works without rules for it.
6. Non-first IP fragments SHALL be allowed only when the first fragment
   of the same datagram (source, destination, protocol, identification)
   was allowed in the same direction within a bounded time; others SHALL
   be dropped and counted.
7. A TCP or UDP flow SHALL be untracked when the NIC's rules allow that
   protocol on every port from and to every address of its family in
   both directions (EC2's untracked connections); an untracked flow is
   re-evaluated on every packet. ICMP, ICMPv6 and other protocols SHALL
   always be tracked. An ICMP error quoting a packet that would be
   untracked SHALL be allowed like one quoting a tracked flow.
8. Changing rules SHALL NOT end tracked flows (EC2's behaviour); it SHALL
   take effect at once for new flows and untracked ones. Removing a NIC
   from every group, changing its membership, or detaching it SHALL
   discard its tracked flows.

### Requirement 3: Where rules are enforced

**User Story:** As the operator, I want each NIC's rules applied where
the NIC is, by a component neither the host nor the guest controls, and
not dependent on any other server's honesty.

#### Acceptance Criteria

1. A NIC's outbound rules and tracking SHALL be applied by its own VTEP
   on transmit, after the source check and, for routed traffic, after the
   router has chosen the target (`vpc-subnets-routing` Requirement 6).
2. A NIC's inbound rules and tracking SHALL be applied by its own VTEP
   on receive, after the ingress and inner checks, for frames from the
   underlay and from NICs on the same VTEP alike.
3. A receiving VTEP SHALL apply its NIC's inbound rules whatever the
   sending VTEP did, so a compromised sending VTEP can skip only its own
   NICs' outbound rules, never a receiver's inbound ones.
4. Traffic forwarded by an appliance NIC (source/destination check off)
   SHALL be subject to the appliance's own rules on the way in and out,
   as in EC2.

### Requirement 4: Limits and abuse resistance

**User Story:** As the operator, I want no tenant able to exhaust a
network role's memory or CPU with flows, and every limit visible.

#### Acceptance Criteria

1. Each NIC SHALL have a flow limit, set per NIC by the controller (EC2
   sizes its conntrack allowance by instance type), and the role SHALL
   have a flow budget shared by its NICs. A new flow over either limit
   SHALL be dropped and counted per NIC (EC2's
   `conntrack_allowance_exceeded`); existing flows SHALL be unaffected.
2. Embryonic flows (TCP not yet established, UDP unreplied) SHALL be
   evicted, oldest first, before a new flow is refused, so a SYN or UDP
   flood cannot lock established flows out.
3. The flow table SHALL be keyed with a hash under a secret key the
   role generates at start, so a peer cannot choose flows that collide.
4. Expiry SHALL do bounded work per poll, and lookups SHALL treat an
   expired flow as absent, so no packet waits on a sweep.
5. Per NIC the role SHALL count allowed and dropped packets by
   direction and cause, tracked flows in use, and flows refused by each
   limit.
6. A NIC's compiled rules SHALL be bounded: at most 16 groups and 1,000
   rules per direction across them (EC2's quotas).

### Requirement 5: Security policy frame

**User Story:** As the operator, I want rules and membership to reach
every server as one signed, versioned snapshot per VPC, like the mapping
and VPC configuration.

#### Acceptance Criteria

1. The controller SHALL deliver a signed `SecurityPolicy` frame per VPC
   to every server hosting a NIC in it, naming its target server and key,
   with a per-VPC version that strictly increases, before the first NIC
   there that enforces security groups is attached and again on every
   change to rules, membership or tracking settings.
2. The frame SHALL carry the membership of every NIC in the VPC, and the
   rules and tracking settings needed by the NICs on the target server:
   every group with a member there, and each local NIC's timeouts and
   flow limit. Groups with no member on the target server MAY be left
   out.
3. The encoding SHALL be canonical (lists strictly ascending, reserved
   bytes zero, every bound checked), decoded with `std::expected` and
   `ak::wire`, with unit tests, signing vectors and a fuzz target.
4. helm SHALL forward the frame unmodified, in chunks over OarLink,
   keep the newest per VPC, and resend it to a network role whose
   sideband reopens before any NIC is prepared there.
5. The network role SHALL verify target, signature and version, and
   apply the frame atomically, leaving the previous one in place when a
   frame is refused. A frame that lists a local NIC as a member of a
   group whose rules it does not carry SHALL be refused whole.
6. A member entry for a NIC not in the role's mapping SHALL be kept and
   used once the NIC appears, so mapping and policy may arrive in either
   order.

### Requirement 6: Mapping and enforcement switch

**User Story:** As the operator, I want a NIC's enforcement to fail
closed when its policy is late or lost, without forcing it on fabric
tests that use no controller.

#### Acceptance Criteria

1. Whether a NIC is subject to security groups SHALL be set by the
   controller in the NIC's signed mapping entry (`vpc-subnets-routing`
   Requirement 5.3, MapUpdate flags bit 1), not by the presence of a
   policy frame.
2. A NIC whose entry enforces security groups and that has no
   membership in the role's current policy SHALL be treated as a member
   of no group (Requirement 1.4). The controller SHALL set the bit on
   every NIC it creates through the EC2 API.
3. A NIC whose entry does not enforce security groups SHALL be
   unfiltered, as today.
4. Each VTEP SHALL judge its own NICs by its own mapping; the bit on a
   remote NIC's entry has no effect there.

### Requirement 7: Controller and EC2 API

**User Story:** As a kythira user, I want the EC2 security group calls
and defaults to work as on AWS.

#### Acceptance Criteria

1. The EC2 module SHALL implement `CreateSecurityGroup`,
   `DeleteSecurityGroup`, `DescribeSecurityGroups`,
   `DescribeSecurityGroupRules`, `AuthorizeSecurityGroupIngress`,
   `AuthorizeSecurityGroupEgress`, `RevokeSecurityGroupIngress`,
   `RevokeSecurityGroupEgress`, `ModifySecurityGroupRules`,
   `UpdateSecurityGroupRuleDescriptionsIngress` and `…Egress`, and
   `ModifyNetworkInterfaceAttribute` with `Groups` and
   `ConnectionTrackingSpecification`, plus `SecurityGroupIds` and
   `ConnectionTrackingSpecification` on `RunInstances` and
   `CreateNetworkInterface`. Controller-interface Requirement 6.4's
   refusal of security groups is lifted.
2. Each VPC SHALL get a default security group that allows all inbound
   traffic from its own members and all outbound traffic, which cannot
   be deleted; a new group SHALL start with one rule allowing all
   outbound traffic; an interface created without groups SHALL join the
   VPC's default group.
3. Rule peers that this spec does not back (prefix lists, groups in
   other VPCs) SHALL be refused with `UnsupportedOperation`, and EC2's
   quotas (Requirement 4.6, 60 inbound and 60 outbound rules per group
   by default) SHALL be enforced with EC2's errors.
4. A group SHALL NOT be deleted while a NIC is a member or another
   group's rule references it (`DependencyViolation`).

### Requirement 8: Testing

**User Story:** As the operator, I want security groups proven end to
end, including against a hostile peer, with real TCP stacks and on
multi-server harbor.

#### Acceptance Criteria

1. The rule compiler, the tracking table, the frame codec and the
   VSwitch hooks SHALL have unit tests and fuzz targets. A differential
   fuzz target SHALL compare the compiled evaluator with a naive one.
   The tracking fuzz target SHALL check that the table never exceeds its
   limits and never admits a packet that neither the rules nor a flow
   the rules admitted allow; `fuzz_vswitch` SHALL check that no frame
   reaches or leaves an enforced NIC without that.
2. In-process tests SHALL run two and three network roles over the
   WireGuard tunnel: stateful replies across servers, group references
   across subnets and servers, a hostile sending role that skips its
   outbound rules and still meets the receiver's inbound ones, rules
   revoked under a live flow, membership removed, flow limits and the
   role budget, and policy and mapping in either order.
3. A network-namespace test with real Linux stacks SHALL run TCP, UDP
   and ICMP through security groups, including path MTU discovery
   through a quoted ICMP error, a TCP connection idle longer than the UDP
   timeouts, a reconnect after the role restarts, and a SYN flood that
   leaves established connections working.
4. harbor SHALL verify, on three servers, stock cloud images behind the
   default group and custom ones: port rules, group references across
   servers and subnets, stateful replies, revocation semantics, flow
   limits, an appliance's own rules, the role restart, and the
   hostile-VTEP build.
5. An AWS CLI run against kythira SHALL create groups and rules, launch
   instances with them on harbor, and see traffic allowed and refused as
   the rules say.
