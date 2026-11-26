# Implementation Plan — VPC security groups

## Status: 0/13 tasks complete

Tasks are in priority order: take the first open one whose prerequisites
are done. "cloud" tasks build and test in a cloud container; "tikhov"
tasks need nested KVM (harbor); "kythira" tasks land in the kythira
repository. Each task updates the owning spec's text (oar-net,
controller-interface, helm-control-plane) and `docs/vpc-gap-analysis.md`
for what it changes.

Prerequisites: `vpc-subnets-routing` tasks 1 (MapUpdate version 4 with
the enforcement bit) and 5 (the router, whose target choice the egress
hook follows) before task 5 here; that spec's task 7 (the
network-namespace harness) before task 8; its task 9 and harbor task 10
(fault injection) before task 11; controller-interface task 7 before
task 13.

## Tasks

### Phase A: parsing and the frame

- [ ] 1. Packet parser additions: TCP flags in `L4Header`, the IPv4 and
  IPv6 fragment identification and offset in `ParsedPacket`, and
  `packet::parse_quoted` for the IP header and first eight L4 bytes
  quoted in ICMP and ICMPv6 errors; tests and `fuzz_packet` extended
  (quoted views stay inside the error's payload).
  _Requirements: 2.2, 2.5, 2.6_ (cloud)
- [ ] 2. `SecurityPolicy` codec (`src/proto/security_policy.hpp`, every
  rule in design "SecurityPolicy frame"), link record type 19, signing
  vectors, `fuzz_security_policy` with a re-encode round trip,
  `ControllerSink::on_security_policy` (default drop), and
  `ak-test-controller security-policy`. _Requirements: 5.1-5.3_ (cloud)

### Phase B: the engine

- [ ] 3. Rule compiler and evaluator (`security_rules`): buckets per
  protocol, group peers through the VNI's owner table and sorted
  memberships, exact `all`/`tcp_all`/`udp_all`, the 1,000-rule bound;
  `security_rules_naive` and the differential `fuzz_security_rules`.
  _Requirements: 1.1-1.3, 2.7, 4.6, 8.1_ (cloud)
- [ ] 4. Flow table (`flow_table`): SipHash-keyed open addressing, TCP,
  UDP, ICMP echo and other-protocol states with EC2's timeouts and the
  per-NIC settings, loose pickup, per-NIC limits and the role budget with
  embryonic eviction, the timer wheel with bounded expiry per poll, the
  fragment cache, related ICMP through `parse_quoted`, per-NIC flushing;
  tests on a fake clock and `fuzz_flow_table` with hostile flow streams.
  _Requirements: 2, 4.1-4.4, 8.1_ (cloud)
- [ ] 5. `SecurityEngine` in the VSwitch: egress after the router or
  unicast lookup, ingress for local targets and on receive, local
  responders exempt, group frames checked statelessly, enforcement from
  the mapping bit, deny-all without membership, `set_security_policy`
  with flushing on membership change only, compile on NIC attach from
  the held policy; `SecurityMeter`s; unit tests per hook;
  `fuzz_vswitch` with enforced NICs.
  _Requirements: 1.4-1.6, 2.1, 2.8, 3, 4.5, 6, 8.1_ (cloud)
- [ ] 6. `NetRole` and helm: OarLink `security_policy` (vendor type
  0x1F, chunked), verified by the role (server, signature, version per
  VNI; the same version answers ok untouched, an older one fails),
  refused whole when a local NIC's group is missing or over the rule
  bound; helm keeps the newest per VNI and replays it on sideband reopen
  before any NIC is prepared; mapping and policy in either order.
  _Requirements: 5.4-5.6_ (cloud)

### Phase C: end to end

- [ ] 7. Multi-role tests in process (`net_role_test`), two and three
  roles over the WireGuard tunnel: stateful TCP, UDP and ICMP replies
  across roles; group references across subnets and roles, following a
  NIC that attaches with no policy change; a hostile sending role that
  skips its outbound rules and meets the receiver's inbound ones;
  revocation keeps tracked flows and stops untracked ones; membership
  removal flushes; flow limits and the budget with embryonic eviction;
  an appliance's own rules on routed traffic; policy before mapping and
  mapping before policy; an enforced NIC with no policy denied.
  _Requirements: 1-6, 8.2_ (cloud)
- [ ] 8. Network-namespace cases in `tests/vpc_netns.sh`: real TCP, UDP
  and ICMP through security groups; PMTU discovery through an appliance
  namespace with a smaller onward MTU and no ICMP rule; a TCP connection
  idle longer than the UDP timeouts; a reconnect after the role restarts
  (loose pickup); a SYN flood from one namespace while another keeps an
  established transfer going. _Requirements: 2, 4, 8.3_ (cloud)
- [ ] 9. Security usage reporting: OarLink `security_usage` (vendor type
  0x20, paged like `group_usage`), report kind 21 with its codec, tests
  and fuzz target, helm polling it and reporting on change and on
  detach. _Requirements: 4.5_ (cloud)
- [ ] 10. Measure the engine: bytes per flow, packets per second for new
  flows, tracked flows and untracked flows with 1,000 rules per
  direction, a full table, and a SYN flood, against `vpc-subnets-routing`
  task 8's baseline; set `flow_budget` and `default_nic_flows` from it
  and answer the gap analysis's open question on per-NIC state. Cloud
  first, then on the board class when one is available.
  _Requirements: 4_ (cloud, then tikhov)
- [ ] 11. harbor multi-server scenarios (design "Test controller and
  harbor"): the `web`/`app`/`db` groups and the default group across
  three servers and two subnets, stock cloud images, allowed and refused
  paths, replies without rules, references following new NICs,
  revocation for tracked and untracked flows, membership removal, flow
  limits, a flood from one guest, an appliance's own rules, the role
  restart, PMTU, and the hostile-VTEP build. _Requirements: 8.4_ (tikhov)

### Phase D: controller and API

- [ ] 12. Amend the kythira `ec2-compatible-api` spec and build it: the
  actions of Requirement 7.1, the default group and new-group defaults,
  refusals and quotas, deletion rules, `ConnectionTrackingSpecification`,
  the enforcement bit on every EC2-made NIC, and the controller producing
  `SecurityPolicy` frames per server (rules of locally used groups, the
  whole membership), delivered before the first enforced NIC on a server
  is attached; `conntrack_allowance_exceeded` from `security_usage`.
  _Requirements: 5.1-5.2, 6.2, 7_ (kythira)
- [ ] 13. End to end from the AWS CLI: `create-security-group`,
  `authorize-security-group-ingress` with a CIDR and with a group,
  `run-instances` with `--security-group-ids` into two subnets on harbor;
  allowed and refused connections as the rules say;
  `revoke-security-group-ingress` under a live connection;
  `modify-network-interface-attribute --groups`. Extends
  controller-interface task 7. _Requirements: 8.5_ (tikhov, kythira)
