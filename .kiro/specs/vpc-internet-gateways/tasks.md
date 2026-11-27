# Implementation Plan — VPC internet gateways, public addresses and NAT

## Status: 0/16 tasks complete

Tasks are in priority order: take the first open one whose prerequisites
are done. "cloud" tasks build and test in a cloud container; "tikhov"
tasks need nested KVM (harbor); "kythira" tasks land in the kythira
repository. Each task updates the owning spec's text (oar-net,
controller-interface, helm-control-plane) and `docs/vpc-gap-analysis.md`
for what it changes.

Prerequisites: `vpc-security-groups` tasks 1 (parser additions), 4 (flow
table) and 5 (`SecurityEngine` in the VSwitch) before tasks 7 and 8
here; `vpc-subnets-routing` task 9 and harbor task 10 before task 12;
kythira `ec2-compatible-api` tasks 1 to 10 before the build half of
task 13.

## Tasks

### Phase A: frames

- [ ] 1. `VpcConfig` version 3 (design "VpcConfig version 3"): gateways
  section, route kinds `igw`, `nat`, `eigw`, every rule, the new largest
  size; signing vectors, `fuzz_vpc_config` with a re-encode round trip;
  the VSwitch keeps refusing the new route kinds (`vpc_unsupported`)
  until task 7; `ak-test-controller vpc-config` gateway and target
  syntax. _Requirements: 3.1, 3.2, 5.2, 11.3_ (cloud)
- [ ] 2. `TunnelPeers` version 2 (edge flag) and the `EdgeMapping` codec
  (`src/proto/edge_mapping.hpp`, link record type 20, every rule in design
  "EdgeMapping frame"), signing vectors, `fuzz_tunnel_peers` updated and
  `fuzz_edge_mapping`, `ControllerSink::on_edge_mapping` (default drop),
  `ak-test-controller tunnel-peers … edge` and `edge-mapping`.
  _Requirements: 7.1, 7.4_ (cloud)
- [ ] 3. `InstanceMetadata` version 2 with per-NIC associations;
  `metadata_http` serves `public-ipv4`, `public-ipv4s` and
  `ipv4-associations/<public-ip>`; tests and fuzz updated.
  _Requirements: 12.2_ (cloud)

### Phase B: the edge role

- [ ] 4. `EdgeTable`: indexes by public address, `(vni, private)`,
  `(public, block)`, gateway per VNI and pools; snapshot assembly off to
  the side and pointer swap; deltas strictly in sequence with a bounded
  hold and gap flag; bounded apply per poll; tests against a naive map
  and `fuzz_edge_table`. _Requirements: 7.2, 11.1_ (cloud)
- [ ] 5. Edge forwarding (`src/oar/net/edge/`): outbound owner checks,
  1:1 IPv4 translation with incremental checksums and ICMP quoted-packet
  rewriting, IPv6 checks without translation, NAT block owner checks,
  hairpin, inbound lookup and Geneve to the owner, TTL, MTU with IPv4
  fragmentation and PTB, outside anti-spoofing, own-address replies,
  per-address rate limit, per-entry meters; `OutsidePort` with a fake
  for tests; unit tests per counter and checksum case; `fuzz_edge`.
  _Requirements: 1.1, 1.4, 3.6, 4.3-4.6, 5.6, 6.2, 8.1, 8.2, 8.4, 8.5, 9_
  (cloud)
- [ ] 6. Edge mode in `NetRole` and `ak-oar-net --edge CONFIG`:
  `PacketSocketPort` (TPACKET_V3 rings, PACKET_FANOUT over the
  data-plane threads), `EdgeConfig`, routed-mode next-hop resolution,
  on-link ARP/ND responder with rendezvous ownership and gratuitous
  announcements on failover; helm: OarLink `edge_mapping` (0x21,
  chunked) with snapshot-plus-deltas buffering and replay on role
  restart, `edge_status` (0x24) polled into report kind 22
  `edge_applied`, `edge_usage` (0x22, paged) into report kind 23; codecs
  for both reports; tests. _Requirements: 1.2, 1.5, 7.2, 7.3, 7.6, 10.1_
  (cloud)

### Phase C: the host side

- [ ] 7. Host route targets `igw` and `eigw`: the edge set from
  `TunnelPeers` version 2, rendezvous choice per flow, `Vtep::send_to`,
  security groups before sending, receive checks of Requirement 3.5 in
  order with the reverse route lookup, `eigw` gateway flows in the flow
  table whether or not the NIC is enforced; counters; unit tests and
  `fuzz_vswitch` with an edge peer. _Requirements: 1.3, 3.3-3.6, 6.3, 8.3_
  (cloud)
- [ ] 8. `NatEngine`: forward and reverse keys in the shared flow table,
  port choice over owned blocks with endpoint-dependent reuse, TCP 350 s
  and UDP/ICMP 60 s timeouts, fragments through the fragment cache,
  block removal flushing, `drop_nat_ports` and `drop_nat_protocol`;
  `nat_usage` (0x23, paged) into report kind 24; tests on a fake clock
  and `fuzz_nat`. _Requirements: 5.4-5.8, 10.2_ (cloud)

### Phase D: end to end

- [ ] 9. In-process: `net_role_test` with two hosts and two edge roles
  over the WireGuard tunnel: Elastic IP in and out, NAT out and back,
  egress-only both ways, hairpin, one edge role stopped mid-stream with
  traffic continuing through the other, a hostile host using another
  NIC's address and ports outside its blocks.
  _Requirements: 1.1, 1.3, 13.3_ (cloud)
- [ ] 10. Network namespaces: `tests/vpc_netns_edge`, edge and internet
  namespaces in `tests/vpc_netns.sh`, routed and on-link modes, `curl`,
  `ping`, `tracepath` and `nc` from guests and from the internet side,
  failover by killing one edge. _Requirements: 1.5, 13.4_ (cloud,
  kernel-interop job)
- [ ] 11. `tests/edge_bench`: outbound, inbound and NAT-return paths with
  1,048,576 entries, the table's memory, and a baseline row in this
  design; the real-port mode over veth at 64, 512 and 1,500 bytes with
  per-core rates split into port, crypto and table time.
  _Requirements: 11.1, 11.4_ (cloud)
- [ ] 12. harbor scenarios of design "Test controller and harbor":
  routed and on-link modes, failover, hostile roles.
  _Requirements: 1.6, 13.5_ (tikhov)
- [ ] 13. Amend the kythira `ec2-compatible-api` spec and build it:
  public pools, edge servers in the inventory, internet and egress-only
  gateways, Elastic IPs and auto-assigned public IPs, NAT gateways with
  port block grants and revocation, `VpcConfig` version 3, `TunnelPeers`
  version 2 with edge peers, the regional edge-table sequence with
  snapshots and deltas and the "live on every edge" wait, metering of
  `edge_usage` and `nat_usage`, `InstanceMetadata` version 2.
  _Requirements: 2, 4.1, 4.2, 5.1-5.3, 7.1, 7.3, 7.5, 10.3, 12_ (kythira)
- [ ] 14. End to end from the AWS CLI on harbor: `create-internet-gateway`,
  `attach-internet-gateway`, `allocate-address`, `associate-address`,
  `create-nat-gateway`, routes with `--gateway-id` and
  `--nat-gateway-id`; an instance reached from the internet VM and
  another reaching it through the NAT gateway; `describe-addresses` and
  instance metadata show the public address. _Requirements: 13.5_
  (tikhov, kythira)

### Phase E: follow-up

- [ ] 15. BGP toward upstream from edge servers, with BFD, announcing the
  pools and withdrawing when the server's edge roles are unhealthy;
  harbor case with the upstream router VM speaking BGP.
  _Requirements: 1.5, 1.6_ (cloud, then tikhov)
- [ ] 16. AF_XDP packet I/O, after task 11: `XdpPort` for the outside
  port and `XdpEndpoint` for the underlay, sharing umem and ring code,
  an XDP program that redirects the role's frames and passes the rest,
  zero-copy with copy-mode fallback, libbpf/libxdp as a QUIET optional
  dependency (`AK_HAS_XDP`, vcpkg, `DEPENDENCIES.md`) with AF_PACKET and
  `UdpEndpoint` as the fallback; the netns harness and `edge_bench` run
  on both; on the 25GbE test hardware, record AF_XDP against AF_PACKET
  and decide from it whether DPDK is worth a spec.
  _Requirements: 11.4_ (cloud, then hardware)
