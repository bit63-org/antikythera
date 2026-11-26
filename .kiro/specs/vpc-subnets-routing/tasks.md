# Implementation Plan — VPC subnets and the implicit router

## Status: 8/12 tasks complete

Tasks are in priority order: take the first open one whose prerequisites
are done. "cloud" tasks build and test in a cloud container; "tikhov"
tasks need nested KVM (harbor); "kythira" tasks land in the kythira
repository. Each task updates the owning spec's text (oar-net,
controller-interface, helm-control-plane) and `docs/vpc-gap-analysis.md`
for what it changes, as earlier VPC tasks did.

Prerequisites outside this spec: oar-net task 11's harbor multi-server
tests and harbor tasks 6 to 8 (topologies, the multi-server bridge,
phase-5 drivers) for task 9; controller-interface task 7 (AWS CLI end to
end) for task 11.

## Tasks

### Phase A: frames

- [x] 1. MapUpdate version 4: 40-byte entries with `subnet_id`, flags
  bit 1 (security groups enforced) defined and decoded, version 3
  refused; signing vectors regenerated; `fuzz_map_update` and
  `proto_map_update_test` updated; `ak-test-controller map-update` takes
  `subnet=ID` and `sg` per entry. Callers keep compiling with subnet 0.
  _Requirements: 2.4, 5.3, 5.4_ (cloud)
- [x] 2. VpcConfig version 2 codec: VPC blocks, subnets, route tables
  with `local` and NIC routes, every rule in design "VpcConfig version
  2", version 1 refused; signing vectors; `fuzz_vpc_config` with a
  re-encode round trip; `ak-test-controller vpc-config` version 2
  syntax. Until task 5 lands, `NetRole` refuses version 2 frames that
  have more than one subnet or any route table other than a main table
  holding only `local` routes, so nothing half-applies.
  _Requirements: 1.2, 4.1-4.4, 5.1, 5.4_ (cloud)
- [x] 3. helm and OarLink: `vpc_config` sent in chunks
  (`send_chunked`) and reassembled by the role's shared chunk receiver,
  bounded by `max_vpc_config_size`; `helm_daemon_test` replays a
  multi-chunk frame on sideband reopen before any NIC is prepared.
  _Requirements: 5.5_ (cloud)

### Phase B: the data plane

- [x] 4. `VpcState` in the network role and the subnet model in the
  VSwitch: `nic_subnet` from the mapping, neighbor tables filtered to
  each NIC's subnet (`map_addr_outside_subnet`), NICs without a known
  subnet carry no IP; per-subnet gateway ARP/ND, ARP/ND proxy scoped to
  the subnet, DHCPv4, RA and DHCPv6 from the subnet's prefixes, the
  querier's source per subnet; unicast across subnets dropped on
  transmit and receive; group replication confined to the sender's
  subnet with per-subnet flood lists; metadata subnet and VPC block
  paths. Mapping and config applied in either order give the same
  state. Unit tests per counter; `fuzz_vswitch` with three subnets.
  _Requirements: 2.6, 3, 5.6, 6.4, 6.6, 6.7_ (cloud)
- [x] 5. The distributed router: `RouteTrie` per table and family
  (tests and a fuzz target against a naive scan), route lookup in the
  sender's subnet's table, `local` → owning NIC, NIC routes as oar-net
  Requirement 12.7, gateway MAC as source on routed frames, TTL and
  checksum; `check_ingress` accepts the VNI's gateway MAC as inner
  source through `MappingView::gateway_mac`; receive-side lookup in the
  source subnet's table (`rx_drop_route_mismatch`). Step-3 routes move
  to the same source-MAC rule. `fuzz_vswitch` checks every Requirement
  8.1 invariant. _Requirements: 4.5, 6.1-6.3, 6.5, 6.8, 8.1_ (cloud)

### Phase C: end to end

- [x] 6. Multi-role tests in process (`net_role_test`), two and three
  roles over the WireGuard tunnel: routing between subnets on one role
  and across roles in both families; a middlebox route to an appliance
  on a third role, with the appliance forwarding back; same-subnet
  traffic bypassing that route; the appliance's NIC removed from the
  mapping (blackhole) and restored; mapping before config and config
  before mapping; a hostile sending role forging routed frames to a
  NIC the table does not lead to, and cross-subnet frames with the
  sender's own MAC. _Requirements: 4.5, 5.6, 6, 8.2_ (cloud)
- [x] 7. Network-namespace test `tests/vpc_netns.sh`: the
  `ak-oar-net --tap NAME=NIC_ID,MAC` test seam, two roles in two
  namespaces over an IPv6 veth underlay with the tunnel, guest
  namespaces on their TAPs in two subnets; real DHCPv4 and RA/DHCPv6
  clients get their subnet's addresses and gateway; ping and TCP across
  subnets in both families; `traceroute` shows one hop; ARP for the
  other subnet's address goes unanswered; a full-size TCP transfer at
  the planned MTU. Runs in CI's sudo job next to
  `tests/geneve_interop.sh`. _Requirements: 3, 6, 8.3_ (cloud)
- [x] 8. Benchmark the router: frames per second for switched versus
  routed traffic through one role, with 4,096 routes and 200 subnets,
  recorded in the spec as a baseline for security groups to compare
  against. _Requirements: 6_ (cloud)
- [ ] 9. harbor multi-server scenarios (design "Test controller and
  harbor"): three servers in both placements, VPC A with three subnets
  spread over them and VPC B overlapping A's CIDR; stock cloud images
  configure themselves per subnet; reachability between every pair of
  subnets on one server and across servers in both families;
  `traceroute` hop counts; VPC isolation; the middlebox appliance on s3,
  blackholed and restored; MTU and PMTU discovery; the hostile-VTEP
  build. Waits for harbor tasks 6-8 and oar-net task 11.
  _Requirements: 8.4_ (tikhov)

### Phase D: controller and API

- [ ] 10. Amend the kythira `ec2-compatible-api` spec and build it: VPC
  CIDR blocks and secondary blocks, subnets beyond one per VPC with
  reserved addresses, route tables and associations, `local` and NIC
  routes with `blackhole` state, the actions of Requirement 7.1 and the
  refusals of 7.2, addresses allocated per subnet, and the controller
  producing VpcConfig version 2 and MapUpdate version 4 frames; the
  subnet ID rendering shared with `src/proto/`. _Requirements: 1, 2.1-2.5,
  4.1-4.3, 7_ (kythira)
- [ ] 11. End to end from the AWS CLI: `create-vpc`, two
  `create-subnet`s, `create-route-table` and `associate-route-table`,
  `run-instances` into each subnet on harbor, ping and TCP from one to
  the other; `create-route` to an appliance instance and check traffic
  takes it; `describe-route-tables` shows `blackhole` after the
  appliance is terminated. Extends controller-interface task 7.
  _Requirements: 8.5_ (tikhov, kythira)

### Phase E: follow-up

- [ ] 12. Per-subnet multicast: `GroupPolicy` version 2 with one entry
  per opted-in subnet (controller-interface design "Multicast policy and
  usage" anticipates it), enablement billed per subnet-hour, the
  VSwitch's policy looked up by the sender's subnet; tests, fuzz, and a
  harbor case where one subnet is opted in and its neighbour is not.
  _Requirements: 6.7_ (cloud, then tikhov)
