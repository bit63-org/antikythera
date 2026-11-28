# Implementation Plan — Network control at fleet scale

## Status: 6/18 tasks complete

Tasks are in priority order: take the first open one whose prerequisites
are done. "cloud" tasks build and test in a cloud container; "tikhov"
tasks need nested KVM (harbor); "kythira" tasks land in the kythira
repository, where `ec2-controller-scale` holds the controller half. Each
task updates the owning spec's text (controller-interface, oar-net,
helm-control-plane, vpc-security-groups, vpc-internet-gateways) and
`docs/vpc-gap-analysis.md` for what it changes.

Prerequisites: vpc-subnets-routing (done) before task 5; the
vpc-security-groups codec (its task 2) before task 5's SG records; the
vpc-internet-gateways edge role (its tasks up to the edge table) before
tasks 14-15. Phases A, B and C can run in parallel.

## Tasks

### Phase A: stable keys and certified peers

- [x] 1. Stable VTEP keys: `TunnelKeyring` derives each VTEP key from
  the secure element (`server_id`, slot, `key_epoch`), `key_epoch` kept
  in helm's state file, `rotate_vtep_key` link record (35) with a
  10-minute two-key grace in the role; tests that a helm restart keeps
  the key and a rotation keeps sessions until the grace ends.
  _Requirements: 1.1-1.4_ (cloud)
- [x] 2. `VtepCredential` and `CredentialRevocations` codecs
  (`src/proto/`), link records 30 and 31, vendor types 0x31 and 0x32,
  report kind 31 `credential_request`, signing vectors, fuzz targets,
  `ak-test-controller` issuing credentials and revocations.
  _Requirements: 2.1-2.4, 10.1_ (cloud)
- [x] 3. Certified handshake in `Tunnel`: the `credential` message (type
  0x10), `CredentialCache`, verification order, per-source and role rate
  limits, cookie handling after the exchange, idle peer reclaim, expiry
  and revocation teardown; a reference model test and
  `fuzz_tunnel_credential`; Linux interop unchanged for list peers.
  _Requirements: 3.1-3.4, 3.6, 3.7, 10.2_ (cloud)
- [x] 4. Coexistence: inventory `certified` flag (`tunnel_flags` bit 0),
  list peers looked up first, refusal counters; a network-namespace test
  (`tests/certified_netns.sh`) moving a live three-role VPC from
  `TunnelPeers` to certified peers and back.
  _Requirements: 3.5, 10.3_ (cloud)

### Phase B: VPC streams

- [ ] 5. `VpcStream` codec: header, the 16 record types, strict
  ordering and size rules, link record 32, vendor type 0x30, vectors,
  `fuzz_vpc_stream` with re-encode. _Requirements: 4.1, 5.1, 5.3, 10.1_
  (cloud)
- [ ] 6. `StreamApplier` and persistent `VniState` tables: sequence,
  holds and gaps, `need_snapshot`, whole-delta validation and refusal,
  atomic publish to the data-plane thread; VSwitch, router, ARP/ND proxy
  and security groups read from `VniState`; `fuzz_stream_applier`
  against a naive full-rebuild applier. _Requirements: 4.2, 5.2, 5.4_
  (cloud)
- [ ] 7. Reused VNIs and MACs: incarnation handling (wipe on newer,
  refuse older), MAC uniqueness per VNI including the gateway MAC;
  controller-interface Requirement 4 rewritten (VNI and MAC as reusable
  handles, VPC ID separate). _Requirements: 4.3-4.6_ (cloud)
- [ ] 8. Frames and streams side by side: per-VNI `frames`/`stream`
  mode, both switches, and a network-namespace test moving a live VPC
  each way. _Requirements: 5.6, 10.3_ (cloud)
- [ ] 9. Budgets and `stream_status`: role-wide budgets replacing the
  per-frame caps for stream VNIs, refusals counted, report kind 30 and
  vendor type 0x34, helm polling and coalescing; inventory budget
  fields. _Requirements: 5.5, 9.1-9.3_ (cloud)

### Phase C: bulk frames over Ethernet

- [x] 10. Network role certificates: role kind `net` in `cert_request`,
  the role's control address as an IP SAN, `tls::RoleIdentity` reused.
  _Requirements: 6.1_ (cloud)
- [x] 11. `FrameNotice` codec (link record 33, vendor type 0x33) and
  OarLink scheduling classes in helm (control, status, bulk; one bulk
  chunk per turn); a test that a lease renewal never waits behind a
  131 KiB transfer. _Requirements: 6.2, 6.4_ (cloud)
- [ ] 12. `BulkFetcher` (TLS 1.3 client, digest then signature, retries
  over endpoints, fallback to OarLink chunks) and a frame store in
  `ak-test-controller`; a network-namespace test moving from SMBus-only
  to the bulk channel and back, with the channel cut mid-transfer.
  _Requirements: 6.1-6.3, 6.5, 6.6, 10.3_ (cloud)

### Phase D: lookups

- [ ] 13. Lookup VNIs: `MapEntry` codec and fuzz target, the lookup
  cache with delta invalidation, bounded per-destination queues,
  receiver-side lookups before `check_ingress`; tests with a frame store
  that delays, refuses and answers negatively. _Requirements: 7.1-7.4_
  (cloud)

### Phase E: edge groups

- [ ] 14. `EdgeGroup` frame (link record 34, vendor type 0x35), hosts
  choosing edge roles from it, `edge_group_id` in `EdgeMapping`,
  per-group table slices; vpc-internet-gateways design updated (its
  "Edge groups" and "Sharding by public prefix" items).
  _Requirements: 8.1-8.3, 8.5_ (cloud)
- [ ] 15. Forward and re-home modes between edge groups (`forward` edge
  entries, the `transit` Geneve option), and moving hosts and prefixes
  between groups; a network-namespace test from one edge group to two
  and back with flows running. _Requirements: 8.4, 8.6, 10.3_ (cloud)

### Phase F: scale and end to end

- [ ] 16. Scale benchmarks: `stream_scale_bench` (1,048,576 NIC
  entries), `certified_peer_bench` (50,000 peers), an edge slice of 1 M
  entries over the bulk channel; results recorded in design
  "Benchmarks". _Requirements: 10.4_ (cloud)
- [ ] 17. Harbor: every migration of Requirement 10.3 on nested boards
  with traffic flowing. _Requirements: 10.5_ (tikhov, Clark's go)
- [ ] 18. Controller side: `ec2-controller-scale` produces credentials,
  revocations, streams, notices, lookups and edge groups; this task is
  done when that spec's matching tasks are. _Requirements: 2.1, 4.3,
  5.1, 7.1, 8.1_ (kythira)
