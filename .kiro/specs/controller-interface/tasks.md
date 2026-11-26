# Implementation Plan — Controller interface and the kythira EC2 integration

## Status: 14/16 tasks complete

## Tasks

- [x] 1. Mailbox protocol v2: assign `key_id` in the reserved header bytes.
  _Requirements: 1.3_ (`key_id` u16 at slot offset 0x12; non-zero on
  commands, zero on responses and events; version 1 is no longer accepted.)
- [x] 2. Envelope and MapUpdate codecs in `src/proto/`, tests, fuzz targets,
  signing test vectors. _Requirements: 1, 5.2_ (Header-only `ak::proto`
  depending only on `ak::common`; vectors in `src/proto/test_vectors.hpp`
  use the RFC 8032 test keys. MapUpdate carries `key_id` and is a full
  per-VPC snapshot; see design "Envelope".)
- [x] 3. helm ControllerLink over mTLS with reconnect and reconciliation.
  _Requirements: 2, 3_ (`src/helm/controller_link.*` over `ak::tls`
  in `src/tls/`; see design "ControllerLink". The management-NIC binding of
  Requirement 2.1 is deployment configuration: helm dials the controller
  address it is given.)
- [x] 4. Inventory/status report schema. _Requirements: 3_ (`Report` in
  `src/proto/report.hpp`: inventory snapshot plus command outcome,
  pool-state, VM-exit, map-applied and host-fault events; link record
  framing and report acks in `src/proto/link.hpp`; tests and fuzz targets.
  See design "Inventory and status reports" and "Link framing".)
- [x] 5. A minimal test controller in harbor (C++ CLI that signs and sends
  envelopes) to drive phases 3–5 before kythira's module exists.
  _Requirements: 1, 5_ (`ak-test-controller` from `src/harbor/`: an
  Ed25519 signer that reproduces `src/proto/test_vectors.hpp`, a script
  language for commands, mapping updates and expected outcomes, and the
  mTLS server side of the ControllerLink. See `harbor/README.md`.)
- [x] 8. Mailbox protocol v3: a signed `server_id` in the slot header and
  the NIC's VPC, NIC ID and MAC in `ATTACH_DEVICE`. _Requirements: 1.2_
  (32-byte header, `server_id` u64 at 0x18, body limit 160; hull refuses
  a slot for another server as `wrong_server` before verifying it; the
  envelope's `server_id` must equal the slot's; helm's CommandRouter
  configures oar-net from the signed command. See design "Envelope".)
- [x] 9. MapUpdate format v2: guest IPv4 and IPv6 addresses per NIC for
  oar-net's ARP/ND proxy. _Requirements: 4, 5_ (Sorted, unique, unicast,
  each owned by a NIC in the same frame; vectors regenerated; harbor's
  `map-update` takes `NIC,MAC,VTEP[,GUEST_IP ...]`. See design
  "Envelope".)
- [x] 10. `GroupPolicy` codec in `src/proto/`, `group_policy` link record,
  signing vectors, tests, fuzz; `ak-test-controller` can send it.
  _Requirements: 7.3_ — Done: `src/proto/group_policy.hpp` (`AKGP`, 0x80
  bytes, Ed25519 over the first 0x40), link record type 6 checked by the
  ControllerSession (`ControllerSink::on_group_policy` gets the exact
  frame), `ak-test-controller group-policy`, `fuzz_group_policy`.
- [x] 11. `group_usage` report kind in `src/proto/report.hpp`, tests,
  fuzz. _Requirements: 7.5_ — Done: kind 7, 96-byte entries with a
  `slot` byte (NIC IDs are unique only per network role), strictly
  ascending (slot, nic_id, attachment), at most 1024 per report.
- [x] 13. Tunnel key distribution. _Requirements: 8_ (`TunnelPeers` frame
  and link record type 7 in `src/proto/`, VTEP public keys in inventory
  format 2, helm's `TunnelKeyring` (per-VTEP X25519 key pairs, newest peer
  set per VTEP, role provisioning), the `tunnel_peers` sideband transfer,
  and oar-net's `TunnelPeerSet`; `tunnel-peers` in the harbor test
  controller's script. See design "TunnelPeers". Wiring the keyring into
  `HelmDaemon` and `TunnelPeerSet` into `NetRole` follows helm main and
  oar-net task 11.)
- [x] 14. `VpcConfig` codec in `src/proto/`, `vpc_config` link record,
  tests, fuzz; `ak-test-controller` can send it. _Requirements: 10_ —
  Done: `src/proto/vpc_config.hpp` (`AKVC`, variable length up to 3,669
  bytes, Ed25519 over everything before the trailing 64), link record
  type 14 checked by the ControllerSession (`ControllerSink::on_vpc_config`
  gets the exact frame; the default drops it), `ak-test-controller
  vpc-config`, `fuzz_vpc_config`. helm's fan-out and the network role's
  side are oar-net task 20; routes are applied by oar-net task 22.
- [x] 15. `GroupMembers` codec and `group_membership` report kind in
  `src/proto/`, `group_members` link record, tests, fuzz;
  `ak-test-controller` can send it. _Requirements: 7.9_ — Done:
  `src/proto/group_members.hpp` (`AKGM`, up to 512 groups and 4,096 VTEP
  entries, Ed25519 over everything before the trailing 64), link record
  type 15 checked by the ControllerSession
  (`ControllerSink::on_group_members`; the default drops it), report kind
  16 (one role's whole join list), `ak-test-controller group-members`,
  `fuzz_group_members`. The oar-net side is task 14.
- [x] 16. `InstanceMetadata` codec in `src/proto/`, `instance_metadata`
  link record (type 16), tests, fuzz; `ak-test-controller` can send it.
  _Requirements: 11_ (helm's side is helm-control-plane task 14, the
  network role's oar-net task 21.) — `src/proto/instance_metadata.hpp`
  (`proto_instance_metadata_test`, `fuzz_instance_metadata`) also checks
  EC2's ID prefixes (`i-`, `ami-`, `eni-`, `vpc-`). The ControllerSession
  checks a record's shape and server and hands it to
  `ControllerSink::on_instance_metadata`, which drops it until helm keeps
  records (helm-control-plane task 14). `ak-test-controller` sends it with
  `instance-metadata NIC VNI VERSION INSTANCE_ID [KEY=VALUE ...]`.
- [x] 6. Draft the kythira `ec2-compatible-api` spec in the kythira
  repository, from Requirements 6 and 9 (network volumes ported from
  `ak_hold_master`). _Requirements: 6, 9_ — Done in kythira
  (`.kiro/specs/ec2-compatible-api/`, 0a4efaf, 2026-11-24); its 21 tasks
  are all open there.
- [ ] 7. End-to-end: AWS CLI `run-instances` against kythira, landing in a
  harbor server. _Requirements: 6.1_
- [ ] 12. Controller policy state, admission checks and usage metering
  (kythira `ec2-compatible-api` spec and module). _Requirements: 7.2,
  7.4, 7.6–7.8_
