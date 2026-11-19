# Implementation Plan — Controller interface and the kythira EC2 integration

## Status: 7/9 tasks complete

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
- [ ] 6. Draft the kythira `ec2-compatible-api` spec in the kythira
  repository, from Requirement 6. _Requirements: 6_
- [ ] 7. End-to-end: AWS CLI `run-instances` against kythira, landing in a
  harbor server. _Requirements: 6.1_
