# Implementation Plan — Controller interface and the kythira EC2 integration

## Status: 3/7 tasks complete

## Tasks

- [x] 1. Mailbox protocol v2: assign `key_id` in the reserved header bytes.
  _Requirements: 1.3_ (`key_id` u16 at slot offset 0x12; non-zero on
  commands, zero on responses and events; version 1 is no longer accepted.)
- [x] 2. Envelope and MapUpdate codecs in `src/proto/`, tests, fuzz targets,
  signing test vectors. _Requirements: 1, 5.2_ (Header-only `ak::proto`
  depending only on `ak::common`; vectors in `src/proto/test_vectors.hpp`
  use the RFC 8032 test keys. MapUpdate carries `key_id` and is a full
  per-VPC snapshot; see design "Envelope".)
- [ ] 3. helm ControllerLink over mTLS with reconnect and reconciliation.
  _Requirements: 2, 3_
- [x] 4. Inventory/status report schema. _Requirements: 3_ (`Report` in
  `src/proto/report.hpp`: inventory snapshot plus command outcome,
  pool-state, VM-exit, map-applied and host-fault events; link record
  framing and report acks in `src/proto/link.hpp`; tests and fuzz targets.
  See design "Inventory and status reports" and "Link framing".)
- [ ] 5. A minimal test controller in harbor (C++ CLI that signs and sends
  envelopes) to drive phases 3–5 before kythira's module exists.
  _Requirements: 1, 5_
- [ ] 6. Draft the kythira `ec2-compatible-api` spec in the kythira
  repository, from Requirement 6. _Requirements: 6_
- [ ] 7. End-to-end: AWS CLI `run-instances` against kythira, landing in a
  harbor server. _Requirements: 6.1_
