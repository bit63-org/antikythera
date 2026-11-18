# Implementation Plan — Controller interface and the kythira EC2 integration

## Status: 1/7 tasks complete

## Tasks

- [x] 1. Mailbox protocol v2: assign `key_id` in the reserved header bytes.
  _Requirements: 1.3_ (`key_id` u16 at slot offset 0x12; non-zero on
  commands, zero on responses and events; version 1 is no longer accepted.)
- [ ] 2. Envelope and MapUpdate codecs in `src/proto/`, tests, fuzz targets,
  signing test vectors. _Requirements: 1, 5.2_
- [ ] 3. helm ControllerLink over mTLS with reconnect and reconciliation.
  _Requirements: 2, 3_
- [ ] 4. Inventory/status report schema. _Requirements: 3_
- [ ] 5. A minimal test controller in harbor (C++ CLI that signs and sends
  envelopes) to drive phases 3–5 before kythira's module exists.
  _Requirements: 1, 5_
- [ ] 6. Draft the kythira `ec2-compatible-api` spec in the kythira
  repository, from Requirement 6. _Requirements: 6_
- [ ] 7. End-to-end: AWS CLI `run-instances` against kythira, landing in a
  harbor server. _Requirements: 6.1_
