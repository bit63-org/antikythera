# Implementation Plan — helm: the control-plane role

## Status: 7/12 tasks complete

## Tasks

- [x] 1. Mailbox codec: BAR0 layout, slot header, strict decode/encode,
  `CREATE_VM` / `DESTROY_VM` bodies, unit tests, fuzz target
  (`src/helm/mailbox.*`). _Requirements: 1.1, 1.4, 10.1_
- [x] 2. Bring existing code to the steering standards: `_member` naming,
  trailing return types, `BOOST_AUTO_TEST_CASE` timeouts, named constants
  in source and tests. _Requirements: 10_
- [x] 3. Remaining command bodies: `ATTACH_DEVICE`, `DETACH_DEVICE`,
  volume commands, `CREATE_NETWORK`/`DELETE_NETWORK`, `GPU_VF_CONFIG`
  (reserved), events. _Requirements: 1, 3.5_
- [x] 4. DevicePool table-driven state machine with exhaustive transition
  tests, GPU types and the `scrub_done` cleaning path
  (`src/helm/device_pool.*`). _Requirements: 3, 10.2_
- [x] 5. MCTP framing codec (SMBus binding header + vendor message types),
  reassembly, tests, fuzz target (`src/helm/mctp.*`). _Requirements: 5.2, 10.1_
- [x] 6. OarLink with `SocketBinding` and `InProcessBinding`.
  _Requirements: 5, 7_ (`src/helm/oar_protocol.*` bodies,
  `src/helm/sideband_binding.*` bindings, `src/helm/oar_link.*` helm's
  `OarLink` and the role's `OarEndpoint`; unit tests over both bindings,
  `fuzz_oar_link`. See design "OarLink".)
- [x] 7. KeyStore with software secure element; `ScopedKey` zeroization;
  wrap/unwrap/rewrap/destroy (`src/helm/key_store.*`,
  `src/helm/secure_element.*`, `src/helm/scoped_key.*`), unit tests,
  wrapped-key fuzz target. _Requirements: 4_
- [ ] 8. MailboxDevice as a vfio-user server (harbor). _Requirements: 1_
- [ ] 9. CommandRouter with compensation and timeouts. _Requirements: 3, 9_
- [ ] 10. PowerSequencer (harbor: process orchestration and L1 launch).
  _Requirements: 6_
- [ ] 11. Audit log and status reporting. _Requirements: 9.2, 9.3_
- [ ] 12. harbor CI: both placements. _Requirements: 7, 10.3_

## Deferred

- SPDM attestation and secure sessions on the sideband (Requirement 5.3).
- Hardware secure element integration.
