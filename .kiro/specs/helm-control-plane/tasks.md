# Implementation Plan — helm: the control-plane role

## Status: 11/12 tasks complete

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
- [x] 8. MailboxDevice as a vfio-user server (harbor). _Requirements: 1_
  (`src/helm/mailbox_device.*`: the BAR0 register file, transport-free,
  implementing `HostPort`. `post_command` writes the slot, bumps
  `CMD_DOORBELL` and raises MSI-X vector 0 under one lock, and withdraws
  the command if the interrupt cannot be raised; the host can write only
  `RSP_SLOT`/`EVT_SLOT`, and a 32-bit doorbell write hands helm a copy of
  that slot. `src/helm/mailbox_vfu_server.*` serves it over vfio-user
  with one MSI-X vector, FLR and no DMA setup at all, so libvfio-user
  ignores the client's DMA maps. `harbor/mailbox_smoke.py` drives it as a
  vfio-user client in ctest where libvfio-user is built. Wiring it into
  `ak-helm` in place of the detached host port waits for helm main.)
- [x] 9. CommandRouter with compensation and timeouts. _Requirements: 3, 9_
  (`src/helm/command_router.*`: sequencing and retries, one command in
  the mailbox, creative steps before relay and destructive steps after
  hull's ok, compensation, timeouts, release and cleaning deadlines; pool
  event `attach_failed`. See design "CommandRouter". NIC VPC/MAC/NIC ID
  come from a configured lookup until a signed command carries them.)
- [x] 10. PowerSequencer (harbor: process orchestration and L1 launch).
  _Requirements: 6_ (`src/helm/power_sequencer.*`: boot order, single-slot
  power cycles, recovery after boot, over a `Backplane`; harbor's
  `ProcessBackplane` runs board processes and the L1 QEMU. See design
  "PowerSequencer".)
- [x] 11. Audit log and status reporting. _Requirements: 9.2, 9.3_
  (`src/helm/audit_log.*`, hash-chained append-only file with a strict,
  fuzzed verifier; the router reports outcomes, pool transitions, VM
  exits, host faults and map versions, and builds the inventory
  snapshot. See design "Audit log".)
- [ ] 12. harbor CI: both placements. _Requirements: 7, 10.3_

Wiring (not a numbered task): `HelmDaemon` and `ak-helm` join the
ControllerLink, CommandRouter, PowerSequencer and per-slot OarLinks into
the running daemon (`src/helm/helm_daemon.*`, `src/helm/helm_config.*`,
`src/helm/helm_main.cpp`; design "HelmDaemon"). The mailbox side plugs in
with task 8.

## Deferred

- SPDM attestation and secure sessions on the sideband (Requirement 5.3).
- Hardware secure element integration.
