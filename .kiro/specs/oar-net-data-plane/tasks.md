# Implementation Plan — oar-net: the network data plane

## Status: 5/11 tasks complete

## Tasks

- [x] 1. Geneve codec with the NIC-pair option: encode/decode, tests, fuzz
  target with a re-encode round-trip check (`src/oar/net/geneve.*`).
  _Requirements: 3, 4.1, 9.1_
- [x] 2. Ingress policy against a `MappingView` (`src/oar/net/vtep_policy.*`),
  tests. _Requirements: 4.2, 4.3_
- [x] 3. Bring existing code to the steering standards (`_member` naming,
  trailing return types, test timeouts, named constants). _Requirements: 9_
- [ ] 4. Kernel Geneve interop test in a network namespace.
  _Requirements: 9.2_
- [x] 5. Shared virtio core: PCI capabilities, split virtqueue with bounds
  checks, fuzz target. _Requirements: 1.4_ — `src/oar/virtio/`:
  `GuestMemory` (registered DMA regions, no straddling), `SplitQueue`
  (copy-once descriptor walk, indirect tables, chain budget, in-flight
  tracking, event-index suppression; errors latch the queue broken), and
  `CommonConfig` + `encode_capability` (spec 4.1 register model with
  feature negotiation and the status machine). Fuzz: `fuzz_virtqueue`,
  `fuzz_virtio_pci`. Packed rings, the notify/ISR/device-config BAR
  handling and the transport binding come with VirtioNetFunction (task 6).
- [ ] 6. VirtioNetFunction on vfio-user. _Requirements: 1_
- [x] 7. MappingTable with atomic snapshots and `map_update` handling
  (`src/oar/net/mapping_table.*`), tests, fuzz target. Takes a decoded
  `MapUpdate`; the wire codec and signature check are controller task 2.
  _Requirements: 2.5, 8_
- [ ] 8. VSwitch: local forwarding, broadcast replication, ARP/ND proxy,
  dead VPC. _Requirements: 2, 7_
- [ ] 9. Vtep runtime: UDP sockets, OAM keepalives, drop counters.
  _Requirements: 3.5, 3.6, 4.4_
- [ ] 10. WireGuard tunnel integration and key delivery from helm.
  _Requirements: 5_
- [ ] 11. MTU computation and advertisement; harbor multi-server tests.
  _Requirements: 6, 9.3_
