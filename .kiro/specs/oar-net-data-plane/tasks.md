# Implementation Plan — oar-net: the network data plane

## Status: 7/11 tasks complete

## Tasks

- [x] 1. Geneve codec with the NIC-pair option: encode/decode, tests, fuzz
  target with a re-encode round-trip check (`src/oar/net/geneve.*`).
  _Requirements: 3, 4.1, 9.1_
- [x] 2. Ingress policy against a `MappingView` (`src/oar/net/vtep_policy.*`),
  tests. _Requirements: 4.2, 4.3_
- [x] 3. Bring existing code to the steering standards (`_member` naming,
  trailing return types, test timeouts, named constants). _Requirements: 9_
- [x] 4. Kernel Geneve interop test in a network namespace.
  _Requirements: 9.2_ — `tests/geneve_interop.sh` with
  `tests/geneve_interop_peer.cpp`: the codec on a UDP socket in one
  namespace, a kernel geneve device (external mode, tc `tunnel_key` adding
  the NIC-pair option, flower matching it on ingress) in another, IPv6
  underlay. Checked both ways: kernel-built packets decode to the
  configured VNI and NIC pair and re-encode byte for byte; codec-built
  packets match flower and reach a socket behind the kernel device. Needs
  root, so plain ctest skips it; CI's `build (gcc-14)` runs it under sudo.
  Finding: the kernel sets the Geneve C bit only when IP_TUNNEL_CRIT_OPT
  is set (Open vSwitch does, tc `tunnel_key` does not), so a critical
  option added through tc goes out with C clear. The codec drops such a
  packet (Requirement 4.1); the test checks that drop, then decodes the
  packet with C set. Our VTEP encodes in user space, so this only matters
  for kernel or tc-based peers.
- [x] 5. Shared virtio core: PCI capabilities, split virtqueue with bounds
  checks, fuzz target. _Requirements: 1.4_ — `src/oar/virtio/`:
  `GuestMemory` (registered DMA regions, no straddling), `SplitQueue`
  (copy-once descriptor walk, indirect tables, chain budget, in-flight
  tracking, event-index suppression; errors latch the queue broken), and
  `CommonConfig` + `encode_capability` (spec 4.1 register model with
  feature negotiation and the status machine). Fuzz: `fuzz_virtqueue`,
  `fuzz_virtio_pci`. Packed rings, the notify/ISR/device-config BAR
  handling and the transport binding come with VirtioNetFunction (task 6).
- [x] 6. VirtioNetFunction on vfio-user. _Requirements: 1_ —
  `virtio::PciFunction` (`src/oar/virtio/function.*`) is the transport seam
  every device shares: one BAR (common, ISR, device config, notify), queues
  built at DRIVER_OK, DEVICE_NEEDS_RESET on ring errors, FLR.
  `VirtioNetFunction` (`src/oar/net/virtio_net.*`): VERSION_1, MAC, MTU,
  STATUS, EVENT_IDX, INDIRECT_DESC, one RX/TX pair; read-only device
  config; TX copied once, offload headers, bad lengths and spoofed source
  MACs dropped and counted, frames tagged with the function's NIC ID.
  `ak::oar::vfu::VirtioBinding` serves a `PciFunction` over vfio-user and
  `ak-oar-net` runs one NIC with an optional TAP backend until the VSwitch
  (task 8). Fuzz: `fuzz_virtio_net`. Not yet: packed rings, the
  `pci-epf` binding, a harbor run of `ak-oar-net` on tikhov.
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
