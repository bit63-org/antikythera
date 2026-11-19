# Implementation Plan — harbor: the virt-on-virt prototype

## Status: 4/10 tasks complete (task 2 written; `deps.sh qemu` not yet run end to end)

## Tasks

- [x] 1. vfio-user test device `ak-testdev`: BAR0 registers, MSI-X, DMA
  fill, FLR, reconnect loop (`src/oar/testdev/`). Built against the
  vcpkg `vfio-user` feature with `-DAK_VFIO_USER=ON` and exercised by
  harbor phase 1 on nested KVM (2026-11-18).
  _Requirements: 5.1, 5.2_
- [ ] 2. `check-host.sh` and `deps.sh` (pinned QEMU 10.2.4 by SHA-256;
  Ubuntu 24.04 image verified against `SHA256SUMS`; libvfio-user comes
  from the vcpkg feature). **Written and shellcheck-clean; `check-host.sh`
  and the vcpkg `vfio-user` feature verified on a nested-KVM host
  (2026-11-18). Phase 1 there ran on QEMU 10.2.1, so `deps.sh qemu`
  (the pinned 10.2.4 build) is still not confirmed end to end.**
  _Requirements: 1_
- [x] 3. `l1/run.sh` / `l1/stop.sh` with switch and root-port topologies
  and a cloud-init seed that sets the IOMMU command line. Run on nested
  KVM (2026-11-18). `rootports` is the default; `switch` is opt-in because
  QEMU 10.2's emulated xio3130 downstream ports have no ACS, so endpoints
  share an IOMMU group with their port (an emulation limit, not a client
  bug). _Requirements: 2_
- [x] 4. `l1/phase1-check.sh` + `testdev_mmio.py` and the `phase1.sh`
  driver (IOMMU/ATS/ACS/group checks, MMIO, reset propagation confirmed
  from both sides). All 21 checks pass on the `rootports` topology with
  two slots (2026-11-18, main at ceafb62): IOMMU command line, each device
  alone in its group with ACS and no ATS, BAR0 magic, slot IDs, scratch
  read/write, and in-L1 resets. The host-side reset check only counts
  slot-log lines written after the checks start, so the attach-time reset
  no longer satisfies it. _Requirements: 2.4, 5.1, 6.1_
- [ ] 5. Phase 2: L2 passthrough, guest-side test program, hot-plug.
  _Requirements: 5.2_
- [ ] 6. Topology file format; combined vs split placement.
  _Requirements: 4.1_
- [ ] 7. Multi-server network namespaces and the datacenter bridge.
  _Requirements: 4.2_
- [ ] 8. Phases 3–5 drivers (depend on helm, hull, oar tasks).
  _Requirements: 5.3, 5.4_
- [ ] 9. Self-hosted runner job for nested phases. _Requirements: 6.2_
- [ ] 10. Fault injection: kill board processes, drop sideband, stall
  resets. _Requirements: 5.4_
