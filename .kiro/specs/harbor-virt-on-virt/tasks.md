# Implementation Plan — harbor: the virt-on-virt prototype

## Status: 4/10 tasks complete

## Tasks

- [x] 1. vfio-user test device `ak-testdev`: BAR0 registers, MSI-X, DMA
  fill, FLR, reconnect loop (`src/oar/testdev/`). Built against the vcpkg
  libvfio-user overlay and run in phase 1 on tikhov (MMIO, slot ID,
  scratch, reset). MSI-X and DMA are exercised in phase 2.
  _Requirements: 5.1, 5.2_
- [x] 2. `check-host.sh` and `deps.sh` (pinned QEMU 10.2.4 by SHA-256;
  Ubuntu 24.04 image verified against `SHA256SUMS`; libvfio-user comes
  from the vcpkg feature). Run on tikhov: `check-host.sh` passed;
  `deps.sh image` verified the image; `deps.sh qemu` was not needed
  because tikhov's system QEMU 10.2.1 already has `vfio-user-pci`, so the
  pinned build is still unexercised. _Requirements: 1_
- [x] 3. `l1/run.sh` / `l1/stop.sh` with root-port (default) and switch
  topologies and a cloud-init seed that sets the IOMMU command line.
  Run on tikhov. _Requirements: 2_
- [x] 4. `l1/phase1-check.sh` + `testdev_mmio.py` and the `phase1.sh`
  driver. **Phase 1 passes on tikhov with `--topology rootports`.** The
  switch topology fails only the ACS and group checks, because QEMU's
  switch ports have no ACS (see design.md). _Requirements: 2.4, 5.1, 6.1_
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
