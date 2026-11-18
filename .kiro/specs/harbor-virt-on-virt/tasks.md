# Implementation Plan — harbor: the virt-on-virt prototype

## Status: 1/10 tasks complete (3 more written, awaiting a first run on nested KVM)

## Tasks

- [x] 1. vfio-user test device `ak-testdev`: BAR0 registers, MSI-X, DMA
  fill, FLR, reconnect loop (`src/oar/testdev/`). Syntax-checked against
  libvfio-user v0.8 headers with GCC 14 and Clang; not yet run.
  _Requirements: 5.1, 5.2_
- [ ] 2. `check-host.sh` and `deps.sh` (pinned QEMU 10.2.4 by SHA-256;
  Ubuntu 24.04 image verified against `SHA256SUMS`; libvfio-user comes
  from the vcpkg feature). **Written and shellcheck-clean; `check-host.sh`
  run here (reports every missing prerequisite); `deps.sh` not yet run end
  to end.** _Requirements: 1_
- [ ] 3. `l1/run.sh` / `l1/stop.sh` with switch and root-port topologies
  and a cloud-init seed that sets the IOMMU command line. **Written; not
  yet run (needs nested KVM).** _Requirements: 2_
- [ ] 4. `l1/phase1-check.sh` + `testdev_mmio.py` and the `phase1.sh`
  driver (IOMMU/ATS/ACS/group checks, MMIO, reset propagation confirmed
  from both sides). **Written; not yet run.** _Requirements: 2.4, 5.1, 6.1_
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
