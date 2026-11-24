# Implementation Plan — The physical backplane

## Status: requirements fixed; design deferred until harbor phase 5

## Tasks

- [ ] 1. Two-board bench prototype: one host, one endpoint board over a
  crossover adapter; run the test device's pci-epf port. _Requirements: 1_
- [ ] 2. Choose the switch family and validate ACS and DPC behaviour on an
  evaluation board. _Requirements: 1.2, 1.3_
- [ ] 3. Sideband design: per-slot mux and I3C evaluation. _Requirements: 2.2_
- [ ] 4. Power sequencing controller and host reset control.
  _Requirements: 2.1, 2.3_
- [ ] 5. Schematic and layout (after decisions in design.md).
  _Requirements: 1–5_
- [ ] 6. Management fabric: per-slot storage ports, control and storage
  VLANs, switch ACLs and the three DSCP/802.1p classes, validated on the
  bench switch with a saturated storage segment and lease traffic.
  _Requirements: 4.4-4.5, 7_
