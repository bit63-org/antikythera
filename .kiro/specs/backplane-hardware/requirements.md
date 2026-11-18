# Requirements Document — The physical backplane

## Introduction

The backplane connects one host to a control-plane role and N data-plane
slots over PCIe, with per-slot management signals that only the control
plane can drive. Its design is deferred until harbor has proven the
protocols, but the requirements below are fixed now because they constrain
everything above them.

## Requirements

### Requirement 1: PCIe fabric

#### Acceptance Criteria

1. A PCIe switch (Broadcom PEX or Microchip Switchtec class) SHALL connect
   the host's root port(s) to every slot, one downstream port per slot.
2. The switch SHALL support ACS with peer-to-peer request and completion
   redirect, so each slot is its own IOMMU group and slots cannot reach
   each other directly.
3. The switch SHALL support Downstream Port Containment.
4. A common reference clock SHALL be distributed to every slot through a
   clock buffer; separate-clock modes SHALL NOT be relied on.
5. Retimers or redrivers SHALL be used wherever channel loss requires them.

### Requirement 2: Per-slot management signals

#### Acceptance Criteria

1. Each slot SHALL have PERST#, power enable, PRSNT# and link-ready (or
   equivalent) signals routed to the control-plane role only.
2. Each slot SHALL have its own electrically isolated sideband segment
   (SMBus/I2C, I3C-capable where possible), muxed or dedicated, controlled
   only by the control-plane role.
3. The host's PERST# and power SHALL be controlled by the control-plane
   role, so the host can be held in reset until slots are ready.

### Requirement 3: Control-plane slot

#### Acceptance Criteria

1. One slot SHALL host the control-plane role (alone or combined with a
   data plane).
2. That slot SHALL provide a secure element (TPM or equivalent) reachable
   only by the control-plane role, and a management Ethernet port for the
   controller link.

### Requirement 4: Data-plane slots

#### Acceptance Criteria

1. Data-plane slots SHALL use a connector with a defined pinout (MCIO,
   OCuLink or U.2/SFF-8639).
2. Network data-plane slots SHALL provide an uplink path (front-panel or
   midplane Ethernet) to the datacenter network.
3. Storage slots SHALL accommodate U.2/E3.S drives or storage boards.

### Requirement 5: GPU provisions

#### Acceptance Criteria

1. At least one slot SHALL be GPU-capable: x16 Gen4+, 75 W plus auxiliary
   power (300–600 W budget), dual-width space and directed airflow, with
   per-slot power control.
2. The host platform SHALL provide a large 64-bit MMIO aperture
   (Above-4G decoding), and bridge windows SHALL be reserved for empty
   GPU slots.

### Requirement 6: Platform

#### Acceptance Criteria

1. The host CPU SHALL support SEV-SNP or TDX, keeping confidential VMs
   possible later.
2. PCIe IDE and TDISP support in the switch SHALL NOT be required in the
   first revision; a later revision MAY add it.
