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
4. Every storage-capable data-plane slot (one that can host an oar-blk
   initiator or a hold role, block-volume-service Requirement 13) SHALL
   provide a management-fabric Ethernet port of its own, separate from
   the control-plane slot's management port (Requirement 3.2), wired to
   the server's management uplink. Storage traffic and object-store
   access from that slot SHALL use only this port; it SHALL NOT be
   bridged to helm's port on the board or the backplane.
5. On a storage server the management uplink SHALL be at least 25 GbE,
   sized for about `replicas` × guest write bandwidth plus reads plus
   the rebuild budget (block-volume-service design "Storage traffic on
   the management fabric").

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

### Requirement 7: Management fabric segments and traffic classes

**User Story:** As the operator, I want storage traffic from untrusted
data-plane boards to share the management fabric without reaching the
control plane or starving it.

#### Acceptance Criteria

1. The management fabric SHALL carry at least two segments, each a VLAN
   with its own address range: the **control segment** (helm's
   controller link, Requirement 3.2, controller-interface Requirement 2)
   and the **storage segment** (initiator, hold and object-store
   traffic, Requirement 4.4).
2. Data-plane management ports SHALL be access ports on the storage
   segment only; the control-plane slot's port SHALL be an access port
   on the control segment only. No board SHALL be able to choose its
   VLAN by tagging.
3. The top-of-rack switches (or the first routed hop) SHALL refuse
   traffic from the storage segment to helm and controller addresses,
   and from the control segment's helm addresses to the storage
   segment, so a compromised data-plane board can reach other storage
   roles but never the control plane (block-volume-service
   Requirement 13.5). The object store SHALL be reachable from the
   storage segment.
4. The fabric SHALL honour three traffic classes, marked by the sender
   in DSCP and, on tagged links, 802.1p:

   | Class | Traffic | DSCP | 802.1p | Scheduling |
   |---|---|---|---|---|
   | control | controller link, lease requests and grants and reports through helm | CS6 (48) | 6 | strict priority, policed to 10 % of the link |
   | storage I/O | initiator to primary, replication (`REPL_WRITE`/`REPL_ACK`) | AF41 (34) | 4 | weighted, 75 % of the remainder |
   | background | rebuild, resync, hydration, scrub, snapshot upload | AF11 (10) | 1 | weighted, 25 % of the remainder, may borrow when idle |

   Ports on the storage segment SHALL re-mark any frame claiming the
   control class to background (an untrusted board cannot promote
   itself); the control segment trusts helm's marking.
5. A saturated storage segment SHALL NOT delay the control class beyond
   its own queueing: lease renewals ride the control class, so storage
   load cannot cost a healthy primary its lease (block-volume-service
   Requirement 13.6).

