# Requirements Document — helm: the control-plane role

## Introduction

helm is the one trusted authority on each server besides the host itself.
It decides which VM gets which device, holds every key, programs every
data-plane role, sequences backplane power, and is the only party that may
tell the host agent (hull) to create or destroy anything. It reaches the
host through a DMA-free PCIe mailbox and reaches data-plane roles through a
per-slot isolated sideband. It never shares a channel with a guest.

helm is a **role**, not a board. It may run on a dedicated control board
beside N data-plane boards, or share a board with a data-plane role in an
isolated domain. Both placements must work with the same code and protocol.

### What this spec does not cover

- The host agent's side of the mailbox (`hull-host-agent`).
- What data-plane roles do with the commands helm sends (`oar-*`).
- The controller that sends helm its commands (`controller-interface`).
- Electrical design of the backplane (`backplane-hardware`).

## Glossary

- **Mailbox** — helm's PCIe function: a register file in BAR0 with command,
  response and event slots (`src/helm/mailbox.hpp`).
- **Sideband** — the per-slot management bus (SMBus/I2C, later I3C) carrying
  MCTP between helm and one data-plane role.
- **Data-plane role (oar)** — a provider of PCIe device functions: NIC VFs,
  storage functions, GPU functions.
- **Device pool** — helm's inventory of every assignable function and its
  state.
- **Secure element** — tamper-resistant key store holding the master key
  (in harbor: a software stand-in).
- **Controller** — the external orchestrator (the kythira EC2 module) that
  signs commands.

## Requirements

### Requirement 1: The mailbox is the only host channel, and it has no DMA

**User Story:** As the host's owner, I want the control plane to reach the
host only through registers it cannot use for DMA, so that a compromised
control plane cannot read or write host memory.

#### Acceptance Criteria

1. helm SHALL expose exactly one PCIe function to the host for control:
   the mailbox, with the BAR0 layout in `src/helm/mailbox.hpp`.
2. All mailbox messages SHALL live in device memory (BAR0 slots). helm SHALL
   NOT require the host to grant it any DMA mapping.
3. WHEN helm has a new command THEN it SHALL write the slot completely
   before incrementing `CMD_DOORBELL` and raising its MSI.
4. Slot contents SHALL be little-endian and SHALL zero every byte past
   `body_len` and every reserved header byte.
5. helm SHALL NOT place a new command in `CMD_SLOT` until the host has
   responded to the previous one or the command timeout (Requirement 9)
   expires.

### Requirement 2: Commands are signed by the controller, and helm relays them

**User Story:** As an operator, I want commands to be unforgeable even by a
compromised control plane, so that helm compromise allows at most denial of
service, not unauthorized VM or device changes.

#### Acceptance Criteria

1. Every command SHALL carry an Ed25519 signature over slot bytes
   `[0x00, 0xC0)`, produced by the controller.
2. helm SHALL forward controller-signed commands unchanged; it SHALL NOT
   hold the controller's signing key.
3. Sequence numbers SHALL be strictly increasing per host; helm SHALL drop
   a command whose sequence number is not greater than the last delivered.
4. IF signing is disabled by configuration THEN hull SHALL refuse to start
   unless an explicit "trust helm" build flag is set, and the build SHALL
   say so in its version string.

### Requirement 3: Device pool and assignment

**User Story:** As the controller, I want helm to own a consistent
inventory of every assignable function, so that a device is never in two
VMs and never handed out dirty.

#### Acceptance Criteria

1. helm SHALL track every function with a type (`nic_vf`, `blk_fn`,
   `gpu_whole`, `gpu_vf`) and a state from:
   `free → assigned → releasing → cleaning → free`, plus `faulted`.
2. A function SHALL be assigned to at most one VM at a time.
3. WHEN a VM releases a function THEN helm SHALL move it to `releasing`,
   wait for hull's `DEVICE_RELEASED` event (reset complete), instruct its
   data-plane role to clean it (wipe, crypto-erase or scrub), and only on
   confirmed completion return it to `free`.
4. IF cleaning fails or times out THEN the function SHALL move to `faulted`
   and SHALL NOT be reassigned until a slot power-cycle succeeds.
5. GPU function types and the `scrub_done` event SHALL exist in the
   protocol from the first release, even though GPU support is built later.

### Requirement 4: Key hierarchy

**User Story:** As a tenant, I want my volumes encrypted with keys only my
VM's attachments can use, and destroyed when I say so.

#### Acceptance Criteria

1. The master key SHALL never leave the secure element.
2. Each VM SHALL have a VM key, stored only wrapped by the master key.
3. Each volume SHALL have a volume key, stored on the media wrapped by its
   owning VM's key.
4. WHEN a volume is attached THEN helm SHALL unwrap its key and deliver it
   only to the storage role serving that attachment, over that role's own
   sideband segment.
5. Key material SHALL NOT appear in any mailbox message or any host-visible
   memory.
6. `DELETE_VOLUME` SHALL destroy the wrapped volume key; destroying a VM
   with `persist_volumes = false` SHALL destroy its VM key (crypto-erasing
   all its volumes).
7. Moving a volume between VMs SHALL require an explicit `REWRAP_VOLUME`.

### Requirement 5: Per-slot isolated sideband

**User Story:** As the host's owner, I want each data-plane role to see
only its own management traffic, so that a compromised board cannot sniff
or forge another slot's keys or commands.

#### Acceptance Criteria

1. Each slot's sideband SHALL be an electrically separate segment (mux or
   dedicated controller); helm SHALL enable only the segment it is talking
   to.
2. helm↔oar messages SHALL be MCTP-framed so the same protocol runs over
   SMBus, I3C, or an in-process channel (co-located placement).
3. helm SHALL authenticate nothing on the sideband in the first release,
   relying on segment isolation; the protocol SHALL reserve room for SPDM
   attestation and sessions.

### Requirement 6: Backplane power sequencing

**User Story:** As the host's owner, I want the host to enumerate a fixed,
fully ready device tree, so that it needs no PCIe hot-plug support.

#### Acceptance Criteria

1. At power-on helm SHALL bring up every data-plane slot, wait until each
   reports link-ready (or times out to `faulted`), and only then release the
   host from reset.
2. helm SHALL be able to power-cycle any single slot without affecting the
   host or other slots.
3. A slot that faults after boot SHALL be recovered by helm (power-cycle,
   retrain) and its functions returned to the pool only after cleaning.

### Requirement 7: Placement independence

**User Story:** As a hardware designer, I want to choose between one
combined board and a control board plus N data-plane boards without
changing software.

#### Acceptance Criteria

1. helm SHALL be the same code in both placements; only the sideband
   transport binding SHALL differ.
2. In the combined placement, helm and the data plane SHALL run in
   separate isolation domains (separate processes in harbor) connected only
   by the helm↔oar protocol.
3. Each data-plane instance SHALL be addressed as an independent role with
   its own function inventory and (for networking) its own VTEP identity.

### Requirement 8: Network policy authority

**User Story:** As a tenant, I want my VPC membership decided only by the
control plane, so that neither my guest nor a compromised NIC can join
another VPC.

#### Acceptance Criteria

1. helm SHALL be the only source of a NIC VF's VPC, MAC address and NIC ID.
2. helm SHALL apply controller `MAP_UPDATE`s to the relevant oar-net roles
   and SHALL report the applied mapping version back to the controller.
3. WHEN a NIC VF is detached THEN helm SHALL move it to an isolated
   ("dead") VPC before any other cleanup.

### Requirement 9: Timeouts, faults and observability

#### Acceptance Criteria

1. Every helm→hull command and every helm→oar request SHALL have a
   timeout; expiry SHALL be reported to the controller, never silently
   retried with side effects.
2. helm SHALL report per-function state, per-slot health and mapping
   versions to the controller on request and on change.
3. helm SHALL keep an append-only audit log of every command relayed and
   every key operation (key IDs only, never material).

### Requirement 10: Testing

#### Acceptance Criteria

1. Every helm parser (mailbox, MCTP, controller envelope) SHALL have unit
   tests and a libFuzzer target.
2. The device-pool state machine SHALL be tested exhaustively for illegal
   transitions.
3. harbor SHALL run helm in both placements (combined and split) in CI.

### Requirement 11: Group policy and usage metering

**User Story:** As the operator, I want multicast enabled only where the
controller allows it, and every replica it causes billed.

#### Acceptance Criteria

1. helm SHALL forward controller `GroupPolicy` frames, unmodified, to every
   network role hosting a NIC in the VNI, and to a role that gains such a
   NIC before that NIC is plugged.
2. helm SHALL read every network role's per-NIC group meters at least
   every 60 seconds, and after every NIC detach, and report them to the
   controller as `group_usage` reports.
3. helm SHALL keep a detached NIC's final reading until the controller
   acknowledges the report that carries it.
4. helm SHALL forward controller `GroupMembers` frames like `GroupPolicy`
   frames, and SHALL report each network role's snooped joins to the
   controller as a `group_membership` report within a few seconds of a
   change, when it first reads a newly attached role, and empty when a
   role that listed joins goes away.

### Requirement 12: Instance metadata records

**User Story:** As the operator, I want each network role to answer its
NICs' metadata requests from the controller's signed records, without
helm in the request path (oar-net Requirement 13).

#### Acceptance Criteria

1. helm SHALL forward each controller `InstanceMetadata` frame,
   unmodified, to the network role that hosts or is about to host its
   NIC, before the `prepare_function` that plugs that NIC.
2. helm SHALL keep the newest frame per NIC (by version; an older or
   equal one is not forwarded) until the NIC is detached, and SHALL
   resend every frame it holds to a network role whose sideband
   reopens, before the router registers that role's functions.
3. helm SHALL NOT read, change or answer from a record; the network role
   verifies it.

