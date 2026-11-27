# Requirements Document — Server provisioning and decommissioning

## Introduction

An antikythera server today assumes it already has an identity: hull is
handed a server ID at boot (hull design "server-id cmdline / file"),
helm presents a certificate from Kythira's CA that names that server
(controller-interface design "ControllerLink"), and helm's secure
element already holds a master key. Nothing says how a factory-fresh
server gets any of them, how its host image reaches it, or how it gives
them up when it leaves the fleet.

Kythira's `.kiro/specs/metal-host-lifecycle/` owns the lifecycle of
every physical host: registration, netboot, enrollment, drain, wipe and
retirement. This spec is antikythera's side of it for `vm_host` servers:
what helm does before it has an identity, how the controller powers and
boots the host through helm, how hull gets its image and its server ID,
and how a server is wiped and returned to factory state.

Two kinds of server use this: storage servers, whose data-plane slots
hold drives (instance-store volumes, and hold or khold roles where the
server runs them), and diskless servers, whose only devices are network
and blk functions with every volume on the network.

### What this spec does not cover

- The lifecycle states, admin API, boot layer and enrollment protocol on
  the controller side (kythira `metal-host-lifecycle`).
- Firmware updates of helm, the oar boards or the host.
- Hosts of the `linux` kind (khold or S3 storage hosts on the Kythira
  host image); they have no helm.

## Glossary

- **Unenrolled helm**: a helm with no server ID, no certificate and no
  master key, as shipped or after a decommission.
- **Boot function**: a read-only block function on the control slot that
  presents the signed hull UKI and its provisioning file to the host's
  UEFI firmware.
- **Provisioning file**: the per-server settings hull reads at boot
  (server ID, controller key IDs in use), measured before use.

## Requirements

### Requirement 1: Unenrolled helm

**User Story:** As the operator, I want a new server to do nothing until
it has been enrolled, so that an unknown board can never run guests or
reach volumes.

#### Acceptance Criteria

1. An unenrolled helm SHALL hold the host in reset, power no data-plane
   slot beyond what discovery needs, and accept no envelope, frame or key
   record.
2. It SHALL boot from its own flash (`.kiro/specs/cold-start/`), obtain
   an address on its management port by DHCP, and contact the metal boot
   layer's HTTPS endpoint named by the proxyDHCP answer.
3. It SHALL report its hardware identity: secure-element endorsement key
   hash, board serial numbers, slot inventory (types, serials, drive
   counts and sizes), firmware versions and the host's CPU and memory as
   far as helm can read them without releasing it from reset.
4. It SHALL create its attestation key and its TLS key inside the secure
   element, and neither SHALL ever leave it.

### Requirement 2: Enrollment through helm

#### Acceptance Criteria

1. helm SHALL enroll with the metal module by credential activation and
   a quote over its own measured boot (metal Requirement 6.1), and SHALL
   receive its server ID and a certificate naming it.
2. Only after enrollment SHALL helm create its master key in the secure
   element and send its `enrollment` report (block-volume-service task 12)
   on the management link.
3. helm SHALL renew its certificate with a fresh quote before it expires;
   an expired certificate SHALL make helm stop opening the management
   link, while running guests continue (controller-interface Requirement
   2.3).
4. The server ID SHALL be stored in helm's persistent configuration and
   written into the boot function's provisioning file; a mismatch between
   the two at boot SHALL keep the host in reset and raise a host fault.

### Requirement 3: Host power through helm

**User Story:** As the controller, I want to power and reset the host
through helm, since helm already owns the host's power and reset lines.

#### Acceptance Criteria

1. A signed `host_power` record (link type 21) SHALL ask helm to power
   the host on, power it off, cycle it, or hold it in reset, with a
   per-server sequence number as an envelope has.
2. helm SHALL refuse `off`, `cycle` and `hold` while any VM runs unless
   the record sets `force`, and SHALL report the outcome.
3. Power-on SHALL follow backplane power sequencing (helm Requirement 6):
   slots first, then the host.

### Requirement 4: The host's boot image

**User Story:** As the operator, I want the host to boot the hull image
the controller chose, though the host has no network stack of its own.

#### Acceptance Criteria

1. helm SHALL fetch the signed hull UKI named by the controller from the
   metal boot layer over HTTPS, verify its signature and digest, and
   present it with the provisioning file through the boot function.
2. The boot function SHALL be read-only to the host and SHALL be in its
   own IOMMU group; after hull starts it SHALL be released and never
   passed to a guest.
3. An image change SHALL take effect at the next host power cycle only.
4. helm SHALL keep the last-known-good hull UKI in its sealed store and
   present it when the assigned image is unchanged or the boot layer
   cannot be reached, fetching only to change images (kythira
   `.kiro/specs/az-cold-start/` Requirement 4).
5. In harbor the boot function MAY be replaced by OVMF HTTP Boot from
   the boot layer, with the same image and provisioning file.

### Requirement 5: Decommission

**User Story:** As the operator, I want a server leaving the fleet to keep
no keys, no data and no identity.

#### Acceptance Criteria

1. A signed `decommission` record (link type 22) SHALL be refused while
   any VM, attachment or storage replica is on the server.
2. helm SHALL first destroy every VM key and then the master key in the
   secure element, crypto-erasing every volume on the server.
3. helm SHALL then ask every storage role to sanitize its media (NVMe
   Sanitize with crypto erase, else block erase) and report per drive,
   including drives that could not be sanitized, by serial.
4. helm SHALL report progress and the result in `decommission_progress`
   reports (kind 26), then clear its attestation and TLS keys and its
   stored server ID, close the link, and become an unenrolled helm.
5. A server that loses power during a decommission SHALL resume it on
   the next boot before doing anything else.

### Requirement 6: Inventory carries hardware identity

#### Acceptance Criteria

1. helm SHALL send a `hardware_identity` report (kind 25) at
   registration and on any change: board and slot serials, drive serials,
   firmware versions, Secure Boot and IOMMU state reported by hull.
2. A change of any of these since enrollment SHALL be reported as a host
   fault; the controller decides what to do with it (metal Requirement
   9.2).

### Requirement 7: Testing

#### Acceptance Criteria

1. The new records and reports SHALL have unit tests, test vectors in
   `src/proto/test_vectors.hpp` and libFuzzer targets.
2. The unenrolled, enrolling, enrolled and decommissioning states of helm
   SHALL be tested exhaustively for illegal transitions.
3. Harbor SHALL run a whole lifecycle with the metal module: an
   unenrolled helm enrolls, boots hull from the boot layer, runs a VM,
   is drained, decommissioned and returns to unenrolled. It runs on
   tikhov on Clark's go.
