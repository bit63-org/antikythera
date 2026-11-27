# Requirements Document — Cold start after a power outage

## Introduction

When an AZ loses power, every antikythera server loses everything it
was told: hull has no writable disk, and helm keeps only its secure
element's keys. A server can start a VM only on a signed command from
the controller, and in a Kythira AZ the controller itself runs in VMs on
these servers. kythira's `.kiro/specs/az-cold-start/` breaks that cycle
with a small **bootstrap tier** of pinned control-plane VMs that their
servers restart with no controller. This spec is the server side:

- a **sealed store** on helm that survives power loss;
- **local boot** of hull from a last-known-good (LKG) image kept there,
  so a server boots without the netboot layer;
- a **local power-on policy** that staggers servers by tier and slot;
- **standing sets**: signed records that let helm start pinned
  instances, with their volumes, NICs and secrets, before any controller
  is reachable;
- replay protection for commands across reboots, which hull lacks today;
- the reports that let the controller see how a cold start went.

It builds on `server-provisioning` (helm enrolls the server, owns its
power, and fills the boot function hull boots from) and
`helm-control-plane`.

### What this spec does not cover

- Which instances are pinned and how the controller builds standing
  sets (kythira `az-cold-start` Requirements 2 and 5 of its tasks).
- Content-addressed image distribution and per-rack caches
  (kythira `fleet-cells`).
- UPS, PDUs and generators.

## Glossary

The `server-provisioning` and kythira `az-cold-start` glossaries apply.
In addition:

- **Sealed store**: helm's persistent storage, encrypted and
  authenticated with a key that never leaves the secure element.
- **LKG image**: the newest hull UKI this server booted, passed its
  checks with, and was told to keep by the controller.
- **Standing set**: the signed record (link type 23) listing the pinned
  instances helm starts after power returns.
- **Standing start**: starting an instance from the standing set, with
  no controller.
- **Power-on policy**: tier, slot and delays (link type 24) that decide
  when helm releases the host after power returns.
- **Boot epoch**: a counter in the secure element, incremented on every
  host boot, that scopes command sequence numbers to one boot.

## Requirements

### Requirement 1: The sealed store

**User Story:** As the operator, I want helm to remember what it needs
after power loss, without anyone who takes the board being able to read
or change it.

#### Acceptance Criteria

1. helm SHALL boot from its own flash, never by netboot (this settles
   `server-provisioning` open question 2), and SHALL keep a sealed store
   in that flash of at least 2 GiB.
2. Every object in the sealed store SHALL be encrypted and authenticated
   with AES-256-GCM under a key derived in the secure element, with the
   object's name and version as additional data.
3. The store SHALL hold: up to two hull UKIs (LKG and previous) with
   their provisioning files, the newest standing set, the newest
   power-on policy, the newest time floor, the last command sequence
   number and boot epoch, and the newest verified network frames for
   standing instances' NICs.
4. A write SHALL be atomic: power lost during a write SHALL leave the
   previous version readable.
5. A rollback of the store to an older version SHALL be detected by a
   version counter anchored in the secure element's monotonic counter,
   and a detected rollback SHALL make helm discard the standing set and
   power-on policy and wait for the controller.
6. An object that fails authentication SHALL be discarded and reported
   (Requirement 6), never used.
7. Decommission (`server-provisioning`) SHALL erase the sealed store by
   destroying its key.

### Requirement 2: Booting hull from the LKG image

**User Story:** As the operator, I want servers to boot after an outage
when the netboot layer is not up yet, and without every server
downloading its image at once.

#### Acceptance Criteria

1. Before releasing the host from reset, helm SHALL fill the boot
   function (`server-provisioning` design "The boot function") with the
   LKG UKI and its provisioning file, unless the controller has assigned
   a different image, in which case helm SHALL fetch that image from the
   metal boot layer.
2. IF the assigned image cannot be fetched within 30 seconds THEN helm
   SHALL boot the LKG image and report the failure.
3. helm SHALL promote an image to LKG only on a signed `keep_image`
   action in the power-on policy record (Requirement 3), which the
   controller sends after the server booted it, renewed its certificate
   with a fresh attestation, and passed its checks. The previous LKG SHALL
   be kept as the fallback.
4. IF hull fails to start (no agent ready within a configured time,
   default 120 s) on the LKG image THEN helm SHALL boot the previous
   image once and report it.
5. A UKI SHALL be verified against helm's compiled-in image signing keys
   before it is written to the store and again before it is booted.

### Requirement 3: Local power-on policy

**User Story:** As the operator, I want each server to wait its turn
after power returns, without asking the controller, so that tiers start
in order and breakers do not trip.

#### Acceptance Criteria

1. A signed `power_policy` record (link type 24) SHALL carry the
   server's tier, slot, tier delay, slot interval, maximum jitter, and an
   optional `keep_image` digest; helm SHALL store the newest one.
2. WHEN helm boots after its own power returned THEN it SHALL hold the
   host in reset for `tier_delay + slot × slot_interval + jitter`, with
   jitter drawn uniformly from `[0, max_jitter]`, then power the host and
   its data-plane slots on in the order of `helm-control-plane`
   Requirement 6.
3. helm SHALL also stagger its own data-plane slots, powering at most one
   slot per 500 ms.
4. With no stored policy, helm SHALL use tier 3, slot 0, and the default
   delays (kythira `az-cold-start` Requirement 5.2).
5. A `host_power` record (`server-provisioning`) SHALL override the wait:
   `on` starts the host at once, `hold` keeps it in reset.
6. The policy SHALL apply only after helm itself lost power, not after a
   host reboot with helm running.

### Requirement 4: Standing sets and standing starts

**User Story:** As the operator, I want the bootstrap tier's VMs to start
on their own after power returns, so that the control plane can start
everything else.

#### Acceptance Criteria

1. A signed `standing_set` record (link type 23) SHALL carry the server
   ID, a `standing_generation`, and for each pinned instance: its launch
   envelope body (instance ID, type, image, CPU, memory, devices), its
   volumes with attachment IDs, generations, khold endpoints and wrapped
   volume keys, its NICs, and its instance secrets wrapped to this
   server's secure element.
2. helm SHALL verify the record's signature and accept it only if its
   generation is higher than the stored one; the accepted generation
   SHALL be committed to the secure element's monotonic counter, so an
   older set is refused even after the store is restored from a copy.
3. An empty standing set SHALL unpin every instance on the server.
4. WHEN helm has released the host from reset after power loss and hull
   is ready THEN helm SHALL, before relaying any controller envelope,
   deliver each standing instance's launch to hull as a **standing
   start**: the set's signed bytes plus the instance's entry index.
5. hull SHALL accept a standing start only: when it verifies against a
   compiled-in controller key; when it names this server; when no live
   envelope has been accepted in this boot; and for an instance ID the
   set names. A standing start SHALL not consume a command sequence
   number.
6. Once the controller link is up, helm SHALL report the standing
   instances it started (Requirement 6) and relay envelopes as usual; the
   controller adopts the instances.
7. A standing start that fails (an image missing, a volume refused, a
   device missing) SHALL be retried with capped backoff (1 s to 30 s)
   and reported, and SHALL never stop other standing starts.

### Requirement 5: Volumes, NICs and secrets of standing instances

#### Acceptance Criteria

1. helm SHALL attach a standing instance's volumes by sending oar-blk
   the stored `ReplicaConfig` and unwrapping the stored volume key in the
   secure element, as for a live attach; khold serves the standing
   attachment's existing ID and generation, and a retired generation is
   refused as usual.
2. helm SHALL keep the newest verified `MapUpdate`, `VpcConfig`,
   `TunnelPeers`, `SecurityPolicy` and `InstanceMetadata` frames for each
   standing instance's NICs in the sealed store, and SHALL forward them to
   the network role before plugging the NICs (`helm-control-plane`
   Requirement 12.2), so standing instances reach one another across
   tier-0 servers with no controller.
3. Tunnel keys between tier-0 servers SHALL survive power loss, which
   the stable secure-element-derived tunnel keys of
   `fleet-scale-networking` provide; until that lands, the standing set
   SHALL carry the tunnel keys wrapped to this server's secure element.
4. helm SHALL unwrap each instance secret in the secure element and
   deliver it to the instance only through its instance metadata, on a
   path served by the network role from a record helm generates for that
   instance alone, and SHALL never write an unwrapped secret to the store.
5. The standing set SHALL carry the image chunks' manifest digest; a
   standing instance's image SHALL be read from its root volume, never
   fetched from S3 during a standing start.

### Requirement 6: Replay protection across reboots

**User Story:** As a security owner, I want an envelope captured before
a power cycle to be refused after it.

#### Acceptance Criteria

1. helm SHALL increment the boot epoch in the secure element before
   every host boot and pass it, with the last accepted command sequence
   number, in the measured provisioning file.
2. hull SHALL refuse any envelope whose sequence number is not greater
   than the one passed in the provisioning file.
3. helm SHALL record the last command sequence number in the sealed store
   after each accepted envelope, before relaying the next.

### Requirement 7: Time floor

#### Acceptance Criteria

1. helm SHALL store the newest time floor it receives in a standing set or
   power-on policy, and SHALL refuse to treat its own RTC as correct when
   it reads below that floor.
2. helm SHALL check certificate `not_before` and `not_after` against
   `max(RTC, time floor)` while it has no time source.

### Requirement 8: Reports

#### Acceptance Criteria

1. helm SHALL send a `cold_start` report (kind 27) on the first link after
   its own power returned: power-return time by RTC and time floor, the
   delay it waited, boot source (`lkg`, `previous`, `netboot`), standing
   starts with their result per instance, store faults, and rollbacks
   detected.
2. helm SHALL send a `boot_cache` report (kind 28) on every inventory:
   the digests of the LKG and previous images, the standing generation,
   the power-on policy version, and free space in the sealed store.
3. Records 23 and 24 and reports 27 and 28 SHALL have codecs with test
   vectors and libFuzzer targets.

### Requirement 9: Testing

#### Acceptance Criteria

1. Harbor SHALL simulate an AZ power loss: every simulated helm, hull and
   role killed at once, the software secure element kept, the sealed
   store kept on a file, and the controller absent; standing instances
   SHALL come back, reach one another, and serve their volumes.
2. The suite SHALL inject: a store write cut at every step, a store
   rolled back to an older copy, a corrupted object, a standing set with
   an old generation, a missing LKG, and an envelope captured before the
   power loss and replayed after it.
3. The QEMU cold-start run of kythira `az-cold-start` Requirement 14.3
   SHALL use this spec's software helm with OVMF and `swtpm`.
