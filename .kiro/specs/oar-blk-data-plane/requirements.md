# Requirements Document — oar-blk: the storage data plane

## Introduction

oar-blk gives VMs local block storage that is encrypted per VM below the
guest: the guest sees an ordinary plaintext virtio-blk disk and holds no
key, the media holds only ciphertext, and the host never sees either keys
or plaintext. Volumes are independent of VMs: they can persist after a VM
is destroyed or be crypto-erased with it. VMs boot from attached volumes,
so the host never handles guest images.

Two backing implementations are in scope: a **storage endpoint board**
that encrypts in its own firmware (implemented first), and **self-encrypting
NVMe** with per-namespace locking behind a storage manager VM (later).

### What this spec does not cover

- Guest-side encryption (explicitly not wanted: the guest must not decrypt).
- Snapshots, replication and live migration of volumes.
- The key hierarchy itself (`helm-control-plane` Requirement 4).

## Glossary

- **Volume** — a block device with its own volume key, owned by one VM.
- **Storage function** — the virtio-blk PCI function presenting one
  attachment to one VM.
- **Crypto-erase** — making a volume unreadable by destroying its key.

## Requirements

### Requirement 1: virtio-blk functions

#### Acceptance Criteria

1. Each attachment SHALL be a modern virtio-blk PCI device with MSI-X,
   presenting the volume's plaintext.
2. The device SHALL support FLR; after reset it SHALL hold no key and no
   plaintext.
3. The device logic SHALL be built on the shared virtio core with the same
   two transports as oar-net.

### Requirement 2: Transparent per-VM encryption

**User Story:** As a tenant, I want my disks encrypted with keys only my
VM's attachments can use, without running any encryption in my guest.

#### Acceptance Criteria

1. Data at rest SHALL be encrypted with AES-256-XTS using the volume key,
   with the sector number as tweak.
2. The volume key SHALL be held only in the storage role's RAM, and only
   while the volume is attached.
3. WHEN the volume is detached, the function is reset, or the role loses
   power THEN the key SHALL be zeroized.
4. The guest SHALL need no key and no encryption software.
5. Keys SHALL arrive only from helm over this role's own sideband segment.

### Requirement 3: Volume lifecycle

#### Acceptance Criteria

1. `CREATE_VOLUME {vol_id, owner_vm, size}` SHALL allocate space and store
   the wrapped volume key with the volume's metadata.
2. `ATTACH_VOLUME` / `DETACH_VOLUME` SHALL follow the device-pool flow
   (assign, hot-plug, reset, clean).
3. `DELETE_VOLUME` SHALL crypto-erase (helm destroys the wrapped key) and
   then release space.
4. Destroying a VM with `persist_volumes = false` SHALL crypto-erase all of
   that VM's volumes.
5. `REWRAP_VOLUME` SHALL be the only way a volume changes owner.

### Requirement 4: Boot from volume

#### Acceptance Criteria

1. A VM SHALL be bootable from an attached volume through the guest
   firmware's virtio-blk support, with no host-supplied image.

### Requirement 5: Self-encrypting NVMe option (later)

#### Acceptance Criteria

1. The design SHALL allow volumes on TCG Opal NVMe namespaces, each with
   its own locking credential delivered by helm, exposed through SR-IOV VFs
   under a storage manager VM.
2. Drives used this way SHALL have FIPS 140-3 validation; SPDM support is
   preferred.

### Requirement 6: Integrity of the device against the guest

#### Acceptance Criteria

1. All virtqueue descriptors and request headers from the guest SHALL be
   bounds-checked; out-of-range sectors SHALL fail the request, never
   wrap or touch another volume.
2. The virtio-blk request parser SHALL have a fuzz target.

### Requirement 7: Testing

#### Acceptance Criteria

1. Unit tests SHALL cover XTS against published test vectors (IEEE 1619).
2. harbor SHALL verify: plaintext in the guest, only ciphertext in the
   backing file, crypto-erase makes data unrecoverable, a detached volume
   attached to another VM without rewrap fails, and boot from volume.
