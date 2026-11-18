# Implementation Plan — oar-blk: the storage data plane

## Status: 1/8 tasks complete

## Tasks

- [x] 1. XtsCipher wrapper with IEEE 1619 vectors. _Requirements: 2.1, 7.1_
  — `src/oar/blk/xts_cipher.*`: OpenSSL `aes-256-xts` over 512-byte or
  4 KiB data units, tweak = data unit number; tests carry IEEE 1619
  vectors 10-14 and 4 KiB cross-checks.
- [ ] 2. KeySlot with zeroization, locked memory, no core dumps.
  _Requirements: 2.2, 2.3_
- [ ] 3. virtio-blk request parser with bounds checks and fuzz target.
  _Requirements: 6_
- [ ] 4. VirtioBlkFunction on the shared virtio core (vfio-user).
  _Requirements: 1_
- [ ] 5. File backend with volume metadata header. _Requirements: 3.1_
- [ ] 6. helm integration: create/attach/detach/delete/rewrap volume flows.
  _Requirements: 3_
- [ ] 7. Boot from volume in harbor. _Requirements: 4_
- [ ] 8. harbor encryption scenarios. _Requirements: 7.2_

## Deferred

- Self-encrypting NVMe behind a storage manager VM (Requirement 5).
- SPDK backend for performance.
