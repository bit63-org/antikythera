# Design Document — oar-blk: the storage data plane

## Overview

```
 guest virtio-blk (plaintext)
      │ DMA through the IOMMU into guest memory
 ┌────┴──────────────────────────────── oar-blk ─┐
 │ VirtioBlkFunction ─► RequestParser (bounds)   │
 │        │                                      │
 │        ▼                                      │
 │ XtsCipher(volume key, tweak = LBA) ◄─ KeySlot │◄── helm: deliver_key / drop_key
 │        │                                      │      (own sideband segment)
 │        ▼                                      │
 │ Backend: file (harbor) / NVMe (board)         │
 └───────────────────────────────────────────────┘
```

## Components

- **VirtioBlkFunction** — virtio-blk on the shared core; `VIRTIO_BLK_T_IN`,
  `T_OUT`, `T_FLUSH`, `T_GET_ID`; discard later.
- **RequestParser** — validates header, sector range against the volume
  size, and descriptor chain shapes before any I/O.
- **KeySlot** — holds at most one `ScopedKey`-equivalent; zeroizes on
  `drop_key`, FLR, detach, or process exit (`OPENSSL_cleanse`, locked
  memory, excluded from core dumps with `MADV_DONTDUMP`). The key page is
  also `MADV_WIPEONFORK`, so forked helpers never inherit it. A second
  `deliver_key` without a `drop_key` is refused and keeps the held key.
  `harden_process()` disables core dumps and ptrace for the whole role.
- **XtsCipher** — OpenSSL EVP `aes-256-xts`, 512-byte or 4 KiB data units.
  The tweak is the data unit number, little-endian (IEEE 1619): for 4 KiB
  units that is the 4 KiB block index, i.e. the 512-byte sector number
  divided by 8, fixed per volume at creation. Equal key halves are
  rejected. One cipher per I/O queue: it reuses its OpenSSL contexts.
- **Backend** — harbor: a sparse file per volume plus a metadata header
  (volume ID, owner VM, wrapped key, size). Board: NVMe via the board's
  root-complex controller.

## Placement notes

A storage board needs one PCIe controller in endpoint mode (backplane) and
one in root-complex mode (SSD). TI J721E-class SoCs fit; RK3588 does not at
useful speed. Throughput target for the first board: about Gen3 x2.

## Testing strategy

- XTS vectors; parser fuzzing; key zeroization checked with a test hook.
- harbor scenarios from Requirement 7.2, including grepping the backing
  file for a known plaintext pattern written by the guest.
