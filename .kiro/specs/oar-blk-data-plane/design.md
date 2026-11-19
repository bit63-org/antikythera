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
  `T_OUT`, `T_FLUSH`, `T_GET_ID`; discard later. A `virtio::Device` behind
  `PciFunction`, so both transports serve it as they serve virtio-net.
  Offers VERSION_1, ACCESS_PLATFORM, INDIRECT_DESC, EVENT_IDX, SIZE_MAX,
  SEG_MAX, BLK_SIZE, FLUSH, RO when read-only and MQ with several queues;
  `size_max` is `max_transfer_bytes / seg_max` (at least one page), so no
  request a driver builds exceeds the parser's transfer cap. Requests are
  served synchronously from a per-queue bounce buffer: writes copy guest
  plaintext once, encrypt in place and hand only ciphertext to the
  backend; reads decrypt in place, copy out and wipe. Without a key IN and
  OUT fail with IOERR. FLR (`function_reset`) and helm's `drop_key` wipe
  the key; a driver reset (status 0) does not, because the guest driver
  resets the device on every probe. helm therefore delivers the key after
  the VMM has opened (and reset) the function during attach.
- **RequestParser** — validates header, sector range against the volume
  size, and descriptor chain shapes before any I/O. It takes the readable
  and writable buffers of a chain the shared virtqueue already validated,
  so it does not depend on the virtio core. Lengths and start sectors
  must be whole logical blocks (512 B or 4 KiB, matching the XTS data
  unit); a request without a writable status byte cannot be completed
  and is left to the transport to treat as a broken chain.
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
  root-complex controller. `BlockBackend` is the seam: volume byte
  offsets, size, read, write, flush. The file header is one 4 KiB block
  so data stays aligned for both block sizes; the wrapped key is opaque
  to oar-blk (helm authenticates it on unwrap) and a SHA-256 over the
  fields catches corruption first. Delete is crypto-erase in helm plus
  `FileBackend::erase`, which overwrites the header, the file's only
  copy of the wrapped key, before unlinking.

## Placement notes

A storage board needs one PCIe controller in endpoint mode (backplane) and
one in root-complex mode (SSD). TI J721E-class SoCs fit; RK3588 does not at
useful speed. Throughput target for the first board: about Gen3 x2.

## Testing strategy

- XTS vectors; parser fuzzing; key zeroization checked with a test hook.
- harbor scenarios from Requirement 7.2, including grepping the backing
  file for a known plaintext pattern written by the guest.
