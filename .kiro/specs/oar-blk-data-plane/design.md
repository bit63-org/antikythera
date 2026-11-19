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

- **BlkRole** (`src/oar/blk/blk_role.*`) — the role's answer to helm's
  sideband (`helm::OarHandler`): volume files `vol-<id>.akv` in one
  directory, and a fixed set of functions, one per transport. A transport
  lives as long as the role (L0 QEMU attaches at boot), so what it serves
  changes: between attachments a placeholder (virtio-blk over an empty
  backend, never keyed), during one the volume's own `VirtioBlkFunction`.
  All of them have the same queues, hence the same PCI shape, which is
  what lets the vfio-user binding retarget without the client noticing.
  `prepare_function` opens the volume (owner checked against the header)
  and calls `await_key`; `clean_function` drops the key and puts the
  placeholder back; `delete_volume` closes a volume still open (a
  destroyed VM's) before erasing it, and a missing file counts as
  deleted so retries succeed; `rewrap_volume` refuses an open volume.
- **ak-oar-blk** (`oar_blk_main.cpp`, `-DAK_VFIO_USER=ON`) — the harbor
  process: one vfio-user socket per function, helm's sideband on a
  listening SOCK_SEQPACKET socket (re-listening if helm goes away), core
  dumps and ptrace off before anything is served.

## Volume lifecycle with helm

helm keeps the wrapped volume keys and the oar-blk role keeps the
volumes; the sideband connects the two (helm-control-plane design,
CommandRouter, for the full rules):

| Command | Before relay (undone on failure) | After hull's ok |
|---|---|---|
| CREATE_VOLUME | create the key; `create_volume` with the wrapped key on the lowest blk slot | — |
| ATTACH_VOLUME | reserve the function (on the volume's slot); `prepare_function` | unwrap, `deliver_key` |
| DETACH_VOLUME | — | release; cleaning drops the key and closes the volume |
| DELETE_VOLUME | — | destroy the key (crypto-erase), `delete_volume` |
| REWRAP_VOLUME | — | rewrap in the KeyStore, `rewrap_volume` |

The key follows hull's ok because hull answers once the VMM has opened the
function, and opening a VFIO device resets it: a key delivered earlier
would be wiped by that FLR. The guest may probe the disk in the gap, so
the function holds its requests until the key comes. A delivery that
fails is reported as a `device_lost` host fault (slot, volume ID) for the
controller to detach. CREATE_VOLUME carries no block size, so volumes are
created with 512-byte blocks; 4 KiB volumes need a body field.

Open: helm keeps wrapped keys only in memory, so after a helm restart it
must reload them from the media (`KeyStore::import_volume_key`); the
sideband has no request to list volumes and their wrapped keys yet.

## Placement notes

A storage board needs one PCIe controller in endpoint mode (backplane) and
one in root-complex mode (SSD). TI J721E-class SoCs fit; RK3588 does not at
useful speed. Throughput target for the first board: about Gen3 x2.

## Testing strategy

- XTS vectors; parser fuzzing; key zeroization checked with a test hook.
- harbor scenarios from Requirement 7.2, including grepping the backing
  file for a known plaintext pattern written by the guest.
