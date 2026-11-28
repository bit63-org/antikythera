# Design Document — Cold start after a power outage

## Overview

```
 AC power returns
   │
 helm boots from its flash ─ secure element: store key, monotonic
   │                          counters (store version, standing
   │                          generation, boot epoch)
   │ open sealed store: LKG UKI, standing set, power policy,
   │ time floor, last seq, network frames
   │
   │ wait tier_delay + slot × interval + jitter      (Req 3)
   │ power data-plane slots, one per 500 ms
   │ fill boot function with LKG UKI + provisioning file
   │   (server ID, boot epoch, last seq)              (Req 2, 6)
   ▼
 host UEFI ─ Secure Boot ─► hull ─ agent ready
   │
   │ helm → network role: stored frames for standing NICs   (Req 5)
   │ helm → oar-blk: ReplicaConfig + unwrapped volume keys  (Req 5)
   │ helm → hull: standing starts (signed set + index)      (Req 4)
   ▼
 pinned VMs running ── bootstrap tier forms quorums ── controller up
   │
 helm link up: cold_start report (27), inventory, boot_cache (28);
 controller adopts standing instances; envelopes resume
```

## Key design decisions

### helm boots from flash and owns the only persistent state

hull stays diskless and stateless: that is a security property worth
keeping. helm already runs before the host and holds the secure element,
so it is the natural place for the few things a server must remember
across power loss. Everything there is sealed under a key the secure
element derives, and the three counters that guard against rollback and
replay live in the secure element's monotonic counters, not in flash.

### Standing starts are verified by hull, not trusted from helm

helm is not trusted to start VMs on its own authority (`helm-control-
plane` Requirement 2: commands are signed by the controller). A standing
start is the controller's signed standing set plus an index, verified by
hull against the same compiled-in keys as any envelope. helm chooses
only when to deliver it. hull accepts standing starts only at the start
of a boot, before the first live envelope, so a compromised helm cannot
use an old set to start something the controller has since stopped while
the controller is talking to the server. The generation anchored in the
secure element stops a replay of an older set.

### Why a boot epoch

hull refuses replayed sequence numbers within a boot, but starts each
boot with no memory, so an envelope captured before a power cycle could
be replayed after it. The provisioning file is measured by hull, so
passing the last accepted sequence number there closes the gap without
giving hull a disk.

### Frames for standing NICs

Pinned instances talk to one another across tier-0 servers over VPC
tunnels, which need mapping, VPC configuration, security policy and
tunnel keys. All of these are already signed and versioned, so helm
keeps the newest verified copy for standing NICs and replays them to the
network role at boot exactly as it does on a sideband reopen. The
network role verifies them itself.

## Records

Numbers taken elsewhere: link types 17-18 (khold), 19
(`security_policy`), 20 (`edge_mapping`, internet gateways draft),
21-22 (`server-provisioning` draft), 30-35 (`fleet-scale-networking`
draft); report kinds 21-26 and 30-31 likewise. This spec takes link
types 23-24 and report kinds 27-28.

| Record | Direction | Body | Signed |
|---|---|---|---|
| `standing_set` (23) | controller → helm | `server_id u64 \| generation u64 \| time_floor u64 \| count u16 \| entries[] (instance launch body, volumes, NICs, wrapped secrets, image manifest digest) \| key_id u16 \| sig [64]` | yes, controller key |
| `power_policy` (24) | controller → helm | `server_id u64 \| version u64 \| tier u8 \| slot u16 \| tier_delay_s u16 \| slot_interval_ms u16 \| max_jitter_ms u16 \| keep_image [32] (zero = none) \| time_floor u64 \| key_id u16 \| sig [64]` | yes |

| Report | Kind | Body |
|---|---|---|
| `cold_start` | 27 | power-return time, time floor, waited ms, boot source, per standing instance: ID and result, store faults, rollback flag, assigned image unavailable flag |
| `boot_cache` | 28 | LKG and previous image digests, standing generation, policy version, store free bytes |

`standing_set` is large (it carries launch bodies and wrapped secrets);
it travels over the bulk path of `fleet-scale-networking` once that
exists, and in chunks over the link until then.

## Sealed store layout

A log-structured store in a flash partition: each object is
`name | version | nonce | ciphertext | tag`, appended; a superblock pair
points at the newest consistent set and carries the store version, which
must equal the secure element's monotonic counter. Garbage collection
copies live objects forward. Images are stored as chunk lists so the LKG
and previous image share unchanged chunks.

## Testing strategy

- Codecs: vectors and fuzz targets for 23, 24, 27, 28.
- Sealed store: power cut at every write step (file-backed flash with
  fault injection), rollback detection, corruption.
- helm state: standing starts before and after live envelopes,
  generations, an unpinning empty set.
- hull: standing-start acceptance rules; sequence floor from the
  provisioning file.
- Harbor AZ power loss with the controller absent (Requirement 9).

## Open questions

1. **Flash size.** 2 GiB holds two hull UKIs and a standing set
   comfortably; a board that also caches instance root images would need
   far more, which is why standing instances read images from their
   khold root volumes instead.
2. **Instance secret delivery.** Instance metadata is the only channel
   into a guest that helm does not need to be in the data path for;
   a virtio-vsock or a vTPM would be stronger but neither exists in hull
   today. As built (task 7): the guest reads
   `/latest/instance-secrets/` (names, one per line) and
   `/latest/instance-secrets/<name>` (the value's bytes) with an IMDSv2
   token, which is required there whatever the record's `http_tokens`,
   so a request relayed through a server-side request forgery cannot
   read one. The paths sit outside `/meta-data`, so tools that walk the
   metadata tree never log a secret.
