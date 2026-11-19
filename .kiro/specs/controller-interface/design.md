# Design Document — Controller interface and the kythira EC2 integration

## Overview

```
 AWS CLI / SDK ──EC2 Query API──► kythira EC2 module (Raft, IAM, KMS/HSM)
                                     │ placement, ID allocation, signing
                                     │ mTLS management link
                                     ▼
                     helm (server 1) … helm (server N)
                         │ mailbox (signed slots)   │ sideband
                         ▼                          ▼
                        hull                       oars
```

## Envelope

```
Envelope {
  server_id    u64
  key_id       u16          // which controller key signed it
  slot         [256]byte    // exact mailbox slot image, signature included
}
MapUpdate {
  server_id u64, key_id u16, vni u32, map_version u64,
  entries [] { nic_id u64, mac [6], owner_vtep [16] },
  signature [64]            // Ed25519 over everything above
}
```

The byte layouts are in `src/proto/envelope.hpp` and
`src/proto/map_update.hpp` (little-endian, a magic and a format version
first). Both decoders are strict: exact length, non-zero server and key
IDs, zero reserved bytes. Encoders enforce the same rules, so the
controller cannot emit a frame helm would refuse. The codecs never sign or
verify; `src/proto/test_vectors.hpp` pins the exact bytes and signatures a
controller must produce under the RFC 8032 test keys.

A MapUpdate carries its own `key_id` (rotation, Requirement 1.3) and
`server_id`, both inside the signed bytes, since no slot header covers
them. It is a full snapshot of the VPC's mapping, not a delta, so applying
one is idempotent and a server that missed versions catches up from the
newest alone. Entries are in strictly increasing NIC ID order (a canonical
encoding with no duplicates), MACs must be locally administered unicast
(Requirement 4.2), owner VTEPs must be unicast IPv6 (IPv4-mapped allowed),
and a frame holds at most 4096 entries; a larger VPC needs a new format
version.

Open question: the envelope's `server_id` is not signed, and the slot
header has no server field, so a command signed for one server would
verify on another whose sequence floor is lower. Today only mTLS to the
right helm prevents that. Closing it means either a server ID in the slot
header (mailbox v3) or per-server signing keys.

`key_id` is carried in the slot header as well, so hull can pick the
verification key without trusting the envelope wrapper. Mailbox protocol
version 2 assigns it two of version 1's six reserved header bytes: a
little-endian u16 at slot offset 0x12, inside the signed range
`[0x00, 0xC0)`, followed by four reserved zero bytes. Commands must carry
a non-zero `key_id` (0 means "unsigned"); responses and events, which are
not signed, must carry 0. A slot that breaks either rule is rejected
before signature verification. The envelope's `key_id` must equal the
slot's; helm may check this, but hull trusts only the slot.

## Placement inputs

From inventory: free whole cores, free 1 GiB pages, free functions by type,
local volumes. The first placement policy: volumes pin the server; otherwise
most free cores.

## Sequencing RunInstances

```
controller                       helm                hull
  CREATE_VOLUME (root)  ───────►  oar-blk prepares
  CREATE_VM             ───────►  ───────────────────► start VMM (paused)
  ATTACH_VOLUME         ───────►  deliver key ───────► hot-plug blk fn
  ATTACH_DEVICE (NIC)   ───────►  set VPC/MAC/NIC ID ► hot-plug VF
  MAP_UPDATE (VPC peers)
  start                  ───────────────────────────► resume VM
```

Each step is acknowledged before the next; failure triggers the
controller's compensation (destroy in reverse order).

## Where the code lives

| Piece | Repository |
|---|---|
| Envelope and MapUpdate codecs, signing test vectors | antikythera `src/proto/` (header-only, consumable by kythira; done) |
| helm's ControllerLink | antikythera |
| EC2 API, placement, Raft state | kythira `services/ec2/` |
