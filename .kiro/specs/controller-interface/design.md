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

## Inventory and status reports

helm reports to the controller with `Report` frames
(`src/proto/report.hpp`): a 32-byte header (magic, format version, kind,
`server_id`, `report_seq`, `body_len`) and one body per kind.

| Kind | Body | Requirement |
|---|---|---|
| `inventory` | full snapshot: boot ID, last command sequence hull accepted, cores and 1 GiB pages (total, free), health, VTEPs, every function with type/state/owner, VMs, local volumes, networks with applied mapping version | 3.1, placement inputs |
| `command_outcome` | hull's response: command sequence and type, status, optional payload | 3.2 |
| `pool_state` | one device-pool transition (function, from, to, VM) | 3.2 |
| `vm_exited` | a VM exit hull did not cause | 3.2 |
| `map_applied` | VNI and mapping version oar-net swapped in | 3.2, 5.3 |
| `host_fault` | hull's fault code, slot and detail | 3.2 |

Reports are not signed. mTLS authenticates helm, and the controller only
trusts a server about that server (Requirement 3.3). The inventory is a
snapshot rather than a delta, for the same reason MapUpdate is: after a
reconnect or a helm reboot the controller replaces what it knew about the
server with the newest inventory, with nothing to replay. `boot_id` is fresh
on every helm boot, so the controller can tell a reconnect (same boot ID:
report sequence numbers continue) from a reboot (new boot ID: they restart).
`last_command_seq` tells the controller where its per-server command
sequence resumes (Requirement 2.3).

Every list in an inventory is in strictly increasing key order and bounded
(8 VTEPs, 1024 functions, 512 VMs, 1024 volumes, 4096 networks), so the
encoding is canonical and the largest report is under 128 KiB. A function
names an owner VM exactly when it is `assigned` or `releasing`. Enum values
are helm's (`FunctionType`, `FunctionState`) and the mailbox's (`Status`,
`ExitReason`, `FaultCode`), pinned by `tests/proto_report_test.cpp`.

## Link framing

The mTLS stream carries records (`src/proto/link.hpp`): `length u32 | type
u16 | reserved u16 | payload`. Controller to helm: `envelope`, `map_update`,
`report_ack` (`server_id u64 | report_seq u64`, acknowledging every report
up to that sequence). Helm to controller: `hello` (`server_id u64 | boot_id
u64`, the first record on every connection) and `report`. Report sequence
numbers restart when helm reboots, so the controller keys them by the
connection's boot ID and drops any `(boot_id, report_seq)` it has already
processed; that makes helm's replay after a reconnect idempotent. The framing only
delimits; each payload goes to its own strict decoder, and a record in the
wrong direction is a protocol error. A record header announcing more than
the largest frame (a full MapUpdate, about 128 KiB) ends the connection
before any payload is buffered.

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
