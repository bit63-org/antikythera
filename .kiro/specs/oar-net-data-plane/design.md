# Design Document — oar-net: the network data plane

## Overview

```
 guest A virtio-net     guest B virtio-net
      │ (VF, IOMMU-confined DMA)   │
 ┌────┴────────────────────────────┴─────────────────────── oar-net ─┐
 │  VirtioNetFunction[f]  ──frames──►  VSwitch  ◄── MappingTable      │
 │   (oar/virtio core)                 │   per-VNI tables, NIC→VF   │
 │                                     ▼                            │
 │                      Vtep: encode/decode (geneve.hpp)            │
 │                            ingress policy (vtep_policy.hpp)      │
 │                            OAM: keepalive, MTU probe             │
 │                      Tunnel: WireGuard (harbor) / ESP            │
 └──────────────────────────────┬───────────────────────────────────┘
                                ▼ IPv6/UDP underlay
```

## Components

### VirtioNetFunction

Built on the shared virtio core (`oar/virtio`): config space, common/notify/
ISR/device config capabilities, virtqueue (split ring first, packed later)
processing with all descriptor reads bounds-checked against registered DMA
regions. RX buffers are posted by the guest; TX frames are pulled and
handed to the VSwitch with the function's identity attached (that identity
is the trusted source NIC ID).

### VSwitch

Per VNI: `MAC → local function | remote (NicId, VTEP)`. Lookup on TX:
- local destination → copy into the destination function's RX queue;
- remote → Vtep encode with `{vni, src = own NicId, dst = remote NicId}`;
- broadcast/multicast → the VNI's group policy (see "Group policy and
  metering"): dropped by default; in an opted-in VNI, IP multicast goes to
  every local member except the sender plus once to each remote VTEP
  hosting the VNI (head-end replication), within the sender's rate limits;
- unknown → drop and count.
ARP/ND for known IPs answered from the mapping (proxy).

### Vtep

Uses `ak::oar::net::geneve::{encode,decode}` and `check_ingress` (both
written and fuzzed). UDP source port = hash(inner 5-tuple) folded into
49152–65535. OAM packets: keepalive every N seconds per peer; peers missing
K keepalives are reported to helm.

### MappingTable

Implements `MappingView`. Populated only by helm `map_update` messages
(versioned per VNI, applied atomically by swapping an immutable snapshot).

### Tunnel

Harbor and first release: WireGuard. Each VTEP's WireGuard peers are the
other VTEPs in shared VNIs. Keys come from helm. Geneve UDP rides inside.

### Group policy and metering

Requirement 10. Each VNI has a `GroupPolicy`: `mode` (`drop`, the
default, or `multicast`), per-source-NIC `rate_frames`/`burst_frames` and
`rate_bytes`/`burst_bytes`, and `max_remote_vteps`, the flood-list cap. A
`multicast` policy must set every limit; a `drop` policy carries none.
Phase 2 adds `max_groups_per_nic` and per-group VTEP lists.

Transmit, after the ARP/ND proxy has had the frame:

1. Admission by destination MAC. Admitted only in `multicast` mode, and
   only `01:00:5e` with the top bit of the fourth byte clear (IPv4
   multicast) or `33:33` except `33:33:ff` (IPv6 multicast other than
   solicited-node). Everything else, `ff:ff:ff:ff:ff:ff` included, is a
   `drop_policy`.
2. Flood list: the distinct other VTEPs owning a NIC in the VNI, from the
   same snapshot. More than `max_remote_vteps` drops the frame whole
   (`drop_fanout`), so a tenant cannot amplify by spreading out.
3. Rate: one token bucket per source NIC holds frame and byte credit in
   units of 1e-9 so refill (rate × elapsed ns) is exact integer math, is
   full on first use, and is capped at the burst. A frame needs one frame
   token and its length in byte tokens, else `drop_rate`. The limit is on
   the sender's frames; with the flood-list cap that bounds replicas.
4. Replicate locally and to each VTEP in the list, and meter it.

Receive: a packet for the broadcast NIC ID is delivered only if this
VTEP's policy for the VNI admits its inner destination MAC by rule 1;
otherwise `rx_drop_group`.

Meters (`GroupMeter`) are cumulative per NIC attachment: `frames`,
`bytes`, `replicas_remote`, `replica_bytes_remote` (the billable pair),
`replicas_local`, `replica_bytes_local`, `drop_policy`, `drop_rate`,
`drop_fanout`. Each attach gets a fresh meter and a new attachment
number, increasing within one oar-net run. On detach the final meter is
kept until the next `group_usage()` read, which returns every attached
NIC's meter and then the retired ones. Counters only grow, so the reader
computes deltas and a missed read loses nothing.

The policy arrives as a controller-signed `GroupPolicy` frame that helm
forwards unmodified over OarLink (`group_policy`), checked like
`map_update` (target server, key ID, Ed25519 signature, version newer
than the applied one). helm polls meters with `group_usage`.

## Data models

- `NicBinding { vni, mac, owner_vtep }` (written).
- `LocalNic { nic_id, function, vni, mac }`.
- Mapping snapshot: `std::shared_ptr<const Snapshot>` swapped atomically.

## Error handling

Data-path errors are counted and dropped, never propagated. Control-path
errors (bad `map_update`) are rejected whole, leaving the old snapshot.

## Testing strategy

- Unit/fuzz: codec and policy (done); VSwitch forwarding table; virtqueue
  parsing (fuzzed against hostile descriptors); group admission, rate
  limits against a fake clock, flood-list cap and meters, with the switch
  fuzzer checking that a `drop` VNI never replicates and that remote
  replicas never exceed frames × the flood-list cap.
- Interop: encode → kernel Geneve device decode, and the reverse, in a
  network namespace (CI-capable, no KVM needed).
- harbor: two and three servers, as listed in Requirement 9.3.
