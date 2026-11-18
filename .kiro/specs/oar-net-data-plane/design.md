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
- broadcast/multicast → every local member except the sender, plus
  head-end replication to each remote VTEP hosting the VNI;
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

## Data models

- `NicBinding { vni, mac, owner_vtep }` (written).
- `LocalNic { nic_id, function, vni, mac }`.
- Mapping snapshot: `std::shared_ptr<const Snapshot>` swapped atomically.

## Error handling

Data-path errors are counted and dropped, never propagated. Control-path
errors (bad `map_update`) are rejected whole, leaving the old snapshot.

## Testing strategy

- Unit/fuzz: codec and policy (done); VSwitch forwarding table; virtqueue
  parsing (fuzzed against hostile descriptors).
- Interop: encode → kernel Geneve device decode, and the reverse, in a
  network namespace (CI-capable, no KVM needed).
- harbor: two and three servers, as listed in Requirement 9.3.
