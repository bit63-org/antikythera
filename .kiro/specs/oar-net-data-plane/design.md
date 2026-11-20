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
49152–65535; a pool of sockets on consecutive ports carries it, since an
ordinary UDP socket has one source port. OAM packets (`oam.hpp`, O bit
set, VNI 0, own Protocol Type): keepalive every N seconds per peer VTEP;
peers missing K keepalives are reported to helm through `PeerObserver`.
Peers are the other VTEPs of VNIs with a local NIC, from the mappings.
MTU (`mtu.hpp`): guest MTU = underlay MTU − 94 − tunnel overhead. The
Vtep drops anything over the planned payload and sends each peer a
full-size, unfragmentable OAM MTU probe every probe interval, so a peer
whose probes arrive is known to share a full-size path.

### MappingTable

Implements `MappingView`. Populated only by helm `map_update` messages
(versioned per VNI, applied atomically by swapping an immutable snapshot).
A `map_update` frame (format v2, `src/proto/map_update.hpp`) also lists
the guest IPv4 and IPv6 addresses each NIC owns; the role hands those to
`VSwitch::set_neighbors()` as that VNI's complete `NeighborUpdate`, after
the mapping itself is applied, so the ARP/ND proxy and the mapping always
come from the same signed frame.

### Tunnel

Harbor and first release: WireGuard. Each VTEP's WireGuard peers are the
other VTEPs in shared VNIs. Keys come from helm. Geneve UDP rides inside.

The protocol runs inside oar-net (`src/oar/net/wireguard.*` messages and
primitives over OpenSSL, `src/oar/net/tunnel.*` the state machine), not
through a kernel `wg` device: the role needs no CAP_NET_ADMIN, keeps its
keys in its own memory, and a forged packet is dropped before the Geneve
decoder sees it (Requirement 5.3). `Tunnel` is a `DatagramSender` between
the Vtep and the `UdpEndpoint`; `Tunnel::receive` returns only payloads
that authenticated, tagged with the configured address of the peer they
authenticated as, and that address (not the outer source) is what the
Vtep and the VSwitch's ingress policy check. A transport message carries
the Geneve UDP payload itself, unpadded; the handshake is WireGuard's and
interoperates with Linux (`tests/wireguard_interop.sh`). Overhead on top
of Geneve: 32 bytes (`wg::transport_overhead`). Keys arrive over the
sideband: `set_tunnel_key` (the role's static private key) and
`set_tunnel_peer` / `remove_tunnel_peer` (per peer VTEP: public key and
pre-shared key).

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
