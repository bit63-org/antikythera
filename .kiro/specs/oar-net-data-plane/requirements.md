# Requirements Document — oar-net: the network data plane

## Introduction

oar-net gives each VM virtio-net NICs that can reach only the other NICs
in the same VPC, on this server or any other. Each NIC is a PCIe function
(an SR-IOV VF, or a whole single-function board) passed through to one VM.
Switching between local NICs happens inside the data-plane role; traffic to
other servers is Geneve over IPv6/UDP between VTEPs. Neither the host nor
the guest can influence which VPC a NIC belongs to.

### What this spec does not cover

- How the controller allocates VPCs and NIC IDs (`controller-interface`).
- Storage (`oar-blk-data-plane`).
- Routing or gateways out of a VPC (future; no uplink by default).

## Glossary

- **VPC** — a virtual network; identified on the wire by a 24-bit **VNI**.
- **NIC ID** — a controller-assigned 64-bit identifier, unique across all
  VPCs and servers, never reused. 0 is invalid; all-ones as a destination
  means broadcast within the VNI.
- **VTEP** — a tunnel endpoint; one per data-plane instance, with its own
  IPv6 address.
- **Dead VPC** — an internal, unroutable VPC holding every unassigned NIC.

## Requirements

### Requirement 1: virtio-net functions

**User Story:** As a tenant, I want a standard virtio-net NIC, so that my
guest needs no special driver.

#### Acceptance Criteria

1. Each NIC SHALL be a modern virtio-net PCI device with MSI-X, at least one
   RX/TX queue pair, and `VIRTIO_NET_F_MTU` and `VIRTIO_NET_F_MAC`.
2. The MAC address and MTU SHALL be set by helm and SHALL NOT be writable by
   the guest.
3. The NIC SHALL support FLR and SHALL return to a clean state (queues
   empty, features reset) after it.
4. The device logic SHALL be written once against the shared virtio core
   and bound to vfio-user (harbor) or `pci-epf` (hardware).

### Requirement 2: VPC isolation enforced in the data plane

**User Story:** As a tenant, I want my traffic to stay in my VPC even if
another tenant's guest or a NIC board is compromised.

#### Acceptance Criteria

1. A NIC's VPC, MAC and NIC ID SHALL come only from helm.
2. Frames from a guest SHALL be forwarded only within the NIC's VPC.
   Guest-supplied VLAN tags SHALL be treated as payload.
3. A frame whose source MAC differs from the NIC's assigned MAC SHALL be
   dropped.
4. An unassigned NIC SHALL be in the dead VPC, where it can reach nothing.
5. Forwarding SHALL use only controller-supplied mappings. The data plane
   SHALL NOT learn addresses from traffic. Unknown unicast SHALL be dropped.
6. ARP and IPv6 neighbor discovery for known addresses SHALL be answered
   locally from the mappings.

### Requirement 3: Geneve encapsulation between servers

**User Story:** As a tenant, I want VMs in my VPC on different servers to
reach each other as if on one network.

#### Acceptance Criteria

1. Traffic to a NIC on another VTEP SHALL be carried as Geneve (RFC 8926)
   over IPv6/UDP, destination port 6081.
2. The VNI SHALL be the global VPC ID; local identifiers SHALL never appear
   on the wire.
3. Every data packet SHALL carry exactly one NIC-pair option — option
   class `option_class`, type `0x81` (critical), 16 bytes: source NIC ID,
   destination NIC ID (big-endian) — and the C bit SHALL be set.
4. The sending VTEP SHALL fill the source NIC ID from the function the
   frame arrived on, never from guest data.
5. The UDP source port SHALL be a hash of the inner flow.
6. OAM-flagged packets SHALL be handled by the VTEP (keepalive, MTU probe)
   and never delivered to a guest.

### Requirement 4: Ingress validation

#### Acceptance Criteria

1. A receiving VTEP SHALL drop any packet that fails structural decode:
   non-zero version, Opt Len past the end, an unknown critical option, a
   critical option without the C bit, a missing or duplicate NIC-pair
   option, an invalid NIC ID, a non-Ethernet payload, or a short inner
   frame.
2. It SHALL drop any packet whose source NIC is unknown, in another VNI,
   owned by a VTEP other than the outer IPv6 source, or whose inner source
   MAC differs from that NIC's MAC.
3. It SHALL drop any packet whose destination is neither broadcast nor a
   local NIC in the same VNI with a matching inner destination MAC, and
   any broadcast whose inner destination MAC is not a group address.
4. Drops SHALL be counted per reason.

### Requirement 5: Authenticated underlay

**User Story:** As the operator, I want forged packets on the datacenter
network rejected, since Geneve itself has no authentication.

#### Acceptance Criteria

1. VTEP-to-VTEP traffic SHALL be carried inside WireGuard in harbor and
   the first release; IPsec ESP SHALL remain a supported option.
2. Tunnel keys SHALL be delivered by helm per peer; a data-plane role SHALL
   hold only its own keys.
3. A packet that fails tunnel authentication SHALL be dropped before Geneve
   decode.

### Requirement 6: MTU

#### Acceptance Criteria

1. The data plane SHALL compute the guest MTU from the underlay MTU minus
   encapsulation overhead (94 bytes for Geneve with the NIC-pair option:
   outer IPv6 and UDP, Geneve, the option, the inner Ethernet header and
   one guest VLAN tag; plus the tunnel's overhead) and advertise it through
   `VIRTIO_NET_F_MTU`.
2. With a 9000-byte underlay, guests SHALL get at least 1500.
3. The tunnel's overhead SHALL be budgeted as the larger of WireGuard (32
   bytes inside the VTEP's UDP datagram) and PSP in transport mode over
   UDP (48: UDP, PSP header, virtualization cookie, ICV), so moving a
   server pair from one to the other never changes a guest's MTU. With a
   9000-byte underlay guests get 8858.

### Requirement 7: Placements

#### Acceptance Criteria

1. Combined placement: the helm and oar-net roles share a board, with SR-IOV
   VFs as NICs and local switching inside the board.
2. Split placement: each oar-net board is its own VTEP. Traffic between two
   local boards SHALL take the encapsulated path.
3. Single-function boards (no SR-IOV) SHALL work as one NIC per board.

### Requirement 8: Lifecycle

#### Acceptance Criteria

1. Attach: helm assigns VPC, MAC and NIC ID, then programs mappings, then
   hull hot-plugs the function.
2. Detach: hull unplugs and resets; helm moves the NIC to the dead VPC;
   oar-net clears queues and state; only then is the function free.

### Requirement 9: Testing

#### Acceptance Criteria

1. The Geneve codec and ingress policy SHALL have unit tests and a fuzz
   target. _(Done for codec and policy.)_
2. The codec SHALL be cross-checked against the Linux kernel's Geneve
   device in a network namespace. _(Done: tests/geneve_interop.sh.)_
3. harbor SHALL verify cross-server reachability within a VPC, isolation
   between VPCs, rejection of forged VNIs and NIC IDs, and MTU behaviour.

### Requirement 10: Broadcast and multicast

**User Story:** As a tenant, I want a VPC that behaves like an AWS VPC by
default, with multicast available when I ask and pay for it; as the
operator, I want no tenant able to turn replication into an amplifier.

#### Acceptance Criteria

1. By default a VPC SHALL carry no broadcast or multicast: group-addressed
   frames that the ARP/ND proxy (Requirement 2.6) does not consume SHALL
   be dropped and counted. DHCP SHALL be answered locally (when built),
   not flooded.
2. A subnet (until subnets exist, a VPC) MAY be opted in to multicast by a
   controller-signed group policy delivered through helm. In an opted-in
   subnet, IPv4 and IPv6 multicast frames SHALL be replicated to the other
   local NICs in the VNI and once to each other VTEP hosting it, as
   unicast Geneve with the broadcast NIC ID (head-end replication).
   Broadcast, IPv6 solicited-node groups and every other group address
   SHALL still be dropped.
3. A receiving VTEP SHALL deliver a replicated frame only if its own
   policy for the VNI admits it, and SHALL count those it drops.
4. Replication SHALL be limited per source NIC by a frame rate and a byte
   rate with bounded bursts, and a frame SHALL be dropped whole when the
   VNI spans more remote VTEPs than the policy's flood-list cap. An
   opted-in policy without every limit SHALL be rejected.
5. Once oar-net parses IP: it SHALL snoop guest IGMPv2/v3 and MLDv1/v2
   membership, report joins and leaves through helm, cap the groups per
   NIC, and replicate a known group only to the VTEPs the controller lists
   for it, falling back to the whole subnet for unknown groups.
6. oar-net SHALL keep cumulative group counters per NIC attachment: frames
   and bytes accepted for replication, replicas and replica bytes sent to
   other VTEPs and delivered locally, and drops by cause (policy, rate,
   flood-list cap). It SHALL keep a detached NIC's final counters until
   helm has read them.
7. Policy changes SHALL apply atomically per VNI; a malformed or unsigned
   policy SHALL be rejected whole, leaving the previous one.

