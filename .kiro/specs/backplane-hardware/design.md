# Design Document — The physical backplane

## Overview

```
                 ┌──────────── host (x86-64, SEV-SNP/TDX capable) ────────────┐
                 │ root port(s)                          PERST#/power ◄──┐    │
                 └──────┬────────────────────────────────────────────────┼────┘
                        │ x16                                            │
                 ┌──────┴───── PCIe switch (ACS, DPC) ─────┐             │
                 │ DSP0     DSP1     DSP2 …       DSPn      │             │
                 └──┬────────┬────────┬────────────┬───────┘             │
                    │        │        │            │                     │
              [helm slot] [oar-net] [oar-blk] … [GPU x16]                │
                │  │  │                                                  │
   mgmt Eth ◄───┘  │  └── secure element                                 │
                   └── per-slot: PERST#, PWR_EN, PRSNT#, sideband mux ───┘
   refclk buffer ──► every slot
```

## Management fabric

```
            top-of-rack switch (ACLs, 3 queues)
          ┌──────────────┬──────────────────────┐
  control VLAN (access)  │  storage VLAN (access, re-mark CS6+ → AF11)
          │              │              │               │
   [helm mgmt port]  [oar-blk port] [hold port] …   object store
   CS6 controller     AF41 I/O       AF41 replication
   link, leases       AF11 hydrate   AF11 rebuild, scrub, upload
```

The storage network of block-volume-service is the management fabric
(Requirement 7). Each storage-capable data-plane slot brings out its own
port (Requirement 4.4), so storage bandwidth does not pass through the
helm board and a storage board's traffic never shares helm's segment.
Isolation is done where the board cannot touch it: access ports put each
board on exactly one VLAN, and the switch ACLs refuse storage-to-control
traffic. Inside the storage segment every session is mutually
authenticated TLS with controller-issued role certificates, so reaching
another storage role gains a compromised board nothing but ciphertext.

Traffic classes follow the block-volume design: control rides strict
priority (policed, so a buggy helm cannot starve storage either), and the
storage segment shares the rest between tenant I/O and background work.
The switch re-marks a storage-segment frame that claims the control
class, which is why helm's lease traffic stays protected even when a
board marks every packet CS6. harbor models the two segments as VLANs on
its management bridge; DSCP queueing there is `tc` on the bridge ports
and only needs to show that marking is applied, not reproduce switch
scheduling.

## Open choices (decide after harbor phase 5)

- Combined helm+net board vs separate boards (both supported in software).
- Switch family and lane budget; connector family.
- First hardware for data-plane roles: TI J721E-class (SR-IOV endpoint,
  multiple controllers) for early boards; FPGA with an SR-IOV PCIe block
  for production NIC density.
- Management port speed per slot (25 GbE floor on storage servers,
  Requirement 4.5) and whether storage boards share one uplink through a
  small on-backplane switch or each go to the top-of-rack switch.
