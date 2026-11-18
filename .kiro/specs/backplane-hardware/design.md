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

## Open choices (decide after harbor phase 5)

- Combined helm+net board vs separate boards (both supported in software).
- Switch family and lane budget; connector family.
- First hardware for data-plane roles: TI J721E-class (SR-IOV endpoint,
  multiple controllers) for early boards; FPGA with an SR-IOV PCIe block
  for production NIC density.
