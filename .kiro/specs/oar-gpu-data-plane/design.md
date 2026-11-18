# Design Document — oar-gpu: GPU devices (designed, built later)

## Overview

```
 whole GPU:   slot ─ vfio-pci ─► tenant VM
                       └─ on release: reset ─► scrubber VM clears VRAM ─► reset ─► free

 SR-IOV GPU:  PF ─ vfio-pci (enable_sriov) ─► GPU manager VM (vendor driver)
              VF[n] ─ vfio-pci ─► tenant VMs
                       └─ on release: FLR ─► manager VM clears VF ─► SCRUB_DONE ─► free
```

There is no GPU "board" in the data-plane sense: GPUs are commodity cards
in backplane slots. The **oar-gpu role** is a logical role inside helm that
drives the manager and scrubber VMs through ordinary `CREATE_VM` and
`ATTACH_DEVICE` commands to hull, plus `GPU_VF_CONFIG` forwarded to the
manager VM over a channel owned by helm (a dedicated small virtio
function from an oar board — never through the host).

## Decisions fixed now

| Item | Where |
|---|---|
| `Type::gpu_vf_config`, `Type::scrub_done` | `src/helm/mailbox.hpp` (reserved, already present) |
| Pool types `gpu_whole`, `gpu_vf`; cleaning = scrub | `helm-control-plane` design |
| x16 slots, power, address windows | `backplane-hardware` |
| No host GPU drivers | `hull-host-agent` Requirement 2.3 |

## Open questions (resolve before building)

- Which GPU families: AMD MxGPU class, or Intel Flex/Arc Pro class SR-IOV?
- Channel from helm to the manager VM: a virtio-vsock function from an oar
  board is the leading option.
- Scrub verification: how to confirm VRAM was cleared, not just commanded.
