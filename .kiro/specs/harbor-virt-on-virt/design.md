# Design Document — harbor: the virt-on-virt prototype

## Overview

```
L0 workstation (nested KVM)
├── netns srv1 ── fd00::1 ─┐
│   ├── helm process (control plane, sideband sockets, power sequencing)
│   ├── board processes (ak-testdev / oar-net / oar-blk), vfio-user sockets
│   └── QEMU L1 (q35, intel-iommu, PCIe switch, vfio-user-pci per slot)
│         └── hull: kernel + agent + cloud-hypervisor
│               └── L2 guests
├── netns srv2 ── fd00::2 ─┤  (same shape)
└── br-dc  ◄───────────────┘  "datacenter network"
```

## QEMU topology (phase 1)

```
-machine q35,accel=kvm,kernel-irqchip=split,memory-backend=mem
-cpu host -smp 4 -m 4G
-object memory-backend-memfd,id=mem,size=4G,share=on
-device intel-iommu,intremap=on,caching-mode=on,device-iotlb=off
-device pcie-root-port,id=rp0,chassis=1,slot=0
-device x3130-upstream,id=sw0,bus=rp0
-device xio3130-downstream,id=slot0,bus=sw0,chassis=2,slot=0
-device '{"driver":"vfio-user-pci","bus":"slot0","socket":{"type":"unix","path":"…/slot0.sock"}}'
```

Fallback `TOPOLOGY=rootports` puts each slot on its own `pcie-root-port`
in case the emulated switch ports lack ACS and merge IOMMU groups. Which
one works is the first thing phase 1 measures.

L1 guest image for phases 1–5: a stock cloud image with cloud-init seed,
a debug kernel built from `harbor/kernel/l1-debug.config`, and Cloud
Hypervisor. Phase 6 replaces it with the strict hull UKI.

## Scripts

| Script | Purpose |
|---|---|
| `harbor/check-host.sh` | KVM, nested, QEMU version, `vfio-user-pci`, RAM/cores |
| `harbor/deps.sh` | builds pinned QEMU and libvfio-user into `harbor/.prefix` |
| `harbor/l1/run.sh` | launches one server from a topology file |
| `harbor/l1/phase1-check.sh` | runs inside L1: groups, ATS, ACS, reset |
| `harbor/phaseN.sh` | set up, check, tear down for phase N |

## Risks to retire early

1. Whether QEMU's vfio-user client works behind an emulated vIOMMU for
   nested passthrough to L2 (phase 1/2 answer this).
2. ACS on emulated switch downstream ports (topology fallback above).
3. Reset propagation from L1 through QEMU to the board process.
