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

L1 guest image for phases 1–5: the Ubuntu 24.04 server cloud image with
its stock kernel, configured by a cloud-init seed that adds
`intel_iommu=on iommu.strict=1 pci=noats` to the kernel command line and
reboots once. Phase 1 needs nothing the stock kernel lacks; a custom debug
kernel (`harbor/kernel/l1-debug.config`) is introduced only when a phase
needs one. Phase 6 replaces the image with the strict hull UKI.

Phase 1 reaches L1 over QEMU user networking with an SSH port forward on
127.0.0.1. That is debug scaffolding for phases 1–5 only.

## Phase 1 checks

Run inside L1 by `l1/phase1-check.sh`, with the device unbound so sysfs
`resource0` can be mapped directly:

| Check | How |
|---|---|
| IOMMU on, strict, ATS off | `/proc/cmdline`, `/sys/class/iommu` |
| N devices, distinct slot IDs | `lspci -d 1de5:a001`, BAR0 `SLOT_ID` |
| one IOMMU group per slot | `/sys/kernel/iommu_groups/<g>/devices` holds only that device |
| ATS not enabled; ACS on every upstream bridge | `lspci -vvv` |
| MMIO reaches the board | BAR0 magic `AKTD`, scratch write/read patterns |
| reset reaches the board | `RESET_COUNT` increments after sysfs `reset`; `phase1.sh` also checks the board process logged it |

DMA and MSI-X need a driver and are phase 2 (a VFIO test program in the
L2 guest).

## Scripts

| Script | Purpose |
|---|---|
| `harbor/check-host.sh` | KVM, nested, QEMU version, `vfio-user-pci`, tools, image, `ak-testdev`, RAM/cores |
| `harbor/deps.sh` | builds pinned QEMU and fetches the verified L1 image into `harbor/.prefix` (libvfio-user comes from vcpkg) |
| `harbor/l1/run.sh`, `stop.sh` | start/stop one server: board processes first, then QEMU |
| `harbor/l1/phase1-check.sh` | runs inside L1: groups, ATS, ACS, MMIO, reset |
| `harbor/phaseN.sh` | set up, check, tear down for phase N |

## Risks to retire early

1. Whether QEMU's vfio-user client works behind an emulated vIOMMU for
   nested passthrough to L2 (phase 1/2 answer this).
2. ACS on emulated switch downstream ports (topology fallback above).
3. Reset propagation from L1 through QEMU to the board process.
