# Design Document — harbor: the virt-on-virt prototype

## Overview

```
L0 workstation (nested KVM)
├── netns srv1 ── fd00::1 ─┐
│   ├── helm process (control plane, sideband sockets, power sequencing)
│   ├── board processes (ak-testdev / oar-net / oar-blk), vfio-user sockets
│   └── QEMU L1 (q35, intel-iommu, a PCIe root port and vfio-user-pci per slot)
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
-device pcie-root-port,id=slot0,chassis=2,slot=0
-device '{"driver":"vfio-user-pci","bus":"slot0","socket":{"type":"unix","path":"…/slot0.sock"}}'
```

The default topology (`--topology rootports`) puts each slot on its own
`pcie-root-port`. The opt-in `--topology switch` puts the slots behind an
emulated switch (`x3130-upstream` on a root port, one `xio3130-downstream`
per slot), which is closer to a real backplane. Phase 1 measured both on
QEMU 10.2.1 (2026-11-18): the emulated switch downstream ports expose no
ACS capability, so each endpoint shares an IOMMU group with its port and
the switch topology fails the group checks; rootports passes every check.
That is a limit of the emulated hardware, not of the vfio-user client.

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

## Phase 2: passthrough to L2

```
L0  ak-testdev (slot N) ◄── vfio-user ── QEMU vfio-user-pci ── intel-iommu
L1  vfio-pci (type1, through the vIOMMU) ── Cloud Hypervisor v54.0
L2  vfio-pci (no-IOMMU) ── ak-guest-testdev
```

`phase2.sh` boots L1 exactly as phase 1 does, then `l1/phase2-check.sh`
binds every test device to `vfio-pci` in L1 and boots an L2 guest with all
but the last. Cloud Hypervisor maps all of L2's RAM into L1's vfio
container, so L1's intel-iommu holds those mappings and QEMU forwards each
one to the board process as a vfio-user DMA region.

The L2 guest is L1's own kernel, decompressed to the ELF `vmlinux` Cloud
Hypervisor boots through PVH, and a busybox initramfs with the vfio
modules and `ak-guest-testdev` (`l1/l2-image.sh`). Nothing beyond L1's
packages is downloaded, and it boots in seconds even two levels down.
L2 has no IOMMU, so vfio runs in no-IOMMU mode there and the guest program
gives the device guest-physical addresses from `/proc/self/pagemap`; those
are the IOVAs L1's vIOMMU translates, so the full translation path is
still exercised. (With a type1 group the program maps a fixed IOVA
instead, for later phases that give L2 a virtio-iommu.)

| Check | How |
|---|---|
| MMIO from L2 | magic, version, `SLOT_ID` matches the slot L1 read before binding, scratch patterns |
| MSI-X from L2 | each vector's `IRQ_DOORBELL` write arrives on its eventfd within 2 s, no other vector fires |
| DMA from L2 | 4 KiB fill lands in the guest buffer; a 512-byte fill writes exactly 512 bytes; length 0 reports an error |
| reset from L2 | `VFIO_DEVICE_RESET` increments `RESET_COUNT` and clears `SCRATCH`; L0 sees the board process log it |
| hot-plug | `ch-remote add-device`; the guest finds the new function, passes every check above on it |
| unplug | `ch-remote remove-device`; the guest sees it go, L1 has it back on `vfio-pci`, Cloud Hypervisor exits 0 on guest poweroff |

The guest reports through `L2: ` marker lines on its serial console; the
L1 script watches for them to sequence the hot-plug. Measured on tikhov
(2026-11-19, QEMU 10.2.1, Ubuntu 24.04 L1 kernel 6.8): every check passes.

Two board-process defects surfaced on the way, both fixed:

- **DMA region cap.** Behind a vIOMMU QEMU registers one vfio-user DMA
  region per IOMMU mapping, so L2's 512 MiB arrives as 256 regions of
  2 MiB. `ak-testdev` and the shared `VirtioBinding` allowed 64; both now
  allow 65536 (the cap only stops a runaway client).
- **DMA by command.** `vfu_sgl_write` sends the data to the client as a
  vfio-user command; the client is at that moment blocked on the BAR0
  write that started the fill, and the two messages collide on the single
  socket. `ak-testdev` now writes through a local mapping (`vfu_sgl_get`),
  as a DMA engine would.

## Scripts

| Script | Purpose |
|---|---|
| `harbor/check-host.sh` | KVM, nested, QEMU version, `vfio-user-pci`, tools, image, `ak-testdev`, RAM/cores |
| `harbor/deps.sh` | builds pinned QEMU and fetches the verified L1 image into `harbor/.prefix` (libvfio-user comes from vcpkg) |
| `harbor/l1/run.sh`, `stop.sh` | start/stop one server: board processes first, then QEMU |
| `harbor/l1/phase1-check.sh` | runs inside L1: groups, ATS, ACS, MMIO, reset |
| `harbor/l1/phase2-check.sh` | runs inside L1: vfio-pci binding, L2 boot, guest checks, hot-plug and unplug |
| `harbor/l1/l2-image.sh` | runs inside L1: builds the L2 kernel and initramfs from L1's own |
| `harbor/phaseN.sh` | set up, check, tear down for phase N |

## Risks to retire early

1. Whether QEMU's vfio-user client works behind an emulated vIOMMU for
   nested passthrough to L2. Retired by phase 2: MMIO, MSI-X, DMA and
   reset all work from L2, and so do hot-plug and unplug.
2. ACS on emulated switch downstream ports. Retired: QEMU 10.2.1's
   xio3130 ports lack it, so phase 1 defaults to root ports (see above).
3. Reset propagation from L1 through QEMU to the board process. Retired:
   phase 1 resets from L1, phase 2 from L2.
