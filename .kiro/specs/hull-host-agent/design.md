# Design Document — hull: the minimal host and its agent

## Overview

```
UEFI Secure Boot ─► UKI (kernel + initramfs + cmdline, measured into TPM)
                       │
                  /init (initramfs)
                    ├─ bind mailbox + all data-plane functions to vfio-pci
                    ├─ record inventory, check IOMMU groups
                    └─ exec hull-agent
                              │
     ┌────────────────────────┼─────────────────────────────┐
     │ MailboxClient          │ VmSupervisor                │
     │  VFIO BAR0 mmap        │  per VM: jail + cloud-      │
     │  MSI-X eventfd         │  hypervisor + API socket    │
     │  decode→verify→validate│  attach/detach/reset        │
     └────────────────────────┴─────────────────────────────┘
```

## Components

### Init

A small static C++ binary (not a shell script — there is no shell). Steps:
mount `/proc`, `/sys`, `/dev`, hugetlbfs; write `driver_override` for each
function in the inventory allow-list; bind to `vfio-pci`; walk
`/sys/kernel/iommu_groups` and fail closed on a shared group; exec the
agent.

### MailboxClient

- Opens the mailbox's VFIO group/device, maps BAR0 read-write, sets up one
  MSI-X vector with an eventfd. No `VFIO_IOMMU_MAP_DMA` is ever issued.
- On doorbell: `memcpy` the 256-byte slot with 32-bit MMIO reads into a
  local `Slot`, then `decode` → `verify(signature, controller_keys)` →
  sequence check → body decode → dispatch.
- Responses and events are encoded into local buffers and written with
  MMIO, then the doorbell is written.

### SignatureVerifier

OpenSSL EVP Ed25519 verify over slot bytes `[0, 0xC0)`. Public keys are a
compiled-in table (supports rotation: up to N keys, selected by the
`key_id` field of the signed slot header, mailbox protocol v2 — see
`controller-interface`).

### VmSupervisor

Per VM: allocate cores (cpuset) and huge pages, create the jail
(`clone3` with new user/pid/mount/ipc namespaces, Landlock allowing only
`/dev/kvm`, the VM's `/dev/vfio/<group>` nodes and its API socket path),
exec `cloud-hypervisor` with:

```
--cpus boot=N --memory size=M,hugepages=on,hugepage_size=1G
--firmware rust-hypervisor-firmware   (or --kernel in harbor)
--device path=/sys/bus/pci/devices/<bdf>   (one per function)
--api-socket path=<jail>/api.sock --serial off --console off
--seccomp true
```

Attach/detach use Cloud Hypervisor's `vm.add-device` / `vm.remove-device`
over the API socket.

### Reset

- Whole-slot functions: secondary bus reset through the downstream port's
  bridge control register (via sysfs `reset_method=bus` on the device).
- VFs: FLR (`reset_method=flr`).
- After reset: `DEVICE_RELEASED {function}` event to helm.

## Error handling

Every command produces exactly one response. Partial failures roll back
(kill VMM, release cores and pages, reset functions). The agent never
blocks the mailbox while a VM boots: long operations respond `accepted`,
then emit a completion event.

## Testing strategy

- Unit: verifier (known vectors), body validation, resource allocator.
- Fuzz: whole MailboxClient path from slot bytes.
- harbor: phase 2 (passthrough of the test device to an L2 guest), then
  full lifecycle loops; measure host overhead.
