# Requirements Document — oar-gpu: GPU devices (designed, built later)

## Introduction

VMs must be able to gain and lose GPUs at runtime, without any GPU vendor
driver ever running on the host. This spec fixes the parts of the design
that are expensive to change later — protocol message types, device-pool
states, backplane provisions and the cleaning step — so that network and
storage can ship first without closing the door on GPUs.

### What this spec does not cover

- NVIDIA vGPU, Intel GVT-g or any model that needs a host GPU driver:
  excluded by the product's attack-surface goal.
- GPU-to-GPU peer-to-peer: conflicts with ACS isolation; out of scope.
- Physical GPU hot-add into a running server.

## Glossary

- **Whole GPU** — a GPU passed through entirely to one VM.
- **GPU VF** — an SR-IOV virtual function of a GPU, passed to one VM.
- **GPU manager VM** — an unprivileged VM owning a GPU's PF and running the
  vendor driver that configures and cleans its VFs.
- **Scrubber VM** — a short-lived VM that clears a whole GPU's memory.

## Requirements

### Requirement 1: No GPU drivers on the host

#### Acceptance Criteria

1. The host SHALL bind GPUs only to `vfio-pci`.
2. For SR-IOV GPUs, the PF SHALL be passed to a GPU manager VM, and the host
   SHALL only set `sriov_numvfs` using `vfio-pci`'s SR-IOV support and VF
   tokens.
3. The manager VM's PF driver SHALL provision VFs it did not create (it
   cannot call `pci_enable_sriov` on a passed-through PF), on request from
   helm over the VM channel.

### Requirement 2: Runtime attach and detach

#### Acceptance Criteria

1. GPUs and GPU VFs SHALL use the same `ATTACH_DEVICE` / `DETACH_DEVICE`
   flow as other functions (`hull-host-agent` Requirement 7).
2. The device-pool types `gpu_whole` and `gpu_vf` SHALL exist from the
   first protocol release (`helm-control-plane` Requirement 3.5).

### Requirement 3: Memory scrubbing between tenants

#### Acceptance Criteria

1. A GPU or GPU VF SHALL NOT return to `free` until its memory is cleared.
2. Whole GPUs SHALL be cleared by attaching them to a scrubber VM, then
   resetting them; GPU VFs SHALL be cleared by the manager VM's PF driver.
3. Completion SHALL be reported to helm with `SCRUB_DONE`.
4. helm SHALL verify each scrub by challenge-response over the VM channel
   (Requirement 6): a fresh random seed for the fill, coverage checked
   against the GPU model's or VF profile's qualified memory map, and
   randomly sampled pages, chosen only after the fill is reported, read back
   on a different path from the one that wrote them.
5. A `gpu_whole` function SHALL return to `free` only after both hull's
   `SCRUB_DONE` (scrubber exited cleanly and the final reset succeeded) and
   a verified scrub result; a `gpu_vf` only after a verified scrub result.
6. A failed or timed-out verification SHALL move the function to `faulted`.

### Requirement 4: Reset reliability

#### Acceptance Criteria

1. Only GPUs with a reliable reset (secondary bus reset or FLR) SHALL be
   admitted to the pool; a GPU failing reset SHALL go to `faulted`.

### Requirement 5: Backplane and host provisions

#### Acceptance Criteria

1. GPU-capable slots SHALL provide x16 lanes (Gen4 or later), 75 W slot
   power plus auxiliary power (300–600 W budget), per-slot power control,
   and cooling for dual-width cards.
2. Bridge windows SHALL reserve prefetchable 64-bit address space for GPU
   BARs (tens of GiB) even when the slot is empty; host firmware SHALL
   enable Above-4G decoding.
3. Cloud Hypervisor's 64-bit PCI aperture per guest SHALL be configurable
   to fit the largest assigned GPU.

### Requirement 6: VM channel and VM lifecycle

#### Acceptance Criteria

1. helm SHALL reach manager and scrubber VMs only through a `vm_channel`
   function: a virtio-vsock PCI function served by an oar board and relayed
   over its OarLink sideband. No GPU control traffic SHALL pass through the
   host.
2. The `vm_channel` function SHALL offer only `SOCK_STREAM` to one helm
   port, with fixed CIDs, and SHALL refuse every other connection.
3. `vm_channel` SHALL NOT be assignable by a controller `ATTACH_DEVICE`;
   hull SHALL attach it only to the manager and scrubber VMs it starts.
4. hull SHALL start one manager VM per SR-IOV GPU at boot, and a scrubber
   VM per released whole GPU, from images pinned in the hull image; neither
   needs a controller command.
5. helm SHALL parse every channel message with `ak::wire` into
   `std::expected`, with unit tests and a fuzz target.
