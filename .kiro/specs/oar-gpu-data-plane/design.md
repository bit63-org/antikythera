# Design Document — oar-gpu: GPU devices (designed, built later)

## Overview

```
 whole GPU:   slot ─ vfio-pci ─► tenant VM
                       └─ on release: reset ─► hull starts scrubber VM, which clears
                          and proves VRAM to helm ─► hull destroys it, reset ─►
                          SCRUB_DONE + verified result ─► free

 SR-IOV GPU:  PF ─ vfio-pci (enable_sriov) ─► GPU manager VM (vendor driver)
              VF[n] ─ vfio-pci ─► tenant VMs
                       └─ on release: FLR ─► manager VM clears and proves VF
                          memory to helm ─► verified result ─► free

 helm ◄─ OarLink ─► oar board ─ vm_channel (virtio-vsock) ─► manager / scrubber VM
```

There is no GPU "board" in the data-plane sense: GPUs are commodity cards
in backplane slots. The **oar-gpu role** is a logical role inside helm. It
talks to the manager and scrubber VMs over a **VM channel**: a small
virtio-vsock function served by an oar board and relayed to helm over that
board's sideband, never through the host ("VM channel" below). hull starts
those VMs itself from fixed images, because helm cannot sign mailbox
commands ("Who starts the manager and scrubber VMs" below).

## Decisions fixed now

| Item | Where |
|---|---|
| `Type::gpu_vf_config`, `Type::scrub_done` | `src/helm/mailbox.hpp` (reserved, already present) |
| Pool types `gpu_whole`, `gpu_vf`; cleaning = scrub | `helm-control-plane` design |
| x16 slots, power, address windows | `backplane-hardware` |
| No host GPU drivers | `hull-host-agent` Requirement 2.3 |


## Resolved questions

Task 4 resolved the open questions below. The GPU family is a purchase
and vendor choice, so it is recorded as a recommendation for Clark to
confirm rather than a decision ("Needs Clark's choice").

### Q1. Which GPU families

Research (November 2026) found that both candidate SR-IOV GPU families
assume their PF driver runs in the hypervisor host:

- **Intel Arc Pro B-series (Battlemage, e.g. B50/B60).** The upstream
  `xe` driver binds the PF, enters "SR-IOV PF mode", and creates VFs when
  `sriov_numvfs` is written on its own PF. The PF then provisions each VF's
  GGTT, LMEM, GuC context IDs and doorbells through the GuC. Users report it
  working on Linux 6.17 or later, with current GuC/HuC/DMC firmware,
  SR-IOV, ARI and Above-4G/ReBAR enabled in firmware, and 12 VFs reported
  on a B50. The B50 has 16 GiB and a 70 W card power cap, so it runs on slot
  power alone. The driver is GPL and upstream, so we can carry a patch.
- **AMD MxGPU.** The GIM driver is the host PF driver (`modprobe gim`,
  host `amdgpu` blacklisted) and creates VFs itself at load (`vf_num`
  parameter). It supports Instinct MI210X, MI300X, MI325X, MI350X/MI355X and
  the Radeon PRO V710. It ships as an out-of-tree DKMS module. AMD has said
  desktop Radeon support may come later but gave no date. Instinct cards
  cost tens of thousands of dollars, and we found no retail listing for the
  V710.

Neither vendor supports our arrangement as shipped, which is hull creating
the VFs through `vfio-pci` (`enable_sriov` + VF token) while the PF
driver runs inside a manager VM. A guest cannot call `pci_enable_sriov` on a
passed-through PF, so the manager VM's PF driver must **provision VFs it
did not create**. Task 7 therefore needs a "provision-only" mode in the
vendor PF driver: skip `pci_enable_sriov` and provision VF *n* when helm asks
over the VM channel. That patch should be modest against `xe` (in tree, GPL, VF
provisioning is its own step after enabling) and larger against GIM (out of
tree, VF creation tied to module load). Its size is an estimate until task
7 tries it.

**Recommendation:** design and build against **Intel Arc Pro B-series**
first, with the B50 as the test card. It is the only family whose PF driver
we can patch in tree, it is by far the cheapest, and it fits
Requirement 5 without auxiliary power. Keep the
protocol vendor-neutral (VF profiles carry sizes, not vendor fields) so AMD
can follow once GIM supports a guest PF or a cheaper part. The whole-GPU
path (task 6) is family-neutral: any card with a reliable reset qualifies
(Requirement 4), and the B50 serves both paths.

If the provision-only patch proves unworkable, the fallback is whole-GPU
only. It needs no vendor PF driver anywhere and keeps Requirement 1.

### Q2. Channel from helm to the manager and scrubber VMs

**Decision: a virtio-vsock PCI function served by an oar board, built on
the shared virtio core (`oar/virtio`), relayed to helm over that board's
OarLink sideband.**

Alternatives considered:

| Option | Why not |
|---|---|
| Through hull's mailbox | The host would need a device inside the VM, and hull emulates none (product goal 1). It also puts an untrusted VM's bytes through the host. |
| VMM virtio-vsock (Cloud Hypervisor's own) | That is device emulation in the host VMM. Same objection. |
| A second helm PCIe function passed to the VM | It would give an untrusted VM MMIO access to helm, the trusted role. oar boards are already untrusted and contained, so a buggy channel there costs less. |
| virtio-console | The device model is a little simpler, but it has no connection semantics, so a manager agent restart is invisible. vsock gives a reset on reconnect, and Linux guests have the transport in tree. |

Profile, to keep the device side small:

- One function per manager or scrubber VM, guest CID fixed at 3 and peer CID
  2. `SOCK_STREAM` only, one listening port (the oar-gpu port). No
  `SEQPACKET`, no datagrams, no guest-initiated connections to any other
  port (refused with `RST`).
- Credit-based flow control as the virtio spec requires, with a small fixed
  buffer (64 KiB). Messages on the channel are at most 4 KiB.
- The oar board does not interpret the stream. It forwards bytes to helm
  with two new OarLink operations, `vm_channel_send` (helm→VM) and
  `vm_channel_poll` (helm reads queued VM bytes with an ack, like
  `hold_reports`), keyed by the channel function number.
- New function type `vm_channel` (wire value 5 in `helm::FunctionType` /
  `proto::FunctionType`, appended, never renumbering). It is **not** in the
  tenant pool: helm never assigns it on a controller `ATTACH_DEVICE`, and
  hull attaches it only to the VMs it starts itself (next section). Any oar
  board on the shared virtio core may serve it. oar-net is the default,
  since every host has one.
- Messages on the channel are framed (`type u16 | len u16 | body`),
  little-endian, parsed with `ak::wire` into `std::expected`, unit-tested and
  fuzzed. helm treats everything from the VM as untrusted input.

Channel messages (helm↔VM): `hello` (VM role, PF or GPU slot, driver and
firmware versions), `vf_provision` / `vf_unprovision` (from
`GPU_VF_CONFIG`), `scrub_begin`, `scrub_filled`, `scrub_challenge`,
`scrub_response`, `scrub_result` (Q3), and `fault` (the manager saw a GPU
error).

### Q3. Scrub verification

The goal is to show that the memory was **overwritten in this scrub**. A
commanded clear is not enough. Reading back zeros proves nothing on its own,
since an unmapped or already-zero range reads the same as a cleared one.
helm therefore runs a challenge-response over the VM channel:

1. **Seed.** helm sends `scrub_begin(fn, seed)` with a fresh 256-bit random
   seed.
2. **Fill.** The scrubber (whole GPU) or manager (VF) overwrites every
   tenant-reachable byte of the function's memory with the ChaCha20
   keystream of `seed`, indexed by byte offset, using the GPU's copy or
   compute engines. It then reports `scrub_filled(fn, bytes_covered,
   excluded ranges)`.
3. **Coverage check.** helm compares `bytes_covered` and the excluded ranges
   with the expected profile for that GPU model or VF profile, recorded at
   qualification (task 6/7). Excluded ranges are firmware carve-outs the
   tenant cannot write either, such as Intel's GSC/WOPCM regions or AMD's
   PSP TMR. Any mismatch fails the scrub.
4. **Challenge.** Only after `scrub_filled` does helm send
   `scrub_challenge(fn, sample_seed)`, which picks 4096 random 4 KiB pages.
   The VM reads those pages **through the BAR, on the CPU path** (not the
   engine that wrote them) and returns `scrub_response(fn, sha256(pages))`.
   helm recomputes the keystream for those pages and compares. Since the
   pages are chosen after the fill, a VM that skipped a fraction *f* of
   memory is caught with probability 1 − (1 − f)^4096: 98 % at f = 0.1 %,
   and almost certainly above that. The read is 16 MiB, well under a second.
5. **Zero.** The VM zero-fills the memory, which also re-initialises ECC,
   and verifies it on the GPU side. Then it sends `scrub_result(fn, ok)`.
6. **Reset.** Caches, registers and compression metadata are cleared by the
   reset that follows (whole GPU, below) or by the VF FLR that came before
   the scrub, plus the PF driver's VF re-provisioning.

Full-BAR CPU reads need ReBAR, which Requirement 5.2's address reservation
already provides. On a card whose BAR cannot map all of VRAM, the VM reads
challenged pages by copying them into the mapped window with the copy
engine. That weakens step 4 to "the engines agree", which is recorded per
model at qualification.

**What this does and does not prove.** It catches bugs, wrong sizes,
silently failed kernels and lazy implementations. It does not defend
against a malicious manager VM. A compromised manager already controls the
PF and can read any VF's memory at any time, so for VFs the manager is
inherently trusted for tenant isolation, and scrub verification cannot
change that. It matches the threat model, which lists manager VMs as
untrusted but contained: a compromised one cannot reach the host, other
GPUs or other VPCs, but the tenants of its own GPU's VFs depend on it.
The scrubber VM runs a fixed image that no tenant code ever runs in. GPU
firmware that lies is out of scope, like other physical-trust issues.

Failure at any step, or a timeout, sends the function `cleaning → faulted`
(`clean_failed`), and the existing power-cycle path then retries it.

### Q4. Who starts the manager and scrubber VMs (found while resolving Q2)

The old overview had helm drive these VMs "through ordinary `CREATE_VM`
and `ATTACH_DEVICE` commands to hull". That cannot work: every mailbox
command must carry a controller signature that hull verifies
(`controller-interface` Requirement 1), and helm holds no signing key.

**Decision: hull starts them itself, from inventory, with fixed images.**

- **Manager VM.** For each SR-IOV GPU in the host inventory
  (`host_setup`), hull starts one manager VM at boot. The VM gets the
  pinned manager image (content-addressed, part of the hull image), the PF,
  and one `vm_channel` function. hull also creates the VFs through
  `vfio-pci` with the VF token shared by the manager's VMM and the VF
  users. If the manager dies, hull restarts it and helm faults every VF of
  that GPU still in `cleaning`.
- **Scrubber VM.** When a `gpu_whole` function is released, hull resets it
  and sends `DEVICE_RELEASED` as for any function. It then starts the
  pinned scrubber image with that GPU and a `vm_channel` function, waits for
  the VM to exit, destroys it, resets the GPU again, and sends `SCRUB_DONE`.
  The result is `ok` only if the VM exited 0 and the final reset succeeded.
- **`SCRUB_DONE` meaning.** The mailbox `SCRUB_DONE` is hull's report on
  the whole-GPU scrubber run and final reset. helm moves a `gpu_whole`
  function to `free` only when **both** that `SCRUB_DONE` (ok) and its own
  verified `scrub_result` from Q3 have arrived. A `gpu_vf` is freed on the
  verified `scrub_result` alone, since hull plays no part after the FLR. At
  build time, helm counts a mailbox `SCRUB_DONE` for a `gpu_vf` as an
  inconsistency. The wire format is unchanged.
- **`GPU_VF_CONFIG`** stays a signed controller command relayed through
  the mailbox, so hull verifies it and applies the host side (the VF count
  through `vfio-pci`, allowed only while all of that GPU's VFs are `free`).
  After hull's `ok`, helm sends `vf_provision` to the manager over the VM
  channel. This follows the router's rule of creative steps before relay
  and destructive ones after hull's ok, applied as "host side first".

Trade-off: hull gains two fixed VM launches that no controller asked for.
They are limited to images baked into hull, functions it already
inventories, and the `vm_channel` type, which it never hands to tenant VMs.
The alternative, having the controller send a signed `CREATE_VM` per
scrub, would make GPU cleaning depend on the controller being reachable.
NIC and storage cleaning do not depend on it.

## Needs Clark's choice

| Choice | Options | Recommendation |
|---|---|---|
| First SR-IOV GPU family (a hardware purchase when tasks 6–7 start) | (a) Intel Arc Pro B-series (B50: about $350 at launch, 16 GiB, 70 W slot power); (b) AMD MxGPU (Instinct MI210+ or Radeon PRO V710: much higher cost, out-of-tree GIM); (c) whole-GPU only, no SR-IOV for now | **(a)**: upstream-patchable PF driver, cheapest, fits slot power. (c) is the fallback if the provision-only patch fails. |

Until Clark confirms, the spec builds the vendor-neutral parts (task 5,
the VM channel, the scrub protocol) and buys nothing.
