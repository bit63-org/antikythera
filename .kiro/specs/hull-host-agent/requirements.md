# Requirements Document — hull: the minimal host and its agent

## Introduction

hull is everything that runs on the server CPU outside the guests: a
stripped, immutable Linux kernel with KVM and VFIO, one small agent
process, and one jailed Cloud Hypervisor process per VM. Its job is to
partition CPU, memory, the IOMMU and interrupts, and to do exactly what
signed commands from the mailbox say — nothing more. It emulates no
devices, has no IP stack and loads no device drivers beyond `vfio-pci`.

### What this spec does not cover

- The mailbox wire format (`helm-control-plane`).
- Guest images and guest-side drivers.
- Confidential-VM support (out of scope; see product steering).

## Glossary

- **Agent** — `hull-agent`, the single privileged userspace process.
- **VMM** — a Cloud Hypervisor process, one per VM.
- **Jail** — the per-VMM confinement: own UID, namespaces, cgroup cpuset,
  Landlock ruleset, seccomp.
- **Inventory** — the fixed set of PCI functions enumerated at boot.

## Requirements

### Requirement 1: Immutable, measured host image

**User Story:** As the host's owner, I want the host software to be one
signed, measured artifact, so that what runs is exactly what was built.

#### Acceptance Criteria

1. The host SHALL boot from a single signed Unified Kernel Image (kernel,
   initramfs, command line) under UEFI Secure Boot with TPM measurement.
2. The root filesystem SHALL be the read-only initramfs; there SHALL be no
   persistent writable host filesystem.
3. Kernel module loading SHALL be disabled and kernel lockdown SHALL be in
   confidentiality mode.
4. The image SHALL contain no shell, no sshd and no package manager.

### Requirement 2: Minimal kernel

#### Acceptance Criteria

1. The kernel SHALL be built from `allnoconfig` plus a committed fragment
   (`harbor/kernel/hull.config` and per-arch fragments).
2. It SHALL include KVM, the IOMMU driver with interrupt remapping, VFIO
   and `vfio-pci` with SR-IOV support, IRQ bypass, PCIe port drivers,
   AER and DPC, a console, and `AF_UNIX`.
3. It SHALL NOT include `CONFIG_INET`, NIC drivers, USB, sound, GPU drivers,
   PCIe hot-plug (`pciehp`) or block filesystems beyond what the initramfs
   needs.
4. The command line SHALL enable the IOMMU in strict mode, disable ATS
   (`pci=noats`), reserve 1 GiB huge pages, and isolate guest cores.

### Requirement 3: The mailbox is read only through VFIO, with no DMA

**User Story:** As the host's owner, I want the host kernel never to parse
control-plane data, so that a compromised control plane meets only a
jailed, strict userspace parser.

#### Acceptance Criteria

1. The initramfs SHALL bind the mailbox function to `vfio-pci` by vendor
   and device ID before the agent starts.
2. The agent SHALL map BAR0 through VFIO and receive MSI-X via eventfd.
3. The agent SHALL create no DMA mappings in the mailbox's IOMMU domain.
4. The agent SHALL copy each slot out once, then decode it with
   `ak::helm::mailbox::decode`, then verify the signature and sequence
   number, then validate the body — rejecting at the first failure.

### Requirement 4: Signed commands only

#### Acceptance Criteria

1. The controller's Ed25519 public key(s) SHALL be compiled into the signed
   host image.
2. WHEN a command's signature does not verify THEN the agent SHALL reject
   it, respond with an error, and take no action.
3. Sequence numbers SHALL be strictly increasing; replays SHALL be rejected.

### Requirement 5: Device inventory and passthrough

**User Story:** As the controller, I want devices assigned to VMs by
passthrough only, so that the host never touches device data.

#### Acceptance Criteria

1. At boot the agent SHALL record the inventory and SHALL bind every
   data-plane function to `vfio-pci`.
2. The agent SHALL verify that every assignable function is alone in its
   IOMMU group and SHALL refuse to assign one that is not.
3. For SR-IOV data-plane boards the agent SHALL bind the PF to `vfio-pci`
   only to set `sriov_numvfs`, and SHALL create no DMA mapping for the PF.
4. The agent SHALL accept only functions from the boot inventory in any
   command.

### Requirement 6: VM lifecycle

#### Acceptance Criteria

1. `CREATE_VM` SHALL start one Cloud Hypervisor process in a fresh jail with
   dedicated whole cores (no SMT sibling shared with another VM), 1 GiB
   huge-page memory, no emulated virtio devices, and no OVMF.
2. The VM SHALL boot through `rust-hypervisor-firmware` (or direct kernel
   boot in harbor) from an attached volume.
3. `DESTROY_VM` SHALL kill the VMM, reset every function it held
   (secondary bus reset on the slot's downstream port, or VF FLR), and send
   one `DEVICE_RELEASED` event per function.
4. An unexpected VMM exit SHALL produce `VM_EXITED` and the same reset and
   release sequence.

### Requirement 7: Runtime attach and detach

#### Acceptance Criteria

1. `ATTACH_DEVICE` SHALL hot-plug a function into a running VM via the
   VMM's API socket (inside the jail).
2. `DETACH_DEVICE` SHALL request guest eject, wait up to the command's
   timeout, then apply the command's policy (`force` or `destroy_vm`).
3. After detach the function SHALL be reset and released exactly as in
   Requirement 6.3.

### Requirement 8: Resource accounting

#### Acceptance Criteria

1. The agent SHALL refuse `CREATE_VM` if cores or huge pages are
   insufficient, without partial allocation.
2. Host overhead SHALL be bounded and measured: at most one core and a
   documented amount of RAM for the agent and kernel.

### Requirement 9: Safety of the agent itself

#### Acceptance Criteria

1. The agent SHALL be built with the hardening flags and SHALL drop every
   capability it does not need after setup.
2. All agent parsers SHALL have unit tests and fuzz targets.

### Requirement 10: Portability

#### Acceptance Criteria

1. Architecture differences (IOMMU, interrupt posting, boot mode) SHALL be
   per-platform configuration; the agent code SHALL be identical on x86-64
   and arm64.
