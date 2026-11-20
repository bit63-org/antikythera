# Requirements Document — harbor: the virt-on-virt prototype

## Introduction

harbor runs the whole system — host, control plane, data planes, guests,
and several servers talking over a datacenter network — as nested VMs and
processes on one Linux workstation with nested KVM. It exists so that every
protocol, lifecycle and isolation property is proven before any hardware is
designed, and so the same role code later runs on real boards unchanged.

### What this spec does not cover

- Performance: numbers from harbor are not meaningful.
- Physical-layer behaviour (link training, signal integrity).

## Glossary

- **L0** — the workstation. Runs QEMU, the board processes and test tooling.
- **L1** — a QEMU VM running the hull image: the "server".
- **L2** — Cloud Hypervisor guests inside L1: the "tenant VMs".
- **Board process** — a vfio-user server process standing in for a PCIe
  endpoint (control or data plane).

## Requirements

### Requirement 1: Host requirements

#### Acceptance Criteria

1. harbor SHALL run on x86-64 Linux with KVM and nested virtualization
   enabled; `harbor/check-host.sh` SHALL verify this and print what is
   missing.
2. harbor SHALL require QEMU ≥ 10.1 with `vfio-user-pci`; IF the installed
   QEMU lacks it THEN `harbor/deps.sh` SHALL build a pinned QEMU into a
   local prefix without touching the system.
3. A single-server run SHALL fit in 8 GiB RAM and 4 cores; the three-server
   run SHALL fit in 16 GiB and 8 cores.

### Requirement 2: Emulated backplane

#### Acceptance Criteria

1. L1 SHALL be a q35 machine with `intel-iommu` (interrupt remapping,
   caching mode, no device IOTLB) and split irqchip.
2. Each slot SHALL be an emulated PCIe port with ACS, by default a
   dedicated root port, with one board process attached through
   `vfio-user-pci`. An emulated-switch topology SHALL remain available. It
   is expected to fail the isolation checks, because QEMU's switch ports
   have no ACS.
3. Guest RAM SHALL be a shared memfd backend, as vfio-user requires.
4. Each slot's function SHALL land in its own IOMMU group in L1;
   `harbor/l1/phase1-check.sh` SHALL verify this, ATS disabled, and that a
   secondary bus reset reaches the board process.

### Requirement 3: Board processes

#### Acceptance Criteria

1. Every data-plane and control-plane role SHALL run in harbor as a board
   process using the same role code as hardware, with only the transport
   binding differing.
2. Each slot's sideband SHALL be its own Unix socket between the helm
   process and that board process.
3. The helm process SHALL start board processes before launching L1 QEMU
   (power sequencing).

### Requirement 4: Topologies

#### Acceptance Criteria

1. harbor SHALL support the combined placement (one board process serving
   the mailbox and NIC functions) and the split placement (separate board
   processes) from a topology file.
2. harbor SHALL support 1 to 3 servers, each in its own network namespace
   with a ULA IPv6 address, joined by a bridge acting as the datacenter
   network.

### Requirement 5: Phased bring-up

#### Acceptance Criteria

1. Phase 1: L1 boots with the emulated backplane and the test device;
   checks in Requirement 2.4 pass.
2. Phase 2: Cloud Hypervisor in L1 passes the test device to an L2 guest;
   MMIO, MSI-X, DMA fill and reset work from the guest; hot-plug and unplug
   work.
3. Phase 3: helm and hull run the mailbox lifecycle (`CREATE_VM`,
   `DESTROY_VM`, attach, detach) with signed commands.
4. Phase 4: oar-blk scenarios. Phase 5: oar-net single and multi-server
   scenarios. Phase 6: the strict hull image. Phase 7: fault injection and
   the GPU stand-in.

### Requirement 6: Automation

#### Acceptance Criteria

1. Every phase SHALL have a single command that sets up, runs its checks,
   and tears down, exiting non-zero on any failure.
2. Phases that need nested KVM SHALL be runnable on a self-hosted runner;
   everything that does not (unit tests, fuzzing, kernel Geneve interop)
   SHALL run in hosted CI.
