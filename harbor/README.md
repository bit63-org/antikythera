# harbor

The virt-on-virt prototype: the whole antikythera system as nested VMs and
processes on one Linux workstation with nested KVM. See
[`.kiro/specs/harbor-virt-on-virt/`](../.kiro/specs/harbor-virt-on-virt/).

## Phase 1: the emulated backplane

Prerequisites (one time):

```bash
sudo apt-get install cloud-image-utils openssh-client ninja-build meson pkg-config \
    libglib2.0-dev libpixman-1-dev libslirp-dev python3-venv flex bison
harbor/deps.sh            # pinned QEMU 10.2.4 + verified Ubuntu 24.04 image into harbor/.prefix
vcpkg install --x-feature=vfio-user
cmake -B build -G Ninja && cmake --build build   # builds build/src/ak-testdev
harbor/check-host.sh
```

Run:

```bash
harbor/phase1.sh                       # 2 slots, one PCIe root port each
harbor/phase1.sh --topology switch     # opt-in: slots behind an emulated PCIe switch
harbor/phase1.sh --keep                # leave L1 running to poke at it
```

Phase 1 boots one L1 server with N `ak-testdev` board processes, then
checks inside L1:

- IOMMU on, strict, ATS off
- one IOMMU group per slot
- ACS on every bridge above each slot
- MMIO reaching each board process
- a function reset reaching each board process

It exits non-zero on any failure. On failure the logs stay in
`harbor/.run/phase1/`: the board processes' `slot*.log`, L1's
`console.log`, and the exact `qemu.cmdline`.

## Layout

| Path | Purpose |
|---|---|
| `lib.sh` | shared paths, pins and helpers |
| `check-host.sh` | prerequisites check; reports every problem at once |
| `deps.sh` | pinned QEMU build and verified L1 image download |
| `l1/run.sh`, `l1/stop.sh` | start and stop one server (board processes, then QEMU) |
| `l1/phase1-check.sh`, `l1/testdev_mmio.py` | the checks that run inside L1 |
| `phase1.sh` | phase 1 end to end |
