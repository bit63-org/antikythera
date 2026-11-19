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
cmake -B build -G Ninja -DAK_VFIO_USER=ON && cmake --build build   # builds build/src/ak-testdev
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

## Test controller

`ak-test-controller` (built from `src/harbor/`) stands in for kythira's EC2
module until it exists: it listens for one server's helm over mutually
authenticated TLS, waits for it to register, then runs a script of signed
commands, mapping updates and expectations, printing every report helm
sends. Phases 3 to 5 drive the system with it.

```bash
openssl genpkey -algorithm ed25519 -out controller-ed25519.pem   # its public key goes in hull's key table
ak-test-controller --listen 0.0.0.0:7443 \
    --ca server-ca.pem --cert controller.pem --key controller-key.pem \
    --signing-key controller-ed25519.pem --key-id 1 --server-id 7 \
    --script phase3.txt
```

```text
# phase3.txt
create-network 0x55
expect ok
create-vm 0x1001 2 1024
expect accepted
map-update 0x55 1 0x10,02:00:00:00:00:10,fd00::1
wait map_applied
```

Command sequence numbers start after the `last_command_seq` in helm's
inventory, as the real controller's do. The full script language is in
`src/harbor/test_controller.hpp`. Exit status 0 means every line passed,
1 that one failed (its line number is printed), 2 a usage or setup error.

## Layout

| Path | Purpose |
|---|---|
| `lib.sh` | shared paths, pins and helpers |
| `check-host.sh` | prerequisites check; reports every problem at once |
| `deps.sh` | pinned QEMU build and verified L1 image download |
| `l1/run.sh`, `l1/stop.sh` | start and stop one server (board processes, then QEMU) |
| `l1/phase1-check.sh`, `l1/testdev_mmio.py` | the checks that run inside L1 |
| `phase1.sh` | phase 1 end to end |
| `kernel/` | hull kernel fragments (strict `hull.config`, per-arch, `l1-debug.config`), resolver and checker; see [`kernel/README.md`](kernel/README.md) |
