# Implementation Plan — hull: the minimal host and its agent

## Status: 5/11 tasks complete

## Tasks

- [x] 1. Kernel config fragment for harbor L1 (permissive: includes IP for
  debugging) and the target `hull.config` (strict). _Requirements: 2_ —
  `harbor/kernel/`: `hull.config`, `x86_64.config`, `l1-debug.config`,
  `build.sh` (allnoconfig + fragments) and `check-config.py`, which
  checks the resolved .config against the fragments and Requirements
  2.2/2.3. CI resolves both variants against Ubuntu's linux-source-6.8.0
  and builds the strict kernel, which boots under QEMU (TCG) to the
  missing-init panic with the IOMMU in strict mode and VFIO loaded. The
  2.4 command line comes with the UKI (task 10).
- [x] 2. Phase-1 check script for L1: IOMMU groups, ATS state, ACS on
  ports, reset reaching the device server. `harbor/l1/phase1-check.sh`
  (harbor task 4); passes on nested KVM with the `rootports` topology
  (2026-11-18).
  _Requirements: 5.2_
- [ ] 3. Init binary: mounts, `vfio-pci` binding by allow-list, IOMMU group
  check. _Requirements: 3.1, 5.1, 5.2_
- [ ] 4. MailboxClient over VFIO (BAR0 mmap, MSI-X eventfd, no DMA).
  _Requirements: 3_
- [x] 5. SignatureVerifier (OpenSSL Ed25519) and sequence tracking.
  _Requirements: 4_ — `src/hull/`: `SignatureVerifier`, `SequenceTracker`
  and `authenticate()` (decode, signature, sequence). The compiled-in key
  table arrives with the agent binary (task 3); `authenticate()` takes the
  key ID from the signed slot header (mailbox protocol v2).
- [x] 6. Resource allocator: cores (whole, SMT-aware) and 1 GiB pages.
  _Requirements: 6.1, 8.1_ — `src/hull/`: `CpuTopology` (strict cpulist
  parser, fuzzed; sysfs SMT siblings, isolated CPUs, free 1 GiB pages) and
  `ResourceAllocator` (whole cores, only cores fully in the isolated set,
  memory rounded up to whole GiB, refusal without partial allocation).
  Not NUMA-aware yet: one pool of cores and pages.
- [x] 7. Jail construction (namespaces, cgroup, Landlock, UID).
  _Requirements: 6.1, 9.1_ — `src/hull/`: `spawn_jailed()` (clone3 into
  new user/PID/mount/IPC/net/UTS/cgroup namespaces, a 1:1 map of the VM's
  own UID/GID from `UidPool`, fresh `/proc`, Landlock ruleset built in the
  parent from the spec's path rules with TCP denied and abstract sockets
  and signals scoped where the ABI allows, every capability set emptied,
  no_new_privs, no core dumps, RLIMIT_MEMLOCK set from outside for VFIO
  pinning, a clean environment; a failing child step is reported with its
  errno) and `VmCgroup` (per-VM cgroup v2 node with cpuset, hugetlb.1GB,
  pids and memory limits from the `Allocation`, entered atomically with
  CLONE_INTO_CGROUP). Tested by running a probe inside real jails, as root
  in CI and unprivileged in ctest. The VmSupervisor (task 8) composes them
  with the Cloud Hypervisor arguments; seccomp stays Cloud Hypervisor's own.
- [ ] 8. VmSupervisor: create/destroy with Cloud Hypervisor; reset and
  `DEVICE_RELEASED`. _Requirements: 6_
- [ ] 9. Attach/detach via the VMM API socket with eject timeout policy.
  _Requirements: 7_
- [ ] 10. UKI build, Secure Boot signing and measured boot in harbor (OVMF
  with Secure Boot at L0). _Requirements: 1_
- [ ] 11. Host overhead measurement and documentation. _Requirements: 8.2_
