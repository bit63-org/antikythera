# Implementation Plan — hull: the minimal host and its agent

## Status: 9/11 tasks complete

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
- [x] 3. Init binary: mounts, `vfio-pci` binding by allow-list, IOMMU group
  check. _Requirements: 3.1, 5.1, 5.2_ — `src/hull/init_main.cpp`
  (`hull-init`) over `src/hull/host_setup.*`: mounts `/proc`
  (`hidepid=2`), `/sys`, `/dev`, `/run`, 1 GiB hugetlbfs and cgroup v2
  with the VM controllers on; reads the allow-list `/etc/hull/hull.conf`
  from the signed initramfs (the mailbox's PCI ID, one line per slot
  naming its downstream port, function type and PCI ID, and where the
  server ID comes from); finds the mailbox (exactly one) and each slot's
  functions in sysfs, numbered per slot in address order, VFs reset by
  FLR and the rest by bus reset; binds each to `vfio-pci` and checks the
  binding took; requires each, the mailbox included, to be alone in its
  IOMMU group; writes `/run/hull/inventory` and execs `hull-agent`. Any
  failure exits, which as PID 1 panics the kernel. `src/hull/agent_main.cpp`
  (`hull-agent`) loads the compiled-in controller keys (CMake cache
  variable `AK_HULL_CONTROLLER_KEYS`; it refuses to start with none),
  the inventory and the CPU and huge-page resources, creates the VM
  cgroup parent, maps the mailbox, drops every capability but the seven
  it needs to run jails (`capabilities.*`, Requirement 9.1) with
  no_new_privs, sends `HOST_FAULT agent_restarted` and runs the poll
  loop over the MSI-X eventfd and the VMMs' pidfds. Tested over a fake
  sysfs tree, including `hull-init` end to end with a stand-in agent
  (`tests/host_setup_test.cpp`) and the capability drop in a child;
  parsers fuzzed by `fuzz_host_config`. Not yet: creating SR-IOV VFs
  from the PF (Requirement 5.3), which waits for a board that needs it;
  today the VFs must exist before init runs.
- [x] 4. MailboxClient over VFIO (BAR0 mmap, MSI-X eventfd, no DMA).
  _Requirements: 3_ — `src/hull/`: `MailboxClient` (doorbell check, one
  copy of `CMD_SLOT` with 32-bit reads, `authenticate()`, body decode,
  `CommandHandler`, exactly one response written in full before
  `RSP_DOORBELL`; refusals answer `malformed`, `wrong_server`, `bad_signature`,
  `stale_sequence` or `unsupported`, and only a slot naming no command
  type goes unanswered; events through `send_event`). The doorbell
  baseline is taken at `attach()`, so a command left in the slot from
  before an agent restart is never re-run. `VfioMailbox` opens the group
  in a type1 container with an empty IOMMU domain (no `MAP_DMA`), maps
  BAR0 (pread/pwrite when it cannot be mapped), enables memory space and
  bus mastering for the MSI-X write, and wires vector 0 to an eventfd.
  Tested end to end against helm's `MailboxDevice`; fuzzed from slot
  bytes. The real-VFIO path runs in harbor.
- [x] 5. SignatureVerifier (OpenSSL Ed25519) and sequence tracking.
  _Requirements: 4_ — `src/hull/`: `SignatureVerifier`, `SequenceTracker`
  and `authenticate()` (decode, server ID, signature, sequence). The
  compiled-in key table arrives with the agent binary (task 3);
  `authenticate()` takes the key ID and server ID from the signed slot
  header (mailbox protocol v3) and the agent's own server ID as an
  argument.
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
- [x] 8. VmSupervisor: create/destroy with Cloud Hypervisor; reset and
  `DEVICE_RELEASED`. _Requirements: 6_ — `src/hull/`: `VmSupervisor`
  (`CREATE_VM` allocates, launches and sends `vm.create`, rolling back on
  any failure; `DESTROY_VM` kills and reaps the VMM, then resets each held
  function and queues one `DEVICE_RELEASED` per function; an exit hull did
  not cause queues `VM_EXITED` first; events go out only after the
  command's response; `LIST_VMS`/`VM_STATUS` answer with the payloads now
  defined in `mailbox.hpp`), `JailedVmmLauncher` (UID, 0700 run
  directory, cgroup, jail, wait for `vmm.ping`; the handle releases all of
  it), `ChApiClient` (one HTTP/1.1 request per connection over the API
  socket with a deadline; strict reply parser and a strict bounded JSON
  reader for `vm.info`, both fuzzed in `fuzz_vmm_reply`),
  `vm_config_json` (vCPUs pinned 1:1 to the allocated cores, 1 GiB pages,
  serial and console off), `DeviceInventory` and `SysfsFunctionResetter`
  (`reset_method` bus or flr, then `reset`), and `AgentHandler`, which
  dispatches every command. Tested with fakes and end to end against
  `tests/fake_vmm`, a stand-in that takes Cloud Hypervisor's command line
  and answers its API, inside real jails (root in kernel-interop,
  unprivileged in ctest). A created VM boots once task 9 attaches its
  volume; the real Cloud Hypervisor runs in harbor (phase 3).
- [x] 9. Attach/detach via the VMM API socket with eject timeout policy.
  _Requirements: 7_ — `src/hull/vm_supervisor.*`: `ATTACH_DEVICE` and
  `ATTACH_VOLUME` check the boot inventory (slot, type, function) and
  that no VM holds the function, hand its VFIO group node to the VM's UID
  (`VmmHandle::grant_group`, chown 0600, refusing anything but a
  character device), then `vm.add-device`: a cold-plug before boot, a
  hot-plug after. The first storage function attached to a created VM is
  its boot volume and the VM boots right after (Requirement 6.2). A
  timed-out add is resolved from `vm.info`, so a function the VMM did
  take is never booked as free. `DETACH_DEVICE` and `DETACH_VOLUME` send
  `vm.remove-device`; before boot that releases at once (`ok`), after it
  the agent answers `accepted` and `poll_detaches()` releases the
  function once it leaves `vm.info` (the guest ejected it). At the
  timeout `destroy_vm` kills the VM (`VM_EXITED`, then every function
  released); `force` resets the function in place, because Cloud
  Hypervisor cannot hot-unplug without the guest, and releases it when
  the guest ejects it or the VM ends. Every release revokes the group
  node, resets the function and sends `DEVICE_RELEASED`. helm now waits
  `timeout_s` longer than `release_timeout` for that event after a
  detach. Tested with fakes and end to end against `tests/fake_vmm`;
  the group-node handover is tested on real device nodes as root.
  `DetachPolicy::wait` (block-volume task 13) gets no deadline: helm
  relays it only after the guest let go, so the agent releases the
  function whenever the eject completes and never forces it.
- [ ] 10. UKI build, Secure Boot signing and measured boot in harbor (OVMF
  with Secure Boot at L0). _Requirements: 1_
- [ ] 11. Host overhead measurement and documentation. _Requirements: 8.2_
