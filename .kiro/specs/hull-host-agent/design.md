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

A small C++ binary (not a shell script — there is no shell). Steps:
mount `/proc`, `/sys`, `/dev`, hugetlbfs; write `driver_override` for each
function in the inventory allow-list; bind to `vfio-pci`; walk
`/sys/kernel/iommu_groups` and fail closed on a shared group; exec the
agent.

As built (task 3):

- The allow-list is `/etc/hull/hull.conf` inside the initramfs, so Secure
  Boot covers it. A slot is named by its PCIe downstream port plus the
  function type and PCI ID it carries; every matching function below
  the port belongs to it, numbered in address order. Matching by port
  rather than by address keeps the file valid when bus numbers move.
- A shared IOMMU group stops the boot rather than only that function, and
  the mailbox's group is checked too: a host whose topology is not what
  the image expects should not run guests at all.
- Init writes the inventory to `/run/hull/inventory`
  (`<slot> <type> <function> <bdf> <group> <reset>` per line) and execs
  the agent with `--mailbox`, `--inventory` and `--server-id`; the agent
  parses the file as strictly as anything else.
- The agent keeps CAP_SYS_ADMIN, CAP_SETUID, CAP_SETGID, CAP_CHOWN,
  CAP_FOWNER, CAP_SYS_RESOURCE and CAP_KILL after setup, all for building
  jails and handing over group nodes, and sets no_new_privs. Running it
  unprivileged (a VMM under a fixed UID, groups pre-chowned) is possible
  but not built.

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
`key_id` field of the signed slot header — see `controller-interface`).
Before verifying, `authenticate` compares the signed header's `server_id`
(mailbox protocol v3) with the server ID the agent was provisioned with
and refuses a mismatch as `wrong_server`. An agent with no server ID (0)
refuses every command. Init hands the agent its server ID at boot; the
allow-list says where init reads it from (`server-id cmdline` for
`hull.server_id=` on the signed UKI's command line, or `server-id file
<path>` for a provisioning file, which production must measure). Both
are supported, so one image per server and one image per fleet plus a
measured file both work.

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

`DETACH_VOLUME` under the `wait` policy (Requirement 7.2) reaches the
agent only after helm has seen the guest release the function through
the oar-blk vendor capability (block-volume-service design "Detach
blocked while mounted"), so `vm.remove-device` completes without a guest
eject wait and the timeout and policy are not applied. helm answers a
guest that never releases with `busy` itself; the agent never sees that
command. Nor does it see `WITHDRAW_DETACH`, with which the controller
cancels a busy request: helm clears the request on the storage role and
answers it. One that reaches the agent anyway is answered
`unsupported`. `CONVERT_VOLUME` (a local volume copied to network
storage or back) needs nothing from the agent: it answers ok once the
signature checks, and helm runs the copy on the storage role.

As built (task 8):

- The VMM starts with only `--api-socket` and `--seccomp true`; the VM
  arrives over the socket with `vm.create` (`vm_config_json`): vCPU *i*
  pinned to the *i*-th allocated core thread, 1 GiB pages, serial and
  console off. `CREATE_VM` answers `ok` once `vm.create` has succeeded;
  the VM is then `created` (configured, not booted, no devices).
  Booting waits for the boot volume, which arrives with the attach
  commands (task 9).
- Cloud Hypervisor always adds a virtio-rng backed by `/dev/urandom` (its
  `RngConfig` cannot be turned off), so that one emulated device remains
  and the jail allows reading `/dev/urandom`. Requirement 6.1's "no
  emulated virtio devices" holds for everything the agent configures.
- Landlock cannot be widened after exec and functions are hot-plugged
  later, so the jail allows the whole of `/dev/vfio`. A group node stays
  root-owned and 0600 until its function is assigned, and the VMM has no
  capabilities, so it can open only the groups the agent hands to its UID
  (task 9). Cloud Hypervisor can also take an already-open VFIO cdev over
  `SCM_RIGHTS`, which would let the jail drop `/dev/vfio` entirely; that
  needs iommufd and is left for later.
- The VMM's replies are untrusted: one request per connection, a deadline
  on every exchange, a strict HTTP reply parser and a strict bounded JSON
  reader (`fuzz_vmm_reply`).
- `LIST_VMS` and `VM_STATUS` answer with payloads defined in
  `helm/mailbox.hpp` (`VmList`, `VmStatusInfo`).
- Events are queued and sent after the command's response, so helm sees
  `DESTROY_VM`'s `ok` before the `DEVICE_RELEASED` events it waits for.
- `VM_EXITED`: exit status 0 is reported as `guest_shutdown` (Cloud
  Hypervisor exits cleanly when the guest powers off), any other exit or a
  signal as `vmm_failure` with the exit code or 128 + signal.

As built (task 9):

- A function's VFIO group node is handed to the VM's UID (0600) for
  exactly as long as the VM holds it, and back to root afterwards; this
  is what confines the VMM to its own functions inside the jail's
  `/dev/vfio` rule.
- The VM boots right after its first storage function is attached:
  before that the firmware has nothing to boot. Functions attached
  before boot are cold-plugged into the configuration; after, hot-plugged.
- Detach on a running VM answers `accepted`; completion is the
  `DEVICE_RELEASED` event, sent once `vm.info` no longer lists the
  function. helm waits `timeout_s` beyond its `release_timeout` for it.
- Cloud Hypervisor has no surprise removal: `vm.remove-device` only asks
  the guest, and a function leaves a running VMM only when the guest
  ejects it. So `force` cannot free the function on time. At the timeout
  the agent resets it in place (the guest loses the device's state and
  sees a function that no longer answers as before) and releases it when
  the guest finally ejects it or the VM ends; until then it stays booked
  to that VM and no other VM can be given it. `destroy_vm` is the policy
  that frees a function on time. A real forced unplug needs upstream
  Cloud Hypervisor support.
- `destroy_vm` reports the VM it killed with `VM_EXITED` (`vmm_failure`,
  128 + SIGKILL), the only event that tells helm a VM is gone.

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
