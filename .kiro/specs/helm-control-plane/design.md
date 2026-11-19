# Design Document — helm: the control-plane role

## Overview

helm is an event loop around four pieces of state — the device pool, the
key store, the mapping table and the slot table — driven by three
channels: controller (inbound signed commands), mailbox (to hull), and
sideband (to each oar). Nothing else can change that state.

```
            controller (kythira EC2 module)
                   │  signed envelopes, MAP_UPDATE, status
                   ▼
┌──────────────────────────── helm ─────────────────────────────┐
│  ControllerLink ──► CommandRouter ──► DevicePool  KeyStore    │
│                         │              MappingTable SlotTable │
│        MailboxDevice ◄──┘                    │                │
│        (BAR0 slots, MSI)         OarLink[slot] (MCTP)         │
│        PowerSequencer ── PERST#/power/link-ready per slot     │
└───────────┬──────────────────────────────────┬────────────────┘
            │ PCIe (no DMA)                    │ isolated sideband segments
            ▼                                  ▼
          hull                        oar-net / oar-blk / oar-gpu
```

## Components

### MailboxDevice

Implements the BAR0 register file (`src/helm/mailbox.hpp`, already
written). In harbor it is a vfio-user server; on hardware, a `pci-epf`
function (or FPGA logic). It owns the slot buffers and doorbells and raises
MSI-X vector 0 for commands. It never initiates DMA.

### CommandRouter

Takes a verified-by-shape controller envelope, checks the sequence number,
and turns it into: device-pool reservations, oar requests (prepare the
function), then a mailbox command to hull, then pool commits on hull's
response. Each step is idempotent on retry by sequence number.

### DevicePool

```
           assign                 VM release / detach
 free ───────────────► assigned ───────────────────► releasing
  ▲                                                     │ hull: DEVICE_RELEASED
  │  oar: clean ok (NIC, blk) / SCRUB_DONE (GPU)        ▼
  └──────────────────────────────────────────────── cleaning ◄────────┐
                                                        │ error /      │ slot power-cycle ok
                                                        ▼ timeout      │
            releasing: reset failed / timeout ──────► faulted ─────────┘
```

Types: `nic_vf`, `blk_fn`, `gpu_whole`, `gpu_vf`. Cleaning action by type:
NIC → dead VPC + clear queues/MAC; blk → drop key from memory; GPU →
scrub VRAM (manager VM or scrubber VM). Implemented as a table-driven state
machine (`src/helm/device_pool.hpp`, `transition_table`) so illegal
transitions are refused without side effects and testable exhaustively.

Decisions made in the implementation:

- GPU functions leave `cleaning` only on `SCRUB_DONE`; NIC and blk
  functions only on the role's clean confirmation.
- A power-cycled `faulted` function returns to `cleaning`, not `free`: a
  power cycle does not guarantee a wipe (VRAM in particular).
- A function added from a role's inventory starts in `cleaning`, since helm
  cannot know what a previous boot left in it.
- A function stays owned by its VM through `releasing`, until hull confirms
  the reset; only the owning VM can release it.

### KeyStore

Wraps the secure element. API: `create_vm_key`, `destroy_vm_key`,
`create_volume_key(vm)`, `unwrap_volume_key(vol) → ScopedKey`,
`rewrap(vol, new_vm)`, `destroy_volume_key`. `ScopedKey` is a move-only
type whose destructor zeroizes (`OPENSSL_cleanse`) and which can only be
consumed by `OarLink::deliver_key`. In harbor the secure element is a
file-backed software implementation behind the same interface.

The secure element interface takes and returns only wrapped keys, so a
plaintext VM key never leaves it; the only plaintext out is a volume key
as a `ScopedKey`. Wrapping is AES-256-GCM with a random 96-bit nonce,
and the AAD binds the blob's header and identity (`vm_id` for a VM key,
`volume_id` and owner `vm_id` for a volume key): a wrapped volume key
copied to another volume, or presented as another VM's, fails
authentication, which is what makes `REWRAP_VOLUME` the only way to move
a volume (Requirement 4.7). Wrapped keys have a versioned wire format
(`version | kind | key_len | nonce | ciphertext | tag`), decoded as
untrusted input since volume keys come back from the media.
`destroy_vm_key` also drops every volume key the VM key wraps and
returns those volumes, crypto-erased. The software secure element keeps
its 32-byte master key in a file created `0600` and refuses a symlink, a
non-regular file, group/other permission bits, or the wrong size.

### OarLink

One per data-plane role. MCTP message types (vendor-defined) for:
`function_inventory`, `prepare_function`, `clean_function`,
`deliver_key`, `drop_key`, `map_update`, `health`. Transport binding:
`SmbusBinding` (hardware), `I3cBinding` (later), `SocketBinding` (harbor,
one Unix socket per slot), `InProcessBinding` (combined placement).

Every binding carries the same encoded SMBus packets (with PEC) that the
wire does, one packet per send: `SocketBinding` is an `AF_UNIX`
`SOCK_SEQPACKET` socket, whose datagram boundaries are packet boundaries,
and `InProcessBinding` a pair of bounded queues. So the MCTP codec and
reassembly run unchanged in every placement and only the binding differs
(Requirement 7.1). Message bodies are in `src/helm/oar_protocol.hpp`:
little-endian, strict both ways, with a 2-byte status head on every
response. helm owns the MCTP tags and has one request outstanding per
link; a response that arrives after its request timed out carries an old
tag and is discarded, never taken for the next answer. Malformed or
misaddressed packets are dropped and counted rather than failing the
request, so noise costs time, not correctness.

`map_update` forwards the controller's MapUpdate frame unmodified,
signature included, so the role can check it itself. A frame (up to
131 KiB) exceeds the 4 KiB MCTP message bound, so it travels as
consecutive chunks (`total`, `offset`, bytes); offset 0 restarts a
transfer, any gap or changed total aborts it, and the last chunk's answer
is the result of applying the frame.

`deliver_key` is the one place a plaintext volume key leaves helm.
`OarLink` takes the `ScopedKey` by value, encodes it into exactly-sized
buffers, and wipes the body, message and every packet after sending,
success or failure. `OarEndpoint` wipes the reassembled request once the
role's handler returns, so the handler must copy the key into its key slot
during the call. Bytes in flight inside a binding (the kernel socket
buffer, a queue entry) are outside this layer.

### PowerSequencer

Per-slot PERST#, power enable, link-ready input; host PERST#/power. Boot
order: slots up → link-ready or timeout → host released. In harbor it
launches/kills board processes and then launches the L1 QEMU.

Built in `src/helm/power_sequencer.*` over a `Backplane` interface (slot
power and PERST#, slot link-ready, host power and PERST#). Decisions made
in the implementation:

- Boot holds the host, powers every slot, and waits for all of them
  together up to one `link_timeout`. A slot without link by then is
  powered off again, so a half-trained link is never on the host's bus,
  and faulted. The host is released either way: the device tree it
  enumerates is fixed, just without that slot.
- `power_cycle` touches only its slot. `check` faults a ready slot whose
  link dropped and retries up to `max_recoveries` power cycles. The
  sequencer tells an observer (`on_slot_ready`, `on_slot_recovered`,
  `on_slot_faulted`); helm's wiring reads the role's inventory into the
  CommandRouter on ready and calls `slot_power_cycled` on recovery, so
  functions return to the pool only after cleaning (Requirement 6.3).
- Time is injected (clock and sleep) so the sequence is unit-tested
  without waiting.
- harbor's `ProcessBackplane`: slot power is a board process
  (`posix_spawn`), link-ready is that process alive with its ready path
  (its sideband socket) present, and host power is the L1 QEMU process.
  A stale ready path is removed before each launch; power-off sends
  SIGTERM, waits a grace period, then SIGKILLs, and always reaps.

### ControllerLink

See `controller-interface` (design "ControllerLink"). Verifies envelope
shape and target server and forwards the signed slot image; never verifies
signatures itself (hull does — helm is not trusted to). Built in
`src/helm/controller_link.*`.

## Data models

- `FunctionId { slot: u8, fn: u16 }`, globally `{server, slot, fn}`.
- `NicId` (u64, controller-assigned, never reused).
- `VmId`, `VolumeId`: u64, controller-assigned.
- Mapping table: `NicId → {vni, mac, owner_vtep}`, versioned per VPC.

## Error handling

All helm operations return `std::expected<T, HelmError>`. A failure after
partial progress triggers compensation (release reserved functions, drop
delivered keys) before reporting. Timeouts are first-class errors.

## Testing strategy

- Unit: mailbox codec (done), pool state machine (all transitions), key
  store with the software secure element, MCTP codec.
- Fuzz: mailbox (done), MCTP, controller envelope.
- harbor integration: create/destroy loops, detach under load, slot kill
  during cleaning, both placements.
