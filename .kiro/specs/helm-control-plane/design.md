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
  │  oar: clean ok                                      ▼
  └──────────────────────────────────────────────── cleaning
                                                        │ timeout / error
                                                        ▼
                                  slot power-cycle ok ◄─ faulted
```

Types: `nic_vf`, `blk_fn`, `gpu_whole`, `gpu_vf`. Cleaning action by type:
NIC → dead VPC + clear queues/MAC; blk → drop key from memory; GPU →
scrub VRAM (manager VM or scrubber VM). Implemented as a table-driven state
machine so illegal transitions are unrepresentable and testable.

### KeyStore

Wraps the secure element. API: `create_vm_key`, `destroy_vm_key`,
`create_volume_key(vm)`, `unwrap_volume_key(vol) → ScopedKey`,
`rewrap(vol, new_vm)`, `destroy_volume_key`. `ScopedKey` is a move-only
type whose destructor zeroizes (`OPENSSL_cleanse`) and which can only be
consumed by `OarLink::deliver_key`. In harbor the secure element is a
file-backed software implementation behind the same interface.

### OarLink

One per data-plane role. MCTP message types (vendor-defined) for:
`function_inventory`, `prepare_function`, `clean_function`,
`deliver_key`, `drop_key`, `map_update`, `health`. Transport binding:
`SmbusBinding` (hardware), `I3cBinding` (later), `SocketBinding` (harbor,
one Unix socket per slot), `InProcessBinding` (combined placement).

### PowerSequencer

Per-slot PERST#, power enable, link-ready input; host PERST#/power. Boot
order: slots up → link-ready or timeout → host released. In harbor it
launches/kills board processes and then launches the L1 QEMU.

### ControllerLink

See `controller-interface`. Verifies envelope shape and forwards the
signed slot image; never verifies signatures itself (hull does — helm is
not trusted to).

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
