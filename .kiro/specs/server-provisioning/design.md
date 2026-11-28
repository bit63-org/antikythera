# Design Document — Server provisioning and decommissioning

## Overview

```
 kythira metal (data, boot)          kythira EC2 (fleet)
   │ HTTPS enrollment, images          │ mTLS link: host_power (21),
   │                                   │ decommission (22); reports 25, 26
   ▼                                   ▼
 helm ── secure element (EK, AK, TLS key, master key)
   │ PERST#/power        │ boot function (read-only UKI + provisioning file)
   ▼                     ▼
 host UEFI ── Secure Boot ──► hull UKI ── init measures provisioning file
                                         ──► hull-agent --server-id
```

helm states:

| State | Holds | Accepts |
|---|---|---|
| `unenrolled` | nothing | discovery and enrollment only; host in reset |
| `enrolling` | AK, TLS key | enrollment replies |
| `enrolled` | server ID, certificate, master key | everything it accepts today, plus 21 and 22 |
| `decommissioning` | a decommission in progress (persisted) | nothing but the decommission's own steps |

## Key design decisions

### helm enrolls, not hull

hull has no network stack and is trusted only to verify signed commands
(product steering). helm already has the management port, the secure
element and the host's reset line, so it is the server's BMC and its
identity. hull's server ID comes from helm through the measured
provisioning file, which hull already supports (hull design
"SignatureVerifier"), so hull needs no change beyond reading the file
from the boot function.

### The boot function

The host has no NIC: every network function belongs to a guest. A
read-only block function on the control slot (an NVMe namespace or a
virtio-blk function from the same virtio core oar-blk uses) holds a FAT
EFI system partition with the UKI and a second small partition with the
provisioning file. helm fills it before releasing the host from reset.
The host's firmware boots it under Secure Boot; hull-init reads the
provisioning file, extends a PCR with its digest, and execs the agent.
After start-up the agent releases the function, which never enters the
device pool. In harbor, OVMF HTTP Boot from the metal boot layer stands
in, with the provisioning file passed as an extra initrd.

### Records

Numbers taken elsewhere: link types 17-18 (khold), 19 (`security_policy`,
vpc-security-groups) and 20 (`edge_mapping`, vpc-internet-gateways
draft); report kinds 21 (`security_usage`) and 22-24 (internet gateways
draft). This spec takes link types 21-22 and 25 and report kinds 25-26.

| Record | Direction | Body | Signed |
|---|---|---|---|
| `host_power` (21) | controller → helm | `magic 'AKHP' \| version u16 \| key_id u16 \| server_id u64 \| seq u64 \| action u8 (on, off, cycle, hold) \| force u8 \| rsvd [6] \| sig [64]` | yes, Ed25519 by the controller key, like an envelope |
| `decommission` (22) | controller → helm | `magic 'AKDC' \| version u16 \| key_id u16 \| server_id u64 \| seq u64 \| rsvd [8] \| sig [64]` | yes |
| `boot_image` (25) | controller → helm | `magic 'AKBI' \| version u16 \| key_id u16 \| server_id u64 \| assignment_version u64 \| rsvd [8] \| HostImage descriptor [0x80] \| sig [64]` | yes, and the descriptor by an image key |

| Report | Kind | Body |
|---|---|---|
| `hardware_identity` | 25 | endorsement key hash, board serial, per-slot serials and firmware, per-drive serial and size, Secure Boot and IOMMU flags |
| `decommission_progress` | 26 | step (`keys_destroyed`, `media`, `identity_cleared`), per-drive result (`sanitized_crypto`, `sanitized_block`, `failed`), drive serial |

The magic and version lead each frame, as on every other frame the
controller key signs, so the signed bytes of one kind of frame never
parse as another (`src/proto/host_lifecycle.hpp`). The reports' exact
layouts are in `src/proto/report.hpp`.

Both records use the same per-server sequence space as envelopes so a
replayed power or decommission record is refused like a replayed
command. helm verifies their signatures itself (unlike a MapUpdate,
which it forwards unchecked), because helm is the one that acts.

### Host images

Every host image travels with a signed `HostImage` descriptor
(`src/proto/host_image.hpp`, fixed 0x80 bytes: key ID, release number,
size, kind, SHA-256): signed by an image signing key, not the controller
key, so a compromised controller still cannot put an image of its own on
a server. helm's image keys are compiled in (`AK_HELM_IMAGE_KEYS`) in a
production build, or configured (`image-keys`) in harbor. The boot layer
serves an image and its descriptor at `v1/images/<hex digest>/data` and
`/descriptor`, so an image is fetched by what it is.

helm keeps up to three images in its sealed store (`src/helm/
image_cache.hpp`): `staged` (assigned and fetched, not yet trusted),
`lkg` and `previous`, as 1 MiB chunks named by digest so releases share
what they have in common. Each is checked when stored and again, from
the chunks read back, before it is booted.

The controller assigns an image with a `boot_image` record
(`src/proto/boot_image.hpp`), which neither this spec nor cold-start
named before: it carries the image's descriptor under the controller's
signature, so helm boots only an image both the release pipeline and
the controller chose, and an `assignment_version` that only grows, so a
captured assignment cannot roll a server back. helm keeps the newest in
its sealed store (dropped, like the power policy, if the store opens
rolled back). Before every host boot (`src/helm/host_boot.hpp`) it
boots the assigned image from its cache, or fetches it by digest from
the boot layer within 30 s and stages it; failing that, the LKG; failing
that, the previous image. An image that just failed to start is
skipped. A staged image with no assignment naming it is never booted.

### Decommission order

Keys first: once the master key is gone every volume is unreadable, so
an interrupted decommission still leaves no readable data. Then media
sanitize through each storage role over its sideband (a new
`sanitize` MCTP request), then helm's own identity. The decommission is
persisted before the first step and resumed at the next boot.

## Testing strategy

- Codecs: vectors and fuzz targets for records 21 and 22 and reports 25
  and 26.
- helm state machine: exhaustive illegal-transition tests; decommission
  interrupted at every step and resumed.
- Harbor: a full lifecycle with the metal module, OVMF HTTP Boot in place
  of the boot function, `swtpm` as helm's secure element, emulated NVMe
  for sanitize.

## Open questions

1. Boot function as NVMe namespace or virtio-blk? virtio-blk reuses
   `oar/virtio`; NVMe is what most server firmware boots best.

Settled: helm boots from its own flash (antikythera
`.kiro/specs/cold-start/`, draft #140), since helm must run before
anything else on the server can.
