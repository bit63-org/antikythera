# Implementation Plan

Pairs with kythira `.kiro/specs/metal-host-lifecycle/` (tasks 8, 12
and 16 there). Each task is one PR unless noted.

- [x] 1. Records and reports
  - `host_power` (21) and `decommission` (22) in `src/proto/link.hpp`;
    `hardware_identity` (25) and `decommission_progress` (26) in
    `src/proto/report.hpp`; vectors and fuzz targets
  - _Requirements: 3.1, 5.1, 5.4, 6.1, 7.1_

- [ ] 2. helm enrollment states
  - `unenrolled`, `enrolling`, `enrolled`, `decommissioning`; host held
    in reset until enrolled; AK and TLS key in the secure element;
    certificate renewal; exhaustive transition tests
  - _Requirements: 1.1-1.4, 2.1-2.4, 7.2_

- [x] 3. Host power records
  - Verify, sequence and apply `host_power`; refusal with running VMs
  - _Requirements: 3.1-3.3_
  - Built: helm verifies the record under the controller keys, claims
    its number in the envelope space (`CommandRouter::claim_sequence`,
    recorded for hull's next floor) and reports a `CommandOutcome` with
    command `0x8000 | 21`. `off`, `cycle` and `hold` are refused
    (`conflict`) while a VM runs unless forced; a forced one forgets
    every VM as a volume-keeping DESTROY_VM would, reports it exited
    and sends its functions to cleaning (`host_reset`). `on` ends the
    power-on wait, or releases a held host onto a freshly filled boot
    function; `hold` keeps the slots up; `off` powers the slots down
    too, so the next `on` sequences them first; `cycle` is a new boot
    with a fresh epoch and its own fallback.

- [ ] 4. Boot function and provisioning file
  - Fetch and verify the UKI; build the ESP and provisioning partition;
    hull-init measures and reads the file, then the agent releases the
    function; last-known-good UKI in helm's sealed store, fetched only
    to change images; harbor stand-in with OVMF HTTP Boot
  - _Requirements: 4.1-4.5_
  - Built: the signed `HostImage` descriptor and image cache, the
    `boot_image` assignment (link type 25), image choice and fetch
    (`src/helm/host_boot.hpp`), the GPT/FAT32 boot disk
    (`src/helm/boot_function.hpp`), hull-init's PCR 15 measurement of
    the provisioning partition (`server-id partition`), and ak-helm's
    `boot-function` / `boot-layer` directives. The harbor stand-in is the
    boot disk attached read-only (`harbor/l1/run.sh --boot-function`)
    rather than OVMF HTTP Boot, so harbor boots the same bytes a board
    would. Left: the agent releasing the function (a mailbox command, with
    helm's mailbox device) and booting the UKI under OVMF (task 7).

- [ ] 5. Decommission
  - Key destruction, `sanitize` MCTP request to storage roles, identity
    clearing, persisted resume
  - _Requirements: 5.1-5.5_

- [ ] 6. Hardware identity report
  - _Requirements: 6.1-6.2_

- [ ] 7. Harbor lifecycle run (Clark's go, on tikhov)
  - _Requirements: 7.3_
