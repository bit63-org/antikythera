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

- [x] 5. Decommission
  - Key destruction, `sanitize` MCTP request to storage roles, identity
    clearing, persisted resume
  - _Requirements: 5.1-5.5_
  - Built (helm): the signed `decommission` record is refused while a
    VM, a network volume attachment or a replica (hold config or khold
    layout naming this server) remains; otherwise it is kept in the
    sealed store (`helm.decommission`, `src/helm/decommission.hpp`) and
    run in order. First every VM key and the secure element's master key
    are destroyed (`KeyStore::destroy_all`,
    `SecureElement::destroy_master_key`). Then each hold and khold role
    is asked to sanitize over the sideband (`sanitize`, oar vendor type
    0x21, start then query). A role that refuses, or does not answer
    within `sanitize_timeout` (12 h), has its known drives reported
    failed. Last comes identity_cleared, after which ak-helm removes its
    TLS key, certificate and master key file, erases the sealed store
    and stops. The host is held from the first step to the end. A power
    loss resumes at the step it reached, before the power-on wait.
  - Built (roles): ak-hold and ak-khold take `--drive-device
    SERIAL:PATH` and answer `sanitize` through `MediaSanitizer`
    (`src/helm/media_sanitize.hpp`), with one worker per drive. Each
    drive gets NVMe Sanitize: crypto erase if SANICAP has it, else (or
    when it fails) block erase, then the Sanitize Status log is polled
    until the operation ends. A drive named with `--drive-serial` but
    given no device is reported failed.
  - Left: helm's server ID stays in its configuration file until
    enrollment states (task 2) give helm an unenrolled state of its own.
    The harbor run with emulated NVMe is task 7.

- [x] 6. Hardware identity report
  - _Requirements: 6.1-6.2_
  - Built: `HardwareIdentityTracker` (`src/helm/hardware_identity.hpp`)
    and the sideband `role_identity` request (oar vendor type 0x20).
    Each role process takes `--serial`, `--firmware` and (storage roles)
    `--drive-serial SERIAL:BYTES` and answers with them; one without
    answers `unsupported` and is left out of the report. ak-helm's
    `board-serial` / `board-firmware` directives turn the report on.
    helm sends `hardware_identity` when the identity changes (first at
    start) and a `hardware_changed` host fault (fault code 6) when it
    differs from the baseline. The baseline is the first report taken
    once every slot has answered, kept in the sealed store as
    `helm.identity-baseline` and dropped by a rolled-back or degraded
    store. Host facts from hull complete the baseline rather than change
    it. Until then the report says they are absent, and only the rest is
    compared.
  - Left: hull reporting Secure Boot, IOMMU, memory and CPUs to helm
    (`HardwareIdentityTracker::set_host`; hull has no mailbox event for
    them yet); the EK hash is the secure element's transport key until
    task 2 brings the TPM's; enrollment and decommission
    (`clear_baseline`) resetting the baseline are tasks 2 and 5.

- [ ] 7. Harbor lifecycle run (Clark's go, on tikhov)
  - _Requirements: 7.3_
