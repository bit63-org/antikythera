# Implementation Plan

Pairs with kythira `.kiro/specs/metal-host-lifecycle/` (tasks 8, 12
and 16 there). Each task is one PR unless noted.

- [ ] 1. Records and reports
  - `host_power` (21) and `decommission` (22) in `src/proto/link.hpp`;
    `hardware_identity` (25) and `decommission_progress` (26) in
    `src/proto/report.hpp`; vectors and fuzz targets
  - _Requirements: 3.1, 5.1, 5.4, 6.1, 7.1_

- [ ] 2. helm enrollment states
  - `unenrolled`, `enrolling`, `enrolled`, `decommissioning`; host held
    in reset until enrolled; AK and TLS key in the secure element;
    certificate renewal; exhaustive transition tests
  - _Requirements: 1.1-1.4, 2.1-2.4, 7.2_

- [ ] 3. Host power records
  - Verify, sequence and apply `host_power`; refusal with running VMs
  - _Requirements: 3.1-3.3_

- [ ] 4. Boot function and provisioning file
  - Fetch and verify the UKI; build the ESP and provisioning partition;
    hull-init measures and reads the file, then the agent releases the
    function; last-known-good UKI in helm's sealed store, fetched only
    to change images; harbor stand-in with OVMF HTTP Boot
  - _Requirements: 4.1-4.5_

- [ ] 5. Decommission
  - Key destruction, `sanitize` MCTP request to storage roles, identity
    clearing, persisted resume
  - _Requirements: 5.1-5.5_

- [ ] 6. Hardware identity report
  - _Requirements: 6.1-6.2_

- [ ] 7. Harbor lifecycle run (Clark's go, on tikhov)
  - _Requirements: 7.3_
