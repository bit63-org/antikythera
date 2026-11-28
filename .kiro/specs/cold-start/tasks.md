# Implementation Plan

Depends on `server-provisioning` (enrollment, boot function, host power)
and `helm-control-plane`. Pairs with kythira's
`.kiro/specs/az-cold-start/`. Each task is one PR unless noted.

- [x] 1. Record and report codecs
  - `standing_set` (23), `power_policy` (24), `cold_start` (27),
    `boot_cache` (28); vectors and libFuzzer targets
  - _Requirements: 8.3_

- [x] 2. Sealed store
  - Log-structured store over a flash interface, AES-256-GCM under a
    secure-element key, atomic writes, rollback detection by monotonic
    counter, erase on decommission; file-backed flash with fault
    injection for tests
  - _Requirements: 1.1-1.7_

- [x] 3. Boot epoch and sequence floor
  - Secure-element boot epoch; last sequence in the store; both in the
    measured provisioning file; hull refuses sequence numbers at or below
    the floor
  - _Requirements: 6.1-6.3_

- [ ] 4. LKG images and fallback boot
  - Store two images, fill the boot function from LKG, fetch an assigned
    image with a 30 s limit, `keep_image` promotion, previous-image
    fallback on a failed start, verification before store and boot
  - _Requirements: 2.1-2.5_

- [x] 5. Local power-on policy
  - Store the newest `power_policy`; tier, slot and jitter wait after
    helm's own power returns; slot stagger; `host_power` override;
    defaults with no policy
  - _Requirements: 3.1-3.6_

- [x] 6. Standing sets and standing starts in helm and hull
  - Verify and store sets by generation with the monotonic counter;
    deliver standing starts before any live envelope; hull acceptance
    rules; retries and reports; empty set unpins
  - _Requirements: 4.1-4.7_
  - Built: hull's half. helm sends the set as unsigned STANDING_CHUNK
    mailbox commands and starts each instance with STANDING_START;
    hull's `StandingStarts` verifies the whole set and applies 4.5.
    helm's `StandingSetKeeper` verifies each set, stores the newest and
    anchors its generation in the secure element; `CommandRouter`
    holds envelopes until hull's agent is up, uploads the set, prepares
    each instance's resources and sends its STANDING_START, retrying
    a failed start with backoff (1 s doubling to 30 s) until the first
    envelope arrives. The `cold_start` report carries the round's
    results. Feeding stored replica configs, keys and network frames
    into the prepare is task 7.

- [ ] 7. Volumes, NICs and secrets of standing instances
  - Stored `ReplicaConfig` and volume keys to oar-blk; stored network
    frames to the network role before plugging NICs; tunnel keys until
    `fleet-scale-networking` lands; instance secrets through instance
    metadata only
  - _Requirements: 5.1-5.5_

- [x] 8. Time floor in helm
  - _Requirements: 7.1, 7.2_

- [x] 9. Cold-start reports
  - `cold_start` on the first link after power returns; `boot_cache` on
    every inventory
  - _Requirements: 8.1, 8.2_
  - Built: the LKG and previous images (task 4) and standing starts
    (task 6) are reported as none until those tasks land

- [ ] 10. Harbor AZ power-loss suite
  - Every component killed at once, controller absent, standing
    instances back and talking; every fault case
  - _Requirements: 9.1, 9.2_

- [ ] 11. Software helm for the kythira QEMU cold-start run
  - _Requirements: 9.3_
