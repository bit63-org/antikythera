# Implementation Plan — oar-gpu: GPU devices

## Status: designed; implementation deferred until network and storage ship

## Tasks

- [x] 1. Reserve protocol message types (`gpu_vf_config`, `scrub_done`).
  _Requirements: 2.2_
- [x] 2. Device-pool types and the scrub cleaning action in helm (lands with
  helm task 4). _Requirements: 2.2, 3_
- [ ] 3. Backplane provisions captured in `backplane-hardware`.
  _Requirements: 5_
- [x] 4. Resolve the open questions in design.md (design "Resolved
  questions"; GPU family awaits Clark under "Needs Clark's choice").
- [ ] 4a. Append `vm_channel` (5) to `helm::FunctionType` /
  `proto::FunctionType`, keep it out of the tenant pool, and add the OarLink
  operations `vm_channel_send` / `vm_channel_poll`. _Requirements: 6_
- [ ] 4b. virtio-vsock `vm_channel` function on the shared virtio core, with
  the restricted profile, in harbor first. _Requirements: 6.1, 6.2_
- [ ] 4c. Channel message codec (`hello`, `vf_provision`, `scrub_*`,
  `fault`) with unit tests and a fuzz target, and helm's scrub
  verifier (seed, coverage, challenge). _Requirements: 3.4-3.6, 6.5_
- [ ] 4d. hull: start manager VMs from inventory and scrubber VMs on
  whole-GPU release, then send `SCRUB_DONE` after the final reset; helm:
  free `gpu_whole` on `SCRUB_DONE` plus a verified result, `gpu_vf` on a
  verified result alone. _Requirements: 3.5, 6.3, 6.4_
- [ ] 5. harbor stand-in: a fake "GPU" vfio-user device with large BARs and
  a scrub register, to exercise attach, detach and scrub flows without
  hardware, including the scrub challenge-response and a stand-in that
  skips pages, which must be caught. _Requirements: 2, 3, 5.3_
- [ ] 6. Whole-GPU passthrough on real hardware with a scrubber VM.
  _Requirements: 1, 3, 4_
- [ ] 7. SR-IOV GPU with a manager VM, including the PF driver's
  provision-only patch. Needs Clark's GPU family choice and purchase first.
  _Requirements: 1.2, 1.3, 3.2_
