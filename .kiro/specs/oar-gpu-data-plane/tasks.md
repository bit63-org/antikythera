# Implementation Plan — oar-gpu: GPU devices

## Status: designed; implementation deferred until network and storage ship

## Tasks

- [x] 1. Reserve protocol message types (`gpu_vf_config`, `scrub_done`).
  _Requirements: 2.2_
- [ ] 2. Device-pool types and the scrub cleaning action in helm (lands with
  helm task 4). _Requirements: 2.2, 3_
- [ ] 3. Backplane provisions captured in `backplane-hardware`.
  _Requirements: 5_
- [ ] 4. Resolve the open questions in design.md.
- [ ] 5. harbor stand-in: a fake "GPU" vfio-user device with large BARs and
  a scrub register, to exercise attach, detach and scrub flows without
  hardware. _Requirements: 2, 3, 5.3_
- [ ] 6. Whole-GPU passthrough on real hardware with a scrubber VM.
  _Requirements: 1, 3, 4_
- [ ] 7. SR-IOV GPU with a manager VM. _Requirements: 1.2, 3.2_
