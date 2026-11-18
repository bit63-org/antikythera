# Implementation Plan — hull: the minimal host and its agent

## Status: 0/11 tasks complete

## Tasks

- [ ] 1. Kernel config fragment for harbor L1 (permissive: includes IP for
  debugging) and the target `hull.config` (strict). _Requirements: 2_
- [ ] 2. Phase-1 check script for L1: IOMMU groups, ATS state, ACS on
  ports, reset reaching the device server. Written as
  `harbor/l1/phase1-check.sh` (harbor task 4); not yet run.
  _Requirements: 5.2_
- [ ] 3. Init binary: mounts, `vfio-pci` binding by allow-list, IOMMU group
  check. _Requirements: 3.1, 5.1, 5.2_
- [ ] 4. MailboxClient over VFIO (BAR0 mmap, MSI-X eventfd, no DMA).
  _Requirements: 3_
- [x] 5. SignatureVerifier (OpenSSL Ed25519) and sequence tracking.
  _Requirements: 4_ — `src/hull/`: `SignatureVerifier`, `SequenceTracker`
  and `authenticate()` (decode, signature, sequence). The compiled-in key
  table arrives with the agent binary (task 3); `authenticate()` takes the
  key ID from the signed slot header (mailbox protocol v2).
- [ ] 6. Resource allocator: cores (whole, SMT-aware) and 1 GiB pages.
  _Requirements: 6.1, 8.1_
- [ ] 7. Jail construction (namespaces, cgroup, Landlock, UID).
  _Requirements: 6.1, 9.1_
- [ ] 8. VmSupervisor: create/destroy with Cloud Hypervisor; reset and
  `DEVICE_RELEASED`. _Requirements: 6_
- [ ] 9. Attach/detach via the VMM API socket with eject timeout policy.
  _Requirements: 7_
- [ ] 10. UKI build, Secure Boot signing and measured boot in harbor (OVMF
  with Secure Boot at L0). _Requirements: 1_
- [ ] 11. Host overhead measurement and documentation. _Requirements: 8.2_
