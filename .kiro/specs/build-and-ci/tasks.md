# Implementation Plan — Build system, dependencies, caching and CI

## Status: 8/12 tasks complete

## Tasks

- [x] 1. CMake skeleton: C++23, toolchain floors (GCC 14 / Clang 19),
  module scanning off, warnings, hardening, sanitizers. _Requirements: 1_
- [x] 2. vcpkg manifest, configuration (kythira baseline, OpenSSL git
  registry), libvfio-user overlay port. _Requirements: 2.1, 2.2_
- [x] 3. `cmake/Vcpkg.cmake` and graceful optional dependency for
  libvfio-user. _Requirements: 2.3, 2.4_
- [x] 4. `AK_COMPILER_LAUNCHER`. _Requirements: 3_
- [x] 5. Boost.Test wiring (one executable per file) and libFuzzer targets;
  verified locally: GCC 14 and Clang 19 pass all tests under ASan/UBSan;
  fuzzers ran 11.2M (Geneve) and 22.2M (mailbox) inputs with no findings.
  _Requirements: 5.2, 5.3_
- [x] 5a. Code brought to the inherited standards and verified clean with
  clang-format 22.1.5 and clang-tidy 19 (zero findings, including the
  test device checked against libvfio-user's headers).
  _Requirements: 5.4_
- [x] 6. `DEPENDENCIES.md`, in kythira's format, including harbor's
  workstation prerequisites and pins. _Requirements: 2.5_
- [x] 7. Verify a real `vcpkg install` (including the libvfio-user overlay)
  and build against `vcpkg_installed/`. Done on tikhov
  (`vcpkg install --x-feature=vfio-user`, then `ak-testdev` built).
  _Requirements: 2_
- [ ] 8. Adapt the `oci-build-cache` action for kythira's shared bucket
  (decided; see design.md) and add antikythera's three credentials as
  repository secrets. _Requirements: 4.2, 4.3_
- [ ] 9. `ci.yml`: build matrix, sanitizers, fuzz smoke, format and tidy,
  arm64 cross-build, tree cache. _Requirements: 4.1, 4.4, 5_
- [ ] 10. Self-hosted runner job for harbor. _Requirements: 5.5_
- [ ] 11. Add GCC 15 to the CI matrix. tikhov's GCC 15.2 caught a
  `-Werror=conversion` failure in a test that GCC 14 and Clang 19 accept
  (fixed; see `tests/geneve_test.cpp`). _Requirements: 5.1_
