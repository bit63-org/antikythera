# Implementation Plan — build-and-ci

## Status: 8/11 tasks complete (task 8 is open only for 8.5, the required-check list)

## Tasks

- [x] 1. CMake scaffold: C++23, module scanning off, GCC 14 / Clang 19
  floor with the Clang 18 `std::expected` message, `AK_WERROR`,
  `AK_SANITIZE`, `AK_FUZZ`, `AK_TESTS`. _Requirements: 1, 3.1_
- [x] 2. vcpkg manifest pinned to kythira's baseline with `version>=`
  floors; OpenSSL from a scoped git registry; consumed through
  `CMAKE_PREFIX_PATH` (`cmake/Vcpkg.cmake`). _Requirements: 2.1, 2.2, 2.4_
- [x] 3. libvfio-user overlay port, `vfio-user` feature, `AK_VFIO_USER`
  (`AUTO`/`ON`/`OFF`), generated `.pc` and find fallback.
  _Requirements: 2.3, 2.5_
- [x] 4. `ak::warnings`, `ak::hardening` and sanitizer modules.
  _Requirements: 3.2_
- [x] 5. `AK_COMPILER_LAUNCHER` selection (`cmake/CompilerLauncher.cmake`).
  _Requirements: 4.1_
- [x] 6. Lint config and conformance: clang-format 22.1.5 and kythira's
  `.clang-tidy` (clang-tidy 19); existing code brought to the coding and
  test standards. _Requirements: 5.3_
- [x] 7. `DEPENDENCIES.md` in kythira's format. _Requirements: 2.6_
- [ ] 8. GitHub Actions CI: GCC 14 and Clang 19 build + ctest, sanitizer
  job, fuzz build and smoke run, clang-format, clang-tidy, shellcheck, L1
  cache; make every job a required check on main.
  _Requirements: 4.2, 4.3, 5.1–5.4, 5.6_ — Most of it runs in
  `.github/workflows/ci.yml` and `kernel-interop.yml`:
  - [x] 8.1 `build (gcc-14)` and `build (clang-19)`: Debug build and
    `ctest` on every pull request and push to main. _Requirements: 5.1_
  - [x] 8.2 The Clang 19 job builds with `AK_SANITIZE=ON` (ASan + UBSan)
    and `AK_FUZZ=ON`, runs `ctest` under the sanitizers and gives every
    `fuzz_*` target a 20-second smoke run. _Requirements: 5.2_
  - [x] 8.3 `lint`: clang-format 22.1.5, clang-tidy 19 with the
    repository's `.clang-tidy`, shellcheck. _Requirements: 5.3, 5.4_
  - [x] 8.4 Build cache: on the self-hosted ARC runners sccache
    stores objects in kythira-cache through its Redis port, with separate
    ACL users for main pushes and pull requests; a missing setting or a
    cache that does not answer builds without a launcher and warns. CI
    takes its libraries from the Ubuntu archive instead of vcpkg, so
    there is no vcpkg installed tree to cache. _Requirements: 4.2, 4.3_
  - [ ] 8.5 Every job a required check on main. `build (gcc-14)`,
    `build (clang-19)`, `lint` and `kernel-interop` are required;
    `kernel-config` is not yet. _Requirements: 5.6_
- [ ] 9. OCI L2 cache: port kythira's `oci-build-cache` composite action,
  wire `scripts/oci-build-cache/start-sccache.sh`, add antikythera's three
  credentials. **Needs Clark's go (real-cloud spend).**
  _Requirements: 4.2–4.4_
- [ ] 10. arm64 cross-build job. _Requirements: 5.5_
- [x] 11. Cloud development environment: `.claude/hooks/session-start.sh`,
  a SessionStart hook that installs the toolchain and test dependencies.
  _Requirements: 6_
