# Requirements Document — Build system, dependencies, caching and CI

## Introduction

Antikythera follows kythira's build, dependency and caching standards so the
two repositories behave the same way for anyone working on both, and so
antikythera inherits what kythira has already measured (see kythira's
`doc/ci_build_cache.md` and `.kiro/specs/oci-build-cache/`).

## Requirements

### Requirement 1: Toolchain

#### Acceptance Criteria

1. The build SHALL require C++23, CMake ≥ 3.28, and GCC ≥ 14 or Clang ≥ 19,
   failing at configure time otherwise with the reason.
2. Module dependency scanning SHALL be disabled.
3. Warnings SHALL be errors by default (`AK_WERROR`), with the warning set
   in `cmake/Warnings.cmake`.
4. Shipped targets SHALL link `ak::hardening`.

### Requirement 2: Dependencies through vcpkg manifest mode

#### Acceptance Criteria

1. Dependencies SHALL be declared in `vcpkg.json` with the same
   `builtin-baseline` as kythira and `version>=` floors.
2. Ports needing a newer commit than the baseline SHALL come from a git
   registry in `vcpkg-configuration.json`; ports not in the registry SHALL
   be overlay ports under `vcpkg-overlays/` with a README.
3. The installed tree SHALL be consumed through `CMAKE_PREFIX_PATH`
   (`cmake/Vcpkg.cmake`); the build SHALL also work against system packages.
4. Optional dependencies SHALL be detected QUIET, exposed as `AK_HAS_<DEP>`,
   and SHALL leave dependent targets undefined when absent.
5. Every dependency SHALL be documented in `DEPENDENCIES.md`.

### Requirement 3: Compiler launcher

#### Acceptance Criteria

1. `AK_COMPILER_LAUNCHER` SHALL accept `auto` (ccache, then sccache, then
   none), `ccache`, `sccache` and `none`.
2. An explicitly requested launcher that is missing SHALL fail configure.

### Requirement 4: CI caches

#### Acceptance Criteria

1. CI SHALL cache the `vcpkg_installed/` tree with `actions/cache`, keyed on
   OS, architecture, compiler and `hashFiles('vcpkg.json',
   'vcpkg-configuration.json', 'vcpkg-overlays/**')`.
2. CI SHALL use the `oci-build-cache` composite action for the vcpkg binary
   cache (`x-aws`) and sccache (`s3`), with kythira's writer policy:
   read-write on `main`, create-only for same-repository pull requests,
   read-only otherwise.
3. Absence of credentials or an unreachable bucket SHALL degrade to building
   from source; the job SHALL still pass.
4. Third-party actions SHALL be pinned by commit SHA; downloaded tools SHALL
   be pinned by version and checksum.

### Requirement 5: CI jobs

#### Acceptance Criteria

1. CI SHALL build and test with GCC 14 (the floor), the newest GCC
   available (15 today), and Clang 19 on x86-64, and cross-build for arm64.
2. CI SHALL run the unit tests under ASan and UBSan.
3. CI SHALL run each fuzz target for a bounded time on every pull request.
4. CI SHALL run clang-format 22.1.5 (kythira's pinned version) and
   clang-tidy 19 with the inherited configs, failing on any diff or finding.
5. Jobs needing nested KVM (harbor phases) SHALL run only on a labelled
   self-hosted runner.

### Requirement 6: Repository conventions

#### Acceptance Criteria

1. Commits SHALL follow Conventional Commits, as in kythira.
2. New files SHALL carry the Apache-2.0 copyright header, as in kythira.
