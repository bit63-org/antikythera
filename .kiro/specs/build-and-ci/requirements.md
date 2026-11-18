# Requirements Document — build-and-ci: toolchain, dependencies, caching and CI

## Introduction

antikythera builds, tests and checks itself the way kythira does, so the two
repositories share a toolchain floor, a vcpkg baseline, lint versions and a
build cache. This spec covers the CMake build, dependency management, the
optional compiler and dependency caches, and the CI that gates merges.

> Reconstructed on 2026-11-18 from the repository as it stands. The
> original was written but never committed: `.gitignore`'s `build-*/` rule
> matched this directory. That rule is now anchored to the repository root.

### What this spec does not cover

- harbor's nested-KVM runs and their self-hosted runner (harbor task 9).
- Release packaging, UKI signing and Secure Boot (hull 10).

## Glossary

- **L1 cache** — the `vcpkg_installed/` tree, cached by `actions/cache`.
- **L2 cache** — the vcpkg binary cache and sccache compiler cache in OCI
  Object Storage, shared with kythira.
- **Floor** — the minimum supported version of a tool.

## Requirements

### Requirement 1: Toolchain floor

#### Acceptance Criteria

1. The build SHALL use C++23, CMake ≥ 3.28 and Ninja, with C++20 module
   scanning off.
2. The build SHALL accept GCC ≥ 14 or Clang ≥ 19, each with libstdc++ ≥ 14.
3. IF the compiler is below its floor THEN configure SHALL fail with a
   message naming the floor and, for Clang 18, the `std::expected` reason.

### Requirement 2: Dependencies

#### Acceptance Criteria

1. Library dependencies SHALL come from vcpkg manifest mode (`vcpkg.json`)
   pinned to kythira's `builtin-baseline`, with `version>=` floors.
2. A port that needs a newer commit than the baseline SHALL come from a git
   registry in `vcpkg-configuration.json` scoped to that port only.
3. A dependency not in the registry SHALL come from an overlay port in
   `vcpkg-overlays/`.
4. The build SHALL consume the installed tree through `CMAKE_PREFIX_PATH`
   (and `PKG_CONFIG_PATH` for `.pc`-only ports), not vcpkg's toolchain
   file, and SHALL also build against system packages.
5. An optional dependency SHALL be found QUIET, exposed as
   `AK_HAS_<DEP>`, and its dependent targets SHALL simply not be defined
   when it is absent. WHEN the vcpkg feature for it is installed and it is
   still not found, configure SHALL fail.
6. Every dependency SHALL be listed in `DEPENDENCIES.md` with status,
   purpose, minimum version and notes.

### Requirement 3: Build options and hardening

#### Acceptance Criteria

1. The build SHALL offer `AK_WERROR` (default ON), `AK_SANITIZE`
   (ASan + UBSan), `AK_FUZZ` (libFuzzer, Clang only) and `AK_TESTS`
   (default ON).
2. Every target SHALL link `ak::warnings` and `ak::hardening` (stack
   protector, stack-clash and CET protection, PIE, full RELRO,
   `_FORTIFY_SOURCE=3` outside Debug and sanitizer builds,
   `_GLIBCXX_ASSERTIONS`).

### Requirement 4: Caching is an accelerant

#### Acceptance Criteria

1. The build SHALL select a compiler launcher with `AK_COMPILER_LAUNCHER`
   (`auto`, `ccache`, `sccache`, `none`); `auto` SHALL prefer ccache, then
   sccache, then none.
2. CI SHALL cache the vcpkg installed tree (L1) and MAY use the shared OCI
   L2 caches.
3. A missing, unreachable or failing cache SHALL never fail a build; CI
   SHALL fall back to building from source and warn.
4. antikythera SHALL use its own credentials for the shared bucket, and
   pull-request jobs SHALL not be able to overwrite existing entries.

### Requirement 5: Continuous integration

#### Acceptance Criteria

1. WHEN a pull request is opened or updated, or main is pushed, CI SHALL
   build and run `ctest` with GCC 14 and with Clang 19.
2. CI SHALL run an ASan + UBSan build with tests, and SHALL build the fuzz
   targets with Clang.
3. CI SHALL check formatting with clang-format 22.1.5 and run clang-tidy 19
   with the repository's `.clang-tidy`.
4. CI SHALL run shellcheck over every shell script.
5. CI SHALL cross-build for arm64.
6. Every CI job SHALL be a required status check on main, so that no PR
   merges without passing CI.

### Requirement 6: Developer environments

#### Acceptance Criteria

1. WHEN a Claude Code cloud session starts in the repository, it SHALL
   install the toolchain floor, lint tools and test dependencies, so a
   fresh container can configure, build and run `ctest`.
2. The install SHALL skip packages already present, so a warm container
   starts quickly.
