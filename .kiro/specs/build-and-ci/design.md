# Design Document — Build system, dependencies, caching and CI

## Overview

```
vcpkg.json ─► vcpkg install (manifest) ─► vcpkg_installed/<triplet>
     ▲                │ L2: x-aws → OCI bucket vcpkg/<triplet>/
     │                ▼
 actions/cache L1 (whole tree, keyed on manifest hashes)
                      │
 cmake (cmake/Vcpkg.cmake: CMAKE_PREFIX_PATH) ─► ninja ─► ctest
             └─ AK_COMPILER_LAUNCHER=sccache (only if start-sccache.sh probe passed)
                          └─ OCI bucket sccache/
```

## Bucket — decided: share kythira's

Antikythera uses **kythira's OCI build-cache bucket**, with its own
credentials (repository secrets in antikythera, same three-key model:
read-write for `main`, create-only for same-repository pull requests,
read-only otherwise).

- vcpkg archives are content-addressed by ABI hash, so identical ports
  (OpenSSL, Boost) built by either repository are reused.
- sccache keys cover the preprocessed source and full compiler invocation,
  so entries from the two repositories cannot collide; the shared
  `sccache/` prefix and its 30-day lifecycle rule apply unchanged.
- No new bucket, lifecycle policy or cost line. Antikythera's traffic
  shows up in kythira's `scripts/oci-build-cache/audit.sh` output.
- Trade-off accepted: a leaked antikythera key can add entries to the
  cache kythira also reads. That is the same residual risk kythira already
  accepts for its own pull-request key (create-only, no overwrite, no
  delete), and IAM bounds it the same way.

The `oci-build-cache` action is copied from kythira with the
Rust/lakers-specific parts (the `RUSTC_WRAPPER` export and its
`VCPKG_KEEP_ENV_VARS` entries) removed.

## Files

| File | Origin |
|---|---|
| `cmake/Vcpkg.cmake`, `cmake/CompilerLauncher.cmake` | adapted from kythira's top-level CMakeLists |
| `scripts/oci-build-cache/start-sccache.sh` | copied from kythira |
| `.github/actions/oci-build-cache/action.yml` | to be adapted from kythira |
| `.clang-format`, `.clang-tidy` | copied from kythira |

## Tool versions

| Tool | Version | Why |
|---|---|---|
| clang-format | 22.1.5 from PyPI (`pip install clang-format==22.1.5`) | the version kythira pins and generated `.clang-format` with |
| clang-tidy | 19 | clang-tidy 18's frontend has the same `std::expected` limitation as Clang 18 and cannot parse this code; kythira's `.clang-tidy` is otherwise used unchanged |
