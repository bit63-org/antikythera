---
title: Technology
inclusion: always
---

# Technology steering

## Language and toolchain

- **C++23**, built with CMake ≥ 3.28 and Ninja.
- **Minimum compilers: GCC 14 or Clang 19**, each with libstdc++ ≥ 14.
  Clang 18 is not enough: it reports `__cpp_concepts 201907`, and
  libstdc++ only exposes `std::expected` when `__cpp_concepts >= 202002`.
- C++20 modules are not used; `CMAKE_CXX_SCAN_FOR_MODULES` is off.
- Code style follows `cpp-coding-standards.md` and tests follow
  `test-execution-standards.md`, both inherited from kythira.
- Formatting: clang-format 22.1.5 (kythira's pinned PyPI version).
  Static analysis: clang-tidy 19 with kythira's `.clang-tidy` (clang-tidy
  18 cannot parse code that uses libstdc++'s `std::expected`).

## C++23 usage

- `std::expected<T, Error>` for every parse and validation; no exceptions on
  untrusted-input paths.
- Wire formats are decoded field by field through `ak::wire` (bounds-checked
  `Reader`/`Writer`/`SpanWriter`), never by casting pointers to structs.
- `std::byteswap` + `std::endian` for byte order.
- Avoid `std::start_lifetime_as` (unimplemented), modules, and
  `std::stacktrace` in release builds.
- C libraries (libvfio-user, OpenSSL) are wrapped in RAII types with
  `std::unique_ptr` and custom deleters, in few, small files.
  libvfio-user is included only through `oar/vfu/libvfio_user.hpp`.

## Dependencies

Managed exactly as kythira manages them (see `build-and-ci` spec):

- **vcpkg manifest mode** (`vcpkg.json`), pinned `builtin-baseline` (the
  same commit kythira uses), `version>=` floors, a git registry in
  `vcpkg-configuration.json` for ports that need a newer commit (OpenSSL),
  and overlay ports in `vcpkg-overlays/` for anything not in the registry
  (libvfio-user).
- Consumed through `CMAKE_PREFIX_PATH` from `<source>/vcpkg_installed`, not
  vcpkg's toolchain file.
- **Optional dependencies degrade gracefully**: `find_package`/`pkg_check_modules`
  QUIET, an `AK_HAS_<DEP>` flag, and dependent targets simply not defined
  when absent.
- Every dependency is documented in `DEPENDENCIES.md` with status, purpose,
  minimum version and notes.

Current set: Boost.Test (tests), OpenSSL ≥ 3 (AES-XTS, Ed25519, later
WireGuard/IPsec keys), libvfio-user v0.8 (harbor device servers).

## Build caching

Mirrors kythira's `doc/ci_build_cache.md`: a `vcpkg_installed/` tree cache
(L1, `actions/cache`) in front of a vcpkg binary cache and an sccache
compiler cache in OCI Object Storage (L2), selected per event by the
`oci-build-cache` composite action. **The cache is never a build
dependency**: absence or failure degrades to building from source.

## External components (not written here)

| Component | Role | Notes |
|---|---|---|
| Linux kernel | hull host kernel | `allnoconfig`-based, KVM + VFIO + IOMMU only |
| Cloud Hypervisor | VMM in hull | Rust; run as a jailed external binary |
| QEMU ≥ 10.1 | harbor L0 only | vfio-user client; never on a real host |
| libvfio-user | harbor device transport | replaced by Linux `pci-epf` on hardware |
| SPDK | possible later storage backend | not yet a dependency |

## Portability

x86-64 first. Arm64 differences (SMMUv3, GICv4.1, guest boot) live in
per-platform configuration, never in agent or role code. CI cross-builds
arm64 from the start.
