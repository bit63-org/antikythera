# libvfio-user overlay port

libvfio-user is not in the vcpkg registry, so this overlay builds it from
upstream at tag `v0.8` (commit `37491ed9af828fc161238dacd82e83ea35a09f87`).

- **Fetch:** `vcpkg_from_git` pinned to the commit. The commit hash is the
  integrity check, so there is no archive SHA512 to maintain.
- **Build:** meson, with the pipe transport, debug logs and the flaky
  client/server test turned off.
- **cmocka:** upstream's `meson.build` requires it unconditionally, even
  though only its own unit tests use it.
- **pkg-config:** upstream installs no `libvfio-user.pc`, so the portfile
  writes one (skipped if upstream ever ships its own). On static triplets
  json-c and `-pthread` are public (`Requires:`/`Libs:`), because CMake's
  `pkg_check_modules(IMPORTED_TARGET)` ignores the `.private` fields.
- **Removed from the package:** sample binaries under `bin/`.
- **Patch `0001`:** DMA unmaps over an address range remove every region
  inside it, as the kernel's VFIO type1 does, instead of failing with
  ENOENT unless the range matches one region exactly. QEMU's intel-iommu
  sends such range unmaps once the guest enables its IOMMU; without the
  patch, stale regions make the next map of a reused IOVA fail and QEMU
  drops the device. It touches upstream's unit and Python tests too; drop
  it once upstream behaves the same.

This is third-party content, so per the copyright-header rules the portfile
carries no antikythera copyright notice.

To bump the version, change `REF` and `version-string` together, reset
`port-version`, and check whether patch `0001` still applies or is still needed. The QEMU
vfio-user client and libvfio-user must speak the same protocol version, so
re-run the harbor phase 1 checks afterwards.
