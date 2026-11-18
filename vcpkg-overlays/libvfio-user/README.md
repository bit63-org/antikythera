# libvfio-user overlay port

libvfio-user is not in the vcpkg registry, so this overlay builds it from
upstream at tag `v0.8` (commit `37491ed9af828fc161238dacd82e83ea35a09f87`).

- **Fetch:** `vcpkg_from_git` pinned to the commit. The commit hash is the
  integrity check, so there is no archive SHA512 to maintain.
- **Build:** meson, with the pipe transport, debug logs and the flaky
  client/server test turned off.
- **cmocka:** upstream's `meson.build` requires it unconditionally, even
  though only its own unit tests use it.
- **Removed from the package:** sample binaries under `bin/`.

This is third-party content, so per the copyright-header rules the portfile
carries no antikythera copyright notice.

To bump the version, change `REF` and `version-string` together. The QEMU
vfio-user client and libvfio-user must speak the same protocol version, so
re-run the harbor phase 1 checks afterwards.
