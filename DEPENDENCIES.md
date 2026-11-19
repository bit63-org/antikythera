# Dependencies

Everything antikythera needs to build, test and run harbor, in the format
kythira's `DEPENDENCIES.md` uses. Library dependencies come from vcpkg
manifest mode (`vcpkg.json`, pinned to kythira's `builtin-baseline`); the
build also works against system packages. See
`.kiro/specs/build-and-ci/`.

## Required

### C++ compiler
- **GCC 14+** or **Clang 19+**, each with **libstdc++ 14+**.
- **Why not Clang 18**: it reports `__cpp_concepts 201907`, and libstdc++
  only declares `std::expected` when `__cpp_concepts >= 202002`. Every
  parser here returns `std::expected`, so Clang 18 cannot compile the
  project. Configure fails with that reason.

### Build system
- **CMake 3.28+** and **Ninja**.
- C++20 module scanning is turned off, so `clang-scan-deps` is not needed.

### Boost.Test
- **Status**: Required when `AK_TESTS=ON` (the default).
- **Purpose**: unit test framework, matching kythira (one executable per
  test file, each with `BOOST_TEST_MODULE`).
- **Minimum version**: 1.89 from vcpkg (`boost-test`). System Boost 1.83
  (Ubuntu 24.04) also works; `tests/CMakeLists.txt` adds
  `BOOST_TEST_DYN_LINK` when it finds a shared library.
- **Installation**: `vcpkg install`, or `sudo apt-get install libboost-test-dev`.

### OpenSSL
- **Status**: Required. `ak_hull` links `OpenSSL::Crypto` for command
  signature verification and `ak_helm` for the key store (AES-256-GCM
  key wrapping, `RAND_bytes`, `OPENSSL_cleanse`); oar-blk follows. CI uses
  Ubuntu 24.04's OpenSSL 3.0 (`libssl-dev`), so 3.0 is the configure
  floor.
- **Purpose**: Ed25519 command signatures, AES-256-GCM key wrapping in
  the helm key store, AES-256-XTS for oar-blk, `OPENSSL_cleanse` for key
  zeroization.
- **Minimum version**: 3.6.5, taken from the `microsoft/vcpkg` git
  registry in `vcpkg-configuration.json` (the same pin kythira uses for
  its crash fixes), leaving every other port on the baseline.

## Optional

### libvfio-user — harbor device servers
- **Status**: Optional. Enabled by the `vfio-user` vcpkg feature
  (`vcpkg install --x-feature=vfio-user`). Linux only.
- **Purpose**: the vfio-user server library behind `ak-testdev` and,
  later, the harbor transports for helm's mailbox, oar-net and oar-blk.
  Real boards use Linux `pci-epf` instead.
- **Version**: v0.8, commit `37491ed9af828fc161238dacd82e83ea35a09f87`,
  from the overlay port in `vcpkg-overlays/libvfio-user/` (it is not in
  the vcpkg registry). Pulls in `json-c`, plus `cmocka`, which upstream's
  meson build requires unconditionally.
- **Notes**: detected through `libvfio-user.pc`. Upstream v0.8 installs no
  `.pc` file, so the overlay port generates one (json-c under `Requires:`,
  since the library is static); a plain upstream `meson install` is found by
  a `find_path`/`find_library` fallback instead. `AK_VFIO_USER` (`AUTO`,
  `ON`, `OFF`) controls a missing library: under `AUTO`, the default, the
  device servers are skipped with a warning and `AK_HAS_LIBVFIO_USER` is
  `OFF`, unless the vcpkg `vfio-user` feature is installed, in which case
  configure fails. C++ code includes it
  only through `src/oar/vfu/libvfio_user.hpp`, which maps the headers' C11
  `_Static_assert` to `static_assert` for the include.

## Development tools

### clang-format
- **Version**: 22.1.5, from PyPI (`pip install clang-format==22.1.5`),
  the version kythira pins and generated `.clang-format` with.

### clang-tidy
- **Version**: 19. clang-tidy 18 cannot parse code that uses libstdc++'s
  `std::expected`, for the same reason Clang 18 cannot compile it.
  Kythira's `.clang-tidy` is used unchanged.

### libFuzzer
- **Status**: Optional, `AK_FUZZ=ON`. Ships with Clang; requires a Clang
  build.

### ccache / sccache
- **Status**: Optional accelerants, selected by `AK_COMPILER_LAUNCHER`
  (see `cmake/CompilerLauncher.cmake`). CI uses sccache against kythira's
  shared OCI bucket. A missing cache never fails a build.

## Claude Code cloud sessions

Cloud containers run Ubuntu 24.04, whose default GCC 13 is too old.
`.claude/hooks/session-start.sh` runs at session start (only when
`CLAUDE_CODE_REMOTE=true`) and installs from the Ubuntu archive: GCC 14,
Clang 19 with clang-tidy 19 and the libFuzzer runtime, CMake, Ninja,
Boost.Test 1.83, OpenSSL and shellcheck, plus clang-format 22.1.5 from
PyPI. It exports `CC=gcc-14`, `CXX=g++-14` and `CMAKE_GENERATOR=Ninja`,
so `cmake -S . -B build && cmake --build build && ctest --test-dir build`
works with no vcpkg step. Packages already present are skipped, so a warm
container starts in well under a second.

## harbor (virt-on-virt prototype)

Needed only on the workstation that runs harbor; none of these are build
dependencies. `harbor/check-host.sh` checks them all.

### KVM with nested virtualization
- `/dev/kvm` readable and writable, and `kvm_intel` or `kvm_amd` loaded
  with `nested=1`.

### QEMU
- **Version**: 10.1 or newer, with the `vfio-user-pci` device. The client
  is built by default on Linux; distribution packages may still be older.
- **Pinned build**: `harbor/deps.sh` builds QEMU **10.2.4** (SHA-256
  `821b545b92f165e57dddccac5077d76d4d436a226595b8813ad59306bbfd0746`)
  into `harbor/.prefix/` without touching the system.
- **Build prerequisites** (Ubuntu): `ninja-build`, `meson`, `pkg-config`,
  `libglib2.0-dev`, `libpixman-1-dev`, `libslirp-dev`, `python3-venv`,
  `flex`, `bison`.

### L1 guest image
- **Ubuntu 24.04 server cloud image (amd64)**, verified against the
  release's `SHA256SUMS` when downloaded by `harbor/deps.sh`.
- **cloud-image-utils** (`cloud-localds`) to build the cloud-init seed.
- **OpenSSH client** to reach L1 during phases 1 to 5 (the strict hull
  image of phase 6 has no network stack).

### hull kernel source
- **Status**: needed only to resolve or build the hull kernel
  (`harbor/kernel/build.sh`); not a build dependency of the C++ tree.
- **Version**: any tree from **6.8** on. CI and cloud threads use
  Ubuntu 24.04's `linux-source-6.8.0` package (signed by the archive);
  the kernel version the UKI pins is chosen with hull task 10.
- **Prerequisites**: `flex`, `bison` and `bc` to resolve the config; a
  full build (`--build`) also needs `libelf-dev` and `libssl-dev`.
- **Python 3** runs `harbor/kernel/check-config.py` and its test
  (`tests/kernel_config_test.py`, skipped by CTest without Python).
