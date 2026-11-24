# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Cross-compile for 64-bit Arm Linux from an x86-64 Ubuntu host with GCC 14
# (g++-14-aarch64-linux-gnu) and Debian multiarch arm64 libraries
# (libssl-dev:arm64, libboost-test-dev:arm64), as installed by
# .github/scripts/arm64-multiarch.sh.
#
#   cmake -S . -B build-arm64 \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake
#
# CMAKE_SYSTEM_PROCESSOR=aarch64 makes cmake/Vcpkg.cmake pick arm64-linux.
# CMAKE_LIBRARY_ARCHITECTURE lets find_package search the multiarch
# directories (/usr/lib/aarch64-linux-gnu) under the usual /usr prefix, so
# no sysroot is needed. The root path modes keep the host's x86-64
# libraries from being picked up for the target.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)

set(_ak_triple aarch64-linux-gnu)
set(CMAKE_C_COMPILER   ${_ak_triple}-gcc-14)
set(CMAKE_CXX_COMPILER ${_ak_triple}-g++-14)
unset(_ak_triple)

set(PKG_CONFIG_EXECUTABLE aarch64-linux-gnu-pkg-config CACHE FILEPATH "")
set(ENV{PKG_CONFIG_LIBDIR} "/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
