# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# vcpkg manifest-mode integration, following kythira's convention: the
# installed tree lives at <source>/vcpkg_installed (produced by
# `vcpkg install` in manifest mode, a separate step from configure) and is
# consumed through CMAKE_PREFIX_PATH rather than vcpkg's toolchain file.
#
# Only 64-bit x86 and 64-bit Arm Linux are targeted; anything else falls back
# to x64-linux rather than failing configure.

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(AK_VCPKG_TRIPLET "arm64-linux")
else()
  set(AK_VCPKG_TRIPLET "x64-linux")
endif()

# Some ports' *-config.cmake scripts reference these two variables, which
# only vcpkg's toolchain file normally defines. Define them unless a caller
# already did (for example by using the real toolchain file).
if(NOT DEFINED _VCPKG_INSTALLED_DIR)
  set(_VCPKG_INSTALLED_DIR "${CMAKE_SOURCE_DIR}/vcpkg_installed" CACHE PATH
      "vcpkg manifest-mode install root, for port *-config.cmake scripts that need it directly")
endif()
if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  set(VCPKG_TARGET_TRIPLET "${AK_VCPKG_TRIPLET}" CACHE STRING
      "vcpkg triplet, for port *-config.cmake scripts that need it directly")
endif()

set(_ak_vcpkg_prefix "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
if(EXISTS "${_ak_vcpkg_prefix}")
  list(PREPEND CMAKE_PREFIX_PATH "${_ak_vcpkg_prefix}")
  # Ports built with meson/autotools (libvfio-user, json-c) ship .pc files only.
  set(ENV{PKG_CONFIG_PATH} "${_ak_vcpkg_prefix}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
  message(STATUS "vcpkg installed tree: ${_ak_vcpkg_prefix}")
else()
  message(STATUS "vcpkg installed tree not found at ${_ak_vcpkg_prefix}; using system packages")
endif()
unset(_ak_vcpkg_prefix)
