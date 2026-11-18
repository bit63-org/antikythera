# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Compiler launcher, matching kythira's KYTHIRA_COMPILER_LAUNCHER semantics:
#
#   auto    ccache if on PATH, else sccache, else none (developer default:
#           a machine that already uses ccache keeps using it)
#   ccache  / sccache   required -- configure fails if it is missing
#   none    no launcher
#
# An explicitly requested launcher that is missing is fatal on purpose: a
# CI leg that asks for a compiler cache and silently gets none still goes
# green, and nobody notices the cost. In CI, sccache is selected by name only
# after scripts/oci-build-cache/start-sccache.sh proved a compile round-trips.

set(AK_COMPILER_LAUNCHER "auto" CACHE STRING
    "Compiler launcher: auto (ccache, then sccache, then none), ccache, sccache or none")
set_property(CACHE AK_COMPILER_LAUNCHER PROPERTY STRINGS auto ccache sccache none)

set(_ak_launcher "")
if(AK_COMPILER_LAUNCHER STREQUAL "auto")
  # Two cache entries, not one find_program(NAMES ccache sccache): a single
  # shared entry would pin whichever launcher the tree was first configured
  # with and silently ignore a later change.
  find_program(AK_CCACHE_PROGRAM ccache)
  find_program(AK_SCCACHE_PROGRAM sccache)
  if(AK_CCACHE_PROGRAM)
    set(_ak_launcher "${AK_CCACHE_PROGRAM}")
  elseif(AK_SCCACHE_PROGRAM)
    set(_ak_launcher "${AK_SCCACHE_PROGRAM}")
  endif()
elseif(NOT AK_COMPILER_LAUNCHER STREQUAL "none")
  string(TOUPPER "${AK_COMPILER_LAUNCHER}" _ak_launcher_upper)
  find_program(AK_${_ak_launcher_upper}_PROGRAM NAMES "${AK_COMPILER_LAUNCHER}")
  set(_ak_launcher "${AK_${_ak_launcher_upper}_PROGRAM}")
  if(NOT _ak_launcher)
    message(FATAL_ERROR "AK_COMPILER_LAUNCHER=${AK_COMPILER_LAUNCHER} but it is not on PATH")
  endif()
  unset(_ak_launcher_upper)
endif()

if(_ak_launcher)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${_ak_launcher}" CACHE STRING "" FORCE)
  message(STATUS "compiler launcher: ${_ak_launcher}")
else()
  # Clear rather than leave alone, so reconfiguring down to `none` sticks.
  set(CMAKE_CXX_COMPILER_LAUNCHER "" CACHE STRING "" FORCE)
  message(STATUS "compiler launcher: none")
endif()
unset(_ak_launcher)

# Clang stamps header mtimes into precompiled headers, which changes the
# sccache key on every fresh configure. Harmless now; matters once a PCH exists.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  list(APPEND CMAKE_CXX_COMPILE_OPTIONS_CREATE_PCH -Xclang -fno-pch-timestamp)
endif()
