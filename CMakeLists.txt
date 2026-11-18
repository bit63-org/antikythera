# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

project(antikythera
  VERSION 0.1.0
  DESCRIPTION "Minimal-attack-surface VM host with a PCIe backplane of control-plane and data-plane roles"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# No C++20 modules (uneven toolchain support); skip CMake's module dependency scan,
# which otherwise requires clang-scan-deps for every Clang build.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Minimum toolchains: GCC 14 or Clang 19, each with libstdc++ 14 or newer.
# Clang 18 is not enough: it reports __cpp_concepts 201907, and libstdc++
# only exposes std::expected when __cpp_concepts >= 202002 (Clang 19+).
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
  message(FATAL_ERROR "antikythera requires GCC >= 14 (found ${CMAKE_CXX_COMPILER_VERSION})")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19)
  message(FATAL_ERROR "antikythera requires Clang >= 19 (found ${CMAKE_CXX_COMPILER_VERSION}); "
                      "Clang 18 cannot use libstdc++'s std::expected")
endif()

option(AK_WERROR   "Treat warnings as errors"                  ON)
option(AK_SANITIZE "Build with AddressSanitizer + UBSan"       OFF)
option(AK_FUZZ     "Build libFuzzer targets (requires Clang)"  OFF)
option(AK_TESTS    "Build unit tests (requires Boost.Test)"    ON)

# Dependencies come from vcpkg manifest mode (vcpkg.json), consumed through
# CMAKE_PREFIX_PATH exactly as kythira does -- see cmake/Vcpkg.cmake.
include(Vcpkg)
include(CompilerLauncher)
include(Warnings)
include(Hardening)
include(Sanitizers)

add_subdirectory(src)

if(AK_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(AK_FUZZ)
  add_subdirectory(fuzz)
endif()
