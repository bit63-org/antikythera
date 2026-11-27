# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Project-wide warning flags, applied through the ak::warnings interface target.
add_library(ak_warnings INTERFACE)
add_library(ak::warnings ALIAS ak_warnings)

target_compile_options(ak_warnings INTERFACE
  -Wall -Wextra -Wpedantic
  -Wshadow -Wconversion -Wsign-conversion
  -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
  -Woverloaded-virtual -Wnull-dereference
  -Wimplicit-fallthrough -Wformat=2)

if(AK_WERROR)
  target_compile_options(ak_warnings INTERFACE -Werror)
  # GCC's flow-sensitive warnings only fire once the optimizer inlines
  # libstdc++ (std::istreambuf_iterator, std::vector, std::optional,
  # std::variant), and under -O2 with _FORTIFY_SOURCE and
  # _GLIBCXX_ASSERTIONS GCC 14 reports paths the code cannot take: about
  # a hundred of them, almost all inside libstdc++ headers. Keep them as
  # warnings so new ones stay visible, but do not fail optimized GCC
  # builds on them. Debug builds never see them, and Clang has no such
  # false positives, so both keep the full -Werror set.
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(ak_warnings INTERFACE
      $<$<NOT:$<CONFIG:Debug>>:-Wno-error=null-dereference>
      $<$<NOT:$<CONFIG:Debug>>:-Wno-error=maybe-uninitialized>
      $<$<NOT:$<CONFIG:Debug>>:-Wno-error=array-bounds>
      $<$<NOT:$<CONFIG:Debug>>:-Wno-error=stringop-overflow>
      $<$<NOT:$<CONFIG:Debug>>:-Wno-error=free-nonheap-object>)
  endif()
endif()
