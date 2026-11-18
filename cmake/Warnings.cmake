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
endif()
