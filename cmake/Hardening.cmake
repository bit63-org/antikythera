# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Hardening flags for everything that ships (agent, control plane, data planes).
add_library(ak_hardening INTERFACE)
add_library(ak::hardening ALIAS ak_hardening)

target_compile_options(ak_hardening INTERFACE
  -fstack-protector-strong
  -fstack-clash-protection
  -fcf-protection=full
  -fPIE)

# _FORTIFY_SOURCE needs optimization and conflicts with ASan.
if(NOT AK_SANITIZE)
  target_compile_options(ak_hardening INTERFACE
    $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3>)
endif()

# libstdc++ bounds/precondition checks on containers and views.
target_compile_definitions(ak_hardening INTERFACE _GLIBCXX_ASSERTIONS)

target_link_options(ak_hardening INTERFACE
  -pie
  -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
