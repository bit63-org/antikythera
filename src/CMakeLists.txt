# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# ak_common: header-only wire helpers shared by every role.
add_library(ak_common INTERFACE)
add_library(ak::common ALIAS ak_common)
target_include_directories(ak_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# oar-net: Geneve encapsulation and VTEP ingress policy (network data plane).
add_library(ak_oar_net
  oar/net/geneve.cpp
  oar/net/vtep_policy.cpp)
add_library(ak::oar_net ALIAS ak_oar_net)
target_link_libraries(ak_oar_net
  PUBLIC ak::common
  PRIVATE ak::warnings ak::hardening)

# helm: control-plane mailbox protocol.
add_library(ak_helm
  helm/mailbox.cpp)
add_library(ak::helm ALIAS ak_helm)
target_link_libraries(ak_helm
  PUBLIC ak::common
  PRIVATE ak::warnings ak::hardening)

# vfio-user device servers. Optional dependency, following kythira's
# graceful-degradation pattern: when libvfio-user is absent the targets are
# simply not defined and the rest of the build is unaffected.
# Supplied by the `vfio-user` vcpkg feature (vcpkg-overlays/libvfio-user).
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBVFIO_USER QUIET IMPORTED_TARGET libvfio-user)
endif()
if(LIBVFIO_USER_FOUND)
  set(AK_HAS_LIBVFIO_USER ON CACHE INTERNAL "libvfio-user found")
  message(STATUS "libvfio-user ${LIBVFIO_USER_VERSION}: building vfio-user device servers")
  add_executable(ak-testdev oar/testdev/main.cpp)
  target_link_libraries(ak-testdev PRIVATE PkgConfig::LIBVFIO_USER ak::common ak::warnings ak::hardening)
  # libvfio-user's capability headers are C with bit-fields and packed
  # structs; keep our strict flags but do not fail on its headers.
  target_compile_options(ak-testdev PRIVATE -Wno-pedantic)
  install(TARGETS ak-testdev RUNTIME DESTINATION bin)
else()
  set(AK_HAS_LIBVFIO_USER OFF CACHE INTERNAL "libvfio-user found")
  message(STATUS "libvfio-user not found: vfio-user device servers not built "
                 "(install the `vfio-user` vcpkg feature to enable)")
endif()
