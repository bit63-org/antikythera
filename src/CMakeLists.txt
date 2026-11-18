# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# ak_common: header-only wire helpers shared by every role.
add_library(ak_common INTERFACE)
add_library(ak::common ALIAS ak_common)
target_include_directories(ak_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# ak_proto: header-only controller wire formats (Envelope, MapUpdate) and
# their signing test vectors. Depends only on ak_common so kythira's EC2
# module can include it directly (.kiro/specs/controller-interface/).
add_library(ak_proto INTERFACE)
add_library(ak::proto ALIAS ak_proto)
target_link_libraries(ak_proto INTERFACE ak::common)

# oar-net: Geneve encapsulation, VTEP ingress policy and the controller
# mapping table (network data plane).
add_library(ak_oar_net
  oar/net/geneve.cpp
  oar/net/mapping_table.cpp
  oar/net/vtep_policy.cpp)
add_library(ak::oar_net ALIAS ak_oar_net)
target_link_libraries(ak_oar_net
  PUBLIC ak::common
  PRIVATE ak::warnings ak::hardening)

# OpenSSL is required: AES-256-GCM key wrapping and OPENSSL_cleanse in the
# helm key store, and Ed25519 in hull (the only implementation here). CI
# builds against Ubuntu 24.04's OpenSSL 3.0, so 3.0 is the configure floor.
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# helm: control-plane mailbox protocol, device pool, MCTP sideband framing
# and key store.
add_library(ak_helm
  helm/device_pool.cpp
  helm/key_store.cpp
  helm/mailbox.cpp
  helm/mctp.cpp
  helm/scoped_key.cpp
  helm/secure_element.cpp)
add_library(ak::helm ALIAS ak_helm)
target_link_libraries(ak_helm
  PUBLIC ak::common
  PRIVATE OpenSSL::Crypto ak::warnings ak::hardening)

# hull: host-agent command authentication (Ed25519 signatures and sequence
# numbers) and the core / huge-page allocator.
add_library(ak_hull
  hull/command_auth.cpp
  hull/cpu_topology.cpp
  hull/resource_allocator.cpp
  hull/sequence_tracker.cpp
  hull/signature_verifier.cpp)
add_library(ak::hull ALIAS ak_hull)
target_link_libraries(ak_hull
  PUBLIC ak::common ak::helm OpenSSL::Crypto
  PRIVATE ak::warnings ak::hardening)

# oar-blk: AES-256-XTS volume encryption (storage data plane).
add_library(ak_oar_blk
  oar/blk/xts_cipher.cpp)
add_library(ak::oar_blk ALIAS ak_oar_blk)
target_link_libraries(ak_oar_blk
  PUBLIC ak::common OpenSSL::Crypto
  PRIVATE ak::warnings ak::hardening)

# vfio-user device servers, built against libvfio-user (the `vfio-user`
# vcpkg feature, vcpkg-overlays/libvfio-user).
#
# AK_VFIO_USER picks what happens when libvfio-user is missing:
#   AUTO  build the device servers if libvfio-user is found, otherwise skip
#         them (kythira's graceful-degradation pattern). If the vcpkg feature
#         is installed, AUTO behaves like ON: a feature that is installed but
#         cannot be found is a bug, not an absent optional dependency.
#   ON    a missing libvfio-user is a configure error.
#   OFF   never build them.
set(AK_VFIO_USER AUTO CACHE STRING "Build vfio-user device servers: AUTO, ON or OFF")
set_property(CACHE AK_VFIO_USER PROPERTY STRINGS AUTO ON OFF)
if(NOT AK_VFIO_USER MATCHES "^(AUTO|ON|OFF)$")
  message(FATAL_ERROR "AK_VFIO_USER must be AUTO, ON or OFF (got '${AK_VFIO_USER}')")
endif()

set(_ak_vfio_user_required OFF)
set(_ak_vfio_user_reason "")
if(AK_VFIO_USER STREQUAL "ON")
  set(_ak_vfio_user_required ON)
  set(_ak_vfio_user_reason "AK_VFIO_USER=ON")
elseif(AK_VFIO_USER STREQUAL "AUTO")
  # vcpkg installs the port's copyright file here; its presence means the
  # `vfio-user` feature was installed into this tree.
  set(_ak_vfio_user_port "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share/libvfio-user")
  if(EXISTS "${_ak_vfio_user_port}")
    set(_ak_vfio_user_required ON)
    set(_ak_vfio_user_reason "the vcpkg `vfio-user` feature is installed (${_ak_vfio_user_port})")
  endif()
  unset(_ak_vfio_user_port)
endif()

if(NOT AK_VFIO_USER STREQUAL "OFF")
  # Preferred: libvfio-user.pc. Upstream installs none, so the overlay port
  # generates one; a hand-written one on PKG_CONFIG_PATH works too.
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBVFIO_USER QUIET IMPORTED_TARGET libvfio-user)
  endif()
  if(LIBVFIO_USER_FOUND)
    add_library(ak_libvfio_user INTERFACE)
    target_link_libraries(ak_libvfio_user INTERFACE PkgConfig::LIBVFIO_USER)
    set(_ak_vfio_user_via "pkg-config, version ${LIBVFIO_USER_VERSION}")
  else()
    # Fallback for a plain upstream `meson install` (no .pc file): find the
    # header and library directly. json-c is needed too, since the library
    # may be static.
    find_path(LIBVFIO_USER_INCLUDE_DIR libvfio-user.h PATH_SUFFIXES vfio-user)
    find_library(LIBVFIO_USER_LIBRARY vfio-user)
    find_package(json-c CONFIG QUIET)
    if(LIBVFIO_USER_INCLUDE_DIR AND LIBVFIO_USER_LIBRARY AND TARGET json-c::json-c)
      find_package(Threads REQUIRED)
      add_library(ak_libvfio_user INTERFACE)
      target_include_directories(ak_libvfio_user SYSTEM INTERFACE ${LIBVFIO_USER_INCLUDE_DIR})
      target_link_libraries(ak_libvfio_user INTERFACE
        ${LIBVFIO_USER_LIBRARY} json-c::json-c Threads::Threads)
      set(LIBVFIO_USER_FOUND ON)
      set(_ak_vfio_user_via "${LIBVFIO_USER_LIBRARY}")
    endif()
  endif()
endif()

if(LIBVFIO_USER_FOUND)
  set(AK_HAS_LIBVFIO_USER ON CACHE INTERNAL "libvfio-user found")
  message(STATUS "libvfio-user (${_ak_vfio_user_via}): building vfio-user device servers")
  add_executable(ak-testdev oar/testdev/main.cpp)
  target_link_libraries(ak-testdev PRIVATE ak_libvfio_user ak::common ak::warnings ak::hardening)
  # libvfio-user's capability headers are C with bit-fields and packed
  # structs; keep our strict flags but do not fail on its headers.
  target_compile_options(ak-testdev PRIVATE -Wno-pedantic)
  install(TARGETS ak-testdev RUNTIME DESTINATION bin)
elseif(_ak_vfio_user_required)
  message(FATAL_ERROR
    "libvfio-user not found, but it is required because ${_ak_vfio_user_reason}.\n"
    "Looked for libvfio-user.pc on PKG_CONFIG_PATH, then for libvfio-user.h and "
    "libvfio-user (with json-c) under CMAKE_PREFIX_PATH.\n"
    "If vcpkg built it, re-run `vcpkg install --x-feature=vfio-user` so the overlay "
    "port regenerates libvfio-user.pc. Pass -DAK_VFIO_USER=OFF to build without "
    "the vfio-user device servers.")
else()
  set(AK_HAS_LIBVFIO_USER OFF CACHE INTERNAL "libvfio-user found")
  if(AK_VFIO_USER STREQUAL "OFF")
    message(STATUS "AK_VFIO_USER=OFF: vfio-user device servers not built")
  else()
    message(WARNING "libvfio-user not found: vfio-user device servers (ak-testdev) not built. "
                    "Install the `vfio-user` vcpkg feature to enable them, or pass "
                    "-DAK_VFIO_USER=OFF to silence this warning.")
  endif()
endif()
unset(_ak_vfio_user_required)
unset(_ak_vfio_user_reason)
unset(_ak_vfio_user_via)
