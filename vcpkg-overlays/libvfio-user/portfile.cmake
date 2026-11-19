# libvfio-user v0.8 (nutanix/libvfio-user, BSD-3-Clause).
#
# Fetched with vcpkg_from_git pinned to the tag's commit rather than a
# GitHub archive tarball: the commit hash is the integrity check, and there
# is no generated-tarball SHA512 to drift.
vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL https://github.com/nutanix/libvfio-user.git
    REF 37491ed9af828fc161238dacd82e83ea35a09f87
    # Range unmaps as VFIO type1 does them; see the patch header.
    PATCHES
        0001-dma-unmap-ranges-like-vfio-type1.patch
)

# cmocka is declared unconditionally by upstream's meson.build even though
# only its unit tests use it, hence the cmocka dependency in vcpkg.json.
vcpkg_configure_meson(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -Dtran-pipe=false
        -Ddebug-logs=disabled
        -Dshadow-ioeventfd=false
        -Dclient-server-test=false
)

vcpkg_install_meson()

# Upstream's meson.build (v0.8) installs no pkg-config file, and
# antikythera finds libvfio-user through pkg-config, so generate one.
# Skipped if a future upstream release starts shipping its own.
#
# json-c goes under Requires, not Requires.private, on static triplets:
# CMake's pkg_check_modules(IMPORTED_TARGET) links only the public fields,
# and a static libvfio-user.a needs json-c (and pthreads) at final link.
if(VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    set(LIBVFIO_USER_PC_REQUIRES "Requires: json-c")
    set(LIBVFIO_USER_PC_LIBS "-L\${libdir} -lvfio-user -pthread")
else()
    set(LIBVFIO_USER_PC_REQUIRES "Requires.private: json-c")
    set(LIBVFIO_USER_PC_LIBS "-L\${libdir} -lvfio-user")
endif()
foreach(pc_dir IN ITEMS "lib/pkgconfig" "debug/lib/pkgconfig")
    if(pc_dir MATCHES "^debug/")
        set(pc_build_type "debug")
        set(pc_includedir "\${prefix}/../include")
    else()
        set(pc_build_type "release")
        set(pc_includedir "\${prefix}/include")
    endif()
    if(NOT VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL pc_build_type)
        set(pc_file "${CURRENT_PACKAGES_DIR}/${pc_dir}/libvfio-user.pc")
        if(NOT EXISTS "${pc_file}")
            # Headers install to include/vfio-user/ and are included as
            # <libvfio-user.h>, hence the subdirectory in Cflags.
            file(WRITE "${pc_file}" "\
prefix=\${pcfiledir}/../..
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=${pc_includedir}

Name: libvfio-user
Description: Framework for emulating PCI devices in userspace over the vfio-user protocol
URL: https://github.com/nutanix/libvfio-user
Version: ${VERSION}
${LIBVFIO_USER_PC_REQUIRES}
Libs: ${LIBVFIO_USER_PC_LIBS}
Cflags: -I\${includedir}/vfio-user
")
        endif()
    endif()
endforeach()
vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")
# Upstream installs sample binaries; they are not part of the library.
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/bin" "${CURRENT_PACKAGES_DIR}/debug/bin")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
