# libvfio-user v0.8 (nutanix/libvfio-user, BSD-3-Clause).
#
# Fetched with vcpkg_from_git pinned to the tag's commit rather than a
# GitHub archive tarball: the commit hash is the integrity check, and there
# is no generated-tarball SHA512 to drift.
vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL https://github.com/nutanix/libvfio-user.git
    REF 37491ed9af828fc161238dacd82e83ea35a09f87
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
vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")
# Upstream installs sample binaries; they are not part of the library.
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/bin" "${CURRENT_PACKAGES_DIR}/debug/bin")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
