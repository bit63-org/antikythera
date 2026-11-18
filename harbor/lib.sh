# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for harbor scripts (.kiro/specs/harbor-virt-on-virt/).
# Sourced, never executed.

# shellcheck shell=bash
# Variables here are consumed by the scripts that source this file.
# shellcheck disable=SC2034

HARBOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${HARBOR_DIR}/.." && pwd)"
PREFIX="${HARBOR_PREFIX:-${HARBOR_DIR}/.prefix}"
RUN_DIR="${HARBOR_RUN_DIR:-${HARBOR_DIR}/.run}"
AK_BUILD_DIR="${AK_BUILD_DIR:-${REPO_DIR}/build}"

# Minimum QEMU with the vfio-user client, and the version deps.sh pins.
QEMU_MIN_MAJOR=10
QEMU_MIN_MINOR=1
QEMU_PIN_VERSION="10.2.4"
QEMU_PIN_SHA256="821b545b92f165e57dddccac5077d76d4d436a226595b8813ad59306bbfd0746"

# L1 guest image: Ubuntu 24.04 server cloud image, verified against the
# release's SHA256SUMS at download time.
L1_IMAGE_URL_BASE="https://cloud-images.ubuntu.com/releases/noble/release"
L1_IMAGE_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
L1_IMAGE="${PREFIX}/images/${L1_IMAGE_NAME}"

# vfio-user test device identity (src/oar/testdev/main.cpp).
TESTDEV_VENDOR="1de5"
TESTDEV_DEVICE="a001"

log() { printf 'harbor: %s\n' "$*" >&2; }
die() {
    printf 'harbor: error: %s\n' "$*" >&2
    exit 1
}

# Prefer the pinned build in $PREFIX; fall back to the system QEMU.
qemu_bin() {
    if [[ -x "${PREFIX}/bin/qemu-system-x86_64" ]]; then
        printf '%s\n' "${PREFIX}/bin/qemu-system-x86_64"
    else
        command -v qemu-system-x86_64 || true
    fi
}

qemu_img_bin() {
    if [[ -x "${PREFIX}/bin/qemu-img" ]]; then
        printf '%s\n' "${PREFIX}/bin/qemu-img"
    else
        command -v qemu-img || true
    fi
}

testdev_bin() { printf '%s\n' "${AK_BUILD_DIR}/src/ak-testdev"; }
