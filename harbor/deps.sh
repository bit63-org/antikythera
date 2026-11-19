#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Fetches harbor's pinned dependencies into harbor/.prefix without touching
# the system (.kiro/specs/harbor-virt-on-virt/ Requirement 1.2):
#
#   qemu   build QEMU ${QEMU_PIN_VERSION} (x86_64-softmmu, vfio-user client)
#   image  download the Ubuntu 24.04 cloud image, verified against SHA256SUMS
#   ch     download Cloud Hypervisor ${CH_PIN_VERSION} (static, pinned SHA-256)
#          for L1 to run L2 guests with (phase 2 on)
#   all    all three (default)
#
# A checksum mismatch is always fatal: a wrong binary or image is never
# something to warn about and continue from.
#
# Usage: harbor/deps.sh [qemu|image|ch|all]

set -euo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

what="${1:-all}"

fetch_qemu() {
    local src="${PREFIX}/src"
    local tarball="qemu-${QEMU_PIN_VERSION}.tar.xz"
    mkdir -p "${src}"
    if [[ ! -f "${src}/${tarball}" ]]; then
        log "downloading ${tarball}"
        curl --retry 3 -sSfL -o "${src}/${tarball}.part" "https://download.qemu.org/${tarball}"
        mv "${src}/${tarball}.part" "${src}/${tarball}"
    fi
    echo "${QEMU_PIN_SHA256}  ${src}/${tarball}" | sha256sum -c - >/dev/null ||
        die "${tarball} does not match its pinned SHA-256; delete it and re-run"
    log "verified ${tarball}"

    rm -rf "${src}/qemu-${QEMU_PIN_VERSION}"
    tar -xJf "${src}/${tarball}" -C "${src}"
    local build="${src}/qemu-${QEMU_PIN_VERSION}/build"
    mkdir -p "${build}"
    (
        cd "${build}"
        # The vfio-user client is built by default on Linux; only the
        # (unneeded) server side has a meson switch.
        ../configure --prefix="${PREFIX}" \
            --target-list=x86_64-softmmu \
            --enable-kvm --enable-slirp \
            --disable-docs --disable-gtk --disable-sdl --disable-opengl
        make -j"$(nproc)"
        make install
    )
    "${PREFIX}/bin/qemu-system-x86_64" -device help | grep -q '"vfio-user-pci"' ||
        die "built QEMU has no vfio-user-pci device"
    log "installed $("${PREFIX}/bin/qemu-system-x86_64" --version | head -1) into ${PREFIX}"
}

fetch_image() {
    local dir="${PREFIX}/images"
    mkdir -p "${dir}"
    curl --retry 3 -sSfL -o "${dir}/SHA256SUMS" "${L1_IMAGE_URL_BASE}/SHA256SUMS"
    local expected
    expected="$(grep " \*${L1_IMAGE_NAME}\$" "${dir}/SHA256SUMS" | cut -d' ' -f1)"
    [[ -n "${expected}" ]] || die "${L1_IMAGE_NAME} not listed in SHA256SUMS"
    if [[ ! -f "${L1_IMAGE}" ]] || ! echo "${expected}  ${L1_IMAGE}" | sha256sum -c - >/dev/null 2>&1; then
        log "downloading ${L1_IMAGE_NAME}"
        curl --retry 3 -sSfL -o "${L1_IMAGE}.part" "${L1_IMAGE_URL_BASE}/${L1_IMAGE_NAME}"
        mv "${L1_IMAGE}.part" "${L1_IMAGE}"
    fi
    echo "${expected}  ${L1_IMAGE}" | sha256sum -c - >/dev/null ||
        die "${L1_IMAGE_NAME} does not match SHA256SUMS"
    log "verified ${L1_IMAGE_NAME}"
}

fetch_ch() {
    mkdir -p "${CH_DIR}"
    local name sum dest
    for pair in "cloud-hypervisor-static:${CH_BIN_SHA256}:cloud-hypervisor" \
                "ch-remote-static:${CH_REMOTE_SHA256}:ch-remote"; do
        IFS=: read -r name sum dest <<<"${pair}"
        if [[ ! -f "${CH_DIR}/${dest}" ]] ||
            ! echo "${sum}  ${CH_DIR}/${dest}" | sha256sum -c - >/dev/null 2>&1; then
            log "downloading ${name} ${CH_PIN_VERSION}"
            curl --retry 3 -sSfL -o "${CH_DIR}/${dest}.part" "${CH_URL_BASE}/${name}"
            mv "${CH_DIR}/${dest}.part" "${CH_DIR}/${dest}"
        fi
        echo "${sum}  ${CH_DIR}/${dest}" | sha256sum -c - >/dev/null ||
            die "${name} does not match its pinned SHA-256; delete ${CH_DIR} and re-run"
        chmod 0755 "${CH_DIR}/${dest}"
    done
    log "verified Cloud Hypervisor ${CH_PIN_VERSION} in ${CH_DIR}"
}

case "${what}" in
    qemu) fetch_qemu ;;
    image) fetch_image ;;
    ch) fetch_ch ;;
    all) fetch_qemu; fetch_image; fetch_ch ;;
    *) die "usage: harbor/deps.sh [qemu|image|ch|all]" ;;
esac
