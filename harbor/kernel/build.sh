#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Resolves (and optionally builds) the hull kernel from `allnoconfig` plus
# the committed fragments (.kiro/specs/hull-host-agent/ Requirement 2.1),
# then checks the resolved .config with check-config.py.
#
# Usage: harbor/kernel/build.sh --src LINUX_TREE [--out DIR]
#            [--variant hull|l1-debug] [--arch x86_64] [--build] [-j N]
#   --src      a Linux source tree (kernel.org tarball or Ubuntu's
#              linux-source package); it is not modified, output goes to
#              --out via O=
#   --out      build directory (default harbor/.run/kernel/<variant>)
#   --variant  hull (strict, default) or l1-debug (hull plus IP, virtio
#              disks and ext4, for booting harbor's L1 disk)
#   --build    also build the kernel image (bzImage on x86_64)

set -euo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

kernel_dir="${HARBOR_DIR}/kernel"
src=""
out=""
variant="hull"
arch="x86_64"
build=0
jobs="$(nproc)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --src) src="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --variant) variant="$2"; shift 2 ;;
        --arch) arch="$2"; shift 2 ;;
        --build) build=1; shift ;;
        -j) jobs="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "${src}" ]] || die "--src LINUX_TREE is required"
[[ -f "${src}/Makefile" && -d "${src}/scripts/kconfig" ]] || die "not a Linux source tree: ${src}"
[[ -f "${kernel_dir}/${arch}.config" ]] || die "no fragment for arch ${arch}"

fragments=("${kernel_dir}/hull.config" "${kernel_dir}/${arch}.config")
case "${variant}" in
    hull) ;;
    l1-debug) fragments+=("${kernel_dir}/l1-debug.config") ;;
    *) die "unknown variant: ${variant}" ;;
esac

out="${out:-${RUN_DIR}/kernel/${variant}}"
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"

# KCONFIG_ALLCONFIG pins every option the fragments name while allnoconfig
# turns everything else off; later fragments override earlier ones.
cat "${fragments[@]}" >"${out}/fragments.config"
log "resolving ${variant} config for ${arch} in ${out}"
make -s -C "${src}" O="${out}" ARCH="${arch}" \
    KCONFIG_ALLCONFIG="${out}/fragments.config" allnoconfig

python3 "${kernel_dir}/check-config.py" --config "${out}/.config" \
    --variant "${variant}" --arch "${arch}" "${fragments[@]}"

if [[ "${build}" -eq 1 ]]; then
    log "building ${variant} kernel (-j${jobs})"
    make -s -C "${src}" O="${out}" ARCH="${arch}" -j"${jobs}"
    log "kernel image: ${out}/$(make -s -C "${src}" O="${out}" ARCH="${arch}" image_name)"
fi
