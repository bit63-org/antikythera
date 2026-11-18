#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Checks that this workstation can run harbor
# (.kiro/specs/harbor-virt-on-virt/ Requirement 1). Prints every problem
# found, not just the first, and exits non-zero if there are any.
#
# Usage: harbor/check-host.sh [--servers N]

set -uo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

servers=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --servers) servers="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# Requirement 1.3: 8 GiB / 4 cores for one server, 16 GiB / 8 cores for three.
if [[ "${servers}" -le 1 ]]; then
    need_mem_gib=8; need_cores=4
else
    need_mem_gib=16; need_cores=8
fi

problems=0
ok() { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; problems=$((problems + 1)); }
warn() { printf '  warn  %s\n' "$*"; }

echo "harbor host check (${servers} server(s))"

if [[ "$(uname -m)" == "x86_64" ]]; then
    ok "x86-64"
else
    bad "harbor's L1 is x86-64 only for now (found $(uname -m))"
fi

if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ok "/dev/kvm is readable and writable"
else
    bad "/dev/kvm missing or not accessible (add yourself to the kvm group)"
fi

nested=""
for mod in kvm_intel kvm_amd; do
    if [[ -r "/sys/module/${mod}/parameters/nested" ]]; then
        nested="$(cat "/sys/module/${mod}/parameters/nested")"
        nested_mod="${mod}"
    fi
done
case "${nested}" in
    Y | y | 1) ok "nested virtualization enabled (${nested_mod})" ;;
    "") bad "neither kvm_intel nor kvm_amd is loaded" ;;
    *) bad "nested virtualization is off: options ${nested_mod} nested=1, then reload the module" ;;
esac

qemu="$(qemu_bin)"
if [[ -z "${qemu}" ]]; then
    bad "qemu-system-x86_64 not found (run harbor/deps.sh qemu)"
else
    version="$("${qemu}" --version | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
    major="${version%%.*}"; rest="${version#*.}"; minor="${rest%%.*}"
    if [[ "${major}" -gt "${QEMU_MIN_MAJOR}" ||
          ( "${major}" -eq "${QEMU_MIN_MAJOR}" && "${minor}" -ge "${QEMU_MIN_MINOR}" ) ]]; then
        ok "QEMU ${version} (${qemu})"
    else
        bad "QEMU ${version} is older than ${QEMU_MIN_MAJOR}.${QEMU_MIN_MINOR} (run harbor/deps.sh qemu)"
    fi
    if "${qemu}" -device help 2>/dev/null | grep -q '"vfio-user-pci"'; then
        ok "QEMU has vfio-user-pci"
    else
        bad "this QEMU lacks vfio-user-pci (run harbor/deps.sh qemu)"
    fi
fi

if [[ -n "$(qemu_img_bin)" ]]; then ok "qemu-img"; else bad "qemu-img not found"; fi
need_tool() {
    if command -v "$1" >/dev/null; then ok "$1"; else bad "$1 not found ($2)"; fi
}
need_tool cloud-localds "apt install cloud-image-utils"
need_tool ssh "apt install openssh-client"
need_tool ssh-keygen "apt install openssh-client"

if [[ -f "${L1_IMAGE}" ]]; then
    ok "L1 image ${L1_IMAGE_NAME}"
else
    bad "L1 image not downloaded (run harbor/deps.sh image)"
fi

if [[ -x "$(testdev_bin)" ]]; then
    ok "ak-testdev built ($(testdev_bin))"
else
    bad "ak-testdev not built: vcpkg install --x-feature=vfio-user, then build into ${AK_BUILD_DIR}"
fi

mem_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
mem_gib=$((mem_kib / 1024 / 1024))
cores="$(nproc)"
if [[ "${mem_gib}" -ge "${need_mem_gib}" ]]; then
    ok "${mem_gib} GiB RAM"
else
    warn "${mem_gib} GiB RAM; ${need_mem_gib} GiB recommended for ${servers} server(s)"
fi
if [[ "${cores}" -ge "${need_cores}" ]]; then
    ok "${cores} cores"
else
    warn "${cores} cores; ${need_cores} recommended for ${servers} server(s)"
fi

if [[ "${problems}" -eq 0 ]]; then
    echo "harbor host check passed"
else
    echo "harbor host check: ${problems} problem(s)"
    exit 1
fi
