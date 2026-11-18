#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Starts one harbor "server": N board processes (ak-testdev for phase 1)
# and an L1 QEMU VM whose slots are emulated PCIe switch downstream ports,
# each with one vfio-user-pci device connected to a board process.
# (.kiro/specs/harbor-virt-on-virt/ Requirements 2 and 3.)
#
# Board processes start before QEMU: that ordering is harbor's stand-in for
# helm's power sequencing (slots ready before the host leaves reset).
#
# Usage: harbor/l1/run.sh [--name srv1] [--slots N] [--topology switch|rootports]
#                         [--mem 4G] [--cpus 4] [--ssh-port 2222]
#
# Topologies:
#   switch     root port -> x3130 upstream -> one xio3130 downstream per slot
#   rootports  one pcie-root-port per slot (fallback if the emulated switch
#              ports lack ACS and merge IOMMU groups)

set -euo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

name="srv1"
slots=2
topology="switch"
mem="4G"
cpus=4
ssh_port=2222
overlay_size="20G"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) name="$2"; shift 2 ;;
        --slots) slots="$2"; shift 2 ;;
        --topology) topology="$2"; shift 2 ;;
        --mem) mem="$2"; shift 2 ;;
        --cpus) cpus="$2"; shift 2 ;;
        --ssh-port) ssh_port="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ "${topology}" == "switch" || "${topology}" == "rootports" ]] || die "unknown topology: ${topology}"

qemu="$(qemu_bin)"; qemu_img="$(qemu_img_bin)"; testdev="$(testdev_bin)"
[[ -n "${qemu}" && -n "${qemu_img}" ]] || die "QEMU not found (harbor/check-host.sh)"
[[ -x "${testdev}" ]] || die "ak-testdev not built at ${testdev}"
[[ -f "${L1_IMAGE}" ]] || die "L1 image missing (harbor/deps.sh image)"

dir="${RUN_DIR}/${name}"
[[ -e "${dir}/qemu.pid" ]] && die "${name} looks like it is running; harbor/l1/stop.sh --name ${name}"
mkdir -p "${dir}"

# --- SSH key and cloud-init seed (phases 1-5 only; the strict hull image
# of phase 6 has no network) -------------------------------------------------
key="${RUN_DIR}/id_ed25519"
[[ -f "${key}" ]] || ssh-keygen -q -t ed25519 -N '' -C harbor -f "${key}"

# The IOMMU has to be on, strict, with ATS off, in L1 exactly as in hull
# (.kiro/specs/hull-host-agent/ Requirement 2.4). cloud-init writes the
# kernel command line and reboots once.
cat >"${dir}/user-data" <<EOF
#cloud-config
hostname: ${name}
users:
  - name: harbor
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "${key}.pub")
packages: [pciutils, python3]
write_files:
  - path: /etc/default/grub.d/90-antikythera.cfg
    content: |
      GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT intel_iommu=on iommu.strict=1 pci=noats"
runcmd:
  - [update-grub]
power_state:
  mode: reboot
  condition: true
EOF
printf 'instance-id: %s\nlocal-hostname: %s\n' "${name}" "${name}" >"${dir}/meta-data"
cloud-localds "${dir}/seed.img" "${dir}/user-data" "${dir}/meta-data"

[[ -f "${dir}/disk.qcow2" ]] ||
    "${qemu_img}" create -q -f qcow2 -F qcow2 -b "${L1_IMAGE}" "${dir}/disk.qcow2" "${overlay_size}"

# --- Board processes ------------------------------------------------------
board_socket_timeout_s=10
for ((i = 0; i < slots; i++)); do
    sock="${dir}/slot${i}.sock"
    "${testdev}" --socket "${sock}" --slot "${i}" >"${dir}/slot${i}.log" 2>&1 &
    echo $! >"${dir}/slot${i}.pid"
    for ((t = 0; t < board_socket_timeout_s * 10; t++)); do
        [[ -S "${sock}" ]] && break
        sleep 0.1
    done
    [[ -S "${sock}" ]] || die "board process for slot ${i} did not create ${sock}; see ${dir}/slot${i}.log"
done
log "${slots} board process(es) ready"

# --- L1 QEMU --------------------------------------------------------------
args=(
    -name "${name}"
    -machine "q35,accel=kvm,kernel-irqchip=split,memory-backend=mem"
    -cpu host -smp "${cpus}" -m "${mem}"
    # vfio-user maps guest RAM into the board processes, so it must be shared.
    -object "memory-backend-memfd,id=mem,size=${mem},share=on"
    # The vIOMMU comes before any PCI device it translates for.
    -device "intel-iommu,intremap=on,caching-mode=on,device-iotlb=off"
    -drive "file=${dir}/disk.qcow2,if=virtio,format=qcow2"
    -drive "file=${dir}/seed.img,if=virtio,format=raw"
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
    -device "virtio-net-pci,netdev=n0"
    -display none -serial "file:${dir}/console.log"
    -pidfile "${dir}/qemu.pid" -daemonize
)

if [[ "${topology}" == "switch" ]]; then
    args+=(-device "pcie-root-port,id=rp0,chassis=1,slot=0"
           -device "x3130-upstream,id=sw0,bus=rp0")
fi
for ((i = 0; i < slots; i++)); do
    if [[ "${topology}" == "switch" ]]; then
        args+=(-device "xio3130-downstream,id=slot${i},bus=sw0,chassis=$((i + 2)),slot=0")
    else
        args+=(-device "pcie-root-port,id=slot${i},chassis=$((i + 2)),slot=0")
    fi
    args+=(-device "{\"driver\":\"vfio-user-pci\",\"id\":\"ep${i}\",\"bus\":\"slot${i}\",\"socket\":{\"type\":\"unix\",\"path\":\"${dir}/slot${i}.sock\"}}")
done

printf '%q ' "${qemu}" "${args[@]}" >"${dir}/qemu.cmdline"
"${qemu}" "${args[@]}"
echo "${ssh_port}" >"${dir}/ssh-port"
log "${name} started (topology=${topology}, slots=${slots}); console: ${dir}/console.log"
