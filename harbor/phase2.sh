#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# harbor phase 2 (.kiro/specs/harbor-virt-on-virt/ Requirement 5.2): boot
# one L1 server with N test devices, then inside it pass them through to an
# L2 guest under Cloud Hypervisor: MMIO, MSI-X, DMA fill and reset from the
# guest on each device, one device hot-plugged into the running guest and
# unplugged again. Confirms from L0 that each board process saw the
# guest's reset, then tears down. Exits non-zero on any failure
# (Requirement 6.1).
#
# Usage: harbor/phase2.sh [--slots N] [--ssh-port P] [--keep]
#   --slots     at least 2: the last slot is the one hot-plugged (default 2)
#   --ssh-port  L1's forwarded SSH port on 127.0.0.1 (default 2223, so a
#               phase 1 run on 2222 can share the host)
#   --keep      leave the server running afterwards for manual inspection

set -euo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

name="phase2"
slots=2
keep=0
ssh_port=2223
while [[ $# -gt 0 ]]; do
    case "$1" in
        --slots) slots="$2"; shift 2 ;;
        --ssh-port) ssh_port="$2"; shift 2 ;;
        --keep) keep=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ "${slots}" -ge 2 ]] || die "phase 2 needs at least 2 slots (the last one is hot-plugged)"

"${HARBOR_DIR}/check-host.sh" || die "host check failed"
[[ -x "${CH_DIR}/cloud-hypervisor" && -x "${CH_DIR}/ch-remote" ]] ||
    die "Cloud Hypervisor missing: harbor/deps.sh ch"
[[ -x "$(guest_testdev_bin)" ]] || die "ak-guest-testdev not built at $(guest_testdev_bin)"

status=1  # pessimistic until the checks below pass
# shellcheck disable=SC2317,SC2329  # invoked by the EXIT trap
cleanup() {
    if [[ "${keep}" -eq 1 ]]; then
        log "left ${name} running: ssh -p ${ssh_port} -i ${RUN_DIR}/id_ed25519 harbor@127.0.0.1"
    elif [[ "${status}" -eq 0 ]]; then
        "${HARBOR_DIR}/l1/stop.sh" --name "${name}" --wipe
    else
        "${HARBOR_DIR}/l1/stop.sh" --name "${name}"  # keep logs for diagnosis
    fi
}
trap cleanup EXIT

"${HARBOR_DIR}/l1/run.sh" --name "${name}" --slots "${slots}" --ssh-port "${ssh_port}"

common_opts=(-i "${RUN_DIR}/id_ed25519" -o StrictHostKeyChecking=no
             -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
l1() { ssh "${common_opts[@]}" -p "${ssh_port}" harbor@127.0.0.1 "$@"; }

boot_timeout_s=900
poll_s=5
log "waiting for L1 (first boot installs packages and reboots)"
deadline=$((SECONDS + boot_timeout_s))
until l1 'grep -q intel_iommu=on /proc/cmdline && cloud-init status --wait >/dev/null 2>&1' 2>/dev/null; do
    [[ "${SECONDS}" -lt "${deadline}" ]] || die "L1 not ready after ${boot_timeout_s}s; see ${RUN_DIR}/${name}/console.log"
    sleep "${poll_s}"
done
l1 'test -c /dev/kvm' || die "L1 has no /dev/kvm: is nested virtualization on in L0?"
log "L1 is up with the IOMMU and KVM"

# scp names the copies after their source, so stage the Cloud Hypervisor
# binaries under the names phase2-check.sh expects.
stage="${RUN_DIR}/${name}/stage"
mkdir -p "${stage}"
cp "${CH_DIR}/cloud-hypervisor" "${CH_DIR}/ch-remote" "$(guest_testdev_bin)" \
   "${HARBOR_DIR}/l1/phase2-check.sh" "${HARBOR_DIR}/l1/l2-image.sh" \
   "${HARBOR_DIR}/l1/l2-init.sh" "${HARBOR_DIR}/l1/testdev_mmio.py" "${stage}/"
scp "${common_opts[@]}" -P "${ssh_port}" "${stage}"/* harbor@127.0.0.1:

declare -a log_offsets=()
for ((i = 0; i < slots; i++)); do
    log_offsets[i]="$(stat -c %s "${RUN_DIR}/${name}/slot${i}.log" 2>/dev/null || echo 0)"
done

status=0
l1 "sudo bash ./phase2-check.sh ${slots}" || status=$?
l1 'sudo cat /run/harbor-l2/console.log' >"${RUN_DIR}/${name}/l2-console.log" 2>/dev/null || true

# From the board side: every slot was reset by its guest (and by L1 when
# vfio-pci took it), and no board process refused a DMA mapping, which is
# how running out of DMA regions behind the vIOMMU shows up.
for ((i = 0; i < slots; i++)); do
    slot_log="${RUN_DIR}/${name}/slot${i}.log"
    since="$(tail -c "+$((log_offsets[i] + 1))" "${slot_log}" 2>/dev/null)"
    if grep -q 'reset type=' <<<"${since}"; then
        echo "PASS  slot ${i}: board process logged a reset during the checks"
    else
        echo "FAIL  slot ${i}: board process logged no reset during the checks"
        status=1
    fi
    if grep -q -e 'hit max regions' -e 'failed to add DMA region' <<<"${since}"; then
        echo "FAIL  slot ${i}: board process refused a DMA mapping (see ${slot_log})"
        status=1
    else
        echo "PASS  slot ${i}: board process accepted every DMA mapping"
    fi
done

if [[ "${status}" -eq 0 ]]; then
    log "phase 2 passed (slots=${slots})"
else
    log "phase 2 FAILED; logs in ${RUN_DIR}/${name} (l2-console.log is the guest; rerun with --keep to inspect)"
fi
exit "${status}"
