#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# harbor phase 1 (.kiro/specs/harbor-virt-on-virt/ Requirement 5.1):
# boot one L1 server with the emulated backplane and N test devices, run
# the in-L1 checks, confirm each board process saw a reset, tear down.
# Exits non-zero on any failure (Requirement 6.1).
#
# Usage: harbor/phase1.sh [--slots N] [--topology rootports|switch] [--keep]
#   --topology  rootports (default) or switch; see harbor/l1/run.sh. The
#               switch topology fails the IOMMU-group checks on QEMU 10.2
#               because its emulated switch downstream ports have no ACS.
#   --keep  leave the server running afterwards for manual inspection

set -euo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

name="phase1"
slots=2
topology="rootports"
keep=0
ssh_port=2222
while [[ $# -gt 0 ]]; do
    case "$1" in
        --slots) slots="$2"; shift 2 ;;
        --topology) topology="$2"; shift 2 ;;
        --ssh-port) ssh_port="$2"; shift 2 ;;
        --keep) keep=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done

"${HARBOR_DIR}/check-host.sh" || die "host check failed"

status=1  # pessimistic until the checks below pass
# shellcheck disable=SC2317  # invoked by the EXIT trap
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

"${HARBOR_DIR}/l1/run.sh" --name "${name}" --slots "${slots}" --topology "${topology}" --ssh-port "${ssh_port}"

common_opts=(-i "${RUN_DIR}/id_ed25519" -o StrictHostKeyChecking=no
             -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
l1() { ssh "${common_opts[@]}" -p "${ssh_port}" harbor@127.0.0.1 "$@"; }

# cloud-init installs packages, sets the IOMMU command line and reboots
# once; wait until L1 is back with that command line.
boot_timeout_s=900
poll_s=5
log "waiting for L1 (first boot installs packages and reboots)"
deadline=$((SECONDS + boot_timeout_s))
until l1 'grep -q intel_iommu=on /proc/cmdline && cloud-init status --wait >/dev/null 2>&1' 2>/dev/null; do
    [[ "${SECONDS}" -lt "${deadline}" ]] || die "L1 not ready after ${boot_timeout_s}s; see ${RUN_DIR}/${name}/console.log"
    sleep "${poll_s}"
done
log "L1 is up with the IOMMU enabled"

scp "${common_opts[@]}" -P "${ssh_port}" \
    "${HARBOR_DIR}/l1/phase1-check.sh" "${HARBOR_DIR}/l1/testdev_mmio.py" harbor@127.0.0.1:

# Each board process logs a reset when QEMU attaches and when L1 boots or
# reboots, so remember how far each slot log has got before the in-L1
# checks run; the host-side reset check below only reads what follows.
declare -a log_offsets=()
for ((i = 0; i < slots; i++)); do
    log_offsets[i]="$(stat -c %s "${RUN_DIR}/${name}/slot${i}.log" 2>/dev/null || echo 0)"
done

status=0
l1 "sudo bash ./phase1-check.sh ${slots}" || status=$?

# The in-L1 reset check only sees RESET_COUNT; confirm from the other side
# that each board process logged the reset it was sent during the checks
# (resets logged before log_offsets was taken do not count).
for ((i = 0; i < slots; i++)); do
    slot_log="${RUN_DIR}/${name}/slot${i}.log"
    # Process substitution, not a pipe: under pipefail, grep -q exiting on
    # the first match could SIGPIPE tail and turn a pass into a fail.
    if grep -q 'reset type=' < <(tail -c "+$((log_offsets[i] + 1))" "${slot_log}" 2>/dev/null); then
        echo "PASS  slot ${i}: board process logged a reset during the checks"
    else
        echo "FAIL  slot ${i}: board process logged no reset during the checks"
        status=1
    fi
done

if [[ "${status}" -eq 0 ]]; then
    log "phase 1 passed (topology=${topology}, slots=${slots})"
else
    log "phase 1 FAILED; logs in ${RUN_DIR}/${name} (rerun with --keep to inspect)"
fi
exit "${status}"
