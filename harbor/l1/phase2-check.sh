#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Runs as root inside L1. Verifies passthrough of the test devices to an L2
# guest (.kiro/specs/harbor-virt-on-virt/ Requirement 5.2):
#
#   1. every test device binds to vfio-pci in L1
#   2. Cloud Hypervisor boots an L2 guest with all but the last device;
#      inside it ak-guest-testdev passes MMIO, MSI-X, DMA fill and reset on
#      each one
#   3. the last device is hot-plugged into the running guest, which finds
#      it and passes the same checks on it
#   4. the device is hot-unplugged, the guest sees it go, and L1 gets it
#      back (vfio-pci still bound)
#   5. the guest shuts down cleanly
#
# The L2 guest is L1's own kernel with a busybox initramfs (l2-image.sh).
# It reports through "L2: " marker lines on its serial console, which this
# script watches to drive the hot-plug.
#
# Prints one line per check and exits non-zero if any check fails.
#
# Usage: phase2-check.sh N   (N = number of slots, at least 2)
#   Expects next to it: cloud-hypervisor, ch-remote, ak-guest-testdev,
#   l2-image.sh, l2-init.sh, testdev_mmio.py.

# shellcheck disable=SC2015  # pass/fail always return 0

set -uo pipefail

expected="${1:?usage: phase2-check.sh N}"
here="$(cd "$(dirname "$0")" && pwd)"
vendor="1de5"
device="a001"
pci_command_memory="0x0002"
work="/run/harbor-l2"
api="${work}/api.sock"
console="${work}/console.log"
l2_mem="512M"
boot_timeout_s=180
step_timeout_s=120
hotplug_id="hotplug0"

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
finish() {
    if [[ "${failures}" -eq 0 ]]; then
        echo "phase 2: all checks passed"
        exit 0
    fi
    echo "phase 2: ${failures} check(s) failed"
    exit 1
}

[[ "${expected}" -ge 2 ]] || { fail "phase 2 needs at least 2 slots (one to hot-plug)"; finish; }

ch_pid=""
# shellcheck disable=SC2317,SC2329  # invoked by the EXIT trap
cleanup() {
    if [[ -n "${ch_pid}" ]] && kill -0 "${ch_pid}" 2>/dev/null; then
        kill "${ch_pid}" 2>/dev/null
        wait "${ch_pid}" 2>/dev/null
    fi
}
trap cleanup EXIT

# Waits for a marker line on the L2 console; prints the matching line.
wait_marker() {
    local pattern="$1" deadline=$((SECONDS + $2)) line
    while [[ "${SECONDS}" -lt "${deadline}" ]]; do
        line="$(grep -a -m1 -E "^L2: ${pattern}" "${console}" 2>/dev/null | tr -d '\r')"
        if [[ -n "${line}" ]]; then
            printf '%s\n' "${line}"
            return 0
        fi
        kill -0 "${ch_pid}" 2>/dev/null || return 1
        sleep 0.5
    done
    return 1
}

# Lines the guest printed for one of its devices, with the L2 address
# replaced by the slot so they read as phase 1's do.
guest_results() {
    local l2_bdf="$1" label="$2"
    grep -a -E "^(PASS|FAIL)  ${l2_bdf}: " "${console}" | tr -d '\r' |
        sed -E "s/^(PASS|FAIL)  ${l2_bdf}: /\1  ${label} (L2 ${l2_bdf}): /"
}

# --- 1. Bind every test device to vfio-pci, noting its slot -----------------
modprobe vfio-pci
mapfile -t devs < <(lspci -D -n -d "${vendor}:${device}" | awk '{print $1}')
[[ "${#devs[@]}" -eq "${expected}" ]] && pass "${#devs[@]} test device(s) in L1" ||
    fail "expected ${expected} test device(s) in L1, found ${#devs[@]}"
[[ "${#devs[@]}" -ge 2 ]] || finish

declare -A slot_of=()
for bdf in "${devs[@]}"; do
    sysfs="/sys/bus/pci/devices/${bdf}"
    if [[ -e "${sysfs}/driver" && "$(basename "$(readlink "${sysfs}/driver")")" != "vfio-pci" ]]; then
        echo "${bdf}" >"${sysfs}/driver/unbind"
    fi
    if [[ ! -e "${sysfs}/driver" ]]; then
        # Read the slot ID while nothing owns the device.
        setpci -s "${bdf}" COMMAND="${pci_command_memory}"
        slot_of[${bdf}]="$(python3 "${here}/testdev_mmio.py" "${bdf}" slot)"
        echo vfio-pci >"${sysfs}/driver_override"
        echo "${bdf}" >/sys/bus/pci/drivers_probe
    fi
    if [[ "$(basename "$(readlink "${sysfs}/driver" 2>/dev/null)")" == "vfio-pci" ]]; then
        pass "${bdf}: bound to vfio-pci in L1 (slot ${slot_of[${bdf}]:-?})"
    else
        fail "${bdf}: did not bind to vfio-pci"
    fi
done
boot_devs=("${devs[@]:0:${#devs[@]}-1}")
hotplug_dev="${devs[-1]}"

# --- 2. Boot L2 with all but the last device ------------------------------
rm -rf "${work}"
mkdir -p "${work}"
"${here}/l2-image.sh" "${work}" "${here}/ak-guest-testdev" "${here}/l2-init.sh" ||
    { fail "could not build the L2 guest"; finish; }

ch_args=(
    --api-socket "path=${api}"
    --kernel "${work}/vmlinux"
    --initramfs "${work}/initramfs.cpio.gz"
    --cmdline "console=ttyS0 panic=-1 quiet"
    --cpus boot=1 --memory "size=${l2_mem}"
    --serial "file=${console}" --console off
)
for bdf in "${boot_devs[@]}"; do
    ch_args+=(--device "path=/sys/bus/pci/devices/${bdf}/")
done
"${here}/cloud-hypervisor" "${ch_args[@]}" >"${work}/cloud-hypervisor.log" 2>&1 &
ch_pid=$!

if ! wait_marker "WAIT-HOTPLUG" "${boot_timeout_s}" >/dev/null; then
    fail "L2 did not finish its boot-time checks within ${boot_timeout_s}s"
    tail -n 30 "${console}" "${work}/cloud-hypervisor.log" 2>/dev/null
    finish
fi
pass "L2 booted under Cloud Hypervisor"
count_line="$(wait_marker "BOOT-DEVICES" 1)"
[[ "${count_line}" == "L2: BOOT-DEVICES ${#boot_devs[@]}" ]] &&
    pass "L2 found ${#boot_devs[@]} passed-through device(s)" ||
    fail "L2 reported '${count_line}', want ${#boot_devs[@]} device(s)"

# CH puts passthrough devices on its PCI segment 0 in --device order, so
# match the guest's addresses to L1 slots by order of appearance.
mapfile -t l2_boot < <(grep -a -oE '^PASS  [0-9a-f:.]+: opened through vfio' "${console}" |
                           awk '{print $2}' | sed 's/:$//')
for ((i = 0; i < ${#boot_devs[@]}; i++)); do
    l2_bdf="${l2_boot[i]:-}"
    if [[ -z "${l2_bdf}" ]]; then
        fail "${boot_devs[i]}: L2 could not open its passthrough device"
        continue
    fi
    while read -r line; do
        [[ "${line}" == PASS* ]] && pass "${line#PASS  }" || fail "${line#FAIL  }"
    done < <(guest_results "${l2_bdf}" "slot ${slot_of[${boot_devs[i]}]:-?}")
    grep -a -q "^PASS  ${l2_bdf}: slot ID ${slot_of[${boot_devs[i]}]:-x}" "${console}" &&
        pass "${boot_devs[i]}: L2 sees the board process of slot ${slot_of[${boot_devs[i]}]}" ||
        fail "${boot_devs[i]}: L2 sees the wrong board process"
done

# --- 3. Hot-plug the last device ------------------------------------------
if "${here}/ch-remote" --api-socket "${api}" add-device \
        "path=/sys/bus/pci/devices/${hotplug_dev}/,id=${hotplug_id}" >"${work}/add-device.log" 2>&1; then
    pass "${hotplug_dev}: hot-plugged into L2 (slot ${slot_of[${hotplug_dev}]:-?})"
else
    fail "${hotplug_dev}: ch-remote add-device failed: $(cat "${work}/add-device.log")"
fi
added_line="$(wait_marker "HOTPLUG-(ADDED|TIMEOUT)" "${step_timeout_s}")"
if [[ "${added_line}" == "L2: HOTPLUG-ADDED "* ]]; then
    l2_hot="${added_line#L2: HOTPLUG-ADDED }"
    pass "L2 found the hot-plugged device at ${l2_hot}"
    if wait_marker "HOTPLUG-TESTS" "${step_timeout_s}" >/dev/null; then
        while read -r line; do
            [[ "${line}" == PASS* ]] && pass "${line#PASS  }" || fail "${line#FAIL  }"
        done < <(guest_results "${l2_hot}" "hot-plugged slot ${slot_of[${hotplug_dev}]:-?}")
        grep -a -q "^PASS  ${l2_hot}: slot ID ${slot_of[${hotplug_dev}]:-x}" "${console}" &&
            pass "hot-plugged device is the board process of slot ${slot_of[${hotplug_dev}]}" ||
            fail "hot-plugged device is not slot ${slot_of[${hotplug_dev}]:-?}"
    else
        fail "L2 did not finish checking the hot-plugged device"
    fi

    # --- 4. Unplug it again ----------------------------------------------
    if "${here}/ch-remote" --api-socket "${api}" remove-device "${hotplug_id}" \
            >"${work}/remove-device.log" 2>&1; then
        pass "${hotplug_dev}: unplug requested"
    else
        fail "${hotplug_dev}: ch-remote remove-device failed: $(cat "${work}/remove-device.log")"
    fi
    unplug_line="$(wait_marker "UNPLUG-(SEEN|TIMEOUT)" "${step_timeout_s}")"
    [[ "${unplug_line}" == "L2: UNPLUG-SEEN ${l2_hot}" ]] && pass "L2 saw ${l2_hot} unplugged" ||
        fail "L2 did not see the unplug (${unplug_line:-no marker})"
else
    fail "L2 did not find the hot-plugged device (${added_line:-no marker})"
fi

# --- 5. Clean shutdown, and the device is L1's again -----------------------
if wait_marker "DONE" "${step_timeout_s}" >/dev/null; then
    for ((t = 0; t < step_timeout_s * 2; t++)); do
        kill -0 "${ch_pid}" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "${ch_pid}" 2>/dev/null; then
        fail "Cloud Hypervisor still running after L2 powered off"
    else
        wait "${ch_pid}"
        ch_status=$?
        ch_pid=""
        [[ "${ch_status}" -eq 0 ]] && pass "L2 shut down cleanly" ||
            fail "Cloud Hypervisor exited with status ${ch_status}"
    fi
else
    fail "L2 did not finish"
fi
[[ "$(basename "$(readlink "/sys/bus/pci/devices/${hotplug_dev}/driver" 2>/dev/null)")" == "vfio-pci" ]] &&
    pass "${hotplug_dev}: back with vfio-pci in L1 after unplug" ||
    fail "${hotplug_dev}: not bound to vfio-pci after unplug"

finish
