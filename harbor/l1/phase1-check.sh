#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Runs as root inside L1. Verifies the emulated backplane
# (.kiro/specs/harbor-virt-on-virt/ Requirement 2.4, hull-host-agent 5.2):
#
#   1. the IOMMU is on, strict, with ATS disabled on the command line
#   2. exactly N test devices enumerated, each reporting a distinct slot ID
#   3. each device is alone in its IOMMU group
#   4. no device has ATS enabled; bridges above each device report ACS
#   5. MMIO reaches the board process (magic, scratch read/write)
#   6. a function reset reaches the board process (RESET_COUNT increments)
#
# Prints one line per check and exits non-zero if any check fails.
#
# Usage: phase1-check.sh N   (N = expected number of slots)

# pass/fail always return 0, so `cond && pass || fail` cannot run both
# (SC2015); ls only lists sysfs directories whose entries are PCI
# addresses (SC2012).
# shellcheck disable=SC2015,SC2012

set -uo pipefail

expected="${1:?usage: phase1-check.sh N}"
here="$(cd "$(dirname "$0")" && pwd)"
mmio="${here}/testdev_mmio.py"
vendor="1de5"
device="a001"
pci_command_memory="0x0002"

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }

# 1. Kernel command line.
cmdline="$(cat /proc/cmdline)"
for want in intel_iommu=on iommu.strict=1 pci=noats; do
    [[ " ${cmdline} " == *" ${want} "* ]] && pass "cmdline has ${want}" || fail "cmdline lacks ${want}"
done
[[ -d /sys/class/iommu ]] && [[ -n "$(ls /sys/class/iommu)" ]] &&
    pass "IOMMU registered ($(ls /sys/class/iommu | tr '\n' ' '))" || fail "no IOMMU registered"

# 2. Enumeration.
mapfile -t devs < <(lspci -D -n -d "${vendor}:${device}" | awk '{print $1}')
[[ "${#devs[@]}" -eq "${expected}" ]] && pass "${#devs[@]} test device(s) enumerated" ||
    fail "expected ${expected} test device(s), found ${#devs[@]}"

declare -A seen_slots=()
for bdf in "${devs[@]}"; do
    # 3. IOMMU group isolation.
    group_link="/sys/bus/pci/devices/${bdf}/iommu_group"
    if [[ -L "${group_link}" ]]; then
        group="$(basename "$(readlink "${group_link}")")"
        members="$(ls "/sys/kernel/iommu_groups/${group}/devices" | tr '\n' ' ')"
        [[ "${members}" == "${bdf} " ]] && pass "${bdf}: alone in IOMMU group ${group}" ||
            fail "${bdf}: IOMMU group ${group} shared with: ${members}"
    else
        fail "${bdf}: no IOMMU group"
    fi

    # 4. ATS off on the device; ACS on every bridge above it.
    if lspci -s "${bdf}" -vvv 2>/dev/null | grep -q 'ATSCtl:.*Enable+'; then
        fail "${bdf}: ATS enabled"
    else
        pass "${bdf}: ATS not enabled"
    fi
    path="$(readlink -f "/sys/bus/pci/devices/${bdf}")"
    parent="$(dirname "${path}")"
    while [[ "$(basename "${parent}")" =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]]; do
        bridge="$(basename "${parent}")"
        if lspci -s "${bridge}" -vvv 2>/dev/null | grep -q 'Access Control Services'; then
            pass "${bdf}: bridge ${bridge} has ACS"
        else
            fail "${bdf}: bridge ${bridge} has no ACS capability"
        fi
        parent="$(dirname "${parent}")"
    done

    # 5. MMIO. Nothing is bound to the device, so enable memory decoding.
    setpci -s "${bdf}" COMMAND="${pci_command_memory}"
    if magic="$(python3 "${mmio}" "${bdf}" magic)"; then
        pass "${bdf}: BAR0 magic ${magic}"
    else
        fail "${bdf}: BAR0 magic ${magic}"
    fi
    slot="$(python3 "${mmio}" "${bdf}" slot)"
    if [[ -n "${seen_slots[${slot}]:-}" ]]; then
        fail "${bdf}: slot ID ${slot} duplicates ${seen_slots[${slot}]}"
    else
        seen_slots[${slot}]="${bdf}"
        pass "${bdf}: slot ID ${slot}"
    fi
    python3 "${mmio}" "${bdf}" scratch-rw >/dev/null && pass "${bdf}: scratch read/write" ||
        fail "${bdf}: scratch read/write"

    # 6. Reset propagation: FLR if offered, else a secondary bus reset.
    before="$(python3 "${mmio}" "${bdf}" reset-count)"
    methods="$(cat "/sys/bus/pci/devices/${bdf}/reset_method" 2>/dev/null || true)"
    if echo 1 >"/sys/bus/pci/devices/${bdf}/reset" 2>/dev/null; then
        setpci -s "${bdf}" COMMAND="${pci_command_memory}"
        after="$(python3 "${mmio}" "${bdf}" reset-count)"
        [[ "${after}" -gt "${before}" ]] &&
            pass "${bdf}: reset reached the board (count ${before} -> ${after}; methods: ${methods})" ||
            fail "${bdf}: reset did not reach the board (count ${before} -> ${after}; methods: ${methods})"
    else
        fail "${bdf}: reset failed (methods: ${methods:-none})"
    fi
done

if [[ "${failures}" -eq 0 ]]; then
    echo "phase 1: all checks passed"
else
    echo "phase 1: ${failures} check(s) failed"
    exit 1
fi
