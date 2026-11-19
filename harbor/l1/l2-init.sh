#!/bin/busybox sh
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck shell=dash
#
# /init of the harbor phase 2 L2 guest (.kiro/specs/harbor-virt-on-virt/
# Requirement 5.2). Packed into the initramfs by l2-image.sh; runs as PID 1
# under Cloud Hypervisor inside L1.
#
# Tests every ak-testdev function present at boot with ak-guest-testdev,
# then waits for one to be hot-plugged, tests it, and waits for it to be
# unplugged. Each step prints an "L2: " marker line on the serial console;
# phase2-check.sh in L1 watches for them to drive the hot-plug and reads
# the results from them. Powers off when done.

# Busybox applets are linked at run time; the initramfs carries only the
# binary.
/bin/busybox --install -s /bin
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

vendor="0x1de5"
device="0xa001"
hotplug_timeout_s=120
unplug_timeout_s=60
poll_s=0.2

say() { echo "L2: $*"; }

# vfio has no IOMMU to work with in L2, so it runs in no-IOMMU mode: the
# test program hands the device guest-physical addresses.
while read -r module params; do
    # shellcheck disable=SC2086  # params is a list of module options
    insmod "/lib/modules/${module}" ${params} || say "insmod ${module} failed"
done </modules.order
noiommu=/sys/module/vfio/parameters/enable_unsafe_noiommu_mode
[ -w "${noiommu}" ] && echo Y >"${noiommu}"

testdevs() {
    for d in /sys/bus/pci/devices/*; do
        [ "$(cat "${d}/vendor")" = "${vendor}" ] && [ "$(cat "${d}/device")" = "${device}" ] &&
            basename "${d}"
    done
}

# Binds one function to vfio-pci and runs the guest checks on it.
test_dev() {
    bdf="$1"
    echo vfio-pci >"/sys/bus/pci/devices/${bdf}/driver_override"
    if [ -e "/sys/bus/pci/devices/${bdf}/driver" ]; then
        echo "${bdf}" >"/sys/bus/pci/devices/${bdf}/driver/unbind"
    fi
    echo "${bdf}" >/sys/bus/pci/drivers_probe
    /bin/ak-guest-testdev "${bdf}"
}

boot_devs="$(testdevs)"
count=0
rc=0
for bdf in ${boot_devs}; do
    count=$((count + 1))
    test_dev "${bdf}" || rc=1
done
say "BOOT-DEVICES ${count}"
say "BOOT-TESTS rc=${rc}"

say "WAIT-HOTPLUG"
added=""
deadline=$(($(date +%s) + hotplug_timeout_s))
while [ -z "${added}" ] && [ "$(date +%s)" -lt "${deadline}" ]; do
    for bdf in $(testdevs); do
        case " ${boot_devs} " in
            *" ${bdf} "*) ;;
            *) added="${bdf}" ;;
        esac
    done
    [ -n "${added}" ] || sleep "${poll_s}"
done
if [ -n "${added}" ]; then
    say "HOTPLUG-ADDED ${added}"
    rc=0
    test_dev "${added}" || rc=1
    say "HOTPLUG-TESTS rc=${rc}"

    say "WAIT-UNPLUG"
    deadline=$(($(date +%s) + unplug_timeout_s))
    while [ -e "/sys/bus/pci/devices/${added}" ] && [ "$(date +%s)" -lt "${deadline}" ]; do
        sleep "${poll_s}"
    done
    if [ -e "/sys/bus/pci/devices/${added}" ]; then
        say "UNPLUG-TIMEOUT ${added}"
    else
        say "UNPLUG-SEEN ${added}"
    fi
else
    say "HOTPLUG-TIMEOUT"
fi

say "DONE"
poweroff -f
