#!/bin/bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# guest/ak-guest-eject against a fake sysfs and procfs
# (.kiro/specs/block-volume-service/ Requirement 3.4): it releases a disk
# whose function asks for it only when nothing uses the disk, and leaves
# everything else alone.
#
# Usage: guest_eject_test.sh PATH_TO_AK_GUEST_EJECT

set -euo pipefail

helper="${1:?usage: guest_eject_test.sh PATH_TO_AK_GUEST_EJECT}"
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

sys="$root/sys"
proc="$root/proc"
bdf="0000:00:05.0"
dev="$sys/bus/pci/devices/$bdf"
failures=0

# put FILE OFFSET HEX...: writes bytes at OFFSET.
put() {
    local file="$1" off="$2" esc="" b
    shift 2
    for b in "$@"; do
        esc+="\\x$b"
    done
    # shellcheck disable=SC2059  # the format is the escapes we built
    printf "$esc" | dd of="$file" bs=1 seek="$off" conv=notrunc status=none
}

# A virtio-blk function with an MSI-X capability, then antikythera's.
setup() {
    rm -rf "$sys" "$proc"
    mkdir -p "$dev/virtio2/block/vda" "$sys/block/vda/holders" "$proc/self" "$proc/1/fd"
    echo 0x1af4 >"$dev/vendor"
    head -c 256 /dev/zero >"$dev/config"
    put "$dev/config" 6 10 00                  # status: capability list
    put "$dev/config" 52 40                    # first capability at 0x40
    put "$dev/config" 64 11 50 0c 00           # MSI-X, next 0x50
    put "$dev/config" 80 09 00 10 09 f4 1a 01 00 41 4b 56 44 00 00 00 00
    echo 253:0 >"$sys/block/vda/dev"
    : >"$proc/self/mountinfo"
    printf 'Filename\tType\tSize\tUsed\tPriority\n' >"$proc/swaps"
}

request() { put "$dev/config" 92 01 00 00 00; }

run() {
    AK_SYSFS="$sys" AK_PROC="$proc" "$helper" --once "$@" 2>"$root/log"
}

check() {
    local what="$1"
    shift
    if "$@"; then
        echo "ok: $what"
    else
        echo "FAIL: $what"
        sed 's/^/  log: /' "$root/log"
        failures=$(( failures + 1 ))
    fi
}

released() { [ "$(cat "$dev/remove" 2>/dev/null)" = 1 ]; }
kept() { [ ! -e "$dev/remove" ]; }
logged() { grep -q -- "$1" "$root/log"; }

setup
run
check "no request: nothing happens" kept

request
echo "36 25 253:0 / /data rw - ext4 /dev/vda rw" >"$proc/self/mountinfo"
run
check "mounted: kept" kept
check "mounted: says why" logged "vda is mounted"

setup
request
mkdir -p "$sys/block/vda/vda1/holders/dm-0"
: >"$sys/block/vda/vda1/partition"
echo 253:1 >"$sys/block/vda/vda1/dev"
run
check "partition under dm-crypt/LVM: kept" kept
check "partition holder: says why" logged "vda1 is held by dm-0"

rm -rf "$sys/block/vda/vda1/holders/dm-0"
echo "37 25 253:1 / /boot rw - ext4 /dev/vda1 rw" >"$proc/self/mountinfo"
run
check "mounted partition: kept" kept
check "mounted partition: says why" logged "vda1 is mounted"

setup
request
printf '/dev/vda\tpartition\t1024\t0\t-2\n' >>"$proc/swaps"
run
check "swap: kept" kept
check "swap: says why" logged "vda is swap"

setup
request
ln -s /dev/vda "$proc/1/fd/3"
run
check "open: kept" kept
check "open: says why" logged "open by pid 1"

setup
request
run --dry-run
check "dry run: kept" kept
check "dry run: says so" logged "would release"

setup
put "$dev/config" 88 41 4b 56 45 01  # another vendor's data, flags set
run
check "foreign vendor data: ignored" kept

setup
echo 0x8086 >"$dev/vendor"
request
run
check "not a virtio function: ignored" kept

setup
request
put "$dev/config" 64 11 40 0c 00    # MSI-X pointing at itself
run
check "a looping capability list ends" kept

setup
request
run
check "unused disk: released" released
check "unused disk: says so" logged "releasing"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
