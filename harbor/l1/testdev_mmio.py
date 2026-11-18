#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside L1. Reads and writes ak-testdev's BAR0 through sysfs
# (resource0) to prove MMIO reaches the board process.
#
# Register offsets mirror src/oar/testdev/main.cpp.
#
# Usage: testdev_mmio.py BDF magic|version|slot|reset-count|scratch-rw

import mmap
import struct
import sys

BAR0_SIZE = 0x1000
REG_MAGIC = 0x00
REG_VERSION = 0x04
REG_SCRATCH = 0x08
REG_RESET_COUNT = 0x10
REG_SLOT_ID = 0x14
MAGIC_AKTD = 0x44544B41
SCRATCH_PATTERNS = (0xA5A5A5A5, 0x5A5A5A5A, 0x00000000, 0xFFFFFFFF)
WORD = struct.Struct("<I")


def bar0(bdf):
    path = f"/sys/bus/pci/devices/{bdf}/resource0"
    with open(path, "r+b", buffering=0) as f:
        return mmap.mmap(f.fileno(), BAR0_SIZE)


def rd(m, off):
    return WORD.unpack(m[off:off + WORD.size])[0]


def wr(m, off, value):
    m[off:off + WORD.size] = WORD.pack(value)


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    bdf, op = sys.argv[1], sys.argv[2]
    m = bar0(bdf)
    if op == "magic":
        value = rd(m, REG_MAGIC)
        print(f"{value:#010x}")
        return 0 if value == MAGIC_AKTD else 1
    if op == "version":
        print(rd(m, REG_VERSION))
        return 0
    if op == "slot":
        print(rd(m, REG_SLOT_ID))
        return 0
    if op == "reset-count":
        print(rd(m, REG_RESET_COUNT))
        return 0
    if op == "scratch-rw":
        for pattern in SCRATCH_PATTERNS:
            wr(m, REG_SCRATCH, pattern)
            got = rd(m, REG_SCRATCH)
            if got != pattern:
                print(f"scratch wrote {pattern:#010x} read {got:#010x}")
                return 1
        print("ok")
        return 0
    print(f"unknown op {op}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
