#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Drive helm's mailbox function as a vfio-user client, with no QEMU.

    build/tests/mailbox_vfu_probe /tmp/mb.sock &
    harbor/mailbox_smoke.py /tmp/mb.sock

Speaks the vfio-user protocol directly against mailbox_vfu_probe, which
posts every event slot back as a command. Checks the PCI identity and
capabilities, the BAR0 identity registers, that a DMA map is accepted and
ignored, that a command posted before MSI-X is wired is withdrawn (the
doorbell does not move), that a posted command raises MSI-X vector 0 with
the slot already complete, that bad access widths fail, that a device
reset clears the register file, and that a response ends the run. Needs no
root. Exits non-zero on the first failed check.
"""

import array
import json
import os
import select
import socket
import struct
import sys
import time

sock_path = sys.argv[1]
CFG, BAR0 = 7, 0
VERSION, DMA_MAP, SET_IRQS, REGION_READ, REGION_WRITE, RESET = 1, 2, 8, 9, 10, 13
MAGIC, VER, CMD_DB, RSP_DB, EVT_DB = 0x000, 0x004, 0x008, 0x00C, 0x010
CMD_SLOT, RSP_SLOT, EVT_SLOT, SLOT = 0x100, 0x200, 0x300, 256
msg_id = 0


def send(cmd, payload=b"", fds=None, ok=True):
    global msg_id
    msg_id += 1
    hdr = struct.pack("HHIII", msg_id, cmd, 16 + len(payload), 0, 0)
    if fds:
        s.sendmsg([hdr + payload],
                  [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
    else:
        s.sendall(hdr + payload)
    data = s.recv(65536)
    _, _, _, _, err = struct.unpack("HHIII", data[:16])
    if ok:
        assert err == 0, f"cmd {cmd} errno {err}"
    return err, data[16:]


def rd(region, off, n):
    return send(REGION_READ, struct.pack("QII", off, region, n))[1][16:]


def rdi(region, off, n=4):
    return int.from_bytes(rd(region, off, n), "little")


def wr(region, off, n, v):
    send(REGION_WRITE, struct.pack("QII", off, region, n) + v.to_bytes(n, "little"))


def write_slot(base, words):
    for i, w in enumerate(words):
        wr(BAR0, base + 4 * i, 4, w)


def read_slot(base):
    return [rdi(BAR0, base + 4 * i) for i in range(SLOT // 4)]


s = socket.socket(socket.AF_UNIX)
for _ in range(50):
    try:
        s.connect(sock_path)
        break
    except OSError:
        time.sleep(0.1)
caps = json.dumps({"capabilities": {"max_msg_fds": 8, "max_data_xfer_size": 1048576}}).encode()
send(VERSION, struct.pack("HH", 0, 1) + caps + b"\0")

cfg = rd(CFG, 0, 256)
vid, did = struct.unpack_from("HH", cfg, 0)
print(f"ids {vid:04x}:{did:04x}")
assert (vid, did) == (0x1DE5, 0xA010)
p, found = cfg[0x34], {}
while p:
    found[cfg[p]] = p
    p = cfg[p + 1]
assert 0x10 in found and 0x11 in found, f"caps {found}"
msix_table_size = (struct.unpack_from("H", cfg, found[0x11] + 2)[0] & 0x7FF) + 1
assert msix_table_size == 1, msix_table_size

assert rdi(BAR0, MAGIC) == 0x424D4B41
assert rdi(BAR0, VER) == 3  # mailbox protocol v3
assert rdi(BAR0, CMD_DB) == 0

# A DMA map is accepted and ignored: the mailbox holds no guest memory.
RAM = 1 << 16
memfd = os.memfd_create("ram")
os.ftruncate(memfd, RAM)
send(DMA_MAP, struct.pack("IIQQQ", 32, 3, 0, 0x100000, RAM), fds=[memfd])

# Before MSI-X is wired the probe's post fails and is withdrawn.
pattern = [0x11110000 + i for i in range(SLOT // 4)]
write_slot(EVT_SLOT, pattern)
wr(BAR0, EVT_DB, 4, 1)
assert rdi(BAR0, CMD_DB) == 0, "a command was left visible after a failed interrupt"
assert read_slot(CMD_SLOT) == [0] * (SLOT // 4)

# Wire MSI-X vector 0 to an eventfd.
efd = os.eventfd(0, os.EFD_NONBLOCK)
VFIO_IRQ_SET_DATA_EVENTFD, VFIO_IRQ_SET_ACTION_TRIGGER, MSIX = 1 << 2, 1 << 5, 2
send(SET_IRQS, struct.pack("IIIII", 20, VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
                           MSIX, 0, 1), fds=[efd])

pattern = [0x22220000 + i for i in range(SLOT // 4)]
write_slot(EVT_SLOT, pattern)
wr(BAR0, EVT_DB, 4, 1)
r, _, _ = select.select([efd], [], [], 3)
assert r, "no MSI-X interrupt for the posted command"
os.eventfd_read(efd)
assert rdi(BAR0, CMD_DB) == 1
assert read_slot(CMD_SLOT) == pattern
print("command posted with interrupt")

# Accesses the register file refuses.
assert send(REGION_READ, struct.pack("QII", MAGIC, BAR0, 3), ok=False)[0] != 0
assert send(REGION_READ, struct.pack("QII", MAGIC + 2, BAR0, 4), ok=False)[0] != 0
# The host cannot write the command slot or the identity registers.
wr(BAR0, CMD_SLOT, 4, 0xFFFFFFFF)
wr(BAR0, MAGIC, 4, 0)
assert rdi(BAR0, CMD_SLOT) == pattern[0] and rdi(BAR0, MAGIC) == 0x424D4B41

# Device reset clears the register file.
send(RESET)
assert rdi(BAR0, CMD_DB) == 0
assert read_slot(CMD_SLOT) == [0] * (SLOT // 4)
assert read_slot(EVT_SLOT) == [0] * (SLOT // 4)
print("reset cleared the mailbox")

write_slot(RSP_SLOT, [0xAB] + [0] * (SLOT // 4 - 1))
wr(BAR0, RSP_DB, 4, 1)
print("SMOKE OK")
