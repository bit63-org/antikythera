#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Drive a running ak-oar-net as a vfio-user client, with no QEMU or guest.

    sudo build/src/ak-oar-net --socket /tmp/n.sock --nic-id 7 \
        --mac 02:00:5e:10:20:30 --mtu 1500 --tap aknet0 &
    sudo harbor/oar_net_smoke.py /tmp/n.sock aknet0

Speaks the vfio-user protocol directly: version handshake, PCI config space
and capability walk, a memfd DMA-mapped as guest RAM, virtio driver
bring-up through BAR0, one frame transmitted out of the TAP and one frame
received from it, then checks the guest cannot rewrite the MAC. Needs root
(the TAP and an AF_PACKET socket on it). Exits non-zero on the first
failed check.
"""

import array
import fcntl
import json
import mmap
import os
import socket
import struct
import sys
import time

sock_path, tap = sys.argv[1], sys.argv[2]
CFG, BAR0 = 7, 0
VERSION, DMA_MAP, REGION_READ, REGION_WRITE = 1, 2, 9, 10
msg_id = 0

def send(cmd, payload=b"", fds=None):
    global msg_id
    msg_id += 1
    hdr = struct.pack("HHIII", msg_id, cmd, 16 + len(payload), 0, 0)
    if fds:
        s.sendmsg([hdr + payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
    else:
        s.sendall(hdr + payload)
    data = s.recv(65536)
    mid, c, size, flags, err = struct.unpack("HHIII", data[:16])
    assert err == 0, f"cmd {cmd} errno {err}"
    return data[16:]

def rd(region, off, n):
    return send(REGION_READ, struct.pack("QII", off, region, n))[16:]

def wr(region, off, n, v):
    send(REGION_WRITE, struct.pack("QII", off, region, n) + v.to_bytes(n, "little"))

def rdi(region, off, n):
    return int.from_bytes(rd(region, off, n), "little")

s = socket.socket(socket.AF_UNIX)
for _ in range(50):
    try:
        s.connect(sock_path); break
    except OSError:
        time.sleep(0.1)
caps = json.dumps({"capabilities": {"max_msg_fds": 8, "max_data_xfer_size": 1048576}}).encode()
send(VERSION, struct.pack("HH", 0, 1) + caps + b"\0")

cfg = rd(CFG, 0, 256)
vid, did = struct.unpack_from("HH", cfg, 0)
print(f"ids {vid:04x}:{did:04x} rev {cfg[8]} class {cfg[11]:02x}{cfg[10]:02x}")
assert (vid, did, cfg[8], cfg[11]) == (0x1AF4, 0x1041, 1, 0x02)
p = cfg[0x34]; vcaps = {}
while p:
    cid, nxt = cfg[p], cfg[p + 1]
    if cid == 0x09:
        t, bar = cfg[p + 3], cfg[p + 4]
        off, ln = struct.unpack_from("II", cfg, p + 8)
        vcaps[t] = (bar, off, ln)
    print(f"cap {cid:02x} at {p:02x}")
    p = nxt
print("virtio caps", vcaps)
assert set(vcaps) == {1, 2, 3, 4}

# Guest RAM: 1 MiB memfd mapped at IOVA 0x100000.
RAM, BASE = 1 << 20, 0x100000
fd = os.memfd_create("ram"); os.ftruncate(fd, RAM)
ram = mmap.mmap(fd, RAM)
send(DMA_MAP, struct.pack("IIQQQ", 32, 3, 0, BASE, RAM), fds=[fd])

def put(gpa, fmt, *v): struct.pack_into(fmt, ram, gpa - BASE, *v)
def get(gpa, fmt): return struct.unpack_from(fmt, ram, gpa - BASE)

mac = bytes(rdi(BAR0, 0x2000 + i, 1) for i in range(6)); mtu = rdi(BAR0, 0x2000 + 10, 2)
print("mac", mac.hex(":"), "mtu", mtu)
# Bring-up (spec 3.1.1).
wr(BAR0, 20, 1, 0); wr(BAR0, 20, 1, 1); wr(BAR0, 20, 1, 3)
wr(BAR0, 8, 4, 0); wr(BAR0, 12, 4, (1 << 5) | (1 << 3))
wr(BAR0, 8, 4, 1); wr(BAR0, 12, 4, 1)
wr(BAR0, 20, 1, 0xB)
assert rdi(BAR0, 20, 1) & 8, "FEATURES_OK refused"
QS = 8
def ring(q): b = BASE + 0x10000 * (q + 1); return b, b + 0x1000, b + 0x2000, b + 0x4000
for q in (0, 1):
    d, a, u, _ = ring(q)
    wr(BAR0, 22, 2, q); wr(BAR0, 24, 2, QS)
    wr(BAR0, 32, 8, d); wr(BAR0, 40, 8, a); wr(BAR0, 48, 8, u); wr(BAR0, 28, 2, 1)
wr(BAR0, 20, 1, 0xF)
assert rdi(BAR0, 20, 1) == 0xF, hex(rdi(BAR0, 20, 1))

# RX: post one 2 KiB writable buffer.
d, a, u, data = ring(0)
put(d, "QIHH", data, 2048, 2, 0); put(a + 4, "H", 0); put(a + 2, "H", 1)
wr(BAR0, 0x3000, 2, 0)

# TX: header + frame from our MAC.
ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ifr = struct.pack("16sH", tap.encode(), 0x1)  # IFF_UP
fcntl.ioctl(ctl, 0x8914, ifr)  # SIOCSIFFLAGS
pk = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88B5))
pk.bind((tap, 0)); pk.settimeout(3)
frame = b"\xff" * 6 + mac + b"\x88\xb5" + b"hello oar-net".ljust(46, b"\0")
d, a, u, data = ring(1)
pkt = b"\0" * 12 + frame
ram[data - BASE:data - BASE + len(pkt)] = pkt
put(d, "QIHH", data, len(pkt), 0, 0); put(a + 4, "H", 0); put(a + 2, "H", 1)
wr(BAR0, 0x3000 + 4, 2, 1)
assert get(u + 2, "H")[0] == 1, "TX not consumed"
got = pk.recv(2048)
print("tap got", len(got), "bytes", got == frame)
assert got == frame

# RX: write a frame into the TAP, see it land in the guest buffer.
inbound = mac + b"\x02\x00\x00\x00\x00\x99" + b"\x88\xb5" + b"to the guest".ljust(46, b"\0")
pk.send(inbound)
d, a, u, data = ring(0)
for _ in range(50):
    if get(u + 2, "H")[0] == 1: break
    time.sleep(0.05)
_, ln = get(u + 4, "II")
body = bytes(ram[data - BASE:data - BASE + ln])
print("rx used len", ln, "num_buffers", struct.unpack_from("H", body, 10)[0], body[12:] == inbound)
assert ln == 12 + len(inbound) and body[12:] == inbound
# Guest cannot rewrite its MAC.
try:
    wr(BAR0, 0x2000, 1, 0xEE)
except AssertionError:
    pass
assert bytes(rdi(BAR0, 0x2000 + i, 1) for i in range(6)) == mac
# FLR-equivalent: driver reset clears status.
wr(BAR0, 20, 1, 0)
assert rdi(BAR0, 20, 1) == 0
print("SMOKE OK")
