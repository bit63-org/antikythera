#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Kernel WireGuard interop test (oar-net task 10, Requirement 5.1).
#
# Cross-checks ak::oar::net::Tunnel against the Linux wireguard driver in a
# pair of network namespaces joined by a veth over IPv6:
#
#   ns A  wireguard_interop_peer: the Tunnel on a UdpEndpoint, port 6081
#   ns B  wg0, a kernel wireguard device on port 6081 whose only peer is
#         ns A's key (with a pre-shared key), allowed-ips 10.98.0.1/32
#
#   1. kernel initiates: a datagram sent into wg0 makes the kernel start a
#      handshake; the peer answers it, decrypts the queued packet (the
#      kernel pads it), checks the marker and replies over the session; the
#      reply must reach a socket in ns B.
#   2. Tunnel initiates: a fresh peer process starts a handshake, and the
#      packet it then sends must reach a socket in ns B.
#
# Needs root, iproute2, wireguard-tools (wg), python3 and the wireguard
# module. Exits 77 (ctest SKIP_RETURN_CODE) when any of those is missing,
# so an unprivileged ctest run skips it; CI runs it under sudo.
#
# Usage: wireguard_interop.sh PATH/TO/wireguard_interop_peer

set -euo pipefail

readonly skip=77
readonly peer=${1:?usage: wireguard_interop.sh PATH/TO/wireguard_interop_peer}

readonly underlay_a=fd5a:6c00::1
readonly underlay_b=fd5a:6c00::2
readonly wg_port=6081
readonly inner_a=10.98.0.1
readonly inner_b=10.98.0.2
readonly port_to_peer=5555
readonly port_to_kernel=5556
readonly timeout_s=10

skip_test() {
    echo "SKIP: $*"
    exit "$skip"
}

[[ $(id -u) -eq 0 ]] || skip_test "needs root (CI runs it under sudo)"
for tool in ip wg python3 base64 od; do
    command -v "$tool" >/dev/null || skip_test "$tool not installed"
done
[[ -x $peer ]] || { echo "FAIL: $peer is not executable"; exit 1; }

ns_a=akwg-a-$$
ns_b=akwg-b-$$
rx_pid=
peer_pid=
workdir=$(mktemp -d)

cleanup() {
    [[ -n $rx_pid ]] && kill "$rx_pid" 2>/dev/null
    [[ -n $peer_pid ]] && kill "$peer_pid" 2>/dev/null
    ip netns del "$ns_a" 2>/dev/null
    ip netns del "$ns_b" 2>/dev/null
    rm -rf "$workdir"
    return 0
}
trap cleanup EXIT

ip netns add "$ns_a" 2>/dev/null || skip_test "cannot create network namespaces"
ip netns add "$ns_b"
in_a() { ip netns exec "$ns_a" "$@"; }
in_b() { ip netns exec "$ns_b" "$@"; }

if ! ip -n "$ns_b" link add wg0 type wireguard 2>/dev/null; then
    modprobe wireguard 2>/dev/null || true
    ip -n "$ns_b" link add wg0 type wireguard 2>/dev/null ||
        skip_test "kernel has no wireguard support"
fi

# Base64 (wg's key format) to the 64 hex digits the peer takes.
hex() { printf '%s' "$1" | base64 -d | od -An -tx1 -v | tr -d ' \n'; }

kernel_key=$(wg genkey)
kernel_pub=$(printf '%s' "$kernel_key" | wg pubkey)
peer_key=$(wg genkey)
peer_pub=$(printf '%s' "$peer_key" | wg pubkey)
psk=$(wg genpsk)
printf '%s\n' "$kernel_key" >"$workdir/kernel.key"
printf '%s\n' "$psk" >"$workdir/psk"

# Underlay: IPv6 over a veth, no DAD so the addresses are usable at once.
ip -n "$ns_a" link add va type veth peer name vb netns "$ns_b"
in_a ip addr add "$underlay_a/64" dev va nodad
in_b ip addr add "$underlay_b/64" dev vb nodad
in_a ip link set va up
in_b ip link set vb up
in_a ip link set lo up
in_b ip link set lo up

in_b wg set wg0 listen-port "$wg_port" private-key "$workdir/kernel.key" \
    peer "$peer_pub" preshared-key "$workdir/psk" \
    endpoint "[$underlay_a]:$wg_port" allowed-ips "$inner_a/32"
in_b ip addr add "$inner_b/24" dev wg0
in_b ip link set wg0 up

peer_args=(--addr "$underlay_a" --port "$wg_port" --private "$(hex "$peer_key")"
    --peer "$underlay_b" --peer-port "$wg_port" --peer-public "$(hex "$kernel_pub")"
    --psk "$(hex "$psk")" --ip "$inner_a" --peer-ip "$inner_b"
    --udp-in "$port_to_peer" --udp-out "$port_to_kernel" --timeout "$timeout_s")

wait_for_line() {  # file pattern
    local i
    for ((i = 0; i < timeout_s * 10; i++)); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# A UDP receiver in ns B on inner_b:port_to_kernel, writing to $1.
start_receiver() {
    in_b python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
s.settimeout(float(sys.argv[3]))
print("listening", flush=True)
data, src = s.recvfrom(65536)
print("received", data.decode(errors="replace"), "from", src[0], flush=True)
' "$inner_b" "$port_to_kernel" "$timeout_s" >"$1" 2>&1 &
    rx_pid=$!
    wait_for_line "$1" '^listening'
}

failures=0

echo "== kernel initiates, Tunnel responds"
marker_in="ak-wg-interop-kernel-$$"
reply="ak-wg-interop-reply-$$"
start_receiver "$workdir/rx1.out"
in_a "$peer" respond "${peer_args[@]}" --marker "$marker_in" --reply "$reply" \
    >"$workdir/peer1.out" 2>&1 &
peer_pid=$!
if wait_for_line "$workdir/peer1.out" '^listening'; then
    # bash's /dev/udp: one datagram from ns B's stack into wg0.
    in_b bash -c "printf '%s' '$marker_in' >/dev/udp/$inner_a/$port_to_peer"
fi
peer_ok=0
wait "$peer_pid" && peer_ok=1
peer_pid=
wait "$rx_pid" || true
rx_pid=
cat "$workdir/peer1.out" "$workdir/rx1.out"
if ((peer_ok)) && grep -q "^received $marker_in\$" "$workdir/peer1.out"; then
    echo "PASS: kernel -> Tunnel (handshake answered, padded packet decrypted)"
else
    echo "FAIL: kernel -> Tunnel"
    failures=$((failures + 1))
fi
if grep -q "^received $reply from $inner_a\$" "$workdir/rx1.out"; then
    echo "PASS: Tunnel -> kernel on the kernel's session"
else
    echo "FAIL: Tunnel -> kernel on the kernel's session"
    failures=$((failures + 1))
fi

echo "== Tunnel initiates"
marker_out="ak-wg-interop-tunnel-$$"
start_receiver "$workdir/rx2.out"
peer_ok=0
in_a "$peer" initiate "${peer_args[@]}" --marker "$marker_out" >"$workdir/peer2.out" 2>&1 &&
    peer_ok=1
wait "$rx_pid" || true
rx_pid=
cat "$workdir/peer2.out" "$workdir/rx2.out"
if ((peer_ok)) && grep -q "^received $marker_out from $inner_a\$" "$workdir/rx2.out"; then
    echo "PASS: Tunnel -> kernel (Tunnel's handshake accepted)"
else
    echo "FAIL: Tunnel -> kernel (Tunnel's handshake)"
    failures=$((failures + 1))
fi

in_b wg show wg0 || true
if ((failures > 0)); then
    echo "wireguard interop: $failures failure(s)"
    exit 1
fi
echo "wireguard interop: all checks passed"
