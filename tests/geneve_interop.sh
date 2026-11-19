#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Kernel Geneve interop test (oar-net task 4, Requirement 9.2).
#
# Cross-checks ak::oar::net::geneve against the Linux geneve driver in a
# pair of network namespaces joined by a veth over IPv6:
#
#   ns A  geneve_interop_peer: the codec on a plain UDP socket, port 6081
#   ns B  gnv0, a kernel geneve device in external (collect_md) mode, with
#         tc tunnel_key adding our NIC-pair option on egress and a flower
#         filter matching that option on ingress
#
#   1. kernel -> codec: a UDP datagram sent into gnv0 is encapsulated by
#      the kernel; the peer must decode it to the configured VNI and NIC
#      pair and re-encode it to the same bytes.
#   2. codec -> kernel: the peer encodes an inner Ethernet/IPv4/UDP frame;
#      the kernel must decapsulate it, match the option in flower, and
#      deliver the inner datagram to a socket in ns B.
#
# Needs root, iproute2 with tc, python3 and the geneve module. Exits 77
# (ctest SKIP_RETURN_CODE) when any of those is missing, so an unprivileged
# ctest run skips it; CI runs it under sudo.
#
# Usage: geneve_interop.sh PATH/TO/geneve_interop_peer

set -euo pipefail

readonly skip=77
readonly peer=${1:?usage: geneve_interop.sh PATH/TO/geneve_interop_peer}

readonly vni=4242
readonly opt_class=FF41   # geneve::option_class
readonly opt_type=81      # geneve::option_type_nic_pair (critical)
readonly src_nic=0x1111222233334444
readonly dst_nic=0x5555666677778888
readonly underlay_a=fd5a:6b00::1
readonly underlay_b=fd5a:6b00::2
readonly inner_a=10.99.0.1
readonly inner_b=10.99.0.2
readonly mac_a=02:00:5a:00:00:01
readonly mac_b=02:00:5a:00:00:02
readonly port_to_codec=5555
readonly port_to_kernel=5556
readonly timeout_s=10

# NIC pair option data: source NIC then destination NIC, 64-bit big-endian.
# For the kernel's egress the kernel host (ns B) is the sender.
opt_data() { printf '%016x%016x' "$1" "$2"; }

skip_test() {
    echo "SKIP: $*"
    exit "$skip"
}

[[ $(id -u) -eq 0 ]] || skip_test "needs root (CI runs it under sudo)"
for tool in ip tc python3; do
    command -v "$tool" >/dev/null || skip_test "$tool not installed"
done
[[ -x $peer ]] || { echo "FAIL: $peer is not executable"; exit 1; }

ns_a=akgnv-a-$$
ns_b=akgnv-b-$$
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

if ! ip -n "$ns_b" link add gnv0 type geneve external dstport 6081 2>/dev/null; then
    modprobe geneve 2>/dev/null || true
    ip -n "$ns_b" link add gnv0 type geneve external dstport 6081 2>/dev/null ||
        skip_test "kernel has no geneve support"
fi

# Underlay: IPv6 over a veth, no DAD so the addresses are usable at once.
ip -n "$ns_a" link add va type veth peer name vb netns "$ns_b"
in_a ip addr add "$underlay_a/64" dev va nodad
in_b ip addr add "$underlay_b/64" dev vb nodad
in_a ip link set va up
in_b ip link set vb up
in_a ip link set lo up
in_b ip link set lo up

# Overlay end in ns B. IPv6 off on gnv0 keeps router solicitations and
# the like out of the tunnel.
in_b sysctl -qw net.ipv6.conf.gnv0.disable_ipv6=1
in_b ip link set gnv0 address "$mac_b"
in_b ip addr add "$inner_b/24" dev gnv0
in_b ip link set gnv0 up
in_b ip neigh add "$inner_a" lladdr "$mac_a" dev gnv0 nud permanent

tc_opts_out="$opt_class:$opt_type:$(opt_data "$src_nic" "$dst_nic")"
tc_opts_in="$opt_class:$opt_type:$(opt_data "$dst_nic" "$src_nic")"
in_b tc qdisc add dev gnv0 clsact
in_b tc filter add dev gnv0 egress matchall \
    action tunnel_key set src_ip "$underlay_b" dst_ip "$underlay_a" \
    id "$vni" dst_port 6081 geneve_opts "$tc_opts_out" pipe \
    action pass
in_b tc filter add dev gnv0 ingress protocol ip flower \
    enc_key_id "$vni" enc_dst_port 6081 geneve_opts "$tc_opts_in" \
    action pass

wait_for_line() {  # file pattern
    local i
    for ((i = 0; i < timeout_s * 10; i++)); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

failures=0

echo "== kernel -> codec"
marker_in="ak-geneve-interop-kernel-$$"
in_a "$peer" recv --addr "$underlay_a" --vni "$vni" \
    --src-nic "$src_nic" --dst-nic "$dst_nic" \
    --marker "$marker_in" --timeout "$timeout_s" >"$workdir/peer.out" 2>&1 &
peer_pid=$!
if wait_for_line "$workdir/peer.out" '^listening'; then
    # bash's /dev/udp: one datagram from ns B's stack into gnv0.
    in_b bash -c "printf '%s' '$marker_in' >/dev/udp/$inner_a/$port_to_codec"
fi
if wait "$peer_pid"; then
    peer_pid=
    cat "$workdir/peer.out"
else
    peer_pid=
    cat "$workdir/peer.out"
    echo "FAIL: kernel -> codec"
    failures=$((failures + 1))
fi

echo "== codec -> kernel"
marker_out="ak-geneve-interop-codec-$$"
in_b python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
s.settimeout(float(sys.argv[3]))
print("listening", flush=True)
data, src = s.recvfrom(65536)
print("received", data.decode(errors="replace"), "from", src[0], flush=True)
' "$inner_b" "$port_to_kernel" "$timeout_s" >"$workdir/rx.out" 2>&1 &
rx_pid=$!
if wait_for_line "$workdir/rx.out" '^listening'; then
    in_a "$peer" send --addr "$underlay_b" --vni "$vni" \
        --src-nic "$dst_nic" --dst-nic "$src_nic" --marker "$marker_out" \
        --src-mac "$mac_a" --dst-mac "$mac_b" \
        --src-ip "$inner_a" --dst-ip "$inner_b" --udp-port "$port_to_kernel" || true
fi
wait "$rx_pid" || true
rx_pid=
cat "$workdir/rx.out"
if grep -q "^received $marker_out from $inner_a\$" "$workdir/rx.out"; then
    echo "PASS: codec -> kernel (inner datagram delivered)"
else
    echo "FAIL: codec -> kernel (inner datagram not delivered)"
    in_b ip -s link show gnv0 || true
    failures=$((failures + 1))
fi

# The ingress flower filter matches only on our VNI and exact option, so a
# hit shows the kernel parsed the NIC-pair option the way we encoded it.
if in_b tc -s filter show dev gnv0 ingress | grep -Eq 'Sent [1-9][0-9]* bytes [1-9][0-9]* pkt'; then
    echo "PASS: codec -> kernel (flower matched VNI and NIC-pair option)"
else
    in_b tc -s filter show dev gnv0 ingress || true
    echo "FAIL: codec -> kernel (flower did not match the option)"
    failures=$((failures + 1))
fi

if ((failures > 0)); then
    echo "geneve interop: $failures failure(s)"
    exit 1
fi
echo "geneve interop: all checks passed"
