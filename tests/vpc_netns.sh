#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Network-namespace VPC test (vpc-subnets-routing task 7, Requirement 8.3).
#
# Two network roles (tests/vpc_netns_role) in namespaces r1 and r2, joined
# by an IPv6 veth underlay and talking WireGuard over it. Their NICs are
# TAP devices moved into guest namespaces, where the kernel's own stack
# is the guest:
#
#   ga  NIC 0x11 on role 1, subnet A (10.0.1.0/24, fd10:0:0:1::/64)
#   gc  NIC 0x33 on role 1, subnet B (10.0.2.0/24, fd10:0:0:2::/64)
#   gb  NIC 0x22 on role 2, subnet B
#
# Checks:
#   1. dhclient (DHCPv4 and DHCPv6) and router advertisements give each
#      guest its subnet's address, gateway, on-link prefix and the
#      planned MTU.
#   2. ping across subnets in both families, on one role (a to c) and
#      across roles (a to b, b to a); TCP across subnets in both families.
#   3. traceroute from a to b: the VPC router is one hop (it lowers the
#      TTL and sends no time-exceeded, so hop 1 is silent) and b answers
#      at hop 2.
#   4. ARP from a for b's address and for subnet B's gateway goes
#      unanswered: another subnet is reached only through the router.
#   5. Full-size packets at the planned guest MTU cross with DF set, and
#      a bulk TCP transfer arrives intact.
#
# Needs root, iproute2, dhclient (isc-dhcp-client), busybox (arping,
# traceroute), ping and python3. Exits 77 (ctest SKIP_RETURN_CODE) when
# any of those is missing, so an unprivileged ctest run skips it; CI runs
# it under sudo.
#
# Usage: vpc_netns.sh PATH/TO/vpc_netns_role

set -euo pipefail

readonly skip=77
readonly role_bin=${1:?usage: vpc_netns.sh PATH/TO/vpc_netns_role}

# The VPC is fixed in tests/vpc_netns_role.cpp; these must match it.
readonly vtep1=fd5a:7600::1
readonly vtep2=fd5a:7600::2
readonly ip_a=10.0.1.17 ip_b=10.0.2.34 ip_c=10.0.2.51  # 10.0.SUBNET.NIC, NIC IDs in decimal
readonly ip6_a=fd10:0:0:1::11 ip6_b=fd10:0:0:2::22 ip6_c=fd10:0:0:2::33
readonly gw_a=10.0.1.1 gw_b=10.0.2.1
readonly tcp_port=7000
readonly bulk_bytes=2097152
readonly timeout_s=15

skip_test() {
    echo "SKIP: $*"
    exit "$skip"
}

[[ $(id -u) -eq 0 ]] || skip_test "needs root (CI runs it under sudo)"
for tool in ip dhclient busybox ping python3; do
    command -v "$tool" >/dev/null || skip_test "$tool not installed"
done
for applet in arping traceroute; do
    busybox --list | grep -qx "$applet" || skip_test "busybox has no $applet"
done
[[ -c /dev/net/tun ]] || skip_test "no /dev/net/tun"
[[ -d /proc/sys/net/ipv6 ]] || skip_test "the kernel has no IPv6"
[[ -x $role_bin ]] || { echo "FAIL: $role_bin is not executable"; exit 1; }

suffix=$$
r1=akvpc-r1-$suffix
r2=akvpc-r2-$suffix
ga=akvpc-ga-$suffix
gb=akvpc-gb-$suffix
gc=akvpc-gc-$suffix
workdir=$(mktemp -d)
role_pids=()

cleanup() {
    local status=$?
    set +e
    for pidfile in "$workdir"/*.pid; do
        [[ -f $pidfile ]] && kill "$(cat "$pidfile")" 2>/dev/null
    done
    for pid in "${role_pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
    done
    if [[ $status -ne 0 ]]; then
        for log in "$workdir"/*.err "$workdir"/*.dhcp*; do
            [[ -f $log ]] && { echo "--- $(basename "$log")"; cat "$log"; }
        done
        for ns in "$ga" "$gb" "$gc"; do
            echo "--- $ns"
            ip -n "$ns" addr show 2>&1
        done
    fi
    for ns in "$r1" "$r2" "$ga" "$gb" "$gc"; do
        ip netns del "$ns" 2>/dev/null
    done
    rm -rf "$workdir"
    exit "$status"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    exit 1
}

in_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$@"
}

# Runs a command until it succeeds, at most $1 times, a second apart.
retry() {
    local tries=$1
    shift
    for ((i = 0; i < tries; ++i)); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

for ns in "$r1" "$r2" "$ga" "$gb" "$gc"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

# The underlay: one IPv6 link between the two roles.
ip link add akvpc1 netns "$r1" type veth peer name akvpc2 netns "$r2"
ip -n "$r1" addr add "$vtep1/64" dev akvpc1 nodad
ip -n "$r2" addr add "$vtep2/64" dev akvpc2 nodad
ip -n "$r1" link set akvpc1 up
ip -n "$r2" link set akvpc2 up

# Guests take router advertisements and skip DAD, so DHCPv6 can start at
# once on the link-local address.
for ns in "$ga" "$gb" "$gc"; do
    for conf in all default; do
        in_ns "$ns" sysctl -qw "net.ipv6.conf.$conf.accept_dad=0"
        in_ns "$ns" sysctl -qw "net.ipv6.conf.$conf.accept_ra=1"
    done
done

# The TAPs start in the roles' namespaces, where the roles open them by
# name; they move to the guests once the roles hold them.
ip -n "$r1" tuntap add dev tapa mode tap
ip -n "$r1" tuntap add dev tapc mode tap
ip -n "$r2" tuntap add dev tapb mode tap

# The roles start with ip netns exec itself, not in_ns: a backgrounded
# shell function is a subshell, so $! would name it rather than the role,
# and SIGTERM would end the subshell and leave the role running.
ip netns exec "$r1" "$role_bin" --role 1 --vtep1 "$vtep1" --vtep2 "$vtep2" \
    --tap tapa=0x11,02:00:00:00:00:11 --tap tapc=0x33,02:00:00:00:00:33 \
    >"$workdir/r1.out" 2>"$workdir/r1.err" &
role_pids+=($!)
ip netns exec "$r2" "$role_bin" --role 2 --vtep1 "$vtep1" --vtep2 "$vtep2" \
    --tap tapb=0x22,02:00:00:00:00:22 \
    >"$workdir/r2.out" 2>"$workdir/r2.err" &
role_pids+=($!)
for out in "$workdir/r1.out" "$workdir/r2.out"; do
    for ((i = 0; i < timeout_s * 10; ++i)); do
        grep -q '^ready' "$out" && break
        sleep 0.1
    done
    grep -q '^ready' "$out" || fail "role did not start ($out)"
done
mtu=$(awk '/^ready/ {print $2}' "$workdir/r1.out")
echo "roles ready, guest MTU $mtu"

# dhclient runs with this script instead of dhclient-script, which would
# rewrite the host's /etc/resolv.conf from inside a namespace. It runs
# from a copy: AppArmor confines /sbin/dhclient by path, and its profile
# allows neither this script nor lease files in $workdir.
cp "$(command -v dhclient)" "$workdir/dhclient"
cat >"$workdir/dhclient-script" <<'EOF'
#!/bin/sh
case "$reason" in
    PREINIT)
        ip link set dev "$interface" up
        ;;
    BOUND | RENEW | REBIND | REBOOT)
        ip -4 addr replace "$new_ip_address/$new_subnet_mask" dev "$interface"
        [ -n "$new_interface_mtu" ] && ip link set dev "$interface" mtu "$new_interface_mtu"
        for router in $new_routers; do
            ip -4 route replace default via "$router" dev "$interface"
        done
        ;;
    BOUND6 | RENEW6 | REBIND6 | REBOOT6)
        ip -6 addr replace "$new_ip6_address/128" dev "$interface" nodad
        ;;
esac
exit 0
EOF
chmod +x "$workdir/dhclient-script"
printf 'timeout %s;\nretry 1;\nrequest subnet-mask, routers, interface-mtu;\n' "$timeout_s" \
    >"$workdir/dhclient.conf"

# The guest's interface takes its NIC's MAC: the VSwitch drops a frame
# whose source MAC is not the NIC's (oar-net Requirement 5), and a TAP
# starts with a random one. dhclient -1 exits 0 even when it gives up
# ("sleeping"), so a lease is checked by its lease file, and its log is
# kept for the failure dump.
guest() {  # ns tap
    local ns=$1 tap=$2
    ip -n "${role_ns[$tap]}" link set "$tap" netns "$ns"
    ip -n "$ns" link set "$tap" address "${nic_mac[$tap]}"
    ip -n "$ns" link set "$tap" up
    for family in 4 6; do
        in_ns "$ns" "$workdir/dhclient" "-$family" -1 -v -cf "$workdir/dhclient.conf" \
            -sf "$workdir/dhclient-script" -lf "$workdir/$tap.lease$family" \
            -pf "$workdir/$tap.dhclient$family.pid" "$tap" \
            >"$workdir/$tap.dhcp$family" 2>&1 || fail "DHCPv$family on $tap"
        grep -q lease "$workdir/$tap.lease$family" 2>/dev/null ||
            fail "DHCPv$family on $tap: no lease"
    done
}
declare -A role_ns=([tapa]=$r1 [tapc]=$r1 [tapb]=$r2)
declare -A nic_mac=([tapa]=02:00:00:00:00:11 [tapc]=02:00:00:00:00:33 [tapb]=02:00:00:00:00:22)
guest "$ga" tapa
guest "$gc" tapc
guest "$gb" tapb

# 1. Each guest configured itself for its subnet.
expect_config() {  # ns tap ipv4 gateway ipv6 prefix6
    local ns=$1 tap=$2 v4=$3 gw=$4 v6=$5 prefix=$6
    ip -n "$ns" -4 addr show dev "$tap" | grep -q "inet $v4/24" || fail "$tap has no $v4/24"
    ip -n "$ns" -4 route show default | grep -q "via $gw dev $tap" || fail "$tap: no default via $gw"
    ip -n "$ns" link show dev "$tap" | grep -q "mtu $mtu " || fail "$tap: MTU is not $mtu"
    ip -n "$ns" -6 addr show dev "$tap" | grep -q "inet6 $v6/128" || fail "$tap has no $v6"
    retry "$timeout_s" sh -c "ip -n $ns -6 route show default | grep -q 'via fe80'" ||
        fail "$tap: no IPv6 default route from a router advertisement"
    ip -n "$ns" -6 route show | grep -q "^$prefix dev $tap" || fail "$tap: $prefix not on-link"
}
expect_config "$ga" tapa "$ip_a" "$gw_a" "$ip6_a" fd10:0:0:1::/64
expect_config "$gc" tapc "$ip_c" "$gw_b" "$ip6_c" fd10:0:0:2::/64
expect_config "$gb" tapb "$ip_b" "$gw_b" "$ip6_b" fd10:0:0:2::/64
echo "ok: DHCP and RA configured every guest"

# 2. ping across subnets, on one role and across roles, both families.
# The first packets across roles may wait for the WireGuard handshake.
reach() {  # ns destination
    retry "$timeout_s" in_ns "$1" ping -c 1 -W 1 "$2" || fail "$1 cannot reach $2"
    in_ns "$1" ping -c 3 -i 0.2 -W 1 "$2" >/dev/null || fail "$1 loses packets to $2"
}
reach "$ga" "$ip_c"
reach "$ga" "$ip_b"
reach "$gb" "$ip_a"
reach "$ga" "$ip6_c"
reach "$ga" "$ip6_b"
reach "$gb" "$ip6_a"
echo "ok: ping across subnets, on one role and across roles, IPv4 and IPv6"

# 3. traceroute: the router is the one hop between subnets.
trace=$(in_ns "$ga" busybox traceroute -n -m 3 -q 1 -w 1 "$ip_b" 2>&1) || true
echo "$trace"
echo "$trace" | grep -Eq '^ *1 +\*' || fail "hop 1 answered: the router sends no time-exceeded"
echo "$trace" | grep -Eq "^ *2 +$ip_b " || fail "$ip_b is not at hop 2"
echo "ok: traceroute shows the router as one hop"

# 4. ARP for another subnet's address, or its gateway, goes unanswered.
in_ns "$ga" busybox arping -c 2 -w 3 -I tapa "$ip_b" >/dev/null 2>&1 &&
    fail "ARP for $ip_b (subnet B) was answered in subnet A"
in_ns "$ga" busybox arping -c 2 -w 3 -I tapa "$gw_b" >/dev/null 2>&1 &&
    fail "ARP for subnet B's gateway was answered in subnet A"
in_ns "$gc" busybox arping -c 2 -w 3 -I tapc "$ip_b" >/dev/null 2>&1 ||
    fail "ARP for $ip_b went unanswered in its own subnet"
echo "ok: no ARP answer across subnets"

# 5. Full-size packets at the planned MTU, then TCP in both families.
in_ns "$ga" ping -c 2 -W 2 -M "do" -s $((mtu - 28)) "$ip_b" >/dev/null ||
    fail "a full-size IPv4 packet ($mtu) did not cross"
in_ns "$ga" ping -c 2 -W 2 -M "do" -s $((mtu - 48)) "$ip6_b" >/dev/null ||
    fail "a full-size IPv6 packet ($mtu) did not cross"

cat >"$workdir/tcp.py" <<'EOF'
import hashlib, os, socket, sys
mode, family, host, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
af = socket.AF_INET6 if family == "6" else socket.AF_INET
if mode == "serve":
    s = socket.socket(af, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    print("listening", flush=True)
    s.settimeout(30)
    c, _ = s.accept()
    h, n = hashlib.sha256(), 0
    while True:
        b = c.recv(65536)
        if not b:
            break
        h.update(b)
        n += len(b)
    print(n, h.hexdigest(), flush=True)
else:
    data = os.urandom(int(sys.argv[5]))
    c = socket.create_connection((host, port), timeout=30)
    c.sendall(data)
    c.close()
    print(len(data), hashlib.sha256(data).hexdigest(), flush=True)
EOF
tcp() {  # family server-address
    local family=$1 addr=$2 any=0.0.0.0
    [[ $family == 6 ]] && any=::
    in_ns "$gb" python3 "$workdir/tcp.py" serve "$family" "$any" "$tcp_port" \
        >"$workdir/tcp$family.out" &
    local server=$!
    retry "$timeout_s" grep -q listening "$workdir/tcp$family.out" || fail "TCP server did not start"
    local sent
    sent=$(in_ns "$ga" python3 "$workdir/tcp.py" send "$family" "$addr" "$tcp_port" "$bulk_bytes") ||
        fail "TCP over IPv$family did not connect"
    wait "$server" || fail "TCP server over IPv$family failed"
    local got
    got=$(tail -n 1 "$workdir/tcp$family.out")
    [[ $got == "$sent" ]] || fail "TCP over IPv$family: sent $sent, received $got"
}
tcp 4 "$ip_b"
tcp 6 "$ip6_b"
echo "ok: full-size packets and $bulk_bytes bytes of TCP across roles in both families"

# The roles saw routed traffic; their counters go to the log.
for pid in "${role_pids[@]}"; do
    kill -TERM "$pid"
    wait "$pid" || fail "a role exited with an error"
done
role_pids=()
cat "$workdir/r1.err" "$workdir/r2.err"
grep -q 'tx_routed' "$workdir/r1.err" || fail "role 1 routed nothing"
echo "PASS"
