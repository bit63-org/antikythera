#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Network-namespace coexistence test for certified VTEPs
# (fleet-scale-networking task 4, Requirement 3.5).
#
# Three network roles (tests/vpc_netns_role) in namespaces r1, r2 and r3,
# joined by an IPv6 underlay through a bridge namespace, start with peer
# lists as today. Each has a TAP NIC moved into a guest namespace:
#
#   ga  NIC 0x11 on role 1, subnet A, 10.0.1.17
#   gb  NIC 0x22 on role 2, subnet B, 10.0.2.34
#   gd  NIC 0x44 on role 3, subnet A, 10.0.1.68
#
# Checks:
#   1. With peer lists, every pair of guests reaches each other (across
#      subnets and within one, across roles).
#   2. Every role takes its controller credential (as helm forwards it
#      before the controller stops listing peers); peer lists still rule.
#      Then, with ping running between every pair, each role in turn takes
#      an empty peer list, so the fleet moves to certified handshakes one
#      VTEP at a time while list and certified VTEPs talk. Loss stays within a handshake per step, and
#      afterwards every role holds two certified peers and no list peers.
#   3. Peer lists come back on every role: the certified peers turn into
#      list peers, sessions kept, with no loss to speak of.
#
# Needs root, iproute2, ping and /dev/net/tun. Exits 77 (ctest
# SKIP_RETURN_CODE) when any of those is missing or the kernel has no
# IPv6, so an unprivileged ctest run skips it; CI runs it under sudo.
#
# Usage: certified_netns.sh PATH/TO/vpc_netns_role

set -euo pipefail

readonly skip=77
readonly role_bin=${1:?usage: certified_netns.sh PATH/TO/vpc_netns_role}

# The VPC is fixed in tests/vpc_netns_role.cpp; these must match it.
readonly vtep1=fd5a:7600::1 vtep2=fd5a:7600::2 vtep3=fd5a:7600::3
readonly ip_a=10.0.1.17 ip_b=10.0.2.34 ip_d=10.0.1.68
readonly gw_a=10.0.1.1 gw_b=10.0.2.1
readonly timeout_s=15
# Pings during a change run every 0.2 s for 12 s. The longest gap a step
# should cause is one handshake round, retried within the 5 s rekey
# timeout, so up to 30 of 60 echoes per pair may go unanswered while the
# roles move; with peer lists back nothing should be lost beyond noise.
readonly ping_count=60 move_loss_max=30 list_loss_max=3

skip_test() {
    echo "SKIP: $*"
    exit "$skip"
}

[[ $(id -u) -eq 0 ]] || skip_test "needs root (CI runs it under sudo)"
for tool in ip ping; do
    command -v "$tool" >/dev/null || skip_test "$tool not installed"
done
[[ -c /dev/net/tun ]] || skip_test "no /dev/net/tun"
[[ -d /proc/sys/net/ipv6 ]] || skip_test "the kernel has no IPv6"
[[ -x $role_bin ]] || { echo "FAIL: $role_bin is not executable"; exit 1; }

suffix=$$
ul=akcrt-ul-$suffix
r1=akcrt-r1-$suffix
r2=akcrt-r2-$suffix
r3=akcrt-r3-$suffix
ga=akcrt-ga-$suffix
gb=akcrt-gb-$suffix
gd=akcrt-gd-$suffix
namespaces=("$ul" "$r1" "$r2" "$r3" "$ga" "$gb" "$gd")
workdir=$(mktemp -d)
role_pids=()
ping_pids=()

cleanup() {
    local status=$?
    set +e
    for pid in "${ping_pids[@]}"; do
        kill "$pid" 2>/dev/null
    done
    for pid in "${role_pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
    done
    if [[ $status -ne 0 ]]; then
        for log in "$workdir"/*.out "$workdir"/*.err "$workdir"/*.ping; do
            [[ -f $log ]] && { echo "--- $(basename "$log")"; cat "$log"; }
        done
    fi
    for ns in "${namespaces[@]}"; do
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

for ns in "${namespaces[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

# The underlay: a bridge in its own namespace, one veth to each role.
ip -n "$ul" link add br0 type bridge
ip -n "$ul" link set br0 up
n=0
for spec in "$r1=$vtep1" "$r2=$vtep2" "$r3=$vtep3"; do
    n=$((n + 1))
    ns=${spec%%=*}
    addr=${spec#*=}
    ip link add "akcrt$n" netns "$ns" type veth peer name "port$n" netns "$ul"
    ip -n "$ul" link set "port$n" master br0 up
    ip -n "$ns" addr add "$addr/64" dev "akcrt$n" nodad
    ip -n "$ns" link set "akcrt$n" up
done

# The TAPs start in the roles' namespaces, where the roles open them by
# name; they move to the guests once the roles hold them.
ip -n "$r1" tuntap add dev tapa mode tap
ip -n "$r2" tuntap add dev tapb mode tap
ip -n "$r3" tuntap add dev tapd mode tap

# The roles start with ip netns exec itself, not in_ns: a backgrounded
# shell function is a subshell, so $! would name it rather than the role.
start_role() {  # role ns tap nic mac
    local role=$1 ns=$2 tap=$3 nic=$4 mac=$5
    mkfifo "$workdir/r$role.ctl"
    ip netns exec "$ns" "$role_bin" --role "$role" \
        --vtep1 "$vtep1" --vtep2 "$vtep2" --vtep3 "$vtep3" \
        --control "$workdir/r$role.ctl" --tap "$tap=$nic,$mac" \
        >"$workdir/r$role.out" 2>"$workdir/r$role.err" &
    role_pids+=($!)
}
start_role 1 "$r1" tapa 0x11 02:00:00:00:00:11
start_role 2 "$r2" tapb 0x22 02:00:00:00:00:22
start_role 3 "$r3" tapd 0x44 02:00:00:00:00:44
for role in 1 2 3; do
    out=$workdir/r$role.out
    for ((i = 0; i < timeout_s * 10; ++i)); do
        grep -q '^ready' "$out" && break
        sleep 0.1
    done
    grep -q '^ready' "$out" || fail "role $role did not start"
done
mtu=$(awk '/^ready/ {print $2}' "$workdir/r1.out")
echo "roles ready, guest MTU $mtu"

# Guests are configured statically: DHCP is vpc_netns.sh's business. The
# interface takes its NIC's MAC, since the VSwitch drops a frame from any
# other.
guest() {  # role-ns guest-ns tap mac address gateway
    local rns=$1 ns=$2 tap=$3 mac=$4 addr=$5 gw=$6
    ip -n "$rns" link set "$tap" netns "$ns"
    ip -n "$ns" link set "$tap" address "$mac" mtu "$mtu" up
    ip -n "$ns" addr add "$addr/24" dev "$tap"
    ip -n "$ns" route add default via "$gw" dev "$tap"
}
guest "$r1" "$ga" tapa 02:00:00:00:00:11 "$ip_a" "$gw_a"
guest "$r2" "$gb" tapb 02:00:00:00:00:22 "$ip_b" "$gw_b"
guest "$r3" "$gd" tapd 02:00:00:00:00:44 "$ip_d" "$gw_a"

# Sends a control command to a role and waits for its answer line.
# Prints the answer.
control_seq=0
control() {  # role verb
    local role=$1 verb=$2
    control_seq=$((control_seq + 1))
    local id=$control_seq out=$workdir/r$1.out
    echo "$verb $id" >"$workdir/r$role.ctl"
    for ((i = 0; i < timeout_s * 10; ++i)); do
        if grep -Eq "^(done|refused|status|unknown) $id( |$)" "$out"; then
            grep -E "^(done|refused|status|unknown) $id( |$)" "$out"
            return 0
        fi
        sleep 0.1
    done
    fail "role $role did not answer '$verb $id'"
}
expect_done() {  # role verb
    local answer
    answer=$(control "$1" "$2")
    [[ $answer == done* ]] || fail "role $1: '$2' gave '$answer'"
}
expect_status() {  # role certified list
    local answer
    answer=$(control "$1" status)
    echo "role $1: $answer"
    [[ $answer == *" certified=$2 list=$3 sessions=2" ]] ||
        fail "role $1: expected certified=$2 list=$3 sessions=2"
}

pairs=("$ga $ip_b" "$ga $ip_d" "$gb $ip_d")

# 1. Peer lists: every pair reaches the other. The first packets may wait
# for the handshake.
for pair in "${pairs[@]}"; do
    read -r ns dst <<<"$pair"
    retry "$timeout_s" in_ns "$ns" ping -c 1 -W 1 "$dst" || fail "$ns cannot reach $dst"
done
for role in 1 2 3; do
    expect_status "$role" 0 2
done
echo "ok: peer lists connect every pair"

# Pings every pair in the background for $ping_count echoes; ping_check
# then reads how many came back.
ping_start() {
    ping_pids=()
    local k=0
    for pair in "${pairs[@]}"; do
        read -r ns dst <<<"$pair"
        k=$((k + 1))
        ip netns exec "$ns" ping -c "$ping_count" -i 0.2 -W 1 "$dst" >"$workdir/$k.ping" 2>&1 &
        ping_pids+=($!)
    done
}
ping_check() {  # max-lost
    local k=0
    for pid in "${ping_pids[@]}"; do
        wait "$pid" || true
    done
    ping_pids=()
    for pair in "${pairs[@]}"; do
        k=$((k + 1))
        local got
        got=$(awk '/packets transmitted/ {print $4}' "$workdir/$k.ping")
        [[ -n $got ]] || fail "ping $pair printed no summary"
        echo "  $pair: $got of $ping_count answered"
        ((ping_count - got <= $1)) || fail "ping $pair lost $((ping_count - got)) (at most $1)"
    done
}

# 2. Credentials first, which change nothing while the lists name every
# peer; then one role at a time drops its list while traffic runs.
for role in 1 2 3; do
    expect_done "$role" credential
    expect_status "$role" 0 2
done
ping_start
for role in 1 2 3; do
    sleep 2
    expect_done "$role" certified
done
ping_check "$move_loss_max"
for role in 1 2 3; do
    expect_status "$role" 2 0
done
echo "ok: the fleet moved to certified handshakes one VTEP at a time under traffic"

# 3. Peer lists come back; the peers keep their sessions.
ping_start
sleep 2
for role in 1 2 3; do
    expect_done "$role" lists
done
ping_check "$list_loss_max"
for role in 1 2 3; do
    expect_status "$role" 0 2
done
echo "ok: peer lists took the certified peers back without a new handshake"

for pid in "${role_pids[@]}"; do
    kill -TERM "$pid"
    wait "$pid" || fail "a role exited with an error"
done
role_pids=()
cat "$workdir"/r*.err
for role in 1 2 3; do
    grep -Eq 'certified_peers_added [1-9]' "$workdir/r$role.err" ||
        fail "role $role added no certified peer"
done
echo "PASS"
