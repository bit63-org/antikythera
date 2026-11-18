#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Stops one harbor server started by harbor/l1/run.sh: QEMU first, then the
# board processes. Safe to run when nothing is running.
#
# Usage: harbor/l1/stop.sh [--name srv1] [--wipe]
#   --wipe  also delete the server's disk overlay, seed and logs

set -uo pipefail
# shellcheck source=harbor/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

name="srv1"
wipe=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) name="$2"; shift 2 ;;
        --wipe) wipe=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done

dir="${RUN_DIR}/${name}"
stop_timeout_s=10

stop_pid_file() {
    local f="$1" pid
    [[ -f "${f}" ]] || return 0
    pid="$(cat "${f}")"
    if kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null
        for ((t = 0; t < stop_timeout_s * 10; t++)); do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${f}"
}

stop_pid_file "${dir}/qemu.pid"
for f in "${dir}"/slot*.pid; do
    [[ -e "${f}" ]] && stop_pid_file "${f}"
done
rm -f "${dir}"/slot*.sock

if [[ "${wipe}" -eq 1 ]]; then
    rm -rf "${dir}"
    log "${name} stopped and wiped"
else
    log "${name} stopped (logs kept in ${dir})"
fi
