#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Print how many parallel jobs this runner should use.
#
# nproc reports every CPU the kernel lets us schedule on, which inside a
# container with a CPU limit is still the whole host (48 on reliant-new,
# where ARC runner pods are capped at 4 CPUs). Ninja, run-clang-tidy and
# make would then start ~48 jobs that the CFS quota throttles. Read the
# cgroup quota instead, and fall back to nproc when there is none.
set -euo pipefail

cpus="$(nproc)"
jobs="${cpus}"

if [[ -r /sys/fs/cgroup/cpu.max ]]; then
    # cgroup v2: "<quota> <period>" or "max <period>"
    read -r quota period < /sys/fs/cgroup/cpu.max
elif [[ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]]; then
    # cgroup v1: quota is -1 when unlimited
    quota="$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)"
    period="$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)"
fi

if [[ -n "${quota:-}" && "${quota}" != max && "${quota}" -gt 0 && "${period:-0}" -gt 0 ]]; then
    jobs=$(( (quota + period - 1) / period ))
fi

(( jobs > cpus )) && jobs="${cpus}"
(( jobs < 1 )) && jobs=1
echo "${jobs}"
