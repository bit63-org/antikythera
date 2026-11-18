#!/bin/bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# SessionStart hook for Claude Code cloud sessions. Cloud containers run
# Ubuntu 24.04, whose default GCC 13 is below antikythera's GCC 14 / Clang 19
# minimum (see DEPENDENCIES.md). This installs the toolchain and the system
# libraries the build accepts in place of vcpkg, then points CMake at GCC 14.
# Local machines are left alone.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Packages from the Ubuntu 24.04 archive; each entry is checked with dpkg so
# a warm container skips apt entirely.
packages=(
  gcc-14 g++-14
  clang-19 clang-tidy-19 libclang-rt-19-dev
  cmake ninja-build
  libboost-test-dev libssl-dev
  shellcheck
)
missing=()
for p in "${packages[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
done
if [ "${#missing[@]}" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
fi

# clang-format is pinned to kythira's PyPI version (.kiro/steering/tech.md).
want_cf=22.1.5
if ! clang-format --version 2>/dev/null | grep -q "version ${want_cf}"; then
  python3 -m pip install -q --root-user-action=ignore "clang-format==${want_cf}"
fi

# CMake reads CC/CXX on first configure, so new build trees get GCC 14.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo 'export CC=gcc-14'
    echo 'export CXX=g++-14'
    echo 'export CMAKE_GENERATOR=Ninja'
  } >>"$CLAUDE_ENV_FILE"
fi
