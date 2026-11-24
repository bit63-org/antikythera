#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Enable arm64 as a foreign dpkg architecture on an Ubuntu 24.04 amd64 host
# and install the GCC 14 aarch64 cross compiler plus the arm64 builds of
# the libraries antikythera links (OpenSSL, Boost.Test). Used by the arm64
# cross-build workflow; runnable in a cloud thread the same way.
#
# archive.ubuntu.com and its mirrors carry amd64 and i386 only; arm64 lives
# on ports.ubuntu.com. So every existing deb822 stanza is pinned to amd64
# and a ports stanza is added for arm64, or apt fails fetching arm64
# indexes from the amd64 mirror.
set -euo pipefail

sources=/etc/apt/sources.list.d/ubuntu.sources
ports=/etc/apt/sources.list.d/ubuntu-ports-arm64.sources

if [ ! -f "$sources" ]; then
  echo "error: $sources not found (expected Ubuntu 24.04 deb822 sources)" >&2
  exit 1
fi

# Pin the host's stanzas to amd64. Idempotent: skip stanzas already pinned.
if ! grep -q '^Architectures:' "$sources"; then
  sudo sed -i '/^Types:/a Architectures: amd64' "$sources"
fi

# shellcheck source=/dev/null
codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
sudo tee "$ports" >/dev/null <<SOURCES
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: ${codename} ${codename}-updates ${codename}-security
Components: main universe
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES

sudo dpkg --add-architecture arm64
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends \
  g++-14-aarch64-linux-gnu cmake ninja-build file \
  libssl-dev:arm64 libboost-test-dev:arm64
