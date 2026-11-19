#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
"""Check a resolved kernel .config against hull's fragments and rules.

Kconfig drops a fragment option silently when its dependencies are not
met, so a fragment alone proves nothing. This checks the .config that
`make allnoconfig` produced from the fragments:

1. every option in every fragment (later fragments win) holds;
2. the options .kiro/specs/hull-host-agent/ Requirement 2.2 asks for are
   built in, independent of what the fragments say, so a fragment edit
   cannot quietly drop one;
3. for the strict hull variant, nothing Requirement 2.3 forbids is
   enabled.

Usage: check-config.py --config .config --variant hull|l1-debug
                       [--arch x86_64] FRAGMENT...
Exits 0 when every check passes, 1 otherwise, listing every problem.
"""

import argparse
import re
import sys

_SET = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
_UNSET = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")

# Requirement 2.2: KVM, IOMMU with interrupt remapping, VFIO and vfio-pci
# with SR-IOV, IRQ bypass, PCIe port drivers, AER, DPC, a console, AF_UNIX.
# Plus the strict-IOMMU default, which makes Requirement 2.4's iommu.strict
# hold even if the command line loses it.
REQUIRED = [
    "CONFIG_KVM",
    "CONFIG_IOMMU_SUPPORT",
    "CONFIG_IOMMU_DEFAULT_DMA_STRICT",
    "CONFIG_IRQ_REMAP",
    "CONFIG_VFIO",
    "CONFIG_VFIO_PCI",
    "CONFIG_PCI_IOV",
    "CONFIG_IRQ_BYPASS_MANAGER",
    "CONFIG_PCIEPORTBUS",
    "CONFIG_PCIEAER",
    "CONFIG_PCIE_DPC",
    "CONFIG_TTY",
    "CONFIG_UNIX",
    "CONFIG_HUGETLBFS",
    "CONFIG_BLK_DEV_INITRD",
]
REQUIRED_ARCH = {
    "x86_64": [
        "CONFIG_KVM_INTEL",
        "CONFIG_KVM_AMD",
        "CONFIG_INTEL_IOMMU",
        "CONFIG_INTEL_IOMMU_DEFAULT_ON",
        "CONFIG_AMD_IOMMU",
        "CONFIG_SERIAL_8250_CONSOLE",
        "CONFIG_EFI_STUB",
    ],
}

# Requirement 2.3: no IP, NIC drivers, USB, sound, GPU drivers, pciehp, or
# block filesystems (the initramfs needs none, so no block layer at all).
# Modules are off so the signed UKI is the whole kernel.
FORBIDDEN_HULL = [
    "CONFIG_INET",
    "CONFIG_NETDEVICES",
    "CONFIG_ETHERNET",
    "CONFIG_WLAN",
    "CONFIG_USB_SUPPORT",
    "CONFIG_USB",
    "CONFIG_SOUND",
    "CONFIG_SND",
    "CONFIG_DRM",
    "CONFIG_FB",
    "CONFIG_HOTPLUG_PCI",
    "CONFIG_HOTPLUG_PCI_PCIE",
    "CONFIG_BLOCK",
    "CONFIG_MODULES",
    "CONFIG_KEXEC",
    "CONFIG_KEXEC_FILE",
]

VARIANTS = ("hull", "l1-debug")


def parse(lines):
    """Map CONFIG_ name to value; "n" for `# ... is not set` lines."""
    values = {}
    for raw in lines:
        line = raw.strip()
        m = _SET.match(line)
        if m:
            values[m.group(1)] = m.group(2)
            continue
        m = _UNSET.match(line)
        if m:
            values[m.group(1)] = "n"
    return values


def is_enabled(config, name):
    return config.get(name, "n") in ("y", "m")


def check(config, fragments, variant, arch):
    """Return a list of problems; empty means the .config passes."""
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant: {variant}")
    if arch not in REQUIRED_ARCH:
        raise ValueError(f"unknown arch: {arch}")

    wanted = {}
    for fragment in fragments:
        wanted.update(fragment)

    problems = []
    for name, want in sorted(wanted.items()):
        got = config.get(name, "n")
        if got != want:
            problems.append(f"{name}: fragment sets {want}, resolved to {got}")

    for name in REQUIRED + REQUIRED_ARCH[arch]:
        if config.get(name) != "y":
            problems.append(f"{name}: required built in (Requirement 2.2), "
                            f"resolved to {config.get(name, 'n')}")

    if variant == "hull":
        for name in FORBIDDEN_HULL:
            if is_enabled(config, name):
                problems.append(f"{name}: forbidden in hull (Requirement 2.3), "
                                f"resolved to {config[name]}")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, help="resolved .config")
    ap.add_argument("--variant", required=True, choices=VARIANTS)
    ap.add_argument("--arch", default="x86_64", choices=sorted(REQUIRED_ARCH))
    ap.add_argument("fragments", nargs="+", help="fragments, in apply order")
    args = ap.parse_args(argv)

    with open(args.config, encoding="utf-8") as f:
        config = parse(f)
    fragments = []
    for path in args.fragments:
        with open(path, encoding="utf-8") as f:
            fragments.append(parse(f))

    problems = check(config, fragments, args.variant, args.arch)
    for p in problems:
        print(f"check-config: {p}", file=sys.stderr)
    if problems:
        print(f"check-config: {args.variant}: {len(problems)} problem(s)",
              file=sys.stderr)
        return 1
    print(f"check-config: {args.variant}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
