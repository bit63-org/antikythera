#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
"""Tests for harbor/kernel/check-config.py and the committed fragments.

The fragment tests need no kernel tree: they check that the fragments
themselves ask for every settable Requirement 2.2 option and never enable
a Requirement 2.3 one. Whether Kconfig keeps those settings is checked
against a real tree by harbor/kernel/build.sh (the kernel-config CI job).
"""

import importlib.util
import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
KERNEL = REPO / "harbor" / "kernel"

_spec = importlib.util.spec_from_file_location("check_config",
                                               KERNEL / "check-config.py")
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

# Selected by other options, with no prompt of their own: a fragment cannot
# set them, so only the resolved-.config check can see them.
HIDDEN = {"CONFIG_IRQ_BYPASS_MANAGER"}


def full_config(**overrides):
    """A resolved .config that satisfies every hull rule, plus overrides."""
    config = {name: "y" for name in cc.REQUIRED + cc.REQUIRED_ARCH["x86_64"]}
    for name in cc.FORBIDDEN_HULL:
        config[name] = "n"
    config.update(overrides)
    return config


def load(name):
    with open(KERNEL / name, encoding="utf-8") as f:
        return cc.parse(f)


class ParseTest(unittest.TestCase):
    def test_values_unset_and_noise(self):
        parsed = cc.parse([
            "# comment",
            "",
            "CONFIG_A=y",
            'CONFIG_LSM="landlock"',
            "# CONFIG_B is not set",
            "CONFIG_NR_CPUS=64",
            "NOT_A_CONFIG=y",
        ])
        self.assertEqual(parsed, {
            "CONFIG_A": "y",
            "CONFIG_LSM": '"landlock"',
            "CONFIG_B": "n",
            "CONFIG_NR_CPUS": "64",
        })


class CheckTest(unittest.TestCase):
    def test_clean_config_passes_both_variants(self):
        for variant in cc.VARIANTS:
            self.assertEqual(cc.check(full_config(), [], variant, "x86_64"), [])

    def test_dropped_fragment_option_is_reported(self):
        problems = cc.check(full_config(), [{"CONFIG_NEW": "y"}], "hull",
                            "x86_64")
        self.assertEqual(len(problems), 1)
        self.assertIn("CONFIG_NEW: fragment sets y, resolved to n", problems[0])

    def test_unset_fragment_option_matches_absent(self):
        self.assertEqual(
            cc.check(full_config(), [{"CONFIG_GONE": "n"}], "hull", "x86_64"),
            [])

    def test_later_fragment_wins(self):
        frags = [{"CONFIG_INET": "n"}, {"CONFIG_INET": "y"}]
        problems = cc.check(full_config(CONFIG_INET="y"), frags, "l1-debug",
                            "x86_64")
        self.assertEqual(problems, [])

    def test_missing_required_is_reported_even_without_fragment(self):
        problems = cc.check(full_config(CONFIG_PCIE_DPC="n"), [], "hull",
                            "x86_64")
        self.assertEqual(len(problems), 1)
        self.assertIn("CONFIG_PCIE_DPC: required", problems[0])

    def test_module_does_not_count_as_built_in(self):
        problems = cc.check(full_config(CONFIG_VFIO_PCI="m"), [], "hull",
                            "x86_64")
        self.assertTrue(any("CONFIG_VFIO_PCI" in p for p in problems))

    def test_forbidden_only_in_hull(self):
        for name in ("CONFIG_INET", "CONFIG_BLOCK", "CONFIG_HOTPLUG_PCI_PCIE"):
            for value in ("y", "m"):
                config = full_config(**{name: value})
                hull = cc.check(config, [], "hull", "x86_64")
                self.assertEqual(len(hull), 1, name)
                self.assertIn(f"{name}: forbidden", hull[0])
                self.assertEqual(cc.check(config, [], "l1-debug", "x86_64"), [])

    def test_unknown_variant_or_arch(self):
        with self.assertRaises(ValueError):
            cc.check({}, [], "lax", "x86_64")
        with self.assertRaises(ValueError):
            cc.check({}, [], "hull", "sparc")


class FragmentTest(unittest.TestCase):
    def setUp(self):
        self.hull = {}
        self.hull.update(load("hull.config"))
        self.hull.update(load("x86_64.config"))
        self.l1 = dict(self.hull)
        self.l1.update(load("l1-debug.config"))

    def test_hull_requests_every_required_option(self):
        for name in cc.REQUIRED + cc.REQUIRED_ARCH["x86_64"]:
            if name in HIDDEN:
                continue
            self.assertEqual(self.hull.get(name), "y", name)

    def test_hull_turns_off_every_forbidden_option(self):
        for name in cc.FORBIDDEN_HULL:
            self.assertFalse(cc.is_enabled(self.hull, name), name)

    def test_hull_turns_off_top_level_forbidden_menus(self):
        # allnoconfig leaves some of these on (they default to y without
        # EXPERT), so the fragment must say so explicitly.
        for name in ("CONFIG_INET", "CONFIG_NETDEVICES", "CONFIG_USB_SUPPORT",
                     "CONFIG_SOUND", "CONFIG_DRM", "CONFIG_HOTPLUG_PCI_PCIE",
                     "CONFIG_BLOCK", "CONFIG_MODULES"):
            self.assertEqual(self.hull.get(name), "n", name)
        self.assertEqual(self.hull.get("CONFIG_EXPERT"), "y")

    def test_l1_debug_keeps_hull_device_paths(self):
        for name in cc.REQUIRED + cc.REQUIRED_ARCH["x86_64"]:
            self.assertEqual(self.l1.get(name), self.hull.get(name), name)
        self.assertEqual(self.l1.get("CONFIG_INET"), "y")
        self.assertEqual(self.l1.get("CONFIG_HOTPLUG_PCI_PCIE"), "n")


if __name__ == "__main__":
    unittest.main()
