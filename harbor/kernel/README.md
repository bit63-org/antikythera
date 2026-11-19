# hull kernel config

The host kernel is `allnoconfig` plus committed fragments
([hull Requirement 2](../../.kiro/specs/hull-host-agent/requirements.md)):

| File | Purpose |
|---|---|
| `hull.config` | strict, arch-neutral: KVM, IOMMU (strict by default), VFIO + vfio-pci with SR-IOV, PCIe ports with AER and DPC, AF_UNIX, jail primitives; no IP, NICs, USB, sound, GPU, pciehp, block layer or modules |
| `x86_64.config` | x86_64 symbols: KVM Intel/AMD, Intel/AMD IOMMU with interrupt remapping (Intel on by default), EFI stub, 8250 console, NUMA and machine checks |
| `l1-debug.config` | permissive overlay for harbor L1 only: IPv4, virtio disks and NIC, ext4, script interpreter, what systemd needs. Never ships |
| `build.sh` | resolves a variant against a Linux tree with `KCONFIG_ALLCONFIG` + `allnoconfig`, runs the checker, optionally builds |
| `check-config.py` | fails if any fragment option was dropped by Kconfig, if a Requirement 2.2 option is not built in, or (strict variant) if a Requirement 2.3 option is enabled |

```bash
sudo apt-get install linux-source-6.8.0 flex bison bc libelf-dev libssl-dev
mkdir -p ~/src/linux && tar -xjf /usr/src/linux-source-6.8.0/linux-source-6.8.0.tar.bz2 \
    -C ~/src/linux --strip-components=1
harbor/kernel/build.sh --src ~/src/linux                       # strict hull, resolve + check
harbor/kernel/build.sh --src ~/src/linux --variant l1-debug    # harbor L1 debug kernel
harbor/kernel/build.sh --src ~/src/linux --build               # also build bzImage
```

Output goes to `harbor/.run/kernel/<variant>/` unless `--out` says
otherwise; the source tree is not modified.

The command line half of Requirement 2.4 (`intel_iommu=on iommu.strict=1
pci=noats`, 1 GiB page reservation, isolated guest cores) depends on the
machine and is part of the UKI (hull task 10). Without it the kernel
still boots with the Intel IOMMU on and in strict mode, from the
`CONFIG_INTEL_IOMMU_DEFAULT_ON` and `CONFIG_IOMMU_DEFAULT_DMA_STRICT`
defaults; `pci=noats` has no Kconfig equivalent.

Phases 1 to 5 still boot L1 on Ubuntu's stock kernel. `l1-debug` is for
the first phase that needs the hull kernel paths in L1; phase 6 boots
the strict `hull` image.
