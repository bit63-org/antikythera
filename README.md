# antikythera

The hardware side of a private cloud whose API layer is
[kythira](https://github.com/crawlins/kythira).

Antikythera is a VM host whose hypervisor does as little as possible. Every
device a guest sees (network, storage, later GPU) is a real PCIe function
supplied by a **data-plane** role on a backplane and passed straight through
to the guest. A **control-plane** role on the same backplane owns policy,
keys and device assignment, and talks to the host over a DMA-free PCIe
mailbox. The host has no IP stack, no device emulation, and no device
drivers beyond `vfio-pci`.

| Name | What it is |
|---|---|
| **hull** | the minimal host image and its agent |
| **helm** | the control-plane role |
| **oar** | a data-plane role: `oar-net`, `oar-blk`, later `oar-gpu` |
| **harbor** | the virt-on-virt prototype that runs all of it under nested KVM |

Start with [`.kiro/steering/product.md`](.kiro/steering/product.md) and the
[spec index](.kiro/specs/README.md).

## Building

Requires CMake ≥ 3.28, Ninja, and GCC ≥ 14 or Clang ≥ 19 (with libstdc++ ≥ 14).

```bash
vcpkg install                       # manifest mode; add --x-feature=vfio-user for device servers
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure
```

Without vcpkg, the build falls back to system packages (Boost.Test, OpenSSL).
Sanitizers: `-DAK_SANITIZE=ON`. Fuzzers (Clang): `-DAK_FUZZ=ON -DAK_TESTS=OFF`.

## License

Apache-2.0. See [LICENSE](LICENSE).
