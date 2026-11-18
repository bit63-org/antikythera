# Specs

Kiro-style specs, one directory per major piece: `requirements.md`
(user stories and EARS acceptance criteria), `design.md`, `tasks.md`.
Steering that applies to all of them is in `../steering/`.

| Spec | Piece | Status |
|---|---|---|
| [helm-control-plane](helm-control-plane/) | Control-plane role: mailbox, device pool, keys, sideband, power sequencing | 6/12 |
| [hull-host-agent](hull-host-agent/) | Minimal host image and agent: VFIO, jailed Cloud Hypervisor, lifecycle | 0/11 |
| [oar-net-data-plane](oar-net-data-plane/) | virtio-net, VPC switching, Geneve VTEP with NIC IDs, WireGuard | 3/11 |
| [oar-blk-data-plane](oar-blk-data-plane/) | virtio-blk with transparent per-VM AES-XTS, crypto-erase | 1/8 |
| [oar-gpu-data-plane](oar-gpu-data-plane/) | GPUs: designed now, built after network and storage | designed |
| [harbor-virt-on-virt](harbor-virt-on-virt/) | Nested-KVM prototype of the whole system | 1/10 (+3 awaiting first run) |
| [controller-interface](controller-interface/) | Signed commands, mappings, inventory; kythira EC2 mapping | 2/7 |
| [backplane-hardware](backplane-hardware/) | Physical PCIe backplane requirements | deferred |
| [build-and-ci](build-and-ci/) | Toolchain, vcpkg, caching and CI, following kythira | 8/11 |

Suggested order: build-and-ci → harbor phases 1–2 → helm + hull (phase 3)
→ oar-blk (phase 4) → oar-net (phase 5) → controller-interface → GPU.
