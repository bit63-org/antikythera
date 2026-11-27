# Specs

Kiro-style specs, one directory per major piece: `requirements.md`
(user stories and EARS acceptance criteria), `design.md`, `tasks.md`.
Steering that applies to all of them is in `../steering/`.

| Spec | Piece | Status |
|---|---|---|
| [helm-control-plane](helm-control-plane/) | Control-plane role: mailbox, device pool, keys, sideband, power sequencing | 13/14 |
| [hull-host-agent](hull-host-agent/) | Minimal host image and agent: VFIO, jailed Cloud Hypervisor, lifecycle | 9/11 |
| [oar-net-data-plane](oar-net-data-plane/) | virtio-net, VPC switching, Geneve VTEP with NIC IDs, WireGuard | 21/22 |
| [oar-blk-data-plane](oar-blk-data-plane/) | virtio-blk with transparent per-VM AES-XTS, crypto-erase, lazy S3 image volumes | 13/16 |
| [block-volume-service](block-volume-service/) | hold: replicated network volumes for VM guests (EBS-like), failover, rebuild, live moves, snapshots | 17/24 |
| [oar-gpu-data-plane](oar-gpu-data-plane/) | GPUs: designed now, built after network and storage | designed |
| [harbor-virt-on-virt](harbor-virt-on-virt/) | Nested-KVM prototype of the whole system | 4/10 |
| [controller-interface](controller-interface/) | Signed commands, mappings, inventory; kythira EC2 mapping | 14/16 |
| [vpc-subnets-routing](vpc-subnets-routing/) | VPC CIDR blocks, subnets, the distributed implicit router, route tables (`local` and NIC targets) | 0/12 |
| [vpc-security-groups](vpc-security-groups/) | Stateful security groups: per-NIC connection tracking and rules in oar-net, the signed `SecurityPolicy` frame | 0/13 |
| [vpc-internet-gateways](vpc-internet-gateways/) | Internet and egress-only gateways, Elastic IPs and NAT gateways: a stateless edge fleet doing 1:1 translation, NAT in port blocks at the source VTEP | 0/16 |
| [cold-start](cold-start/) | Server side of kythira's AZ cold start: helm's sealed store, LKG boot, local staggered power-on, standing starts of pinned instances, replay protection across reboots | 0/11 |
| [fleet-scale-networking](fleet-scale-networking/) | Certified VTEP credentials instead of peer lists, stable tunnel keys, VPC delta streams, bulk frames over Ethernet, mapping lookups, edge groups, reusable VNIs and MACs | 0/18 |
| [server-provisioning](server-provisioning/) | helm's side of the kythira metal host lifecycle: enrollment, host power and boot, decommission | 0/7 |
| [backplane-hardware](backplane-hardware/) | Physical PCIe backplane requirements | deferred |
| [build-and-ci](build-and-ci/) | Toolchain, vcpkg, caching and CI, following kythira | 9/11 |

Suggested order: build-and-ci → harbor phases 1–2 → helm + hull (phase 3)
→ oar-blk (phase 4) → oar-net (phase 5) → controller-interface → GPU.

The remaining AWS VPC features (gateways, NACLs, peering and more) are
mapped against these specs in
[docs/vpc-gap-analysis.md](../../docs/vpc-gap-analysis.md). The EBS
features are mapped the same way in
[docs/ebs-gap-analysis.md](../../docs/ebs-gap-analysis.md).
