# Requirements Document — Controller interface and the kythira EC2 integration

## Introduction

Antikythera servers do nothing on their own: every VM, device, volume and
VPC change originates at a **controller** and reaches a server's helm as a
signed command. The controller is a kythira service module that implements
the EC2 API, in the pattern of kythira's `kms-compatible-api` and
`dynamodb-compatible-api` (Raft-replicated state, IAM authorization through
`iam-compatible-auth`, opt-in module under `services/`). That module lives in
the kythira repository; this spec defines the contract it drives and how
EC2 concepts map onto it.

### What this spec does not cover

- The EC2 module's own implementation (a kythira spec, to be written there).
- Billing, quotas and scheduling policy beyond placement inputs.

## Glossary

- **Controller** — the kythira EC2 module cluster.
- **Envelope** — a signed command addressed to one server's helm.
- **Server inventory** — what a server's helm reports: cores, memory,
  functions by type, VTEPs, health.

## Requirements

### Requirement 1: Signed command envelopes

#### Acceptance Criteria

1. The controller SHALL sign each command with Ed25519 over the exact
   mailbox slot image bytes `[0x00, 0xC0)` that hull will verify.
2. Envelopes SHALL name the target server and carry a per-server, strictly
   increasing sequence number, both inside the signed bytes, so a command
   signed for one server is refused by every other.
3. Signing keys SHALL be held in kythira's virtual HSM or KMS and SHALL
   support rotation by key ID; hull SHALL accept any compiled-in key ID.
4. helm SHALL relay envelopes without modification.

### Requirement 2: Transport between controller and helm

#### Acceptance Criteria

1. helm SHALL reach the controller over its own management network
   interface, never through the host.
2. The link SHALL be mutually authenticated TLS; the controller's
   certificate authority SHALL be kythira's.
3. Loss of the link SHALL NOT affect running VMs; commands resume with the
   next sequence number when it returns.

### Requirement 3: Inventory and status

#### Acceptance Criteria

1. helm SHALL report server inventory at registration and on any change.
2. helm SHALL report every command outcome, every device-pool state change,
   VM exits, and applied mapping versions.
3. The controller SHALL treat a server as authoritative only for state it
   reported; it SHALL reconcile after reconnect.

### Requirement 4: Identifier allocation

#### Acceptance Criteria

1. VM IDs, volume IDs, VPC IDs (VNIs) and NIC IDs SHALL be allocated by the
   controller, unique across the whole region, and never reused.
2. MAC addresses SHALL be allocated by the controller from a locally
   administered range.

### Requirement 5: Mapping distribution

#### Acceptance Criteria

1. WHEN a NIC is attached or detached THEN the controller SHALL send a
   versioned `MAP_UPDATE` for that VPC to every server hosting a NIC in it.
2. Mapping updates SHALL be signed like commands.
3. The controller SHALL track, per server and VPC, the last applied version,
   and SHALL report a VPC as converged only when every member has applied it.

### Requirement 6: EC2 API mapping

**User Story:** As a kythira user, I want the AWS CLI and SDKs' EC2 calls to
work against kythira, backed by antikythera servers.

#### Acceptance Criteria

1. The EC2 module SHALL map at least these actions:

   | EC2 action | Antikythera commands |
   |---|---|
   | `RunInstances` | place → `CREATE_VOLUME` (root, from AMI) → `CREATE_VM` → `ATTACH_VOLUME` → `ATTACH_DEVICE` (NIC) per ENI |
   | `TerminateInstances` | `DESTROY_VM {persist_volumes = !DeleteOnTermination}` |
   | `StopInstances` / `StartInstances` | `DESTROY_VM {persist_volumes = true}` / `CREATE_VM` + re-attach on any server holding capacity |
   | `CreateVolume` / `DeleteVolume` | `CREATE_VOLUME` / `DELETE_VOLUME` (crypto-erase) |
   | `AttachVolume` / `DetachVolume` | `ATTACH_VOLUME` / `DETACH_VOLUME` |
   | `CreateVpc` / `DeleteVpc` | `CREATE_NETWORK` / `DELETE_NETWORK` (VNI allocation) |
   | `CreateNetworkInterface`, `AttachNetworkInterface`, `DetachNetworkInterface` | NIC ID + MAC allocation; `ATTACH_DEVICE` / `DETACH_DEVICE`; `MAP_UPDATE` |
   | `DescribeInstances`, `DescribeVolumes`, `DescribeVpcs` | served from controller state |

2. Volumes SHALL be server-local in the first release; an instance's
   volumes and the instance SHALL be co-located, and `StartInstances` SHALL
   prefer the server holding them.
3. EC2 encryption parameters (`Encrypted`, `KmsKeyId`) SHALL map to
   antikythera's always-on per-VM encryption; IF a `KmsKeyId` is given THEN
   the controller SHALL wrap the server's VM key under that kythira KMS key
   as an additional layer (design to be agreed in the kythira spec).
4. Features with no backing yet (subnets beyond one per VPC, security
   groups, Elastic IPs, internet gateways) SHALL be refused with EC2's
   `UnsupportedOperation`, never silently accepted.

### Requirement 7: Opt-in multicast and its billing

**User Story:** As a kythira user, I want to turn multicast on for a
subnet and see what it costs; as the operator, I want to charge for it and
keep it from being abused.

#### Acceptance Criteria

1. Broadcast and multicast SHALL be off by default for every VPC and
   subnet (oar-net Requirement 10.1).
2. The controller SHALL record a per-subnet multicast setting (until
   subnets exist, per VPC) with its limits: per-NIC frame and byte rates
   and bursts, a flood-list cap (most servers the subnet may span) and,
   with snooping, a per-NIC group cap. Region-wide defaults and maxima
   SHALL bound what a tenant may set.
3. The controller SHALL deliver the setting as a signed, versioned
   `GroupPolicy` frame to every server hosting a NIC in the VNI, signed
   like `MAP_UPDATE` and applied before the first NIC of an opted-in
   subnet can send.
4. The controller SHALL refuse to opt in a subnet that spans more servers
   than its flood-list cap, and SHALL refuse a placement that would push an
   opted-in subnet past it, with a clear error.
5. helm SHALL report per-NIC group usage (`group_usage` report) at least
   every 60 seconds while a NIC has new usage, and once more with the final
   counters when a NIC is detached.
6. The controller SHALL turn successive cumulative readings into usage
   deltas per NIC attachment, attribute them to the NIC's account, and
   record billable usage: replica bytes and frames sent to other servers.
   A reading lower than the previous one for the same attachment SHALL be
   treated as a fault and never billed negatively.
7. The controller SHALL record enablement time per opted-in subnet as a
   second billable quantity.
8. The EC2 module SHALL expose the setting and the usage (design in the
   kythira spec); prices are kythira billing configuration, not part of
   this interface.

