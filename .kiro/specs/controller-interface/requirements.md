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
4. helm's management interface SHALL be on the management fabric's
   control segment, which the storage segment cannot reach (backplane
   Requirement 7.1-7.3), and helm SHALL mark the controller link,
   including lease traffic it relays, as the control class (backplane
   Requirement 7.4).

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
4. Each entry SHALL carry the NIC's source/destination check setting
   (on unless the tenant turns it off, like EC2's `SourceDestCheck`), so
   every VTEP enforces the same setting from the same signed frame.

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
   | `CreateVolume` / `DeleteVolume` | network volume: Requirement 9; local volume: `CREATE_VOLUME` / `DELETE_VOLUME` (crypto-erase) |
   | `AttachVolume` / `DetachVolume` | `ATTACH_VOLUME` / `DETACH_VOLUME`; for a network volume with the ReplicaConfig, `VolumeKey` and fencing steps of Requirement 9 |
   | `CreateVpc` / `DeleteVpc` | `CREATE_NETWORK` / `DELETE_NETWORK` (VNI allocation) |
   | `CreateNetworkInterface`, `AttachNetworkInterface`, `DetachNetworkInterface` | NIC ID + MAC allocation; `ATTACH_DEVICE` / `DETACH_DEVICE`; `MAP_UPDATE` |
   | `DescribeInstances`, `DescribeVolumes`, `DescribeVpcs` | served from controller state |

2. EBS volumes (`CreateVolume`, `RunInstances` `Ebs` block device
   mappings) SHALL be network volumes of block-volume-service, attachable
   from any server; they SHALL NOT pin an instance to a server, and
   `StopInstances` / `StartInstances` MAY place the instance on any
   server with capacity (Requirement 9.9). Local volumes are the
   instance-store analogue (`VirtualName` `ephemeralN` mappings): they
   stay server-local, an instance with one SHALL be co-located with it,
   and `StartInstances` SHALL use the server holding it. This replaces
   the first release's rule that every volume is server-local.
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
9. helm SHALL report each network role's snooped multicast joins whole
   (`group_membership` report) whenever they change. The controller SHALL
   turn the joins into per-group VTEP lists (the servers hosting a NIC
   that joined) and deliver them as a signed, versioned `GroupMembers`
   frame per VPC to every server hosting a NIC in it, so a known group
   reaches only those servers (oar-net Requirement 10.5).


### Requirement 8: Tunnel key distribution

**User Story:** As the operator, I want each VTEP to learn its WireGuard
peers' public keys from the controller, so the authenticated underlay
(oar-net Requirement 5) works without per-pair configuration.

#### Acceptance Criteria

1. Every VTEP SHALL have its own X25519 key pair, derived by helm from its
   secure element so that it survives a helm restart, and changed only by
   a controller rotation or re-provisioning (fleet-scale-networking
   Requirement 1); the private key SHALL go only to that VTEP's network
   role.
2. helm SHALL report each VTEP's public key in its inventory.
3. The controller SHALL send each VTEP a versioned, full snapshot of its
   peers (the other VTEPs it shares a VNI with) and their public keys,
   whenever that set or one of those keys changes, signed like commands
   and naming the target server and VTEP.
4. helm SHALL forward peer sets unmodified; the network role SHALL verify
   the signature, target and version before installing the peers.
5. Each VTEP SHALL advertise the tunnel modes it supports (WireGuard, and
   later PSP offload) in the inventory, and each peer in a peer set SHALL
   name its mode, so the controller can move a fleet from WireGuard to PSP
   one pair at a time, choosing PSP only where both ends support it. Only
   WireGuard is implemented; a role SHALL refuse a peer set naming a mode
   it does not run.

### Requirement 9: EC2 mapping of network volumes

**User Story:** As a kythira user, I want the AWS CLI and SDKs' EBS calls
to drive block-volume-service's replicated network volumes, with EBS's
parameters, states and errors.

This is the mapping block-volume-service Requirement 14 asks for. Volume
classes, ReplicaConfig, VolumeOp, VolumeKey and the reports are defined
in block-volume-service; this requirement says what each EC2 call does
with them. Design "Network volumes in EC2" gives the parameter and state
tables.

#### Acceptance Criteria

1. `CreateVolume` SHALL place a replica set and publish its first
   ReplicaConfig, with no mailbox command. `VolumeType` `gp2` and `gp3`
   SHALL map to the `general` class and `io1` and `io2` to
   `provisioned`; `st1`, `sc1` and `standard` SHALL be refused with
   `UnsupportedOperation`. `Size`, `Iops` and `Throughput` SHALL become
   the config's capacity and QoS, validated against EBS's rules for the
   type and the class's hardware maxima. `SnapshotId` SHALL make a
   same-lineage restore, or a keyed copy into a new lineage when
   `KmsKeyId` differs from the snapshot's (block-volume Requirement 12.5).
   `MultiAttachEnabled` SHALL set `multi_attach` and SHALL be refused
   with `InvalidParameterCombination` outside the `provisioned` class.
   `Encrypted` and `KmsKeyId` SHALL follow Requirement 6.3; every volume
   is encrypted and SHALL report `Encrypted = true`.
2. `DeleteVolume` SHALL be refused with `VolumeInUse` while the volume
   has an attachment; otherwise it SHALL send `delete_replica` to every
   member, and the lineage's KMS key SHALL be scheduled for deletion when
   its last volume and snapshot are gone.
3. `AttachVolume` SHALL add an attachment (new ID and generation) at a
   new epoch, send the ReplicaConfig to the members and to the
   instance's server, send that server a `VolumeKey`, and then
   `ATTACH_VOLUME`. A second attachment SHALL be refused with
   `VolumeInUse` unless the volume is `multi_attach`, and the sixteenth
   is the last. Attaching to a stopped instance SHALL record the
   attachment only; the key and the mailbox command follow at start.
4. `DetachVolume` without `Force` SHALL send `DETACH_VOLUME` with
   `DetachPolicy` `wait` and the volume's detach timeout; a timeout SHALL
   leave the attachment `busy`, attached and serving, until the guest
   releases or a forced detach replaces it. `DetachVolume` with `Force`
   SHALL first publish a ReplicaConfig without the attachment's
   generation, wait for the primary to report it `fenced` (or for the
   primary's lease to lapse), and only then send `DETACH_VOLUME`
   `force`. Detaching the root volume of a running instance SHALL be
   refused with `OperationNotPermitted`.
5. `ModifyVolume` SHALL apply `Size` (grow only; shrink refused with
   `InvalidParameterValue`), `VolumeType`, `Iops`, `Throughput` and
   `MultiAttachEnabled` while attached, as a new epoch; a change of
   replication factor SHALL add or remove members as a move.
   `DescribeVolumesModifications` SHALL report `modifying` until every
   member and initiator has applied the epoch, `optimizing` while added
   replicas rebuild, then `completed` (or `failed`).
6. `DescribeVolumes` and `DescribeVolumeStatus` SHALL report the volume
   states, attachment states and status checks of block-volume
   Requirement 14.2, derived from reports as design "Network volumes in
   EC2" tabulates; a volume with `io_suspended` SHALL report status
   `impaired` with a `potential-data-inconsistency` event and the
   `enable-volume-io` action. `EnableVolumeIO` SHALL run block-volume
   Requirement 6.8, and the `AutoEnableIO` volume attribute
   (`ModifyVolumeAttribute`, `DescribeVolumeAttribute`) SHALL make the
   controller run it without being asked.
7. `CreateSnapshot` SHALL take a single-volume cut and upload;
   `CreateSnapshots` SHALL take one multi-volume cut across the
   instance's network volumes (excluding the root with
   `ExcludeBootVolume`; local volumes, like instance store, are never
   included). Snapshots SHALL report `pending` with `Progress` from
   `snapshot_progress`, then `completed` or `error`. `DeleteSnapshot`
   SHALL delete the manifest and garbage-collect the lineage's chunks;
   `DescribeSnapshots` SHALL be served from controller state.
8. `EnableFastSnapshotRestores` (and `Disable…`, `Describe…`) SHALL
   record a per-snapshot, per-zone flag; volumes created from a flagged
   snapshot SHALL stay `creating` until fully hydrated and report
   `FastRestored = true`. `CopyVolumes` SHALL clone the source into a new
   volume of the same lineage in seconds, refusing parameters that would
   need a new key.
9. `RunInstances` `Ebs` block device mappings SHALL create and attach a
   network volume each (the root from the AMI as a plaintext-image or
   snapshot restore), honouring `DeleteOnTermination` (default true for
   the root from the AMI); `TerminateInstances` SHALL delete those that
   carry it and leave the rest `available`. `StopInstances` SHALL retire
   every attachment's generation before the instance can start
   elsewhere (block-volume Requirement 6.9); `StartInstances` SHALL
   attach them again with new generations on the chosen server.
10. EBS features with no backing SHALL be refused with
    `UnsupportedOperation`, never silently accepted, among them: HDD
    volume types, snapshot archive tier, cross-region `CopySnapshot`,
    snapshot sharing across accounts, Recycle Bin and snapshot lock,
    Outposts, and the EBS direct APIs.

### Requirement 10: VPC configuration

**User Story:** As the operator, I want every server hosting a VPC to
answer DHCP, router solicitations and the gateway's addresses from one
record the controller signs, so that no guest can configure another and
every server answers the same way (oar-net Requirement 12).

#### Acceptance Criteria

1. The controller SHALL keep one configuration per VPC (until subnets
   exist; then per subnet): the gateway MAC, allocated from the MAC pool of
   Requirement 4.2 so it never collides with a NIC; the IPv4 prefix and
   gateway address; an optional IPv6 /64; up to four DNS servers per
   family; a domain name; the DHCPv4 lease time; and the route table.
2. Each route SHALL name a destination prefix (IPv4 or IPv6, a default
   route allowed) and a target NIC in the same VPC. Routes to anything
   other than a NIC (gateways, peering, endpoints) come with those
   features and a new frame version.
3. The controller SHALL deliver the configuration as a signed, versioned
   `VpcConfig` frame, a full snapshot naming its target server and key, to
   every server hosting a NIC in the VPC, before the first NIC there is
   attached and again on every change.
4. helm SHALL forward `VpcConfig` frames unmodified, keep the newest per
   VPC, and resend it to a network role whose sideband reopens before any
   NIC is prepared there; the network role SHALL verify the signature,
   target and version and apply the configuration atomically, leaving
   the previous one in place when a frame is refused.
5. A route whose target NIC is not in the receiving server's current
   mapping for the VPC SHALL match nothing there (its traffic is dropped
   and counted) rather than refuse the whole frame, so mapping and
   configuration updates need not arrive in a fixed order.

### Requirement 11: Instance metadata

**User Story:** As a kythira user, I want `curl http://169.254.169.254/`
and the AWS SDKs' instance metadata clients to work in my instances,
IMDSv2 included; as the operator, I want each instance to read only its
own record (oar-net Requirement 13).

#### Acceptance Criteria

1. The controller SHALL keep one instance metadata record per attached
   NIC: the instance ID, image ID, instance type, account ID, local
   hostname, availability zone and region, the interface ID, VPC ID and
   device index, the launch index and pending time, the user data (at
   most 16,384 bytes, EC2's limit), and the instance's metadata options:
   `HttpEndpoint` (enabled or disabled), `HttpTokens` (optional or
   required) and `HttpPutResponseHopLimit` (1 to 64), with EC2's
   defaults (enabled, optional, 1).
2. The NIC's MAC and guest addresses and the VPC's IPv4 prefix SHALL NOT
   be repeated in the record: the server answers them from the NIC's
   mapping entry and the VPC's `VpcConfig`, so the three can never
   disagree.
3. The controller SHALL deliver the record as a signed, versioned
   `InstanceMetadata` frame naming its target server, key and NIC, to the
   server hosting the NIC, before the `ATTACH_DEVICE` that plugs the NIC
   and again whenever the record changes (`ModifyInstanceMetadataOptions`,
   user data changed while stopped, an interface moved to another
   instance). Versions are per NIC and strictly increasing.
4. helm SHALL forward `InstanceMetadata` frames unmodified, keep the
   newest per NIC until the NIC is detached, and resend them to a network
   role whose sideband reopens before any NIC is prepared there; the
   network role SHALL verify the signature, target and version, keep the
   record for the NIC until the NIC is cleaned, and leave the previous
   record in place when a frame is refused.
5. The EC2 module SHALL accept `MetadataOptions` on `RunInstances` and
   implement `ModifyInstanceMetadataOptions`. Instance profile
   credentials (`iam/`), signed identity documents and instance tags in
   metadata come with IAM instance profiles, a controller signing key for
   identity documents, and tags; until then those paths answer 404 and
   `InstanceMetadataTags` other than disabled is refused with
   `UnsupportedOperation`.

