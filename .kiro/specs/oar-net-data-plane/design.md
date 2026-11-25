# Design Document — oar-net: the network data plane

## Overview

```
 guest A virtio-net     guest B virtio-net
      │ (VF, IOMMU-confined DMA)   │
 ┌────┴────────────────────────────┴─────────────────────── oar-net ─┐
 │  VirtioNetFunction[f]  ──frames──►  VSwitch  ◄── MappingTable      │
 │   (oar/virtio core)                 │   per-VNI tables, NIC→VF   │
 │                                     ▼                            │
 │                      Vtep: encode/decode (geneve.hpp)            │
 │                            ingress policy (vtep_policy.hpp)      │
 │                            OAM: keepalive, MTU probe             │
 │                      Tunnel: WireGuard (harbor) / ESP            │
 └──────────────────────────────┬───────────────────────────────────┘
                                ▼ IPv6/UDP underlay
```

## Components

### VirtioNetFunction

Built on the shared virtio core (`oar/virtio`): config space, common/notify/
ISR/device config capabilities, virtqueue (split ring first, packed later)
processing with all descriptor reads bounds-checked against registered DMA
regions. RX buffers are posted by the guest; TX frames are pulled and
handed to the VSwitch with the function's identity attached (that identity
is the trusted source NIC ID).

### VSwitch

Per VNI: `MAC → local function | remote (NicId, VTEP)`. Lookup on TX:
- local destination → copy into the destination function's RX queue;
- remote → Vtep encode with `{vni, src = own NicId, dst = remote NicId}`;
- broadcast/multicast → the VNI's group policy (see "Group policy and
  metering"): dropped by default; in an opted-in VNI, IP multicast goes to
  every local member except the sender plus once to each remote VTEP
  hosting the VNI (head-end replication), within the sender's rate limits;
- unknown → drop and count.
ARP/ND for known IPs answered from the mapping (proxy).

### Vtep

Uses `ak::oar::net::geneve::{encode,decode}` and `check_ingress` (both
written and fuzzed). UDP source port = hash(inner 5-tuple) folded into
49152–65535; a pool of sockets on consecutive ports carries it, since an
ordinary UDP socket has one source port. OAM packets (`oam.hpp`, O bit
set, VNI 0, own Protocol Type): keepalive every N seconds per peer VTEP;
peers missing K keepalives are reported to helm through `PeerObserver`.
Peers are the other VTEPs of VNIs with a local NIC, from the mappings.
MTU (`mtu.hpp`): guest MTU = underlay MTU − 94 − tunnel overhead. The
Vtep drops anything over the planned payload and sends each peer a
full-size, unfragmentable OAM MTU probe every probe interval, so a peer
whose probes arrive is known to share a full-size path.

### MappingTable

Implements `MappingView`. Populated only by helm `map_update` messages
(versioned per VNI, applied atomically by swapping an immutable snapshot).
A `map_update` frame (format v3, `src/proto/map_update.hpp`) also lists
the guest IPv4 and IPv6 addresses each NIC owns, and each entry's flags
byte can turn that NIC's source/destination check off (`NicBinding::
source_dest_check`, Requirement 11.10); the role hands those to
`VSwitch::set_neighbors()` as that VNI's complete `NeighborUpdate`, after
the mapping itself is applied, so the ARP/ND proxy and the mapping always
come from the same signed frame.

### Tunnel

Harbor and first release: WireGuard. Each VTEP's WireGuard peers are the
other VTEPs in shared VNIs. Keys come from helm. Geneve UDP rides inside.

The protocol runs inside oar-net (`src/oar/net/wireguard.*` messages and
primitives over OpenSSL, `src/oar/net/tunnel.*` the state machine), not
through a kernel `wg` device: the role needs no CAP_NET_ADMIN, keeps its
keys in its own memory, and a forged packet is dropped before the Geneve
decoder sees it (Requirement 5.3). `Tunnel` is a `DatagramSender` between
the Vtep and the `UdpEndpoint`; `Tunnel::receive` returns only payloads
that authenticated, tagged with the configured address of the peer they
authenticated as, and that address (not the outer source) is what the
Vtep and the VSwitch's ingress policy check. A transport message carries
the Geneve UDP payload itself, unpadded; the handshake is WireGuard's and
interoperates with Linux (`tests/wireguard_interop.sh`). Overhead on top
of Geneve: 32 bytes (`wg::transport_overhead`). Keys arrive over the
sideband: `set_tunnel_key` (the role's static private key, which helm
generates per VTEP) and `set_tunnel_peer` / `remove_tunnel_peer` (per peer
VTEP: public key and pre-shared key).

Peers normally come from the controller instead: `tunnel_peers` carries a
signed TunnelPeers frame (controller-interface design "TunnelPeers"), the
full list of this VTEP's peers and their public keys, which helm forwards
unmodified. `TunnelPeerSet` (`src/oar/net/tunnel_peers.*`) checks that it
names this server and VTEP, verifies its Ed25519 signature with the
controller keys, ignores a re-delivered version and refuses an older one,
then makes its peers the Tunnel's controller-managed peers: peers that left
or were re-keyed are removed first (so a key moving between VTEPs is never
held twice), then every listed peer is set, and unchanged peers keep their
sessions. Peers added by hand with `set_tunnel_peer` are left alone unless
the frame names their VTEP. Every peer must be in WireGuard mode: the role
advertises only WireGuard, so a peer in PSP mode (reserved for a later
move to NIC offload) refuses the whole frame.

### Group policy and metering

Requirement 10. Each VNI has a `GroupPolicy`: `mode` (`drop`, the
default, or `multicast`), per-source-NIC `rate_frames`/`burst_frames` and
`rate_bytes`/`burst_bytes`, and `max_remote_vteps`, the flood-list cap. A
`multicast` policy must set every limit; a `drop` policy carries none.
`max_groups_per_nic` (0 to 256) caps snooped joins per NIC; 0 refuses
every join, so every group stays unknown (see "Multicast snooping").

Transmit, after the ARP/ND proxy has had the frame:

1. Admission by destination MAC. Admitted only in `multicast` mode, and
   only `01:00:5e` with the top bit of the fourth byte clear (IPv4
   multicast) or `33:33` except `33:33:ff` (IPv6 multicast other than
   solicited-node). Everything else, `ff:ff:ff:ff:ff:ff` included, is a
   `drop_policy`.
2. Flood list: the distinct other VTEPs owning a NIC in the VNI, from the
   same snapshot. More than `max_remote_vteps` drops the frame whole
   (`drop_fanout`), so a tenant cannot amplify by spreading out.
3. Rate: one token bucket per source NIC holds frame and byte credit in
   units of 1e-9 so refill (rate × elapsed ns) is exact integer math, is
   full on first use, and is capped at the burst. A frame needs one frame
   token and its length in byte tokens, else `drop_rate`. The limit is on
   the sender's frames; with the flood-list cap that bounds replicas.
4. Replicate locally and to each VTEP in the list, and meter it.

Receive: a packet for the broadcast NIC ID is delivered only if this
VTEP's policy for the VNI admits its inner destination MAC by rule 1;
otherwise `rx_drop_group`.

Meters (`GroupMeter`) are cumulative per NIC attachment: `frames`,
`bytes`, `replicas_remote`, `replica_bytes_remote` (the billable pair),
`replicas_local`, `replica_bytes_local`, `drop_policy`, `drop_rate`,
`drop_fanout`. Each attach gets a fresh meter and a new attachment
number, increasing within one oar-net run. On detach the final meter is
kept until the next `group_usage()` read, which returns every attached
NIC's meter and then the retired ones. Counters only grow, so the reader
computes deltas and a missed read loses nothing.

The policy arrives as a controller-signed `GroupPolicy` frame that helm
forwards unmodified over OarLink (`group_policy`), checked like
`map_update` (target server, key ID, Ed25519 signature, version newer
than the applied one). helm polls meters with `group_usage`.

### Multicast snooping

Requirement 10.5, task 14; `src/oar/net/igmp.*` reads the messages.

- Reports. In an opted-in VNI, IGMPv1/v2/v3 and MLDv1/v2 reports from a
  guest (after the source check; IGMP from `0.0.0.0` and MLD from
  link-local are allowed) record or remove `(NIC, group)` joins. v3/v2
  group records join on EXCLUDE modes and on INCLUDE or ALLOW with
  sources, and leave on INCLUDE with none; sources are not tracked,
  because replication is per group. Groups the GroupMembers rules call
  unreplicable (solicited-node, non-multicast) are skipped. Reports are
  consumed, never replicated. Over `max_groups_per_nic`, or over
  `max_role_memberships` (1024) in the role, a join is refused
  (`snoop_drop_cap`). A lowered cap trims, a `drop` policy clears.
  Guests' queries and other IGMP types are `tx_drop_router_msg`.
- Querier. The VPC gateway (it needs a `VpcConfig`) sends every attached
  NIC of an opted-in VNI an IGMPv3 general query, and an MLDv2 one with
  an IPv6 prefix, at once and then every 125 s (Router Alert, TTL 1,
  max response 10 s, robustness 2). A join not refreshed within 260 s
  expires (`snoop_expired`). A restarted role therefore relearns its
  NICs' joins within one interval.
- VTEP lists. `set_group_members(vni, lists)` holds the controller's
  per-group VTEP lists (the signed `GroupMembers` frame). A frame for a
  listed group goes to the listed VTEPs except this one, and only to the
  local NICs that joined it, on transmit and receive
  (`tx_replicas_pruned`); an unlisted group still goes to the whole VNI,
  so a new group works before the controller has heard of it. The rate
  limit and `max_remote_vteps` apply to whichever list is used.
- Reporting. `memberships()` lists every join of an attached, mapped NIC
  with its VNI, ascending; `membership_changes()` tells a reader when to
  look again. helm reports a role's whole list as a `group_membership`
  report (controller-interface design "Multicast policy and usage").


### IP awareness

Requirements 11–13. `src/oar/net/packet.*` parses a guest frame once:

```
struct ParsedPacket {
    std::uint16_t ethertype;            // IPv4 or IPv6 only
    IpFamily family;
    IpAddress src, dst;                 // 4 or 16 bytes, network order
    std::uint8_t protocol;              // final next-header / IPv4 protocol
    std::uint8_t hop_limit;             // TTL or hop limit
    bool fragment, first_fragment;      // L4 present only when !fragment || first
    std::optional<L4> l4;               // ports (TCP/UDP) or type/code (ICMP/ICMPv6)
    std::span<const std::byte> l3;      // the IP header onward, total-length bounded
    std::span<const std::byte> payload; // after the L4 header
};
```

Rules: untagged Ethernet; IPv4 version 4, IHL ≥ 5, total length within
the frame (trailing Ethernet padding ignored), header checksum not
verified (the receiver's stack does, and a bad one cannot pass the source
check any better); IPv6 version 6, payload length within the frame, at
most 8 extension headers (hop-by-hop only first; routing, fragment,
destination options, AH by length), anything else ends the walk as the
upper-layer protocol. TCP needs data offset ≥ 5 within the packet, UDP a
length between 8 and the rest of the IP payload (unfragmented), ICMP/ICMPv6
four bytes; a first fragment too short for its L4 header is refused. Errors are a
`PacketError` enum, each counted (`tx_drop_malformed`).

Each IPv4/IPv6 neighbor table entry already names its NIC, so the source
check is one lookup: `table.ipv4[src] == source NIC`. A source is `own`,
`local_only` (Requirement 11.4) or `spoofed`.

Transmit order, after the existing dead-VPC, length and source-MAC checks:

1. EtherType: ARP goes to the ARP handler (which now also requires the
   sender IP to be the NIC's or `0.0.0.0`); IPv4/IPv6 are parsed; anything
   else is `tx_drop_ethertype`.
2. Parse; failure is `tx_drop_malformed`.
3. Classify the source; `spoofed` is `tx_drop_ip_spoofed`, unless the
   sending NIC's check is off.
4. Router-only messages (RA, redirect, UDP source port 67/547 to a client
   port) are `tx_drop_router_msg`.
5. Local responders, which consume what they match: DHCPv4 (UDP 68→67),
   ICMPv6 RS, NS (gateway target, then the existing proxy), DHCPv6
   (UDP 546→547), then the metadata intercept.
6. `local_only` packets left are `tx_drop_local_only`.
7. Destination MAC is the gateway MAC: routed (see "Routing").
8. Group frame: group policy; admitted frames also need an IP multicast
   destination (`tx_drop_ip_dst`).
9. Unicast: destination NIC by MAC as today, then its address table must
   hold the IP destination (`tx_drop_ip_dst`) unless that NIC's check is
   off, then deliver or send.

NA target checks run in step 5's ND handling (`tx_drop_neighbor_spoofed`).
Receive runs steps 1–3 and 9's address check on the inner frame against
the receiving VTEP's tables (`rx_drop_ethertype`, `rx_drop_malformed`,
`rx_drop_ip_spoofed`, `rx_drop_ip_dst`) before delivery.

The address tables are the ones `set_neighbors()` holds (fed from
MapUpdate v2 by `NetRole`), so the ARP/ND proxy and the source check can
never disagree, and a VNI whose map carries no addresses carries no IP.

### Routing

`VpcConfig::routes` (from the signed frame's route table, Requirement
12.7) is searched longest prefix first, per family, for unicast IP
packets sent to the gateway MAC that are not metadata. The packet goes to
the route's target NIC like a unicast frame (`send_unicast`, local port or
tunnel) after a router's rewrite: destination MAC set to the target's,
TTL or hop limit minus one, the IPv4 header checksum updated
incrementally (RFC 1624). The source MAC stays the sender's, because the
Geneve ingress policy ties a frame's inner source MAC to its source NIC
and the target is often a virtual appliance that does not care. Drops:
`tx_drop_no_route` (no route, broadcast or multicast),
`tx_drop_route_target` (target unmapped here or in another VNI),
`tx_drop_hairpin` (the sender is the target), `tx_drop_ip_dst` (the
target keeps its check and does not own the destination) and
`tx_drop_ttl`. Routed packets count as `tx_routed` and also as
`tx_local` or `tx_remote`.

The receiving VTEP does not trust the sender's route lookup: its inner
destination check passes only if the target owns the destination or its
own mapping turns the target's check off, so a hostile VTEP cannot use a
routed hop to reach an address the controller never gave it.

### VPC gateway: DHCP and router advertisements

`VSwitch::set_vpc_config(vni, VpcConfig)`:

```
struct VpcConfig {
    MacAddress gateway_mac;              // locally administered unicast
    Ipv4Prefix ipv4;                     // e.g. 10.0.0.0/16, length 8..30
    Ipv4Address ipv4_gateway;            // inside ipv4, not network/broadcast
    std::optional<Ipv6Prefix> ipv6;      // a /64
    std::vector<Ipv4Address> dns4;       // ≤ 4
    std::vector<Ipv6Address> dns6;       // ≤ 4
    std::string domain;                  // ≤ 253 bytes, DNS name syntax
    std::uint32_t lease_seconds;         // 60 .. 2^31-1
};
```

Validated whole (`VpcConfigError`); an empty optional clears the VNI. The
interface MTU comes from the NIC, not the config: `attach()` takes the
MTU its function advertises (set by the MTU plan), so DHCP option 26 and
the RA MTU option always match `VIRTIO_NET_F_MTU`.

DHCPv4 (`src/oar/net/dhcp4.*`): parse BOOTP + options (RFC 2131/2132,
option overload ignored, at most 1500 bytes of options), build replies.
Stateless: the reply is a pure function of the message, the mapping and
the config. Server identifier = gateway address; replies go to the NIC's
MAC with IP destination `255.255.255.255` when the broadcast flag is set
or `ciaddr` is zero, else `ciaddr`; source is the gateway address and
MAC. T1 = lease/2, T2 = lease × 7/8. Address: the NIC's lowest IPv4 guest
address inside the prefix; a NIC with none gets no answer
(`dhcp4_no_address`). A future MapUpdate flag marking the primary
address replaces "lowest".

Router advertisements and DHCPv6 (`src/oar/net/dhcp6.*`): the gateway's
link-local address is `fe80::` + EUI-64(gateway MAC); the server DUID is
DUID-LL (type 3, hardware type 1) of the gateway MAC. RAs: hop limit 64,
M and O set, router lifetime 1800 s, prefix information (L=1, A=0,
lifetimes infinite), MTU, source link-layer address. `VSwitch::poll(now)`,
called by the Vtep runtime's loop, sends an unsolicited RA to each
attached NIC in a VNI with an IPv6 prefix every 200 s (and right after
attach). DHCPv6 lifetimes: preferred = valid = lease, T1/T2 as DHCPv4.

### Metadata intercept

`MetadataEndpoint` (an interface, like `Underlay`):

```
class MetadataEndpoint {
    virtual auto deliver(geneve::NicId nic, std::span<const std::byte> ip_packet) -> void = 0;
};
VSwitch::set_metadata_endpoint(MetadataEndpoint*);
VSwitch::inject_metadata(geneve::NicId nic, std::span<const std::byte> ip_packet) -> bool;
```

The endpoint receives the IP packet (no Ethernet header) and the trusted
NIC ID. `inject_metadata` wraps a reply in Ethernet (gateway MAC → NIC
MAC) after checking Requirement 13.3. A per-NIC token bucket (the group
policy's integer bucket, frames only; default 1024 packets/s, burst 256)
bounds intercepted packets (`metadata_drop_rate`).

### Metadata service

Requirement 13.4 to 13.8, controller-interface Requirement 11 and design
"InstanceMetadata". The network role answers metadata requests itself;
helm only forwards the signed per-NIC records. The first sketch relayed
each HTTP request over the sideband to a service in helm, but OarLink is
an SMBus link with one helm-initiated request outstanding, so every guest
request would wait on a helm poll and compete with mapping updates. The
records change rarely, are signed by the controller, and the role already
holds the NIC ID that identifies the caller, so serving on the board is
both faster and no less trusted.

Three parts, each testable alone:

- **Records** (`src/oar/net/metadata_store.*`). `NetRole` verifies an
  `InstanceMetadata` frame (server, signature, then version per NIC: the
  same version answers ok untouched, an older one fails) and keeps it
  for the NIC. `clean_function` drops the NIC's record, and a record for
  a NIC that is not plugged is kept for its attach. At most one record
  per NIC the role can host.
- **Translation** (`src/oar/net/metadata_nat.*`, pure functions with a
  fuzz target). The board's kernel does TCP for the service through a
  TAP device, `akmd0`, in the role's own network namespace, holding
  `169.254.169.254/32` and `fd00:ec2::254/128`. Guests in different VPCs
  may share addresses, so each (NIC, guest address) pair gets an alias:
  `100.64.0.0/10` for IPv4 and `fd00:ec2:1::/96` for IPv6, routed to the
  TAP. A packet from `MetadataEndpoint::deliver` has its source rewritten
  to the pair's alias (IP and TCP checksums updated as in RFC 1624) and
  is written to the TAP; a packet read from the TAP to an alias has its
  destination rewritten back and goes to `VSwitch::inject_metadata` for
  that NIC. Only TCP to port 80 is written; anything else, and anything
  from the kernel that is not TCP from port 80 (ICMP errors included), is
  dropped and counted. A NIC has at most 16 aliases (least recently used
  replaced); a NIC's aliases are released when it is cleaned, and an
  alias is not reused for another NIC while the kernel may still hold a
  connection for it (a 2-minute quarantine, longer than TIME_WAIT).
- **HTTP** (`src/oar/net/metadata_http.*` for the parser, tokens and
  path table as pure functions; `src/oar/net/metadata_server.*` for the
  connections). An accept loop on port 80
  in the namespace maps each peer alias back to its NIC and serves
  HTTP/1.0 and 1.1 (keep-alive, one request at a time) from the NIC's
  record. Limits: request line 2 KiB, headers 8 KiB and 32 fields in
  all, no body except an empty one on the token `PUT`, 2 s to read a
  request, 5 s idle, 16 connections per NIC and 1,024 per role. `GET`,
  `HEAD` and the token `PUT` are served; other methods get 405.

Paths, for `latest` and for any dated version from `2007-01-19` on
(answered the same): `/` lists `latest`; `meta-data/` lists its keys;
`ami-id`, `ami-launch-index`, `hostname` and `local-hostname`,
`instance-id`, `instance-type`, `local-ipv4` (the NIC's first IPv4
address), `mac`, `placement/availability-zone`, `placement/region`,
`network/interfaces/macs/<mac>/` (`device-number`, `interface-id`,
`local-ipv4s`, `ipv6s`, `mac`, `subnet-ipv4-cidr-block`, `vpc-id`);
`user-data` (404 when empty); `dynamic/instance-identity/document` (the
JSON document, unsigned: `signature`, `pkcs7` and `rsa2048` answer 404
until the controller signs documents); `iam/` answers 404 until instance
profiles exist. Anything else is 404.

Tokens are `base64url(version u8 | nic_id u64 | expiry u64 | nonce [16]
| HMAC-SHA256 [32])`, the MAC over everything before it and the record's
instance ID, under a 32-byte key from the OpenSSL RNG made when the role
starts and held in `SecretBytes`. A token presented on another NIC, after
its expiry, or after its NIC's interface moved to another instance fails
the check. The token `PUT` response's socket gets `IP_TTL` or
`IPV6_UNICAST_HOPS` set to the record's hop limit before it is written,
so a container behind a NAT on the guest (one hop more) never sees it
when the limit is 1, as in EC2. The socket keeps that limit for the
rest of the connection, since every later answer goes to the same peer;
if it cannot be set, the token is not sent (500 and close). Token
expiry is on the role's steady clock, and a request carrying a token
gets the seconds it has left in `X-aws-ec2-metadata-token-ttl-seconds`. `HttpEndpoint` disabled makes the accept
loop close the NIC's connections with `SO_LINGER` 0 (a reset).

The TAP needs `CAP_NET_ADMIN` in the role's namespace on the board,
which is its own machine; nothing on the host is involved. Harbor's
in-process placement and the unit tests run the HTTP layer over socket
pairs and the translation layer on byte buffers; a test that needs a real
TAP skips where namespaces are unavailable, like `jail_test`.

## Data models

- `NicBinding { vni, mac, owner_vtep }` (written).
- `VpcConfig` per VNI (above); guest address tables per VNI, from
  MapUpdate v2 through `set_neighbors()`.
- `LocalNic { nic_id, function, vni, mac }`.
- Mapping snapshot: `std::shared_ptr<const Snapshot>` swapped atomically.

## Error handling

Data-path errors are counted and dropped, never propagated. Control-path
errors (bad `map_update`) are rejected whole, leaving the old snapshot.

## Testing strategy

- Unit/fuzz: codec and policy (done); VSwitch forwarding table; virtqueue
  parsing (fuzzed against hostile descriptors); group admission, rate
  limits against a fake clock, flood-list cap and meters, with the switch
  fuzzer checking that a `drop` VNI never replicates and that remote
  replicas never exceed frames × the flood-list cap.
- The packet parser, DHCPv4 and DHCPv6 codecs each get unit tests and a
  fuzz target; `fuzz_vswitch` also checks that no frame leaves a NIC
  (delivered or sent to the underlay) with an IP source that NIC does not
  own, that link-local traffic is never forwarded, and that DHCP and
  metadata traffic never reaches the underlay. DHCP replies are checked
  against captured `dhclient`/`systemd-networkd` exchanges, and harbor
  boots a stock cloud image that must come up with its mapped address.
- Interop: encode → kernel Geneve device decode, and the reverse, in a
  network namespace (CI-capable, no KVM needed).
- harbor: two and three servers, as listed in Requirement 9.3.
