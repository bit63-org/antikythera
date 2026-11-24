# Implementation Plan — oar-net: the network data plane

## Status: 16/22 tasks complete

## Tasks

- [x] 1. Geneve codec with the NIC-pair option: encode/decode, tests, fuzz
  target with a re-encode round-trip check (`src/oar/net/geneve.*`).
  _Requirements: 3, 4.1, 9.1_
- [x] 2. Ingress policy against a `MappingView` (`src/oar/net/vtep_policy.*`),
  tests. _Requirements: 4.2, 4.3_
- [x] 3. Bring existing code to the steering standards (`_member` naming,
  trailing return types, test timeouts, named constants). _Requirements: 9_
- [x] 4. Kernel Geneve interop test in a network namespace.
  _Requirements: 9.2_ — `tests/geneve_interop.sh` with
  `tests/geneve_interop_peer.cpp`: the codec on a UDP socket in one
  namespace, a kernel geneve device (external mode, tc `tunnel_key` adding
  the NIC-pair option, flower matching it on ingress) in another, IPv6
  underlay. Checked both ways: kernel-built packets decode to the
  configured VNI and NIC pair and re-encode byte for byte; codec-built
  packets match flower and reach a socket behind the kernel device. Needs
  root, so plain ctest skips it; CI's `build (gcc-14)` runs it under sudo.
  Finding: the kernel sets the Geneve C bit only when IP_TUNNEL_CRIT_OPT
  is set (Open vSwitch does, tc `tunnel_key` does not), so a critical
  option added through tc goes out with C clear. The codec drops such a
  packet (Requirement 4.1); the test checks that drop, then decodes the
  packet with C set. Our VTEP encodes in user space, so this only matters
  for kernel or tc-based peers.
- [x] 5. Shared virtio core: PCI capabilities, split virtqueue with bounds
  checks, fuzz target. _Requirements: 1.4_ — `src/oar/virtio/`:
  `GuestMemory` (registered DMA regions, no straddling), `SplitQueue`
  (copy-once descriptor walk, indirect tables, chain budget, in-flight
  tracking, event-index suppression; errors latch the queue broken), and
  `CommonConfig` + `encode_capability` (spec 4.1 register model with
  feature negotiation and the status machine). Fuzz: `fuzz_virtqueue`,
  `fuzz_virtio_pci`. Packed rings, the notify/ISR/device-config BAR
  handling and the transport binding come with VirtioNetFunction (task 6).
- [x] 6. VirtioNetFunction on vfio-user. _Requirements: 1_ —
  `virtio::PciFunction` (`src/oar/virtio/function.*`) is the transport seam
  every device shares: one BAR (common, ISR, device config, notify), queues
  built at DRIVER_OK, DEVICE_NEEDS_RESET on ring errors, FLR.
  `VirtioNetFunction` (`src/oar/net/virtio_net.*`): VERSION_1, MAC, MTU,
  STATUS, EVENT_IDX, INDIRECT_DESC, one RX/TX pair; read-only device
  config; TX copied once, offload headers, bad lengths and spoofed source
  MACs dropped and counted, frames tagged with the function's NIC ID.
  `ak::oar::vfu::VirtioBinding` serves a `PciFunction` over vfio-user and
  `ak-oar-net` runs one NIC with an optional TAP backend until the VSwitch
  (task 8). Fuzz: `fuzz_virtio_net`. Not yet: packed rings, the
  `pci-epf` binding, a harbor run of `ak-oar-net` on tikhov.
- [x] 7. MappingTable with atomic snapshots and `map_update` handling
  (`src/oar/net/mapping_table.*`), tests, fuzz target. Takes a decoded
  `MapUpdate`; the wire codec and signature check are controller task 2.
  _Requirements: 2.5, 8_
- [x] 8. VSwitch: local forwarding, broadcast replication, ARP/ND proxy,
  dead VPC. _Requirements: 2, 7_ — `VSwitch` (`src/oar/net/vswitch.*`) is
  every function's `FrameSink` and delivers through `RxPort` (implemented
  by `VirtioNetFunction`). One mapping snapshot per frame. Transmit checks
  the source is attached and mapped to this VTEP (otherwise dead VPC) and
  that its MAC is the mapped one, then delivers locally, hands remote
  unicast to an `Underlay` with `{vtep, vni, src, dst}` for the Vtep
  (task 9), drops unknown unicast and hairpins, and floods group frames to
  local members plus once per remote VTEP with the broadcast NIC ID.
  `receive()` runs `check_ingress` against the same snapshot it delivers
  with; policy drops are counted per reason. The dead VPC is not a table:
  a NIC is in it when it is not mapped to this VTEP, so helm detaches by
  dropping it from the map_update. ARP/ND (`src/oar/net/neighbor.*`):
  bounds-checked parsers, proxy answers for addresses helm registers per
  VNI through `set_neighbors()` (reply MAC from the current snapshot), ARP
  with another NIC's sender MAC or IP and NS with a foreign source
  link-layer option dropped, DAD probes never answered. Fuzz:
  `fuzz_vswitch` (parsers, and isolation invariants over frame streams).
  The controller's map_update (format v2) carries the guest addresses
  for `set_neighbors()`; the role handler that applies a frame to both
  the MappingTable and the VSwitch is not written yet. Not yet: NA
  spoofing checks; the
  VSwitch is not wired into `ak-oar-net` (it serves one NIC; task 9 adds
  the Vtep runtime that drives both).
- [x] 9. Vtep runtime: UDP sockets, OAM keepalives, drop counters.
  _Requirements: 3.5, 3.6, 4.4_ — `Vtep` (`src/oar/net/vtep.*`) is the
  VSwitch's `Underlay`: it Geneve-encodes each `RemoteFrame` and sends it
  to the peer's port 6081 with a UDP source port hashed from the inner
  flow (`flow_port()`: VNI, IP addresses, protocol, and ports for
  unfragmented TCP/UDP/SCTP, guest VLAN tags skipped, folded into
  49152-65535). `Vtep::receive()` decodes one UDP payload, counts decode
  drops per `DecodeError`, consumes OAM and returns data packets for
  `VSwitch::receive()`, which counts policy drops per `PolicyError`.
  OAM (`src/oar/net/oam.*`): a keepalive is a Geneve packet with O set,
  VNI 0, Protocol Type 0x88B6 (placeholder) and a 12-byte body (version,
  type, sequence); the MTU probe is type 2 (task 11). Every
  `keepalive_interval` the Vtep sends one to each peer VTEP
  (`MappingSnapshot::peer_vteps()`: the other owners in VNIs with a NIC
  here); a peer is up when one arrives and down after `keepalive_misses`
  silent intervals, reported through `PeerObserver` for helm. Keepalives
  from addresses that are not peers are dropped and counted; until
  WireGuard (task 10) liveness is advisory, since OAM is unauthenticated.
  Time is passed in (`tick(now)` returns the next deadline).
  `UdpEndpoint` (`src/oar/net/udp_endpoint.*`): an IPv6-only non-blocking
  socket bound to the VTEP address and 6081 for receive, plus an optional
  pool of sockets on consecutive source ports chosen by flow port (a plain
  socket cannot pick its source port per datagram; a raw socket needs
  CAP_NET_RAW); `pump()` feeds received datagrams through the Vtep into the
  VSwitch. Fuzz: `fuzz_vtep`. Tests include two VTEPs joined end to end
  and loopback UDP (skipped where the sandbox has no IPv6). `NetRole`
  (`src/oar/net/net_role.*`, task 11) wires the whole VTEP behind helm's
  sideband: MappingTable, VSwitch, Vtep and one virtio-net function per
  transport; `prepare_function` gives a function helm's NIC ID and MAC and
  connects it, `clean_function` resets it to a placeholder in the dead
  VPC, and `map_update` checks the target server and the controller's
  Ed25519 signature before applying (an already-applied version answers
  ok unchanged). `ak-oar-net` runs it with a `UdpEndpoint` underlay and
  helm's sideband socket; `--socket` keeps the single-NIC TAP mode for
  `harbor/oar_net_smoke.py`. Peer state reaches helm only as `health`
  (degraded while a peer is down).
- [x] 10. WireGuard tunnel integration and key delivery from helm.
  _Requirements: 5_ — `Tunnel` (`src/oar/net/tunnel.*`) runs WireGuard
  (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s) between the Vtep and the
  `UdpEndpoint`, as a `DatagramSender` the Vtep sends through unchanged;
  `pump(endpoint, tunnel, vtep, vswitch, ...)` authenticates every
  datagram before Geneve decode. Messages, a strict parser, the primitives
  (BLAKE2s, keyed BLAKE2s, HKDF, X25519, ChaCha20-Poly1305, TAI64N, all
  OpenSSL 3.0) and the RFC 6479 replay window: `src/oar/net/wireguard.*`.
  The Tunnel follows Linux's handshake, session rotation (current /
  previous / unconfirmed next), rekey and reject timers, with endpoints
  fixed by helm (no roaming), mac1 checked before any DH, initiation
  replay and flood limits, and drops counted per reason. Simplifications
  that do not change the wire: no packet queue (a send with no session
  starts a handshake and is dropped; the Vtep's keepalives bring sessions
  up), no cookie replies (mac2 sent as zero; a received cookie reply is
  dropped), no passive keepalives. Transport payloads are Geneve, not IP,
  so they are not padded. Key delivery: sideband `set_tunnel_key`,
  `set_tunnel_peer` (VTEP, public key, PSK) and `remove_tunnel_peer`
  (vendor types 0x0B-0x0D; `OarLink` methods wipe every buffer, the
  `OarHandler` defaults answer unsupported). Tests: `wireguard_test`
  (parser, RFC 7748/7693 vectors, AEAD, replay window), `tunnel_test`
  (handshake both ways and crossed, PSK, forgeries, replays, timers, key
  changes, two Vteps end to end over the Tunnel, UDP pump),
  `tunnel_keys_test` (OarLink delivering keys to two roles that then talk),
  `fuzz_wireguard`, and the kernel interop test
  (`tests/wireguard_interop.sh`, CI under sudo: kernel-initiated and
  Tunnel-initiated handshakes, data both ways). Keys from the controller
  (controller-interface task 10): helm's `TunnelKeyring` generates each
  VTEP's key pair and reports the public key; the controller's signed
  `TunnelPeers` frame reaches the role over the sideband (`tunnel_peers`,
  vendor type 0x0E, chunked), where `TunnelPeerSet`
  (`src/oar/net/tunnel_peers.*`) verifies it and installs the peers;
  `tunnel_peers_test`, `tunnel_keyring_test`, the signed end-to-end case
  in `tunnel_keys_test`, and `fuzz_tunnel_peers`. Wiring: with
  `NetRoleConfig::tunnel` set, `NetRole` runs a Tunnel between its Vtep and
  the underlay and a TunnelPeerSet over the same controller keys as its
  map_updates, answers `set_tunnel_key`, `set_tunnel_peer`,
  `remove_tunnel_peer` and `tunnel_peers`, and authenticates every datagram
  in `NetRole::receive`/`pump` before Geneve decode; `ak-oar-net` runs the
  tunnel unless `--tunnel-overhead 0`. helm's daemon holds the
  TunnelKeyring: a network role's key pair is made when its sideband
  first opens, the role is provisioned (key, then the newest peer set) on
  every attach and retried on check until it takes the key, a role that
  answers unsupported has its pair dropped, the public keys go in the
  inventory, and controller peer sets are kept by version and forwarded
  to their VTEP's role. Tests: `net_role_test`
  (`guests_talk_through_the_wireguard_tunnel`), `helm_daemon_test`
  (`net_roles_get_their_tunnel_key_and_peer_sets`, unkeyed and tunnel-less
  roles). Not yet: cookie replies under load; IPsec ESP (Requirement 5.1's
  alternative).
- [ ] 11. MTU computation and advertisement; harbor multi-server tests.
  _Requirements: 6, 9.3_ — Done: `plan_mtu()` (`src/oar/net/mtu.*`)
  turns the underlay MTU and the tunnel's overhead into the guest MTU and
  the Vtep's largest Geneve payload. The encapsulation overhead is 94, not
  the requirement's 90: guest VLAN tags are payload and VirtioNetFunction
  admits one beyond the MTU, so a tagged full-size frame needs the extra 4.
  oar-net's WireGuard adds 32 inside the same UDP datagram
  (`wireguard_overhead`), PSP transport mode 48 (`psp_overhead`), and
  plans reserve the larger (`tunnel_overhead_budget`, Requirement 6.3)
  so a later move to PSP keeps guest MTUs; 9000 gives guests 8858, 1500 gives 1358. `ak-oar-net
  --underlay-mtu N [--tunnel-overhead N]` advertises the planned MTU
  through `VIRTIO_NET_F_MTU`. `VtepConfig::max_payload` drops and counts
  (`tx_drop_too_big`) any datagram over the plan, and every
  `probe_interval` sends each peer an OAM `mtu_probe` padded to exactly
  that size; `UdpEndpoint` sets `IPV6_DONTFRAG`, so a probe arrives whole
  or not at all, and `PeerStatus::mtu_ok` records that full-size
  datagrams from that peer get through. `NetRole::health` reports it to
  helm: degraded with `fault_code` bits `net_fault_peer_down`,
  `net_fault_mtu` (a peer up for `mtu_grace`, default two probe intervals,
  without `mtu_ok`) and `net_fault_no_tunnel_key`; helm polls every network
  role's health on each check, degrades the inventory's health while one is
  degraded, and sends the controller a fresh inventory whenever its VTEPs,
  tunnel keys or health change (`helm_daemon_test`
  `a_degraded_net_role_degrades_the_inventory`; `net_role_test`
  `health_reports_a_path_too_small_for_full_size_frames`). Not yet: the
  harbor multi-server tests (cross-server reachability, VPC isolation,
  forged VNI and NIC IDs, MTU behaviour; tikhov). `NetRole::map_update` hands the
  frame's guest addresses (MapUpdate v2) to `VSwitch::set_neighbors` after
  applying the mapping, failing closed (no proxy answers for the VNI) if
  they were ever refused.
- [x] 12. Group policy in the VSwitch: drop group frames by default,
  opt-in `multicast` mode per VNI with per-NIC frame/byte token buckets
  and the flood-list cap, receive-side admission, cumulative per-NIC
  `GroupMeter`s with retained final readings, tests and fuzz.
  _Requirements: 10.1–10.4, 10.6_ — `VSwitch::set_group_policy()` takes a
  validated `GroupPolicy` per VNI (`drop` erases it). Group frames the
  proxy did not consume go through `replicate()`: admission by MAC, then
  the flood-list cap (dropped whole, local copies too), then the sender's
  bucket, which is primed full and refilled from an injected clock
  (`VSwitch::Now`, default `steady_clock::now`). `receive()` applies the
  local policy to broadcast-NIC-ID packets (`rx_drop_group`).
  `group_meter()` and `group_usage()` expose the meters with an attachment
  number per attach. `fuzz_vswitch` opts one VNI in and checks that the
  drop VNI never replicates and that meters stay consistent. With drop
  as the default, ARP and ND between VTEPs depend on the proxy, which
  `NetRole` feeds from MapUpdate v2 (task 11).
- [ ] 13. `GroupPolicy` frame (controller-interface task 10) applied by
  `NetRole` over OarLink `group_policy`, and `group_usage` answered from
  the VSwitch meters. _Requirements: 10.2, 10.6, 10.7_
- [ ] 14. IGMP/MLD snooping, per-NIC group cap, join reports through helm
  and per-group VTEP lists. Needs the L3 parser. _Requirements: 10.5_
  - [x] 14.1 Data plane: `src/oar/net/igmp.*` reads IGMPv1-3 and
    MLDv1-2 reports and builds the gateway's general queries (tests,
    `fuzz_igmp`); the VSwitch snoops joins under `max_groups_per_nic`,
    queries every 125 s from the gateway, expires joins after 260 s,
    lists them (`memberships()`), and prunes listed groups to their VTEPs
    and joined local NICs (`set_group_members`). See design "Multicast
    snooping". The frame and report are controller-interface task 15.
  - [ ] 14.2 Sideband and helm: OarLink `group_members` (chunked, like
    `tunnel_peers`) verified by `NetRole` and applied with
    `set_group_members`, a paged membership read, `max_groups_per_nic`
    carried from the GroupPolicy, and helm keeping the newest frame per
    VNI, forwarding it like a GroupPolicy and reporting each role's list
    as `group_membership` when it changes (an empty one when a role goes
    away). Builds on task 13's NetRole and HelmDaemon group wiring.
- [x] 15. L3/L4 packet parser (`src/oar/net/packet.*`): untagged
  Ethernet, IPv4 with options, IPv6 with a bounded extension-header walk,
  TCP/UDP/ICMP/ICMPv6 headers, fragments; tests and `fuzz_packet`.
  _Requirements: 11.2_ — `packet::parse` returns a `ParsedPacket` (both
  address families, protocol, hop limit, fragment flags, L4 ports or
  ICMP type/code, and nested views of the IP packet, L4 data and
  payload) or a `PacketError`. `fuzz_packet` checks that every view lies
  inside the one before it and that L4 only appears in first fragments.
  Test frames come from `tests/net_frames.hpp`.
- [x] 16. Source/destination check in the VSwitch on transmit and
  receive: EtherType allowlist, source classes (own, local-only,
  spoofed), destination owned by the destination NIC, multicast
  destination for replicated frames, ARP sender and NA target checks,
  router and DHCP-server messages dropped, per-cause counters;
  `fuzz_vswitch` invariants. _Requirements: 11.1, 11.3–11.9_ — the
  address tables are the `set_neighbors()` ones, which `NetRole` fills
  from each applied map_update's guest addresses, so a VNI whose map
  carries no addresses carries no IP (the tests now give every NIC
  10.0.0.<id> and fd10::<id>). Local-only packets (DHCP client from
  0.0.0.0, link-local or unspecified IPv6) end at `tx_drop_local_only`
  unless the ND proxy answers them, until the gateway responders (tasks
  17–18) consume them. On receive the replicated-frame policy check runs
  before the inner IP check, so group meters and `rx_drop_group` keep
  their meaning. `fuzz_vswitch` checks that every forwarded frame is ARP
  or IP from the true sender's own address.
- [x] 17. `VpcConfig` per VNI (`set_vpc_config`, MTU taken at attach),
  gateway ARP/ND answers, `tx_drop_no_route`, and the stateless DHCPv4
  server (`src/oar/net/dhcp4.*`), tests and fuzz. _Requirements: 12.1–12.3,
  12.6_ — `attach(nic, port, mtu)` defaults the MTU to 0, which leaves
  option 26 out, so callers that do not pass one yet keep working. The
  gateway answers ARP for its address and `169.254.169.254` (broadcast or
  a unicast refresh to its MAC) and, with an IPv6 prefix, NS for its
  link-local address and `fd00:ec2::254`. DHCPv4 client messages are
  UDP 68→67 from `0.0.0.0` or to the broadcast or gateway address; a NAK
  goes to `255.255.255.255`, other replies to `ciaddr`, broadcast on
  request, else to `yiaddr`, always to the NIC's MAC and only its port.
  Packet builders with full checksums (`packet::build_ipv4_udp`,
  `build_ipv6_udp`, `build_icmpv6`, `build_ethernet`) serve the later
  responders too. Fuzz: `fuzz_dhcp4`; `fuzz_vswitch` gives one VNI a
  gateway and checks its replies reach only the asking NIC.
- [x] 18. Router advertisements (solicited, and periodic through
  `VSwitch::poll`) and the DHCPv6 server (`src/oar/net/dhcp6.*`), tests
  and fuzz. _Requirements: 12.4–12.6_ — Only VNIs whose `VpcConfig` has
  an IPv6 prefix get RAs. An RS with hop limit 255 is answered to its
  source, or all-nodes from `::`; `poll()` sends each local attached NIC
  one every `ra_interval` (200 s), unicast to its MAC. RAs carry M and O,
  the /64 with L set and A clear, the NIC's MTU when known and RDNSS for
  `dns6` with three intervals' lifetime. DHCPv6 is stateless: the server
  DUID is DUID-LL from the gateway MAC; server-identifier rules follow
  RFC 8415 16; Solicit/Request/Renew/Rebind get the NIC's in-prefix IPv6
  addresses from the neighbor table (NoAddrsAvail when none, Rapid
  Commit honoured), Confirm gets Success or NotOnLink, Release and
  Decline get Success. Fuzz: `fuzz_dhcp6`.
- [x] 19. Metadata intercept: `MetadataEndpoint`, per-NIC packet rate
  limit, `inject_metadata` checks. _Requirements: 13.1–13.3_ — Packets
  to `169.254.169.254` or `fd00:ec2::254` at the gateway MAC go to the
  endpoint as IP packets keyed by source NIC, after the source check, at
  most `metadata_rate_pps` (1024) with a burst of 256 per NIC. With no
  endpoint they count as `metadata_no_endpoint`. `inject_metadata` only
  delivers to a local attached NIC in a configured VNI, from the
  metadata address, to an address that NIC owns. `fuzz_vswitch` checks
  that the endpoint only hears a NIC from that NIC's own address.
- [x] 20. Signed `VpcConfig` frame (controller-interface Requirement 10,
  task 14) forwarded by helm over OarLink and applied by `NetRole`.
  _Requirements: 12.1_ — OarLink `vpc_config` (vendor type 0x18) carries
  the frame whole (at most 3,669 bytes, one message). `HelmDaemon` keeps
  the newest per VNI and sends it to every attached network role, and all
  of them again, before the router registers functions, to a role whose
  sideband reopens. `NetRole` checks it like a map_update (server, then
  signature, then version per VNI: the same version answers ok untouched,
  an older one fails) and applies it with `VSwitch::set_vpc_config`; a
  frame the VSwitch refuses leaves the previous config. Routes are
  applied by task 22.
- [ ] 21. Metadata service: the endpoint on the oar-net board, helm's
  service keyed by NIC ID, IMDSv2 tokens (helm and controller specs).
  _Requirements: 13.4_
- [x] 22. Per-NIC source/destination check opt-out, with route-table
  targets that name a NIC (VPC step 3). _Requirements: 11.10, 12.7_ —
  MapUpdate format v3 carries the opt-out in each entry's flags byte
  (`map_entry_no_source_dest_check`); `NicBinding::source_dest_check`
  skips the source check on transmit and receive and the destination
  check for packets to that NIC. `NetRole` applies the VpcConfig route
  table, and the VSwitch routes unicast packets for the gateway MAC to
  the longest-prefix target (MAC rewrite, TTL/hop limit minus one; see
  design "Routing"). Receivers recheck with their own mapping. Harbor's
  `map-update` takes `nocheck` per entry.
