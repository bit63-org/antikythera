# Implementation Plan — oar-net: the network data plane

## Status: 10/14 tasks complete

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
  in `tunnel_keys_test`, and `fuzz_tunnel_peers`. Not yet: `NetRole`/`ak-oar-net`
  are not wired to the Tunnel or a TunnelPeerSet (task 11), nor helm's
  daemon to the keyring (after helm main);
  cookie replies under load; IPsec ESP (Requirement 5.1's alternative).
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
  datagrams from that peer get through. Not yet: the harbor multi-server
  tests (cross-server reachability, VPC isolation, forged VNI and NIC IDs,
  MTU behaviour; tikhov), reporting `mtu_ok` to helm. `NetRole::map_update` hands the
  frame's guest addresses (MapUpdate v2) to `VSwitch::set_neighbors` after
  applying the mapping, failing closed (no proxy answers for the VNI) if
  they were ever refused.
- [ ] 12. Group policy in the VSwitch: drop group frames by default,
  opt-in `multicast` mode per VNI with per-NIC frame/byte token buckets
  and the flood-list cap, receive-side admission, cumulative per-NIC
  `GroupMeter`s with retained final readings, tests and fuzz.
  _Requirements: 10.1–10.4, 10.6_ Note: with drop as the default, ARP and
  ND between VTEPs depend on the proxy, which `NetRole` feeds from
  MapUpdate v2 (task 11).
- [ ] 13. `GroupPolicy` frame (controller-interface task 10) applied by
  `NetRole` over OarLink `group_policy`, and `group_usage` answered from
  the VSwitch meters. _Requirements: 10.2, 10.6, 10.7_
- [ ] 14. IGMP/MLD snooping, per-NIC group cap, join reports through helm
  and per-group VTEP lists. Needs the L3 parser. _Requirements: 10.5_
