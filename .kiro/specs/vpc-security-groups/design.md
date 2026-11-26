# Design Document — VPC security groups

## Overview

```
 controller (kythira EC2)
   CreateSecurityGroup / Authorize... / ModifyNetworkInterfaceAttribute
        │ signed SecurityPolicy (per VPC per server): groups' rules,
        │   every NIC's membership, local NICs' tracking settings
        │ signed MapUpdate v4: per-NIC "security groups enforced" bit
        ▼
 helm ──OarLink, chunked──► network role
                              VSwitch transmit                     VSwitch receive
                               source check                         ingress + inner checks
                               router picks the target              routed recheck
                               ── egress(src NIC) ──┐        ┌── ingress(dst NIC) ──
                                                    ▼        ▼
                                          SecurityEngine (per role)
                                           compiled rules per local NIC
                                           FlowTable: per-NIC flows, budget,
                                             timer wheel, fragment cache
```

Every NIC's rules run only at its own VTEP: outbound when it sends,
inbound when it receives, from a local NIC or from the underlay. Two NICs
on different servers therefore each have their own flow entry for a
connection, at their own VTEP, and neither server relies on the other.

## Decisions

- **Enforce both directions at the NIC's own VTEP.** The gap analysis
  phrased it as "egress at the source VTEP and ingress at the destination
  VTEP", which is the same thing seen per packet. Seen per NIC, it means
  each table holds only the flows of NICs on that board, replies always
  return through the same table, and a receiver's inbound rules are
  applied by the receiver whatever the sender did (Requirement 3.3).
- **Security-group references are resolved by the network role, not
  expanded by the controller.** The gap analysis suggested expanding
  references into address sets in the frame. The role already holds a
  signed, VPC-wide address-to-NIC table (MapUpdate guest addresses, used
  by the source check), so the frame carries each NIC's membership
  instead, and a rule naming a group matches a remote address whose
  owning NIC is a member. The frame is smaller (one membership list,
  not an address set per referencing rule), a NIC that attaches or
  changes addresses is matched by every reference as soon as the mapping
  says so, and the address set and the source check can never disagree.
- **The enforcement switch lives in the mapping.** If the presence of a
  policy frame switched filtering on, a lost or refused frame would leave
  NICs wide open. MapUpdate version 4's flags bit 1 marks a NIC as
  enforced, so a NIC the controller made under EC2 rules is filtered from
  the first frame it can send, and is denied everything until its
  membership arrives. Fabric tests with no controller keep working
  unfiltered.
- **Rules are sent only where they are needed.** A server needs the
  rules of the groups its own NICs belong to, and the membership of every
  NIC in the VPC (for references). Leaving out other groups' rules keeps
  the frame for one server well under the largest one.
- **No TCP window tracking.** Within a VPC a packet already passed the
  source/destination check at both ends, so it came from the NIC that
  owns its source address; only the real peer can send on a flow. Window
  tracking adds per-flow state and per-packet work for no gain here. The
  gateway role, whose internet-side traffic lacks that property, decides
  for itself.
- **Loose TCP pickup.** A non-SYN TCP packet that the rules allow starts
  an established flow, as Linux's `nf_conntrack_tcp_loose` does, so a
  role restart (which loses the table) costs at most a retransmit instead
  of every connection whose reply direction no rule allows. Pickup only
  happens when the rules allow the packet in its own direction, so it
  admits nothing the rules would not.

## SecurityPolicy frame

```
SecurityPolicy {              // controller -> helm -> oar-net, signed;
                              // src/proto/security_policy.hpp, LE
  0x00 magic 'AKSP' u32, 0x04 version u16 (1), 0x06 key_id u16,
  0x08 server_id u64, 0x10 vni u32,
  0x14 group_count u16 (<= 1024), 0x16 tracking_count u16 (<= 1024),
  0x18 policy_version u64,    // per VNI, starts at 1, strictly increasing
  0x20 rule_count u16 (<= 4096), 0x22 member_count u16 (<= 4096),
  0x24 membership_count u16 (<= 16384), 0x26 reserved u16,
  0x28 groups x group_count, group_id ascending {           // 16 bytes
         group_id u64 | inbound_count u16 | outbound_count u16 | reserved u32 }
       rules x rule_count, group by group, inbound then outbound, // 32 bytes
         each list strictly ascending by its bytes {
         protocol u8 | flags u8 (bit 0 all protocols, bit 1 peer is a group) |
         family u8 (4, 6; 0 for a group peer) | length u8 |
         from u16 | to u16 |  // TCP/UDP: port range; ICMP: type, code (0xFFFF any)
         reserved [8] | peer [16] }  // prefix, or group_id u64 then 8 zero bytes
       members x member_count, nic_id ascending {             // 16 bytes
         nic_id u64 | group_count u8 (1..16) | reserved [7] }
       memberships x membership_count, member by member,      // 8 bytes
         group_id u64 ascending within a member
       tracking x tracking_count, nic_id ascending {          // 24 bytes
         nic_id u64 | tcp_established u32 (60..432000) |
         udp_stream u16 (60..180) | udp u16 (30..60) |
         max_flows u32 (0: role default, else 1..2^24) | reserved u32 }
       signature [64]         // Ed25519 over every byte before it
}
```

Rules: group IDs and NIC IDs non-zero; `rule_count` equals the sum of
every group's two counts, and `membership_count` the sum of every
member's `group_count`. With the all-protocols flag, `protocol`, `from`
and `to` are zero. TCP (6) and UDP (17) have `from <= to`; ICMP (1) and
ICMPv6 (58) carry a type and code, each 0 to 255 or 0xFFFF for any (a
specific code needs a specific type), and their `family` must match
(ICMP 4, ICMPv6 6) unless the peer is a group; every other protocol has
`from` and `to` zero. A prefix peer has `family` 4 or 6, a length within
the family, and no bits past it; a group peer has `family` 0, `length`
0, a non-zero group ID and the rest of `peer` zero. A rule's peer group
need not be listed (its members are what matter), and neither need a
remote NIC's groups.

The network role adds two checks the decoder cannot make alone: every
group a local NIC belongs to is listed (else the frame is refused
whole, Requirement 5.5), and no local NIC has more than 1,000 rules per
direction across its groups (refused whole; the controller enforces EC2's
quotas first).

The largest frame (1,024 groups, 4,096 rules, 4,096 members, 16,384
memberships, 1,024 tracking entries) is 368,744 bytes: under the largest
MapUpdate, so `proto::max_record_payload` does not grow. It travels as
link record type 19 (`security_policy`; 17 and 18 are khold's) and over
OarLink as vendor type 0x1F (`security_policy`), in chunks like
`group_members`.

## Rule compiler

`src/oar/net/security_rules.*`, pure functions. Input: one local NIC's
groups from the policy. Output, per direction and family:

```
struct CompiledDirection {
    bool all;                           // all protocols, any address: allow everything
    bool tcp_all, udp_all;              // all ports, any address (for untracked)
    std::vector<CompiledRule> tcp, udp, icmp, other, any_protocol;
};
struct CompiledRule {
    Prefix peer;                        // or group_id with peer_is_group
    std::uint64_t group_id;
    bool peer_is_group;
    std::uint16_t from, to;             // ports, or ICMP type/code with 0xFFFF any
    std::uint8_t protocol;              // for `other`
};
```

Duplicate rules collapse, and rules covered by an any-address rule of
the same protocol and ports are dropped, so `all`, `tcp_all` and
`udp_all` are exact. A group peer matches when the packet's remote
address has an owner in the VNI's neighbor tables (VPC-wide, both
families) whose membership, a sorted vector of at most 16 IDs, holds the
group. Evaluation is a scan of the bucket for the packet's protocol plus
`any_protocol`; at most 1,000 rules per direction, and it runs only for
packets that start a flow, for untracked flows and for group frames. A
`security_rules_naive` evaluator straight from Requirement 1 is the
differential fuzz target's reference.

## Flow table

`src/oar/net/flow_table.*`. One table per network role, shared by its
NICs, so the budget is one number.

```
struct FlowKey {                        // from the NIC's point of view
    std::uint16_t nic;                  // the role's local index for the NIC
    IpFamily family;
    std::uint8_t protocol;
    IpAddress local, remote;
    std::uint16_t local_port, remote_port;  // ICMP echo: identifier in local_port
};
struct Flow {
    FlowKey key;
    FlowState state;                    // per protocol, below
    bool initiated_inbound;
    std::uint32_t expires;              // seconds on the role's steady clock
    links: hash chain, timer wheel slot, per-NIC embryonic FIFO
};
```

- **Hashing.** Open addressing over a power-of-two array sized from the
  role's budget, keyed by SipHash-2-4 under a 128-bit key from the
  OpenSSL RNG at start (Requirement 4.3). About 96 bytes per flow with
  IPv6 keys; the budget's default (`NetRoleConfig::flow_budget`,
  262,144 flows, about 24 MiB) is set by task 10's measurement on the
  board class.
- **Limits.** Per-NIC `max_flows` from the policy's tracking entry (or
  `NetRoleConfig::default_nic_flows`, 65,536) and the role budget. A new
  flow over the NIC's limit first evicts that NIC's oldest embryonic
  flow; over the budget, it evicts the requesting NIC's oldest embryonic
  flow, then the oldest embryonic flow of the NIC holding the most
  flows. With nothing to evict the packet is dropped and counted
  (`drop_flow_limit` or `drop_flow_budget`), and existing flows are
  untouched (Requirement 4.1-4.2).
- **States and timeouts.** TCP: `syn` 120 s and `syn_ack` 60 s (both
  embryonic), `established` per NIC (default 432,000 s), `fin_one` and
  `fin_both` 120 s, `closed` (after RST) 10 s; a SYN on a `closed` or
  `fin_both` flow starts it again. UDP and other protocols: `unreplied`
  (embryonic) and `replied` at the NIC's UDP timeout (default 30 s),
  `stream` after the initiator sends again following a reply, at the
  UDP stream timeout (default 180 s). ICMP echo: `unreplied` and
  `replied` at the UDP timeout. States only drive timeouts; there is no
  sequence check.
- **Expiry.** A timer wheel with 1-second slots and 4,096 slots; flows
  further out wait in their slot for further rounds. `VSwitch::poll`
  (already called by the role's loop) advances it, expiring at most
  4,096 flows per call; a lookup that finds an expired flow treats it as
  absent and frees it (Requirement 4.4).
- **Fragments.** A first fragment that is allowed records `(nic,
  direction, source, destination, protocol, identification)` in a
  fragment cache (per NIC 256 entries, per role 65,536, 30 s, least
  recently used replaced). A non-first fragment passes only on a hit,
  else `drop_fragment`. The packet parser gains the identification and
  offset (task 1).
- **Related ICMP.** `packet::parse_quoted` reads the IP header and first
  eight L4 bytes quoted in an ICMP or ICMPv6 error, bounded and
  `std::expected`. An error to a NIC is allowed when the quoted packet,
  which that NIC sent, matches one of its flows (or would be untracked);
  an error from a NIC likewise when the quoted packet is one it received.
  Errors that match nothing go through the rules like any packet.
- **Flushing.** `clean_function`, a membership change and a NIC leaving
  the enforced set drop all of the NIC's flows and fragment entries at
  once (Requirement 2.8): the per-NIC lists make that proportional to the
  NIC's own flows.

## SecurityEngine and the VSwitch

`SecurityEngine` (`src/oar/net/security_engine.*`) owns the flow table,
the compiled rules per local NIC and the per-NIC meters, and exposes two
calls the VSwitch makes with the parsed packet it already has:

```
auto egress(NicId nic, const ParsedPacket& p, Now now) -> Verdict;   // NIC sends
auto ingress(NicId nic, const ParsedPacket& p, Now now) -> Verdict;  // NIC receives
```

`Verdict` is `allow` or a drop cause. Each call: untracked check (the
NIC's compiled `all`, or `tcp_all`/`udp_all` in both directions for
TCP/UDP), flow lookup (hit: update state, allow), related-ICMP check,
fragment check, then rules (allow: record a flow unless untracked).

Hook points in the transmit order of oar-net design "IP awareness" as
amended by `vpc-subnets-routing`:

- After the router has chosen the target (route step 2) or the unicast
  destination NIC is known (step 9): `egress(sender)` if the sender is
  enforced; then, for a local target, `ingress(target)` if the target is
  enforced; then rewrite, deliver or send.
- Local responders (step 5) run before any hook, so DHCP, ND, RS and
  metadata never meet rules (Requirement 1.5).
- Group frames (step 8): the sender's outbound rules once per frame,
  each local receiver's inbound rules per copy, stateless (the rules
  only, no flow).

Receive: after `check_ingress`, the inner checks and the routed-frame
recheck, `ingress(destination)` if it is enforced; replicated frames are
checked per local receiver, stateless.

A NIC is enforced when its mapping entry has bit 1 set; its compiled
rules come from the current policy's membership, or are empty (deny all
governed traffic, `drop_no_group`) when the policy has none for it.

`set_security_policy(vni, std::shared_ptr<const SecurityState>)` swaps
the VNI's decoded policy and the compiled rules of its local NICs at
once. The VSwitch compares each local NIC's old and new membership and
flushes the NIC's flows when it changed; rule and tracking changes keep
flows (new timeouts apply when a flow next moves state). A mapping
change that adds a local NIC compiles its rules from the policy already
held (Requirement 5.6).

## Meters and reporting

Per NIC attachment (`SecurityMeter`, cumulative, like `GroupMeter`):
`allowed_out`, `allowed_in`, `drop_out_rule`, `drop_in_rule`,
`drop_no_group`, `drop_fragment`, `drop_flow_limit`, `drop_flow_budget`,
`flows_evicted`, plus the gauge `flows_in_use`. Role-wide: flows in use
against the budget. helm reads them with a paged OarLink read
`security_usage` (vendor type 0x20, like `group_usage`) and reports them
as report kind 21 `security_usage`, keyed like `group_usage` by
`(server_id, boot_id, slot, nic_id, attachment)`. The controller exposes
`drop_flow_limit` as EC2's `conntrack_allowance_exceeded` and the rest as
metrics. Flow logs later add per-flow accept and reject records from the
same engine.

## Test controller and harbor

`ak-test-controller security-policy VNI VERSION` takes `group=ID`,
`in=GROUP,PROTO,PORTS|TYPE/CODE,PEER` and `out=…` (PEER a prefix or
`sg:ID`), `member=NIC,GROUP[,GROUP…]` and `track=NIC,TCP,UDPSTREAM,UDP,MAX`.

harbor scenarios (task 11) reuse `vpc-subnets-routing`'s three-server
topology, VPC A with subnets A1 and A2:

- **Groups.** `web` (in TCP 80 from `0.0.0.0/0` and `::/0`), `app` (in
  TCP 8080 from `sg:web`), `db` (in TCP 5432 from `sg:app`), and the
  VPC's default group; web guests on s1, app on s2, db on s3.
- **Checks.** Allowed paths connect and refused ones time out (counted
  as `drop_in_rule` at the receiver's VTEP); replies need no rules; a
  new app instance is reachable from web as soon as its mapping lands,
  with no policy change; revoking `app`'s rule leaves an open `nc`
  stream working and refuses a new connection; in a group that allows
  everything both ways, revoking stops traffic at once (untracked);
  removing a NIC from `db` cuts its open flows; a NIC with `max_flows`
  1,000 refuses the 1,001st connection (`drop_flow_limit`) while the
  first 1,000 keep working; a UDP flood from one guest leaves another
  guest's established TCP working; an appliance with its own group
  forwards only what that group allows; killing the network role on s2
  (harbor task 10's fault injection) and letting helm bring it back
  leaves open TCP connections working after a retransmit; PMTU discovery
  through an appliance with a smaller onward MTU works with no ICMP
  rule.
- **Hostile VTEP.** The harbor-only build flag lets s1's role skip its
  NICs' outbound rules; s2's and s3's inbound rules still refuse what
  they should.

## Testing strategy

- Codec: unit tests, signing vectors, `fuzz_security_policy` with a
  re-encode round trip.
- Rules: unit tests per protocol and peer kind; `fuzz_security_rules`
  compares the compiled evaluator with `security_rules_naive` on random
  policies, mappings and packets.
- Flow table: unit tests on a fake clock for every state, timeout,
  limit, eviction order, fragment and related-ICMP case;
  `fuzz_flow_table` drives hostile flow streams and checks the limits,
  the budget, and that every admitted packet is allowed by the rules or
  by a flow the rules admitted.
- VSwitch: unit tests per hook and meter; `fuzz_vswitch` gains enforced
  NICs and checks Requirement 8.1's invariant.
- In-process end to end (`net_role_test`), network namespaces
  (`tests/vpc_netns.sh` gains security-group cases, with `nc`, `iperf3`
  where present, and an appliance namespace with a smaller onward MTU
  for PMTU), the benchmark, harbor and the AWS CLI run, as the tasks
  list.
