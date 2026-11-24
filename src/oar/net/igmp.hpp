// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// IGMP and MLD snooping messages (.kiro/specs/oar-net-data-plane/
// Requirement 10.5, design "Multicast snooping", task 14).
//
// A guest joins and leaves multicast groups with IGMP (IPv4, protocol 2)
// and MLD (ICMPv6). oar-net reads its membership reports, so a known
// group's frames go only where they are wanted, and plays the querier
// itself, from the VPC gateway, so a guest that never leaves cleanly ages
// out and a restarted network role relearns its NICs' groups within one
// query interval. Guests are never queriers: their queries are refused.
//
// parse_report() turns one report into joins and leaves:
//   - IGMPv1/v2 report (0x12, 0x16): join; IGMPv2 leave (0x17): leave.
//   - IGMPv3 report (0x22) and MLDv2 report (ICMPv6 143), per record:
//     MODE_IS_EXCLUDE and CHANGE_TO_EXCLUDE join; MODE_IS_INCLUDE,
//     CHANGE_TO_INCLUDE and ALLOW_NEW_SOURCES join when they name a source
//     and leave when they name none; BLOCK_OLD_SOURCES changes nothing.
//     Sources are not tracked: oar-net replicates per group, not per
//     (source, group), so a source-specific join is a join.
//   - MLDv1 report (131): join; MLDv1 done (132): leave.
// Groups that are not replicable (proto::detail::valid_member_group: IPv4
// outside 224.0.0.0/4, IPv6 solicited-node groups) are skipped, not errors,
// because every IPv6 guest joins its solicited-node groups by MLD. The
// IGMP checksum and the ICMPv6 checksum must verify; a record that runs
// past the message refuses the whole report.
//
// The queries are IGMPv3 and MLDv2 general queries (group zero) with the
// Router Alert option, TTL/hop limit 1, to 224.0.0.1 or ff02::1 at their
// group MACs: what RFC 3376 and RFC 3810 hosts expect from a querier.

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include "oar/net/neighbor.hpp"
#include "oar/net/packet.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net::igmp {

inline constexpr std::uint8_t ipproto_igmp = 2;
inline constexpr std::uint8_t igmp_query = 0x11;
inline constexpr std::uint8_t igmp_v1_report = 0x12;
inline constexpr std::uint8_t igmp_v2_report = 0x16;
inline constexpr std::uint8_t igmp_v2_leave = 0x17;
inline constexpr std::uint8_t igmp_v3_report = 0x22;
inline constexpr std::uint8_t mld_query = 130;
inline constexpr std::uint8_t mld_v1_report = 131;
inline constexpr std::uint8_t mld_v1_done = 132;
inline constexpr std::uint8_t mld_v2_report = 143;

// What a querier announces (RFC 3376 8.2 and 8.14.2, RFC 3810 9.2).
inline constexpr std::uint32_t query_interval_seconds = 125;
inline constexpr std::uint32_t query_response_seconds = 10;
inline constexpr std::uint32_t robustness = 2;
// How long a join lasts without a fresh report (RFC 3376 8.4).
inline constexpr std::uint32_t membership_seconds =
    (robustness * query_interval_seconds) + query_response_seconds;

// A group: IPv4 in the first four bytes (the rest zero) or IPv6.
struct Group {
    bool ipv6{false};
    Ipv6Address address{};

    friend auto operator<=>(const Group&, const Group&) = default;
};

struct Change {
    Group group;
    bool join{false};

    friend auto operator==(const Change&, const Change&) -> bool = default;
};

enum class Kind : std::uint8_t {
    query,   // a guest acting as querier: refused
    report,  // a membership report, leave or done
    other,   // some other IGMP message (DVMRP, mtrace...): refused
};

enum class SnoopError : std::uint8_t {
    malformed,     // too short, a bad length or a record past the end
    bad_checksum,  // the IGMP or ICMPv6 checksum does not verify
    unknown_type,  // a group record type RFC 3376/3810 does not define
};

[[nodiscard]] auto to_string(SnoopError e) noexcept -> const char*;

// Whether `p` is IGMP or MLD at all, and which kind; nullopt for anything
// else (including other ICMPv6). A fragment is never a membership message.
[[nodiscard]] auto classify(const packet::ParsedPacket& p) noexcept -> std::optional<Kind>;

// The joins and leaves in a report `classify` called Kind::report, in
// message order.
[[nodiscard]] auto parse_report(const packet::ParsedPacket& p)
    -> std::expected<std::vector<Change>, SnoopError>;

// Whether oar-net replicates `g` at all (the GroupMembers rules).
[[nodiscard]] auto replicable(const Group& g) noexcept -> bool;

// The group a parsed multicast packet is sent to.
[[nodiscard]] auto destination_group(const packet::ParsedPacket& p) noexcept -> Group;

// General queries from the gateway to one NIC.
[[nodiscard]] auto build_query4(const MacAddress& gateway_mac,
                                const neighbor::Ipv4Address& gateway_ip) -> std::vector<std::byte>;
[[nodiscard]] auto build_query6(const MacAddress& gateway_mac,
                                const Ipv6Address& gateway_link_local) -> std::vector<std::byte>;

}  // namespace ak::oar::net::igmp
