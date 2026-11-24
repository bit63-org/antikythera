// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The controller-pushed mapping table for one VTEP (.kiro/specs/
// oar-net-data-plane/ Requirements 2.5 and 8, design "MappingTable").
//
// Every binding comes from a helm `map_update`; nothing is learned from
// traffic. A map_update carries the complete NIC list of one VNI at a
// version: applying it replaces that VNI's entries, and an empty list
// removes the VNI. Updates are validated as a whole; a bad one is rejected
// and leaves the current snapshot untouched.
//
// Readers never lock. The table publishes an immutable Snapshot through an
// atomic shared_ptr, and an update builds a new Snapshot and swaps it in.
// The data path should take one snapshot() per packet and run every check
// against it, so a packet never sees half of one update and half of the
// next. MappingTable's own MappingView overrides load the current snapshot
// on each call; they are consistent per call, not across calls.
//
// is_local() means "owned by this VTEP": a NIC whose owner_vtep is the
// address this table was built with. In split placement every oar-net board
// is its own VTEP (Requirement 7.2), so ownership is exactly locality.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/vtep_policy.hpp"

namespace ak::oar::net {

// One entry of a map_update: a NIC in the update's VNI.
struct MapEntry {
    geneve::NicId nic_id{};
    MacAddress mac{};
    Ipv6Address owner_vtep{};
    bool source_dest_check{true};  // false: may send and receive for others (Requirement 11.10)
    friend auto operator==(const MapEntry&, const MapEntry&) -> bool = default;
};

// A decoded, signature-checked map_update for one VNI. The wire codec and
// signature check live with the controller protocol (src/proto/); this is
// what helm hands oar-net after them.
struct MapUpdate {
    std::uint32_t vni{0};
    std::uint64_t version{0};
    std::vector<MapEntry> entries;
};

enum class MapUpdateError : std::uint8_t {
    vni_out_of_range,  // 0, or wider than 24 bits
    stale_version,     // version <= the version already applied for this VNI
    invalid_nic_id,    // 0 or the broadcast ID
    duplicate_nic_id,  // the same NIC twice in one update
    nic_in_other_vni,  // NIC IDs are region-unique; it is mapped in another VNI
    invalid_mac,       // all-zero, or a group (multicast/broadcast) address
    duplicate_mac,     // two NICs with one MAC in the same VNI
    invalid_vtep,      // all-zero owner VTEP address
};

[[nodiscard]] auto to_string(MapUpdateError e) noexcept -> const char*;

// An immutable view of every VNI's mappings at one moment.
class MappingSnapshot final : public MappingView {
public:
    explicit MappingSnapshot(const Ipv6Address& local_vtep) : _local_vtep(local_vtep) {}

    [[nodiscard]] auto lookup(geneve::NicId id) const -> std::optional<NicBinding> override;
    [[nodiscard]] auto is_local(geneve::NicId id) const -> bool override;

    // The NIC holding `mac` in `vni`, if any (for the VSwitch and ARP/ND proxy).
    [[nodiscard]] auto find_by_mac(std::uint32_t vni, const MacAddress& mac) const
        -> std::optional<geneve::NicId>;
    // Version applied for `vni`; 0 if no update for it was ever applied.
    [[nodiscard]] auto version(std::uint32_t vni) const -> std::uint64_t;
    // Entries of `vni` in update order; empty if it has none.
    [[nodiscard]] auto entries(std::uint32_t vni) const -> std::span<const MapEntry>;
    // The other VTEPs this VTEP exchanges traffic with: every owner VTEP,
    // other than this one, of a VNI that has at least one NIC of this VTEP.
    // Sorted, without duplicates. The Vtep keeps OAM keepalives running to
    // exactly these.
    [[nodiscard]] auto peer_vteps() const -> std::vector<Ipv6Address>;
    // Number of VNIs with at least one NIC.
    [[nodiscard]] auto vni_count() const noexcept -> std::size_t;
    [[nodiscard]] auto nic_count() const noexcept -> std::size_t { return _nics.size(); }
    [[nodiscard]] auto local_vtep() const noexcept -> const Ipv6Address& { return _local_vtep; }

private:
    friend class MappingTable;

    struct NicIdHash {
        auto operator()(geneve::NicId id) const noexcept -> std::size_t {
            return std::hash<std::uint64_t>{}(id.value);
        }
    };

    struct Vpc {
        std::uint64_t version{0};
        std::vector<MapEntry> entries;
    };

    Ipv6Address _local_vtep;
    // Every VNI that has ever had an update applied, including emptied ones,
    // so a replayed older update for a removed VNI is still refused.
    std::unordered_map<std::uint32_t, Vpc> _vpcs;
    std::unordered_map<geneve::NicId, NicBinding, NicIdHash> _nics;
};

class MappingTable final : public MappingView {
public:
    explicit MappingTable(const Ipv6Address& local_vtep);

    // The current snapshot; never null. Hold it for the duration of one
    // packet's checks.
    [[nodiscard]] auto snapshot() const -> std::shared_ptr<const MappingSnapshot>;

    // Validates `update` against the current snapshot and, if it is good,
    // publishes a new snapshot with that VNI replaced. Returns the applied
    // version, which helm reports to the controller. Updates are serialized;
    // readers are never blocked.
    auto apply(const MapUpdate& update) -> std::expected<std::uint64_t, MapUpdateError>;

    [[nodiscard]] auto lookup(geneve::NicId id) const -> std::optional<NicBinding> override;
    [[nodiscard]] auto is_local(geneve::NicId id) const -> bool override;

private:
    std::mutex _writer;
    std::atomic<std::shared_ptr<const MappingSnapshot>> _current;
};

}  // namespace ak::oar::net
