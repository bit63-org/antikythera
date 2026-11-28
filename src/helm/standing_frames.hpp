// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The network frames of standing NICs (.kiro/specs/cold-start/
// Requirement 5.2, design "Frames for standing NICs"; task 7).
//
// Standing instances reach one another across tier-0 servers over VPC
// tunnels before any controller is up, so helm keeps, in the sealed
// store, the newest verified copy of every frame those NICs need:
//
//   vpc_config, map_update   for each VNI a standing NIC is on
//   instance_metadata        for each standing NIC (and its VNI)
//   tunnel_peers             for each VTEP, while any standing NIC exists
//
// Each frame is its own store object, named by kind and key
// ("helm.standing-frame.map.<vni>" and so on), so an update rewrites one
// frame, not all of them. offer() decodes the frame, needs this server,
// a NIC or VNI the standing set names, a version above the one held and
// a controller signature that verifies; helm's ControllerSession checks
// only shape, so this is the only signature check helm itself makes on
// these frames before keeping them across a power loss. The network role
// verifies them again when they are replayed.
//
// load() reads the stored frames at start and verifies each again; a
// store that opened rolled back or degraded is not trusted (Requirement
// 1.5) and its frames are removed. retain() follows a new standing set:
// frames for NICs and VNIs it no longer names are removed.
//
// SecurityPolicy frames join this list when the security-group build
// adds the record. Tunnel keys are not kept: they come from the stable
// secure-element-derived keys of fleet-scale-networking (Requirement
// 5.3), so the stored peer sets name keys that survive the power loss.

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "proto/link.hpp"
#include "proto/map_update.hpp"
#include "proto/standing_set.hpp"

namespace ak::helm {

inline constexpr std::string_view standing_frame_prefix = "helm.standing-frame.";

enum class FrameVerdict : std::uint8_t {
    kept,           // verified, newer, stored (or held only, with no store)
    not_standing,   // not a kind kept, or for no NIC or VNI of the standing set
    stale,          // version not above the one held
    wrong_server,   // names another server
    bad_signature,  // does not verify, or no verifier to check it
    corrupt,        // does not decode
    store_failed,   // could not be written; the frame held is unchanged
};

[[nodiscard]] auto to_string(FrameVerdict v) noexcept -> const char*;

struct StandingFrame {
    proto::RecordType type{proto::RecordType::map_update};
    std::vector<std::byte> frame;
    friend auto operator==(const StandingFrame&, const StandingFrame&) -> bool = default;
};

class StandingFrames {
public:
    // `store` and `verifier` may be null: frames then live in memory only,
    // or every frame is refused. Neither is owned.
    StandingFrames(std::uint64_t server_id, SealedStore* store,
                   const RecordVerifier* verifier) noexcept;

    // Reads the stored frames for the NICs of `set` (null: none). Call
    // once at start, after the standing set is loaded. Returns how many
    // were kept.
    auto load(const proto::StandingSet* set) -> std::size_t;
    // A new standing set was kept: follow its NICs, dropping the rest.
    auto retain(const proto::StandingSet* set) -> void;
    // A frame from the controller, of any record type; kinds not kept are
    // not_standing.
    auto offer(proto::RecordType type, std::span<const std::byte> frame) -> FrameVerdict;

    // The frames held, in replay order: tunnel peers, VPC configurations,
    // maps, then instance metadata, each by key.
    [[nodiscard]] auto frames() const -> std::vector<StandingFrame>;
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _held.size(); }

private:
    // Kinds in replay order.
    enum class Kind : std::uint8_t {
        peers,
        vpc,
        map,
        metadata
    };
    struct Key {
        Kind kind{Kind::map};
        std::uint64_t id{0};        // VNI or NIC ID; 0 for peers
        proto::VtepAddress vtep{};  // peers only
        friend auto operator<=>(const Key&, const Key&) = default;
    };
    struct Held {
        proto::RecordType type{proto::RecordType::map_update};
        std::uint64_t version{0};
        std::uint32_t vni{0};  // the VNI it serves (metadata: the NIC's)
        std::vector<std::byte> frame;
    };
    struct Parsed {
        Key key;
        Held held;
    };

    [[nodiscard]] auto parse(proto::RecordType type, std::span<const std::byte> frame) const
        -> std::expected<Parsed, FrameVerdict>;
    [[nodiscard]] auto wanted(const Key& key, std::uint32_t vni) const -> bool;
    [[nodiscard]] static auto object_name(const Key& key) -> std::string;
    auto follow(const proto::StandingSet* set) -> void;
    auto drop_unwanted() -> void;

    std::uint64_t _server_id;
    SealedStore* _store;
    const RecordVerifier* _verifier;
    std::set<std::uint32_t> _vnis;                 // of the standing NICs
    std::map<std::uint64_t, std::uint32_t> _nics;  // standing NIC -> VNI
    std::map<Key, Held> _held;
};

}  // namespace ak::helm
