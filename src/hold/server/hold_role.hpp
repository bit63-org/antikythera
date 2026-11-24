// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The hold role's end of helm's sideband (.kiro/specs/block-volume-service/
// task 12): an OarHandler over a HoldServer. helm relays the controller's
// ReplicaConfig and VolumeOp frames byte for byte, so the role checks
// them itself, as oar-net checks map updates: each must decode, name this
// server, and verify under a controller key (Requirement 13.1). helm
// verifies nothing on this path; a compromised helm can withhold frames
// but cannot forge one.
//
//   function_inventory  role hold, no functions (a hold role serves the
//                       storage network, not guests)
//   replica_config      decode, verify, HoldServer::apply_config
//   volume_op           decode, verify; no operation is implemented yet,
//                       so each verified op is answered with an OpOutcome
//                       report, status unsupported (snapshots, clones and
//                       scrubs arrive with their tasks)
//   lease_grant         HoldServer::grant_lease (helm forwards only the
//                       controller's grants for this server)
//   hold_reports        pump() moves HoldServer::take_reports into an
//                       oar::ReportQueue as encoded proto::Reports
//                       numbered from a random start, which helm drains
//
// A refusal answers failed (a frame that decodes but fails its checks) or
// bad_request (one that does not decode). Single-threaded: call it from
// the loop that runs the HoldServer.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

#include "helm/oar_link.hpp"
#include "hold/server/server.hpp"

namespace ak::hold {

namespace oar = helm::oar;

// Verifies an Ed25519 signature over `message` under controller key `key_id`.
using FrameVerifier =
    std::function<bool(std::span<const std::byte> message, std::span<const std::byte, 64> signature,
                       std::uint16_t key_id)>;

struct HoldRoleStats {
    std::uint64_t configs{0};  // applied
    std::uint64_t ops{0};      // verified
    std::uint64_t grants{0};
    std::uint64_t refused{0};  // configs and ops that failed a check
    std::uint64_t reports{0};  // queued for helm
};

class HoldRole final : public helm::OarHandler {
public:
    // `server` must outlive the role. `first_seq` numbers the first report
    // (non-zero; random, so a restarted role is not mistaken for a replay).
    HoldRole(HoldServer& server, std::uint64_t server_id, FrameVerifier verify,
             std::uint64_t first_seq, std::function<Clock::time_point()> clock = Clock::now);

    // Takes what the server has for helm's report path.
    auto pump(Clock::time_point now) -> void;

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override;
    auto prepare_function(const oar::PrepareFunction& request) -> oar::Status override;
    auto clean_function(const oar::CleanFunction& request) -> oar::Status override;
    auto deliver_key(const oar::DeliverKey& request) -> oar::Status override;
    auto drop_key(const oar::DropKey& request) -> oar::Status override;
    auto map_update(std::span<const std::byte> frame) -> oar::Status override;
    auto health() -> std::expected<oar::Health, oar::Status> override;
    auto replica_config(std::span<const std::byte> frame) -> oar::Status override;
    auto volume_op(std::span<const std::byte> frame) -> oar::Status override;
    auto lease_grant(const oar::LeaseGrant& grant) -> oar::Status override;
    auto hold_reports(const oar::ReportRequest& request)
        -> std::expected<oar::ReportChunk, oar::Status> override;

    [[nodiscard]] auto stats() const noexcept -> const HoldRoleStats& { return _stats; }
    [[nodiscard]] auto queued_reports() const noexcept -> std::size_t { return _reports.size(); }

private:
    auto queue(proto::ReportBody body) -> void;

    HoldServer& _server;
    std::uint64_t _server_id;
    FrameVerifier _verify;
    std::uint64_t _next_seq;
    std::function<Clock::time_point()> _clock;
    Clock::time_point _started;
    oar::ReportQueue _reports;
    HoldRoleStats _stats;
};

}  // namespace ak::hold
