// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/server/hold_role.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "proto/volume_op.hpp"

namespace ak::hold {

HoldRole::HoldRole(HoldServer& server, std::uint64_t server_id, FrameVerifier verify,
                   std::uint64_t first_seq, std::function<Clock::time_point()> clock)
    : _server{server},
      _server_id{server_id},
      _verify{std::move(verify)},
      _next_seq{first_seq == 0 ? 1 : first_seq},
      _clock{std::move(clock)},
      _started{_clock()} {}

auto HoldRole::queue(proto::ReportBody body) -> void {
    const auto seq = _next_seq;
    _next_seq = _next_seq == std::numeric_limits<std::uint64_t>::max() ? 1 : _next_seq + 1;
    auto bytes =
        proto::encode_report({.server_id = _server_id, .report_seq = seq, .body = std::move(body)});
    if (bytes && _reports.push(seq, std::move(*bytes))) {
        ++_stats.reports;
    }
}

auto HoldRole::pump(Clock::time_point now) -> void {
    for (auto& body : _server.take_reports(now)) {
        queue(std::move(body));
    }
}

auto HoldRole::function_inventory() -> std::expected<oar::Inventory, oar::Status> {
    return oar::Inventory{.role = oar::Role::hold, .vtep = {}, .functions = {}};
}

auto HoldRole::prepare_function(const oar::PrepareFunction& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto HoldRole::clean_function(const oar::CleanFunction& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto HoldRole::deliver_key(const oar::DeliverKey& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto HoldRole::drop_key(const oar::DropKey& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto HoldRole::map_update(std::span<const std::byte> /*frame*/) -> oar::Status {
    return oar::Status::unsupported;
}

auto HoldRole::cert_request() -> std::expected<oar::CertAnswer, oar::Status> {
    if (_enrollment == nullptr) {
        return std::unexpected(oar::Status::unsupported);
    }
    return _enrollment->answer();
}

auto HoldRole::role_certificate(std::span<const std::byte> chain) -> oar::Status {
    return _enrollment == nullptr ? oar::Status::unsupported : _enrollment->install(chain);
}

auto HoldRole::health() -> std::expected<oar::Health, oar::Status> {
    const auto up = std::chrono::duration_cast<std::chrono::seconds>(_clock() - _started);
    const auto secs = static_cast<std::uint64_t>(std::max<std::int64_t>(0, up.count()));
    return oar::Health{.state = oar::HealthState::ok,
                       .fault_code = 0,
                       .uptime_seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                           secs, std::numeric_limits<std::uint32_t>::max()))};
}

auto HoldRole::replica_config(std::span<const std::byte> frame) -> oar::Status {
    const auto c = proto::decode_replica_config(frame);
    if (!c) {
        ++_stats.refused;
        return oar::Status::bad_request;
    }
    if (c->server_id != _server_id ||
        !_verify(proto::replica_config_signed_bytes(frame), c->signature, c->key_id)) {
        ++_stats.refused;
        return oar::Status::failed;
    }
    if (!_server.apply_config(*c, _clock())) {
        ++_stats.refused;
        return oar::Status::failed;
    }
    ++_stats.configs;
    return oar::Status::ok;
}

auto HoldRole::volume_op(std::span<const std::byte> frame) -> oar::Status {
    const auto op = proto::decode_volume_op(frame);
    if (!op) {
        ++_stats.refused;
        return oar::Status::bad_request;
    }
    if (op->server_id != _server_id ||
        !_verify(proto::volume_op_signed_bytes(frame), op->signature, op->key_id)) {
        ++_stats.refused;
        return oar::Status::failed;
    }
    ++_stats.ops;
    queue(proto::OpOutcome{.volume_id = op->volume_id,
                           .op_id = op->op_id,
                           .epoch = op->epoch,
                           .detail = 0,
                           .kind = proto::volume_op_kind(op->args),
                           .status = proto::OpStatus::unsupported,
                           .slot = 0});
    return oar::Status::ok;
}

auto HoldRole::lease_grant(const oar::LeaseGrant& grant) -> oar::Status {
    _server.grant_lease(grant.volume_id, grant.epoch, _clock());
    ++_stats.grants;
    return oar::Status::ok;
}

auto HoldRole::hold_reports(const oar::ReportRequest& request)
    -> std::expected<oar::ReportChunk, oar::Status> {
    return _reports.serve(request);
}

}  // namespace ak::hold
