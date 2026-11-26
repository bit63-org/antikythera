// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "khold/khold_role.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include "proto/volume_layout.hpp"

namespace ak::khold {

namespace {

// What a khold node may report through its role; capacity goes through the
// merge instead.
[[nodiscard]] auto relayed_kind(const proto::ReportBody& body) -> bool {
    return std::holds_alternative<proto::GroupStatus>(body) ||
           std::holds_alternative<proto::GroupFault>(body) ||
           std::holds_alternative<proto::VolumeFault>(body);
}

[[nodiscard]] auto names_server(const proto::VolumeLayout& l, std::uint64_t server) -> bool {
    const auto in_group = [&](const proto::StripeGroup& g) {
        return std::ranges::any_of(
            g.members, [&](const proto::LayoutMember& m) { return m.server_id == server; });
    };
    return std::ranges::any_of(l.groups, in_group) ||
           std::ranges::any_of(
               l.gateways, [&](const proto::LayoutGateway& g) { return g.server_id == server; });
}

}  // namespace

KholdRole::KholdRole(KholdNode& node, std::uint64_t server_id, FrameVerifier verify,
                     std::uint64_t first_seq, SelfTestFn self_test,
                     std::function<Clock::time_point()> clock)
    : _node{node},
      _server_id{server_id},
      _verify{std::move(verify)},
      _next_seq{first_seq == 0 ? 1 : first_seq},
      _run_test{std::move(self_test)},
      _clock{std::move(clock)},
      _started{_clock()},
      _node_generation{node.generation()} {
    start_self_test();
}

KholdRole::~KholdRole() {
    if (_test.valid()) {
        _test.wait();
    }
}

auto KholdRole::queue(proto::ReportBody body) -> void {
    const auto seq = _next_seq;
    _next_seq = _next_seq == std::numeric_limits<std::uint64_t>::max() ? 1 : _next_seq + 1;
    auto bytes =
        proto::encode_report({.server_id = _server_id, .report_seq = seq, .body = std::move(body)});
    if (bytes && _reports.push(seq, std::move(*bytes))) {
        ++_stats.reports;
    }
}

auto KholdRole::start_self_test() -> void {
    if (_test.valid() || !_run_test) {
        return;
    }
    _test = std::async(std::launch::async, _run_test);
}

auto KholdRole::merge_capacity() -> void {
    if (!_measured && !_from_node) {
        return;
    }
    proto::Capacity c{.slot = 0, .link_mbps = _measured ? _measured->link_mbps : 0, .drives = {}};
    std::map<std::uint8_t, proto::DriveCapacity> drives;
    if (_from_node) {
        for (const auto& d : _from_node->drives) {
            drives[d.drive] = d;
        }
        if (!_measured) {
            c.link_mbps = _from_node->link_mbps;
        }
    }
    if (_measured) {
        for (const auto& m : _measured->drives) {
            auto [it, added] = drives.try_emplace(m.drive, m);
            auto& d = it->second;
            if (!added) {
                d.capacity_bytes = m.capacity_bytes;
                d.read_iops = m.read_iops;
                d.write_iops = m.write_iops;
                d.read_mib_per_s = m.read_mib_per_s;
                d.write_mib_per_s = m.write_mib_per_s;
                if (m.state == proto::DriveState::failed) {
                    d.state = proto::DriveState::failed;
                }
            }
            // The report's rule: allocated never exceeds capacity.
            d.allocated_bytes = std::min(d.allocated_bytes, d.capacity_bytes);
        }
    }
    for (auto& [n, d] : drives) {
        if (c.drives.size() >= proto::max_capacity_drives) {
            break;
        }
        c.drives.push_back(d);
    }
    if (_merged && *_merged == c) {
        return;  // nothing new for the controller
    }
    _merged = c;
    queue(std::move(c));
}

auto KholdRole::pump() -> void {
    // A restarted node starts from nothing: give it every layout again.
    if (const auto gen = _node.generation(); gen != _node_generation && _node.running()) {
        bool all = true;
        for (const auto& [volume, kept] : _layouts) {
            if (_node.apply_layout(volume, kept.epoch, kept.frame)) {
                ++_stats.replays;
            } else {
                all = false;
            }
        }
        if (all) {
            _node_generation = gen;  // otherwise tried again next pump
        }
    }
    bool capacity_changed = false;
    for (auto& body : _node.take_reports()) {
        if (auto* c = std::get_if<proto::Capacity>(&body)) {
            _from_node = std::move(*c);
            capacity_changed = true;
        } else if (relayed_kind(body)) {
            queue(std::move(body));
        } else {
            ++_stats.reports_dropped;
        }
    }
    if (_test.valid() && _test.wait_for(std::chrono::seconds{0}) == std::future_status::ready) {
        _measured = _test.get();
        ++_stats.self_tests;
        capacity_changed = true;
    }
    if (capacity_changed) {
        merge_capacity();
    }
}

auto KholdRole::function_inventory() -> std::expected<oar::Inventory, oar::Status> {
    return oar::Inventory{.role = oar::Role::khold, .vtep = {}, .functions = {}};
}

auto KholdRole::prepare_function(const oar::PrepareFunction& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto KholdRole::clean_function(const oar::CleanFunction& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto KholdRole::deliver_key(const oar::DeliverKey& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto KholdRole::drop_key(const oar::DropKey& /*request*/) -> oar::Status {
    return oar::Status::unknown_function;
}

auto KholdRole::map_update(std::span<const std::byte> /*frame*/) -> oar::Status {
    return oar::Status::unsupported;
}

auto KholdRole::health() -> std::expected<oar::Health, oar::Status> {
    const auto up = std::chrono::duration_cast<std::chrono::seconds>(_clock() - _started);
    const auto secs = static_cast<std::uint64_t>(std::max<std::int64_t>(0, up.count()));
    std::uint16_t faults = 0;
    if (!_node.running()) {
        faults |= fault_node_down;
    }
    if (_merged && std::ranges::any_of(_merged->drives, [](const proto::DriveCapacity& d) {
            return d.state == proto::DriveState::failed;
        })) {
        faults |= fault_drive_failed;
    }
    return oar::Health{.state = faults == 0 ? oar::HealthState::ok : oar::HealthState::degraded,
                       .fault_code = faults,
                       .uptime_seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                           secs, std::numeric_limits<std::uint32_t>::max()))};
}

auto KholdRole::volume_layout(std::span<const std::byte> frame) -> oar::Status {
    const auto l = proto::decode_volume_layout(frame);
    if (!l) {
        ++_stats.refused;
        return oar::Status::bad_request;
    }
    if (l->server_id != _server_id ||
        !_verify(proto::volume_layout_signed_bytes(frame), l->signature, l->key_id)) {
        ++_stats.refused;
        return oar::Status::failed;
    }
    const auto it = _layouts.find(l->volume_id);
    if (it != _layouts.end()) {
        if (l->epoch < it->second.epoch) {
            ++_stats.refused;
            return oar::Status::failed;  // fencing: never step a volume back
        }
        if (l->epoch == it->second.epoch && std::ranges::equal(frame, it->second.frame)) {
            return oar::Status::ok;  // helm's replay: the node has it
        }
    } else if (_layouts.size() >= max_kept_layouts) {
        ++_stats.refused;
        return oar::Status::busy;
    }
    if (!_node.apply_layout(l->volume_id, l->epoch, frame)) {
        ++_stats.refused;
        return oar::Status::failed;
    }
    ++_stats.layouts;
    if (!names_server(*l, _server_id)) {
        // The node has been told to let the volume go; nothing to replay.
        if (it != _layouts.end()) {
            _layouts.erase(it);
        }
        ++_stats.layouts_dropped;
        return oar::Status::ok;
    }
    _layouts[l->volume_id] = KeptLayout{.epoch = l->epoch, .frame = {frame.begin(), frame.end()}};
    return oar::Status::ok;
}

auto KholdRole::self_test() -> oar::Status {
    if (!_run_test) {
        return oar::Status::unsupported;
    }
    start_self_test();  // a test already running answers this request too
    return oar::Status::ok;
}

auto KholdRole::hold_reports(const oar::ReportRequest& request)
    -> std::expected<oar::ReportChunk, oar::Status> {
    return _reports.serve(request);
}

auto KholdRole::cert_request() -> std::expected<oar::CertAnswer, oar::Status> {
    if (_enrollment == nullptr) {
        return std::unexpected(oar::Status::unsupported);
    }
    return _enrollment->answer();
}

auto KholdRole::role_certificate(std::span<const std::byte> chain) -> oar::Status {
    if (_enrollment == nullptr) {
        return oar::Status::unsupported;
    }
    const auto status = _enrollment->install(chain);
    if (status == oar::Status::ok) {
        start_self_test();  // enrollment: fresh measurements for the controller
    }
    return status;
}

}  // namespace ak::khold
