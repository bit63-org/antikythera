// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/network_volume_backend.hpp"

#include <utility>

#include "proto/hold_wire.hpp"

namespace ak::oar::blk {

namespace {

using Clock = InitiatorCore::Clock;

}  // namespace

auto NetworkVolumeBackend::create(NetworkVolumeConfig config)
    -> std::expected<std::unique_ptr<NetworkVolumeBackend>, NetworkVolumeError> {
    auto transport = HoldTransport::create({.tls = config.tls,
                                            .connect_timeout = config.connect_timeout,
                                            .write_timeout = config.write_timeout,
                                            .wire_version = proto::hold_version});
    if (!transport) {
        return std::unexpected(transport.error());
    }
    return std::unique_ptr<NetworkVolumeBackend>{
        new NetworkVolumeBackend{std::move(config), std::move(*transport)}};
}

NetworkVolumeBackend::NetworkVolumeBackend(NetworkVolumeConfig config,
                                           std::unique_ptr<HoldTransport> transport) noexcept
    : _config{std::move(config)}, _core{_config.initiator}, _transport{std::move(transport)} {}

NetworkVolumeBackend::~NetworkVolumeBackend() = default;

auto NetworkVolumeBackend::set_tls(const tls::Config& config) -> void {
    _transport->set_tls(config);
}

auto NetworkVolumeBackend::set_route(const proto::ReplicaConfig& c)
    -> std::expected<void, RouteError> {
    auto r = _core.set_route(c, Clock::now());
    publish();
    return r;
}

auto NetworkVolumeBackend::routed() const noexcept -> bool {
    return _core.routed();
}

auto NetworkVolumeBackend::fenced() const noexcept -> bool {
    return _core.fenced();
}

auto NetworkVolumeBackend::session_open() const noexcept -> bool {
    return _core.session_open();
}

auto NetworkVolumeBackend::take_faults() -> std::vector<FaultEvent> {
    return _core.take_faults();
}

auto NetworkVolumeBackend::size_bytes() const noexcept -> std::uint64_t {
    return _core.capacity_bytes();
}

auto NetworkVolumeBackend::submit_read(std::uint64_t offset, std::span<std::byte> out,
                                       BackendCompletion done) -> void {
    _core.submit_read(offset, out, std::move(done), Clock::now());
    publish();
}

auto NetworkVolumeBackend::submit_write(std::uint64_t offset, std::span<const std::byte> in,
                                        BackendCompletion done) -> void {
    _core.submit_write(offset, in, std::move(done), Clock::now());
    publish();
}

auto NetworkVolumeBackend::submit_hydrate(std::uint64_t offset, std::span<const std::byte> in,
                                          BackendCompletion done) -> void {
    _core.submit_hydrate(offset, in, std::move(done), Clock::now());
    publish();
}

auto NetworkVolumeBackend::submit_flush(BackendCompletion done) -> void {
    _core.submit_flush(std::move(done));
}

auto NetworkVolumeBackend::poll() -> bool {
    for (auto& e : _transport->take_events()) {
        const auto now = Clock::now();
        switch (e.kind) {
            case HoldTransport::EventKind::connected:
                _core.connected(e.session, now);
                break;
            case HoldTransport::EventKind::disconnected:
                _core.disconnected(e.session, now);
                break;
            case HoldTransport::EventKind::frame:
                if (const auto f = proto::decode_hold_frame(e.frame)) {
                    _core.on_frame(e.session, *f, now);
                } else {
                    _core.disconnected(e.session, now);  // a payload that does not decode
                }
                break;
        }
    }
    _core.tick(Clock::now());
    publish();
    return _core.pending() != 0;
}

auto NetworkVolumeBackend::wake_fd() const noexcept -> int {
    return _transport->wake_fd();
}

auto NetworkVolumeBackend::publish() -> void {
    const auto now = Clock::now();
    const auto target = _core.target(now);
    std::vector<HoldTarget> targets;
    std::vector<HoldTransport::Outgoing> frames;
    auto out = _core.take_output();
    if (target) {
        targets.push_back(*target);
        // The core's frames are all for its current session.
        for (auto& f : out) {
            frames.push_back({.session = target->session, .frame = std::move(f)});
        }
    }
    _transport->sync(targets, std::move(frames));
    _transport->arm(_core.next_wake(now));
}

}  // namespace ak::oar::blk
