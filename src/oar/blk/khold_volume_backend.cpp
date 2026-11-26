// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/khold_volume_backend.hpp"

#include <utility>

#include "proto/hold_wire_v2.hpp"

namespace ak::oar::blk {

namespace {

using Clock = KholdInitiatorCore::Clock;

}  // namespace

auto KholdVolumeBackend::create(KholdVolumeConfig config)
    -> std::expected<std::unique_ptr<KholdVolumeBackend>, NetworkVolumeError> {
    auto transport = HoldTransport::create({.tls = config.tls,
                                            .connect_timeout = config.connect_timeout,
                                            .write_timeout = config.write_timeout,
                                            .wire_version = proto::hold_v2_version});
    if (!transport) {
        return std::unexpected(transport.error());
    }
    return std::unique_ptr<KholdVolumeBackend>{
        new KholdVolumeBackend{std::move(config), std::move(*transport)}};
}

KholdVolumeBackend::KholdVolumeBackend(KholdVolumeConfig config,
                                       std::unique_ptr<HoldTransport> transport) noexcept
    : _config{std::move(config)}, _core{_config.initiator}, _transport{std::move(transport)} {}

KholdVolumeBackend::~KholdVolumeBackend() = default;

auto KholdVolumeBackend::set_layout(const proto::VolumeLayout& l)
    -> std::expected<void, RouteError> {
    auto r = _core.set_layout(l, Clock::now());
    publish();
    return r;
}

auto KholdVolumeBackend::set_tls(const tls::Config& config) -> void {
    _transport->set_tls(config);
}

auto KholdVolumeBackend::routed() const noexcept -> bool {
    return _core.routed();
}

auto KholdVolumeBackend::fenced() const noexcept -> bool {
    return _core.fenced();
}

auto KholdVolumeBackend::take_faults() -> std::vector<FaultEvent> {
    return _core.take_faults();
}

auto KholdVolumeBackend::sessions_open() const noexcept -> std::size_t {
    return _core.sessions_open();
}

auto KholdVolumeBackend::size_bytes() const noexcept -> std::uint64_t {
    return _core.capacity_bytes();
}

auto KholdVolumeBackend::submit_read(std::uint64_t offset, std::span<std::byte> out,
                                     BackendCompletion done) -> void {
    _core.submit_read(offset, out, std::move(done), Clock::now());
    publish();
}

auto KholdVolumeBackend::submit_write(std::uint64_t offset, std::span<const std::byte> in,
                                      BackendCompletion done) -> void {
    _core.submit_write(offset, in, std::move(done), Clock::now());
    publish();
}

auto KholdVolumeBackend::submit_flush(BackendCompletion done) -> void {
    _core.submit_flush(std::move(done));
}

auto KholdVolumeBackend::submit_discard(std::uint64_t offset, std::uint64_t length,
                                        BackendCompletion done) -> void {
    _core.submit_discard(offset, length, std::move(done), Clock::now());
    publish();
}

auto KholdVolumeBackend::submit_write_zeroes(std::uint64_t offset, std::uint64_t length,
                                             BackendCompletion done) -> void {
    _core.submit_write_zeroes(offset, length, std::move(done), Clock::now());
    publish();
}

auto KholdVolumeBackend::submit_hydrate(std::uint64_t /*offset*/,
                                        std::span<const std::byte> /*in*/,
                                        BackendCompletion done) -> void {
    done(std::unexpected(BackendError::io));  // khold hydration is phase 2
}

auto KholdVolumeBackend::poll() -> bool {
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
                if (const auto f = proto::decode_hold_v2_frame(e.frame)) {
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

auto KholdVolumeBackend::wake_fd() const noexcept -> int {
    return _transport->wake_fd();
}

auto KholdVolumeBackend::publish() -> void {
    const auto now = Clock::now();
    std::vector<HoldTransport::Outgoing> frames;
    for (auto& f : _core.take_output()) {
        frames.push_back({.session = f.session, .frame = std::move(f.frame)});
    }
    _transport->sync(_core.targets(now), std::move(frames));
    _transport->arm(_core.next_wake(now));
}

}  // namespace ak::oar::blk
