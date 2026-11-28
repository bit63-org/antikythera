// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/controller_link.hpp"

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <random>
#include <utility>
#include <variant>

namespace ak::helm {

auto to_string(SessionError e) noexcept -> const char* {
    switch (e) {
        case SessionError::bad_record:
            return "bad_record";
        case SessionError::wrong_direction:
            return "wrong_direction";
        case SessionError::wrong_server:
            return "wrong_server";
        case SessionError::bad_ack:
            return "bad_ack";
        case SessionError::not_connected:
            return "not_connected";
    }
    return "unknown";
}

// ---- ControllerSession ----------------------------------------------------

ControllerSession::ControllerSession(std::uint64_t server_id, std::uint64_t boot_id,
                                     InventorySource inventory, ControllerSink& sink)
    : _server_id{server_id}, _boot_id{boot_id}, _inventory{std::move(inventory)}, _sink{&sink} {}

auto ControllerSession::queue(proto::ReportBody body) -> std::uint64_t {
    const std::uint64_t seq = _next_seq++;
    const proto::Report report{.server_id = _server_id, .report_seq = seq, .body = std::move(body)};
    auto payload = proto::encode_report(report);
    if (!payload) {
        // helm built a report its own schema refuses: a helm bug. Dropping
        // it (and counting it) beats sending a frame the controller would
        // reject and disconnect over.
        ++_dropped;
        return seq;
    }
    auto record = proto::encode_record(proto::RecordType::report, *payload);
    if (!record) {
        ++_dropped;
        return seq;
    }
    if (_connected) {
        _outbound.insert(_outbound.end(), record->begin(), record->end());
    }
    // A connection restates the inventory, the boot cache and the
    // enrollment, so an older unacknowledged one is never replayed.
    const bool inventory = std::holds_alternative<proto::Inventory>(report.body);
    _pending.push_back(
        {.seq = seq,
         .snapshot = inventory || std::holds_alternative<proto::BootCache>(report.body),
         .enrollment = std::holds_alternative<proto::Enrollment>(report.body),
         .record = std::move(*record)});
    while (_pending.size() > max_pending_reports) {
        _pending.pop_front();
        ++_dropped;
    }
    // The boot cache rides behind every inventory (cold-start Requirement
    // 8.2), so the controller sees what helm could restart from whenever
    // it learns what the host has.
    if (inventory && _boot_cache) {
        if (auto cache = _boot_cache(); cache) {
            (void)queue(std::move(*cache));
        }
    }
    return seq;
}

auto ControllerSession::report(proto::ReportBody body) -> std::uint64_t {
    return queue(std::move(body));
}

auto ControllerSession::on_connected() -> void {
    _connected = true;
    _decoder = proto::RecordDecoder{};
    _outbound.clear();
    // hello names the boot that every report on this connection belongs to.
    auto hello = proto::encode_hello({.server_id = _server_id, .boot_id = _boot_id});
    auto hello_record =
        hello ? proto::encode_record(proto::RecordType::hello, *hello) : std::move(hello);
    if (hello_record) {
        _outbound = std::move(*hello_record);
    }
    // An inventory, boot cache or enrollment the controller never
    // acknowledged is superseded by the fresh one below, so it is not
    // replayed.
    std::erase_if(_pending, [](const Pending& p) { return p.snapshot || p.enrollment; });
    // The replay, in sequence order, then the fresh inventory and the
    // enrollment with the highest sequence numbers: the controller
    // processes reports in order and ends up holding the newest snapshot
    // and transport key.
    for (const auto& p : _pending) {
        _outbound.insert(_outbound.end(), p.record.begin(), p.record.end());
    }
    auto inventory = _inventory();
    inventory.boot_id = _boot_id;
    (void)queue(std::move(inventory));
    if (_enrollment) {
        (void)queue(*_enrollment);
    }
}

auto ControllerSession::set_enrollment(const proto::Enrollment& enrollment) -> void {
    _enrollment = enrollment;
    if (_connected) {
        std::erase_if(_pending, [](const Pending& p) { return p.enrollment; });
        (void)queue(enrollment);
    }
}

auto ControllerSession::on_disconnected() noexcept -> void {
    _connected = false;
    _outbound.clear();
}

auto ControllerSession::take_outbound() -> std::vector<std::byte> {
    return std::exchange(_outbound, {});
}

auto ControllerSession::handle(const proto::Record& rec) -> std::expected<void, SessionError> {
    switch (rec.type) {
        case proto::RecordType::envelope: {
            auto env = proto::decode_envelope(rec.payload);
            if (!env) {
                return std::unexpected(SessionError::bad_record);
            }
            // Until the slot itself names its server (the open question in
            // the controller-interface design), this check and mTLS are
            // what keep one server's commands off another.
            if (env->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_envelope(*env);
            return {};
        }
        case proto::RecordType::map_update: {
            auto update = proto::decode_map_update(rec.payload);
            if (!update) {
                return std::unexpected(SessionError::bad_record);
            }
            if (update->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_map_update(*update, rec.payload);
            return {};
        }
        case proto::RecordType::group_policy: {
            auto policy = proto::decode_group_policy(rec.payload);
            if (!policy) {
                return std::unexpected(SessionError::bad_record);
            }
            if (policy->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_group_policy(*policy, rec.payload);
            return {};
        }
        case proto::RecordType::vpc_config: {
            auto config = proto::decode_vpc_config(rec.payload);
            if (!config) {
                return std::unexpected(SessionError::bad_record);
            }
            if (config->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_vpc_config(*config, rec.payload);
            return {};
        }
        case proto::RecordType::group_members: {
            auto members = proto::decode_group_members(rec.payload);
            if (!members) {
                return std::unexpected(SessionError::bad_record);
            }
            if (members->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_group_members(*members, rec.payload);
            return {};
        }
        case proto::RecordType::instance_metadata: {
            auto metadata = proto::decode_instance_metadata(rec.payload);
            if (!metadata) {
                return std::unexpected(SessionError::bad_record);
            }
            if (metadata->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_instance_metadata(*metadata, rec.payload);
            return {};
        }
        case proto::RecordType::tunnel_peers: {
            auto peers = proto::decode_tunnel_peers(rec.payload);
            if (!peers) {
                return std::unexpected(SessionError::bad_record);
            }
            if (peers->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_tunnel_peers(*peers, rec.payload);
            return {};
        }
        case proto::RecordType::replica_config: {
            auto config = proto::decode_replica_config(rec.payload);
            if (!config) {
                return std::unexpected(SessionError::bad_record);
            }
            if (config->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_replica_config(*config, rec.payload);
            return {};
        }
        case proto::RecordType::volume_op: {
            auto op = proto::decode_volume_op(rec.payload);
            if (!op) {
                return std::unexpected(SessionError::bad_record);
            }
            if (op->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_volume_op(*op, rec.payload);
            return {};
        }
        case proto::RecordType::volume_key: {
            auto key = proto::decode_volume_key(rec.payload);
            if (!key) {
                return std::unexpected(SessionError::bad_record);
            }
            if (key->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_volume_key(*key, rec.payload);
            return {};
        }
        case proto::RecordType::image_key: {
            auto key = proto::decode_image_key(rec.payload);
            if (!key) {
                return std::unexpected(SessionError::bad_record);
            }
            if (key->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_image_key(*key, rec.payload);
            return {};
        }
        case proto::RecordType::lease_grant: {
            auto grant = proto::decode_lease_grant(rec.payload);
            if (!grant) {
                return std::unexpected(SessionError::bad_record);
            }
            if (grant->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_lease_grant(*grant);
            return {};
        }
        case proto::RecordType::role_certificate: {
            auto cert = proto::decode_role_certificate(rec.payload);
            if (!cert) {
                return std::unexpected(SessionError::bad_record);
            }
            if (cert->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_role_certificate(*cert);
            return {};
        }
        case proto::RecordType::volume_layout: {
            auto layout = proto::decode_volume_layout(rec.payload);
            if (!layout) {
                return std::unexpected(SessionError::bad_record);
            }
            if (layout->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_volume_layout(*layout, rec.payload);
            return {};
        }
        case proto::RecordType::self_test: {
            auto request = proto::decode_self_test(rec.payload);
            if (!request) {
                return std::unexpected(SessionError::bad_record);
            }
            if (request->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_self_test(*request);
            return {};
        }
        case proto::RecordType::standing_set: {
            auto set = proto::decode_standing_set(rec.payload);
            if (!set) {
                return std::unexpected(SessionError::bad_record);
            }
            if (set->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_standing_set(*set, rec.payload);
            return {};
        }
        case proto::RecordType::power_policy: {
            auto policy = proto::decode_power_policy(rec.payload);
            if (!policy) {
                return std::unexpected(SessionError::bad_record);
            }
            if (policy->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_power_policy(*policy, rec.payload);
            return {};
        }
        case proto::RecordType::host_power: {
            auto power = proto::decode_host_power(rec.payload);
            if (!power) {
                return std::unexpected(SessionError::bad_record);
            }
            if (power->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_host_power(*power, rec.payload);
            return {};
        }
        case proto::RecordType::decommission: {
            auto order = proto::decode_decommission(rec.payload);
            if (!order) {
                return std::unexpected(SessionError::bad_record);
            }
            if (order->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_decommission(*order, rec.payload);
            return {};
        }
        case proto::RecordType::boot_image: {
            auto assignment = proto::decode_boot_image(rec.payload);
            if (!assignment) {
                return std::unexpected(SessionError::bad_record);
            }
            if (assignment->server_id != _server_id) {
                return std::unexpected(SessionError::wrong_server);
            }
            _sink->on_boot_image(*assignment, rec.payload);
            return {};
        }
        case proto::RecordType::report_ack: {
            auto ack = proto::decode_report_ack(rec.payload);
            if (!ack) {
                return std::unexpected(SessionError::bad_record);
            }
            if (ack->server_id != _server_id || ack->report_seq >= _next_seq) {
                return std::unexpected(SessionError::bad_ack);
            }
            // Acks may repeat or arrive late after a reconnect: only move
            // forward.
            _acked = std::max(_acked, ack->report_seq);
            while (!_pending.empty() && _pending.front().seq <= _acked) {
                _pending.pop_front();
            }
            return {};
        }
        case proto::RecordType::report:
        case proto::RecordType::hello:
            return std::unexpected(SessionError::wrong_direction);
    }
    return std::unexpected(SessionError::bad_record);
}

auto ControllerSession::on_bytes(std::span<const std::byte> bytes)
    -> std::expected<void, SessionError> {
    if (!_connected) {
        return std::unexpected(SessionError::not_connected);
    }
    _decoder.feed(bytes);
    for (;;) {
        auto rec = _decoder.next();
        if (!rec) {
            return std::unexpected(SessionError::bad_record);
        }
        if (!rec->has_value()) {
            return {};
        }
        if (auto ok = handle(**rec); !ok) {
            return ok;
        }
    }
}

// ---- ControllerLink -------------------------------------------------------

namespace {

constexpr std::size_t read_chunk = 16 * 1024;

auto jittered(std::chrono::milliseconds base) -> std::chrono::milliseconds {
    // Up to 25% random spread, so a controller restart does not get every
    // server reconnecting in the same instant.
    thread_local std::minstd_rand rng{std::random_device{}()};
    const auto spread = std::max<std::chrono::milliseconds::rep>(base.count() / 4, 1);
    std::uniform_int_distribution<std::chrono::milliseconds::rep> dist{0, spread};
    return base + std::chrono::milliseconds{dist(rng)};
}

}  // namespace

ControllerLink::ControllerLink(LinkOptions options, ControllerSession& session, tls::Context ctx,
                               int wake_fd)
    : _options{std::move(options)}, _session{&session}, _ctx{std::move(ctx)}, _wake_fd{wake_fd} {}

ControllerLink::~ControllerLink() {
    if (_wake_fd >= 0) {
        (void)::close(_wake_fd);
    }
}

auto ControllerLink::create(LinkOptions options, ControllerSession& session)
    -> std::expected<std::unique_ptr<ControllerLink>, tls::Error> {
    options.tls.role = tls::Role::client;
    auto ctx = tls::Context::create(options.tls);
    if (!ctx) {
        return std::unexpected(ctx.error());
    }
    const int wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd < 0) {
        return std::unexpected(tls::Error::io);
    }
    return std::unique_ptr<ControllerLink>{
        new ControllerLink{std::move(options), session, std::move(*ctx), wake_fd}};
}

auto ControllerLink::wake() noexcept -> void {
    static_cast<void>(::eventfd_write(_wake_fd, 1));
}

auto ControllerLink::drain_wake() noexcept -> void {
    std::uint64_t value = 0;
    static_cast<void>(::eventfd_read(_wake_fd, &value));
}

auto ControllerLink::report(proto::ReportBody body) -> std::uint64_t {
    std::uint64_t seq = 0;
    {
        const std::scoped_lock lock{_mutex};
        seq = _session->report(std::move(body));
    }
    wake();
    return seq;
}

auto ControllerLink::stats() const -> ControllerLinkStats {
    const std::scoped_lock lock{_mutex};
    return _stats;
}

auto ControllerLink::flush(tls::Stream& stream) -> bool {
    std::vector<std::byte> out;
    {
        const std::scoped_lock lock{_mutex};
        out = _session->take_outbound();
    }
    if (out.empty()) {
        return true;
    }
    return stream.write_all(out, tls::Clock::now() + _options.io_timeout).has_value();
}

auto ControllerLink::serve(tls::Stream& stream, const std::stop_token& stop) -> void {
    std::array<std::byte, read_chunk> buf{};
    while (!stop.stop_requested()) {
        if (!flush(stream)) {
            return;
        }
        if (!stream.pending()) {
            std::array<pollfd, 2> fds{pollfd{.fd = stream.fd(), .events = POLLIN, .revents = 0},
                                      pollfd{.fd = _wake_fd, .events = POLLIN, .revents = 0}};
            const int n = poll(fds.data(), fds.size(), -1);
            if (n < 0) {
                continue;  // EINTR
            }
            if ((fds[1].revents & POLLIN) != 0) {
                drain_wake();
            }
            if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
                continue;
            }
        }
        // Drain everything TLS has, so pending() is false before the next
        // poll and buffered records are not left waiting on the socket.
        do {
            auto got = stream.read_some(buf);
            if (!got) {
                return;
            }
            if (*got == 0) {
                break;
            }
            const std::scoped_lock lock{_mutex};
            if (auto ok = _session->on_bytes(std::span{buf}.first(*got)); !ok) {
                ++_stats.protocol_errors;
                return;
            }
        } while (stream.pending());
    }
}

auto ControllerLink::sleep_backoff(std::chrono::milliseconds delay, const std::stop_token& stop)
    -> void {
    const auto until = tls::Clock::now() + jittered(delay);
    while (!stop.stop_requested()) {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(until - tls::Clock::now());
        if (left.count() <= 0) {
            return;
        }
        pollfd p{.fd = _wake_fd, .events = POLLIN, .revents = 0};
        // Reports queued while disconnected also wake this poll; they
        // must not cut the backoff short, so only a stop request ends it.
        (void)poll(&p, 1,
                   static_cast<int>(std::min<std::chrono::milliseconds::rep>(left.count(), 1000)));
        drain_wake();
    }
}

auto ControllerLink::run(const std::stop_token& stop) -> void {
    const std::stop_callback on_stop{stop, [this] { wake(); }};
    auto delay = _options.min_backoff;
    while (!stop.stop_requested()) {
        auto stream = tls::Stream::connect(_ctx, _options.host, _options.port,
                                           tls::Clock::now() + _options.io_timeout);
        if (!stream) {
            {
                const std::scoped_lock lock{_mutex};
                ++_stats.failures;
            }
            sleep_backoff(delay, stop);
            delay = std::min(delay * 2, _options.max_backoff);
            continue;
        }
        {
            const std::scoped_lock lock{_mutex};
            ++_stats.connects;
            _session->on_connected();
        }
        delay = _options.min_backoff;
        serve(*stream, stop);
        stream->close();
        {
            const std::scoped_lock lock{_mutex};
            _session->on_disconnected();
            if (!stop.stop_requested()) {
                ++_stats.failures;
            }
        }
        if (!stop.stop_requested()) {
            sleep_backoff(delay, stop);
        }
    }
}

}  // namespace ak::helm
