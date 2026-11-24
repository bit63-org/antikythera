// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/initiator.hpp"

#include <algorithm>
#include <utility>

#include "common/crc32c.hpp"

namespace ak::oar::blk {

namespace {

using proto::HoldOpcode;
using proto::HoldStatus;

constexpr std::uint64_t qos_io_unit = 256 * 1024;
constexpr double mib = 1024.0 * 1024.0;
constexpr int read_retries = 1;
constexpr int write_retries = 2;
constexpr int suspended_backoff_factor = 4;

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto find_attachment(const proto::ReplicaConfig& c, std::uint64_t id)
    -> const proto::VolumeAttachment* {
    const auto it = std::ranges::find(c.attachments, id, &proto::VolumeAttachment::attachment_id);
    return it == c.attachments.end() ? nullptr : &*it;
}

}  // namespace

auto to_string(RouteError e) noexcept -> const char* {
    switch (e) {
        case RouteError::wrong_volume:
            return "wrong_volume";
        case RouteError::stale:
            return "stale";
        case RouteError::mismatch:
            return "mismatch";
    }
    return "unknown";
}

InitiatorCore::InitiatorCore(InitiatorConfig config) noexcept : _config{config} {}

auto InitiatorCore::capacity_bytes() const noexcept -> std::uint64_t {
    return _route ? _route->config.capacity_blocks * _route->config.block_size : 0;
}

// ---- route -------------------------------------------------------------------

auto InitiatorCore::set_route(const proto::ReplicaConfig& c, Clock::time_point now)
    -> std::expected<void, RouteError> {
    const bool first = !_route;
    std::uint64_t old_primary = 0;
    if (_route) {
        const auto& old = _route->config;
        if (c.volume_id != old.volume_id) {
            return std::unexpected(RouteError::wrong_volume);
        }
        if (c.epoch < old.epoch) {
            return std::unexpected(RouteError::stale);
        }
        if (c.epoch == old.epoch) {
            return {};
        }
        // A resize only grows the volume (design "QoS and elasticity").
        if (c.block_size != old.block_size || c.capacity_blocks < old.capacity_blocks) {
            return std::unexpected(RouteError::mismatch);
        }
        if (const auto* p = proto::primary_member(old); p != nullptr) {
            old_primary = p->server_id;
        }
    }
    const auto* att = find_attachment(c, _config.attachment_id);
    if (att == nullptr || (_route && att->generation != _route->generation)) {
        // Detached, forced off or replaced: this attachment is over.
        if (_route) {
            _route->config = c;
        }
        fence();
        run_completions();
        return {};
    }
    if (first || c.qos != _route->config.qos) {
        _ios = TokenBucket{static_cast<double>(c.qos.iops), static_cast<double>(c.qos.burst_iops),
                           now};
        _mib = TokenBucket{static_cast<double>(c.qos.mib_per_s),
                           static_cast<double>(c.qos.burst_mib), now};
    }
    _route = Route{.config = c, .generation = att->generation, .mode = att->mode};
    const bool was_stale = std::exchange(_stale, false);
    const auto* primary = proto::primary_member(c);
    const std::uint64_t new_primary = primary != nullptr ? primary->server_id : 0;
    if (first) {
        std::vector<std::uint64_t> ids;
        for (const auto& [id, op] : _ops) {
            ids.push_back(id);
        }
        for (const auto id : ids) {
            if (auto it = _ops.find(id); it != _ops.end()) {
                it->second.deadline = now + _config.request_timeout;
                split(id, it->second);
            }
        }
    }
    if (_state == State::down || was_stale || new_primary != old_primary) {
        drop_session(now);  // open the next session at once
    }
    pump(now);
    run_completions();
    return {};
}

// ---- requests ----------------------------------------------------------------

auto InitiatorCore::submit_read(std::uint64_t offset, std::span<std::byte> out,
                                BackendCompletion done, Clock::time_point now) -> void {
    const auto id = _next_op++;
    auto& op = _ops[id];
    op.kind = Kind::read;
    op.offset = offset;
    op.out = out;
    op.done = std::move(done);
    // Held without a deadline until the route arrives (Requirement 2.2).
    op.deadline = _route ? now + _config.request_timeout : Clock::time_point::max();
    if (_route) {
        split(id, op);
    }
    pump(now);
    run_completions();
}

auto InitiatorCore::submit_write(std::uint64_t offset, std::span<const std::byte> in,
                                 BackendCompletion done, Clock::time_point now) -> void {
    const auto id = _next_op++;
    auto& op = _ops[id];
    op.kind = Kind::write;
    op.offset = offset;
    op.in = in;
    op.done = std::move(done);
    // Held without a deadline until the route arrives (Requirement 2.2).
    op.deadline = _route ? now + _config.request_timeout : Clock::time_point::max();
    if (_route) {
        split(id, op);
    }
    pump(now);
    run_completions();
}

auto InitiatorCore::submit_flush(BackendCompletion done) -> void {
    // Every completed write is durable on every in-sync replica already.
    _ready.emplace_back(std::move(done), BackendResult{});
    run_completions();
}

auto InitiatorCore::split(std::uint64_t id, Op& op) -> void {
    const auto& c = _route->config;
    const std::uint64_t bs = c.block_size;
    const std::uint64_t len = op.kind == Kind::read ? op.out.size() : op.in.size();
    const std::uint64_t cap = c.capacity_blocks * bs;
    if (len == 0 || op.offset % bs != 0 || len % bs != 0 || op.offset > cap ||
        len > cap - op.offset) {
        complete(id, std::unexpected(BackendError::out_of_range));
        return;
    }
    if (op.kind == Kind::write && _route->mode == proto::AttachMode::ro) {
        complete(id, std::unexpected(BackendError::io));
        return;
    }
    if (op.kind == Kind::write) {
        op.crcs = proto::block_crcs(op.in, static_cast<std::uint32_t>(bs));
    }
    const std::uint64_t total = len / bs;
    const std::uint64_t per_part =
        std::min<std::uint64_t>(proto::max_hold_blocks, proto::max_hold_data_bytes / bs);
    for (std::uint64_t first = 0; first < total; first += per_part) {
        const auto n = static_cast<std::uint32_t>(std::min(per_part, total - first));
        _parts.push_back(Part{.op = id,
                              .request_id = _next_request++,
                              .kind = op.kind,
                              .lba = (op.offset / bs) + first,
                              .blocks = n,
                              .first_block = static_cast<std::size_t>(first),
                              .sent = false,
                              .retries = 0,
                              .not_before = {}});
        ++op.parts_left;
    }
    op.split = true;
}

auto InitiatorCore::header(HoldOpcode op) const -> proto::HoldHeader {
    proto::HoldHeader h;
    h.opcode = op;
    h.volume_id = _route->config.volume_id;
    h.epoch = _route->config.epoch;
    h.attachment_id = _config.attachment_id;
    h.generation = _route->generation;
    return h;
}

auto InitiatorCore::outstanding() const -> bool {
    return _ping_out || std::ranges::any_of(_parts, &Part::sent);
}

auto InitiatorCore::blocked(std::deque<Part>::const_iterator it) const -> bool {
    if (it->kind != Kind::write) {
        return false;
    }
    const auto end = it->lba + it->blocks;
    return std::any_of(_parts.cbegin(), it, [&](const Part& p) {
        return p.kind == Kind::write && p.op != it->op && p.lba < end && it->lba < p.lba + p.blocks;
    });
}

auto InitiatorCore::admit(std::uint64_t bytes, Clock::time_point now) -> bool {
    _ios.refill(now);
    _mib.refill(now);
    if (!_ios.ready() || !_mib.ready()) {
        return false;
    }
    _ios.take(
        static_cast<double>(std::max<std::uint64_t>(1, (bytes + qos_io_unit - 1) / qos_io_unit)));
    _mib.take(static_cast<double>(bytes) / mib);
    return true;
}

auto InitiatorCore::qos_wait() const -> Clock::duration {
    return std::max(_ios.wait(), _mib.wait());
}

auto InitiatorCore::pump(Clock::time_point now) -> void {
    if (_state != State::open || !_route) {
        return;
    }
    const std::uint32_t bs = _route->config.block_size;
    std::size_t in_flight = static_cast<std::size_t>(std::ranges::count_if(_parts, &Part::sent));
    for (auto it = _parts.begin(); it != _parts.end() && in_flight < _config.max_in_flight; ++it) {
        if (it->sent || now < it->not_before || blocked(it)) {
            continue;
        }
        if (!admit(std::uint64_t{it->blocks} * bs, now)) {
            break;  // keep the order: nothing overtakes a request held by QoS
        }
        const Op& op = _ops.at(it->op);
        auto h = header(it->kind == Kind::read ? HoldOpcode::read : HoldOpcode::write);
        h.request_id = it->request_id;
        h.lba = it->lba;
        h.blocks = it->blocks;
        proto::HoldPayload payload;
        if (it->kind == Kind::write) {
            payload = proto::BlockData{
                .block_size = bs,
                .crcs = std::span{op.crcs}.subspan(
                    it->first_block * proto::hold_block_crc_size,
                    std::size_t{it->blocks} * proto::hold_block_crc_size),
                .data = op.in.subspan(it->first_block * bs, std::size_t{it->blocks} * bs)};
        }
        auto frame = proto::encode_hold_frame({.header = h, .payload = payload});
        if (!frame) {
            complete(it->op, std::unexpected(BackendError::io));
            return;  // `it` is gone; the next pump continues
        }
        if (!outstanding()) {
            _last_heard = now;  // waiting starts now
        }
        _out.push_back(std::move(*frame));
        it->sent = true;
        _last_sent = now;
        ++in_flight;
    }
}

// ---- sessions ----------------------------------------------------------------

auto InitiatorCore::target(Clock::time_point now) const -> std::optional<HoldTarget> {
    if (!_route || _fenced || _stale ||
        (_route->config.flags & proto::replica_flags::io_suspended) != 0) {
        return std::nullopt;
    }
    if (_state == State::down && now < _reconnect_at) {
        return std::nullopt;
    }
    const auto* p = proto::primary_member(_route->config);
    if (p == nullptr) {
        return std::nullopt;
    }
    return HoldTarget{
        .server_id = p->server_id, .endpoint = p->endpoint, .port = p->port, .session = _session};
}

auto InitiatorCore::send_hello() -> void {
    auto h = header(HoldOpcode::hello);
    h.request_id = _next_request++;
    auto frame = proto::encode_hold_frame(
        {.header = h,
         .payload = proto::HoldHello{.role = proto::HoldPeerRole::initiator, .replica_gen = 0}});
    if (frame) {
        _out.push_back(std::move(*frame));
    }
}

auto InitiatorCore::connected(std::uint64_t session, Clock::time_point now) -> void {
    if (session != _session || _state != State::down || !_route || _fenced) {
        return;
    }
    _state = State::hello;
    _last_heard = now;
    _last_sent = now;
    _ping_out = false;
    send_hello();
    run_completions();
}

auto InitiatorCore::disconnected(std::uint64_t session, Clock::time_point now) -> void {
    if (session != _session) {
        return;
    }
    drop_session(now + _config.retry_backoff);
    run_completions();
}

auto InitiatorCore::drop_session(Clock::time_point retry_at) -> void {
    _state = State::down;
    ++_session;
    for (auto& p : _parts) {
        p.sent = false;  // resent, in order, on the next session
    }
    _ping_out = false;
    _out.clear();
    _reconnect_at = retry_at;
}

auto InitiatorCore::on_frame(std::uint64_t session, const proto::HoldFrame& f,
                             Clock::time_point now) -> void {
    if (session != _session || _state == State::down || !proto::is_response(f.header)) {
        return;
    }
    _last_heard = now;
    switch (f.header.opcode) {
        case HoldOpcode::hello_ok:
            if (_state != State::hello) {
                break;
            }
            if (f.header.status == HoldStatus::ok) {
                _state = State::open;
            } else if (f.header.status == HoldStatus::stale_epoch) {
                // Behind the hold only if its epoch is newer than the route.
                _stale = f.header.epoch > _route->config.epoch;
                drop_session(now);
            } else if (f.header.status == HoldStatus::fenced) {
                fence();
            } else {
                drop_session(now + _config.retry_backoff);
            }
            break;
        case HoldOpcode::redirect:
            on_redirect(f, now);
            break;
        case HoldOpcode::ping:
            _ping_out = false;
            break;
        case HoldOpcode::read:
        case HoldOpcode::write: {
            const auto it = std::ranges::find_if(_parts, [&](const Part& p) {
                return p.sent && p.request_id == f.header.request_id;
            });
            if (it != _parts.end()) {
                on_reply(it, f, now);
            }
            break;
        }
        default:
            break;
    }
    pump(now);
    run_completions();
}

auto InitiatorCore::on_redirect(const proto::HoldFrame& f, Clock::time_point now) -> void {
    const auto* r = std::get_if<proto::HoldRedirect>(&f.payload);
    if (r != nullptr && r->primary_epoch > _route->config.epoch) {
        _stale = true;  // helm will bring the newer config
        drop_session(now);
    } else {
        drop_session(now + _config.retry_backoff);
    }
}

auto InitiatorCore::on_reply(std::deque<Part>::iterator it, const proto::HoldFrame& f,
                             Clock::time_point now) -> void {
    const std::uint32_t bs = _route->config.block_size;
    switch (f.header.status) {
        case HoldStatus::ok: {
            if (it->kind == Kind::write) {
                part_done(it);
                return;
            }
            const auto* d = std::get_if<proto::BlockData>(&f.payload);
            bool good = d != nullptr && d->block_size == bs && f.header.blocks == it->blocks &&
                        d->data.size() == std::size_t{it->blocks} * bs;
            for (std::size_t b = 0; good && b < it->blocks; ++b) {
                const auto block = d->data.subspan(b * bs, bs);
                const auto crc = proto::block_crc(*d, b);
                good = crc32c::of(block) == crc || (crc == 0 && all_zero(block));
            }
            if (!good) {
                _faults.push_back(InitiatorFault::checksum);
                if (it->retries < read_retries) {
                    ++it->retries;
                    it->sent = false;
                } else {
                    complete(it->op, std::unexpected(BackendError::io));
                }
                return;
            }
            Op& op = _ops.at(it->op);
            std::ranges::copy(d->data,
                              op.out.begin() + static_cast<std::ptrdiff_t>(it->first_block * bs));
            part_done(it);
            return;
        }
        case HoldStatus::throttled:
            it->sent = false;
            it->not_before = now + _config.retry_backoff;
            return;
        case HoldStatus::io_suspended:
            it->sent = false;
            it->not_before = now + (_config.retry_backoff * suspended_backoff_factor);
            return;
        case HoldStatus::checksum:
            if (it->retries < write_retries) {
                ++it->retries;
                it->sent = false;
            } else {
                complete(it->op, std::unexpected(BackendError::io));
            }
            return;
        case HoldStatus::stale_epoch:
            if (f.header.epoch > _route->config.epoch) {
                _stale = true;  // helm will bring the newer config
                drop_session(now);
            } else {
                it->sent = false;  // sent before the route moved on: again, at its epoch
            }
            return;
        case HoldStatus::fenced:
            fence();
            return;
        case HoldStatus::range:
            complete(it->op, std::unexpected(BackendError::out_of_range));
            return;
        default:
            complete(it->op, std::unexpected(BackendError::io));
            return;
    }
}

auto InitiatorCore::part_done(std::deque<Part>::iterator it) -> void {
    const auto id = it->op;
    _parts.erase(it);
    auto op = _ops.find(id);
    if (op != _ops.end() && --op->second.parts_left == 0) {
        complete(id, {});
    }
}

auto InitiatorCore::complete(std::uint64_t id, BackendResult r) -> void {
    const auto it = _ops.find(id);
    if (it == _ops.end()) {
        return;
    }
    _ready.emplace_back(std::move(it->second.done), r);
    _ops.erase(it);
    std::erase_if(_parts, [id](const Part& p) { return p.op == id; });
}

auto InitiatorCore::fail_all(BackendError e) -> void {
    std::vector<std::uint64_t> ids;
    for (const auto& [id, op] : _ops) {
        ids.push_back(id);
    }
    for (const auto id : ids) {
        complete(id, std::unexpected(e));
    }
}

auto InitiatorCore::fence() -> void {
    if (!_fenced) {
        _faults.push_back(InitiatorFault::fenced);
    }
    _fenced = true;
    fail_all(BackendError::io);
    drop_session(Clock::time_point::max());
}

// ---- time --------------------------------------------------------------------

auto InitiatorCore::tick(Clock::time_point now) -> void {
    if (_fenced) {
        fail_all(BackendError::io);  // anything submitted since
    }
    std::vector<std::uint64_t> late;
    for (const auto& [id, op] : _ops) {
        if (op.deadline <= now) {
            late.push_back(id);
        }
    }
    for (const auto id : late) {
        complete(id, std::unexpected(BackendError::io));
    }
    if (_state != State::down && (outstanding() || _state == State::hello) &&
        now - _last_heard >= _config.primary_timeout) {
        _faults.push_back(InitiatorFault::primary_timeout);
        drop_session(now + _config.retry_backoff);
    }
    if (_state == State::open && !outstanding() &&
        now - std::max(_last_heard, _last_sent) >= _config.ping_interval) {
        auto h = header(HoldOpcode::ping);
        h.request_id = _next_request++;
        if (auto frame = proto::encode_hold_frame({.header = h, .payload = proto::HoldPing{}})) {
            _out.push_back(std::move(*frame));
            _ping_out = true;
            _last_heard = now;
            _last_sent = now;
        }
    }
    pump(now);
    run_completions();
}

auto InitiatorCore::next_wake(Clock::time_point now) const -> std::optional<Clock::time_point> {
    std::optional<Clock::time_point> wake;
    const auto at = [&](Clock::time_point t) { wake = wake ? std::min(*wake, t) : t; };
    for (const auto& [id, op] : _ops) {
        if (op.deadline != Clock::time_point::max()) {
            at(op.deadline);
        }
    }
    if (_state != State::down && (outstanding() || _state == State::hello)) {
        at(_last_heard + _config.primary_timeout);
    }
    if (_state == State::open && !outstanding()) {
        at(std::max(_last_heard, _last_sent) + _config.ping_interval);
    }
    if (_state == State::down && _reconnect_at > now && _reconnect_at != Clock::time_point::max() &&
        _route && !_stale) {
        at(_reconnect_at);
    }
    bool unsent = false;
    for (const auto& p : _parts) {
        if (!p.sent) {
            unsent = true;
            if (p.not_before > now) {
                at(p.not_before);
            }
        }
    }
    if (_state == State::open && unsent && qos_wait() > Clock::duration::zero()) {
        at(now + qos_wait());
    }
    return wake;
}

auto InitiatorCore::take_output() -> std::vector<std::vector<std::byte>> {
    return std::exchange(_out, {});
}

auto InitiatorCore::take_faults() -> std::vector<InitiatorFault> {
    return std::exchange(_faults, {});
}

auto InitiatorCore::run_completions() -> void {
    if (_running_completions) {
        return;
    }
    _running_completions = true;
    while (!_ready.empty()) {
        auto batch = std::exchange(_ready, {});
        for (auto& [done, result] : batch) {
            if (done) {
                done(result);
            }
        }
    }
    _running_completions = false;
}

}  // namespace ak::oar::blk
