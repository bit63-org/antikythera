// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/khold_initiator.hpp"

#include <algorithm>
#include <utility>

#include "common/crc32c.hpp"

namespace ak::oar::blk {

namespace {

using proto::HoldV2Opcode;
using proto::HoldV2Status;
using proto::MemberKind;

constexpr std::uint64_t qos_io_unit = 256 * 1024;
constexpr double mib = 1024.0 * 1024.0;
constexpr int read_retries = 1;
constexpr int write_retries = 2;
constexpr int suspended_backoff_factor = 4;

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto find_attachment(const proto::VolumeLayout& l, std::uint64_t id)
    -> const proto::VolumeAttachment* {
    const auto it = std::ranges::find(l.attachments, id, &proto::VolumeAttachment::attachment_id);
    return it == l.attachments.end() ? nullptr : &*it;
}

// The data members of a group, in layout order (server IDs ascending).
auto data_members(const proto::StripeGroup& g) -> std::vector<const proto::LayoutMember*> {
    std::vector<const proto::LayoutMember*> out;
    for (const auto& m : g.members) {
        if (m.kind == MemberKind::data) {
            out.push_back(&m);
        }
    }
    return out;
}

auto is_data_member(const proto::StripeGroup& g, std::uint64_t server) -> bool {
    return std::ranges::any_of(g.members, [&](const proto::LayoutMember& m) {
        return m.server_id == server && m.kind == MemberKind::data;
    });
}

}  // namespace

KholdInitiatorCore::KholdInitiatorCore(KholdInitiatorConfig config) noexcept : _config{config} {}

auto KholdInitiatorCore::capacity_bytes() const noexcept -> std::uint64_t {
    return _layout ? _layout->capacity_blocks * _layout->block_size : 0;
}

auto KholdInitiatorCore::sessions_open() const noexcept -> std::size_t {
    return static_cast<std::size_t>(std::ranges::count_if(
        _sessions, [](const auto& kv) { return kv.second.state == State::open; }));
}

auto KholdInitiatorCore::leader_of(std::size_t index) const noexcept -> std::uint64_t {
    return index < _groups.size() ? _groups[index].leader : 0;
}

auto KholdInitiatorCore::suspended() const noexcept -> bool {
    return _layout && (_layout->flags & proto::layout_flags::io_suspended) != 0;
}

auto KholdInitiatorCore::fault(InitiatorFault kind, std::uint64_t server) -> void {
    _faults.push_back(
        {.kind = kind, .server = server, .epoch = _layout ? _layout->epoch : std::uint64_t{0}});
}

// ---- layout ------------------------------------------------------------------

auto KholdInitiatorCore::set_layout(const proto::VolumeLayout& l, Clock::time_point now)
    -> std::expected<void, RouteError> {
    const bool first = !_layout;
    bool topology_changed = first;
    if (_layout) {
        const auto& old = *_layout;
        if (l.volume_id != old.volume_id) {
            return std::unexpected(RouteError::wrong_volume);
        }
        if (l.epoch < old.epoch) {
            return std::unexpected(RouteError::stale);
        }
        if (l.epoch == old.epoch) {
            return {};
        }
        // A resize only grows; the striping is fixed (re-striping is a
        // mirror migration to a new volume).
        if (l.block_size != old.block_size || l.capacity_blocks < old.capacity_blocks ||
            l.stripe_unit != old.stripe_unit || l.groups.size() != old.groups.size()) {
            return std::unexpected(RouteError::mismatch);
        }
        topology_changed = l.gateways.empty() != old.gateways.empty();
    }
    const auto* att = find_attachment(l, _config.attachment_id);
    if (att == nullptr || (_layout && att->generation != _generation)) {
        // Detached, forced off or replaced: this attachment is over.
        if (_layout) {
            _layout = l;
        }
        fence();
        run_completions();
        return {};
    }
    if (first || l.qos != _layout->qos) {
        _ios = TokenBucket{static_cast<double>(l.qos.iops), static_cast<double>(l.qos.burst_iops),
                           now};
        _mib = TokenBucket{static_cast<double>(l.qos.mib_per_s),
                           static_cast<double>(l.qos.burst_mib), now};
    }
    _layout = l;
    _generation = att->generation;
    _mode = att->mode;
    const bool was_stale = std::exchange(_stale, false);
    seed_groups();
    if (topology_changed || was_stale || suspended()) {
        drop_all(now);
    } else {
        // Sessions to servers that are no longer destinations close in
        // plan_sessions; those whose server left the layout close now.
        std::vector<std::uint64_t> gone;
        for (const auto& [server, s] : _sessions) {
            if (!endpoint_of(server)) {
                gone.push_back(server);
            }
        }
        for (const auto server : gone) {
            drop_session(_sessions.at(server), now);
        }
    }
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
    pump(now);
    run_completions();
    return {};
}

auto KholdInitiatorCore::seed_groups() -> void {
    const auto& l = *_layout;
    _groups.resize(l.groups.size());
    for (std::size_t i = 0; i < l.groups.size(); ++i) {
        const auto& lg = l.groups[i];
        Group& g = _groups[i];
        if (g.group_id != lg.group_id) {
            g = Group{.group_id = lg.group_id, .leader = 0, .term = 0, .gateway = 0};
        }
        if (g.leader == 0 || !is_data_member(lg, g.leader)) {
            const auto data = data_members(lg);  // never empty: the decoder checks
            g.leader = data.empty() ? 0 : data[i % data.size()]->server_id;
            g.term = 0;
        }
        if (!l.gateways.empty()) {
            g.gateway %= l.gateways.size();
        }
    }
}

auto KholdInitiatorCore::group_index(std::uint64_t group_id) const -> std::optional<std::size_t> {
    for (std::size_t i = 0; i < _groups.size(); ++i) {
        if (_groups[i].group_id == group_id) {
            return i;
        }
    }
    return std::nullopt;
}

auto KholdInitiatorCore::destination(std::size_t group) const -> std::uint64_t {
    const auto& l = *_layout;
    if (!l.gateways.empty()) {
        return l.gateways[(group + _groups[group].gateway) % l.gateways.size()].server_id;
    }
    return _groups[group].leader;
}

auto KholdInitiatorCore::endpoint_of(std::uint64_t server) const
    -> std::optional<std::pair<proto::StorageEndpoint, std::uint16_t>> {
    const auto& l = *_layout;
    if (!l.gateways.empty()) {
        const auto it = std::ranges::find(l.gateways, server, &proto::LayoutGateway::server_id);
        if (it == l.gateways.end()) {
            return std::nullopt;
        }
        return std::pair{it->endpoint, it->port};
    }
    for (const auto& g : l.groups) {
        for (const auto& m : g.members) {
            if (m.server_id == server) {
                return std::pair{m.endpoint, m.port};
            }
        }
    }
    return std::nullopt;
}

auto KholdInitiatorCore::rotate(Group& g, std::size_t index) -> void {
    const auto& l = *_layout;
    if (!l.gateways.empty()) {
        g.gateway = (g.gateway + 1) % l.gateways.size();
        return;
    }
    const auto data = data_members(l.groups[index]);
    if (data.empty()) {
        return;
    }
    const auto it = std::ranges::find(data, g.leader, &proto::LayoutMember::server_id);
    const std::size_t at = it == data.end() ? 0 : static_cast<std::size_t>(it - data.begin()) + 1;
    g.leader = data[at % data.size()]->server_id;
    g.term = 0;  // whoever leads next is found by its answers
}

auto KholdInitiatorCore::rotate_from(std::uint64_t server) -> void {
    if (!_layout) {
        return;
    }
    for (std::size_t i = 0; i < _groups.size(); ++i) {
        if (destination(i) == server) {
            rotate(_groups[i], i);
        }
    }
}

// ---- requests ----------------------------------------------------------------

auto KholdInitiatorCore::submit(Kind kind, std::uint64_t offset, std::uint64_t length,
                                std::span<std::byte> out, std::span<const std::byte> in,
                                BackendCompletion done, Clock::time_point now) -> void {
    const auto id = _next_op++;
    auto& op = _ops[id];
    op.kind = kind;
    op.offset = offset;
    op.length = length;
    op.out = out;
    op.in = in;
    op.done = std::move(done);
    // Held without a deadline until the layout arrives.
    op.deadline = _layout ? now + _config.request_timeout : Clock::time_point::max();
    if (_layout) {
        split(id, op);
    }
    pump(now);
    run_completions();
}

auto KholdInitiatorCore::submit_read(std::uint64_t offset, std::span<std::byte> out,
                                     BackendCompletion done, Clock::time_point now) -> void {
    submit(Kind::read, offset, out.size(), out, {}, std::move(done), now);
}

auto KholdInitiatorCore::submit_write(std::uint64_t offset, std::span<const std::byte> in,
                                      BackendCompletion done, Clock::time_point now) -> void {
    submit(Kind::write, offset, in.size(), {}, in, std::move(done), now);
}

auto KholdInitiatorCore::submit_discard(std::uint64_t offset, std::uint64_t length,
                                        BackendCompletion done, Clock::time_point now) -> void {
    submit(Kind::discard, offset, length, {}, {}, std::move(done), now);
}

auto KholdInitiatorCore::submit_write_zeroes(std::uint64_t offset, std::uint64_t length,
                                             BackendCompletion done, Clock::time_point now)
    -> void {
    submit(Kind::write_zeroes, offset, length, {}, {}, std::move(done), now);
}

auto KholdInitiatorCore::submit_flush(BackendCompletion done) -> void {
    // Every completed write is durable on its group's in-sync replicas.
    _ready.emplace_back(std::move(done), BackendResult{});
    run_completions();
}

auto KholdInitiatorCore::split(std::uint64_t id, Op& op) -> void {
    const auto& l = *_layout;
    const std::uint64_t bs = l.block_size;
    const std::uint64_t len = op.length;
    const std::uint64_t cap = l.capacity_blocks * bs;
    if (len == 0 || op.offset % bs != 0 || len % bs != 0 || op.offset > cap ||
        len > cap - op.offset) {
        complete(id, std::unexpected(BackendError::out_of_range));
        return;
    }
    if (op.kind != Kind::read && _mode == proto::AttachMode::ro) {
        complete(id, std::unexpected(BackendError::io));
        return;
    }
    if (op.kind == Kind::write) {
        op.crcs = proto::block_crcs(op.in, static_cast<std::uint32_t>(bs));
    }
    const std::uint64_t unit_blocks = l.stripe_unit / bs;
    const std::uint64_t per_part =
        std::min<std::uint64_t>(proto::max_hold_blocks, proto::max_hold_data_bytes / bs);
    const std::uint64_t first_lba = op.offset / bs;
    const std::uint64_t total = len / bs;
    for (std::uint64_t done = 0; done < total;) {
        const std::uint64_t lba = first_lba + done;
        const std::uint64_t to_boundary = unit_blocks - (lba % unit_blocks);
        const auto n = static_cast<std::uint32_t>(std::min({per_part, to_boundary, total - done}));
        _parts.push_back(
            Part{.op = id,
                 .request_id = _next_request++,
                 .kind = op.kind,
                 .group = static_cast<std::size_t>((lba / unit_blocks) % l.groups.size()),
                 .lba = lba,
                 .blocks = n,
                 .first_block = static_cast<std::size_t>(done),
                 .sent_on = 0,
                 .retries = 0,
                 .not_before = {}});
        ++op.parts_left;
        done += n;
    }
}

auto KholdInitiatorCore::header(HoldV2Opcode op) const -> proto::HoldV2Header {
    proto::HoldV2Header h;
    h.opcode = op;
    h.volume_id = _layout->volume_id;
    h.epoch = _layout->epoch;
    h.attachment_id = _config.attachment_id;
    h.generation = _generation;
    return h;
}

auto KholdInitiatorCore::blocked(std::deque<Part>::const_iterator it) const -> bool {
    if (it->kind == Kind::read) {
        return false;
    }
    const auto end = it->lba + it->blocks;
    return std::any_of(_parts.cbegin(), it, [&](const Part& p) {
        return p.kind != Kind::read && p.op != it->op && p.lba < end && it->lba < p.lba + p.blocks;
    });
}

auto KholdInitiatorCore::admit(std::uint64_t bytes, Clock::time_point now) -> bool {
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

auto KholdInitiatorCore::qos_wait() const -> Clock::duration {
    return std::max(_ios.wait(), _mib.wait());
}

auto KholdInitiatorCore::in_flight_on(const Session& s) const -> bool {
    return s.ping_out ||
           std::ranges::any_of(_parts, [&](const Part& p) { return p.sent_on == s.id; });
}

auto KholdInitiatorCore::session_of(std::uint64_t id) -> Session* {
    for (auto& [server, s] : _sessions) {
        if (s.id == id) {
            return &s;
        }
    }
    return nullptr;
}

// Opens sessions to the servers that unsent parts wait for, and closes the
// ones no group needs any more.
auto KholdInitiatorCore::plan_sessions(Clock::time_point now) -> void {
    if (!_layout || _fenced || _stale || suspended()) {
        return;
    }
    std::erase_if(_cooldown, [&](const auto& kv) { return kv.second <= now; });
    std::vector<std::uint64_t> wanted;  // destinations of waiting parts, in part order
    for (const auto& p : _parts) {
        if (p.sent_on == 0) {
            const auto d = destination(p.group);
            if (std::ranges::find(wanted, d) == wanted.end()) {
                wanted.push_back(d);
            }
        }
    }
    // Close sessions that are nobody's destination and carry nothing.
    std::vector<std::uint64_t> idle;
    for (const auto& [server, s] : _sessions) {
        bool dest = false;
        for (std::size_t i = 0; i < _groups.size() && !dest; ++i) {
            dest = destination(i) == server;
        }
        if (!dest && !in_flight_on(s)) {
            idle.push_back(server);
        }
    }
    for (const auto server : idle) {
        _sessions.erase(server);
    }
    for (const auto server : wanted) {
        if (_sessions.contains(server)) {
            continue;
        }
        if (_sessions.size() >= _config.max_sessions) {
            // Make room: close a session nothing waits for and nothing uses.
            const auto victim = std::ranges::find_if(_sessions, [&](const auto& kv) {
                return std::ranges::find(wanted, kv.first) == wanted.end() &&
                       !in_flight_on(kv.second);
            });
            if (victim == _sessions.end()) {
                break;  // the rest wait for a session to come free
            }
            _sessions.erase(victim);
        }
        const auto ep = endpoint_of(server);
        if (!ep) {
            continue;
        }
        const auto cool = _cooldown.find(server);
        _sessions.emplace(server,
                          Session{.id = _next_session++,
                                  .server = server,
                                  .endpoint = ep->first,
                                  .port = ep->second,
                                  .state = State::down,
                                  .connect_at = cool == _cooldown.end() ? now : cool->second,
                                  .last_heard = now,
                                  .last_sent = now,
                                  .ping_out = false});
    }
}

auto KholdInitiatorCore::pump(Clock::time_point now) -> void {
    if (!_layout || _fenced) {
        return;
    }
    plan_sessions(now);
    if (_stale || suspended()) {
        return;
    }
    const std::uint32_t bs = _layout->block_size;
    std::size_t in_flight = static_cast<std::size_t>(
        std::ranges::count_if(_parts, [](const Part& p) { return p.sent_on != 0; }));
    for (auto it = _parts.begin(); it != _parts.end() && in_flight < _config.max_in_flight; ++it) {
        if (it->sent_on != 0 || now < it->not_before || blocked(it)) {
            continue;
        }
        const auto dest = _sessions.find(destination(it->group));
        if (dest == _sessions.end() || dest->second.state != State::open) {
            continue;  // waits for its session; other groups go on
        }
        Session& s = dest->second;
        const bool data = it->kind == Kind::read || it->kind == Kind::write;
        if (!admit(data ? std::uint64_t{it->blocks} * bs : 0, now)) {
            break;  // keep the order: nothing overtakes a request held by QoS
        }
        const Op& op = _ops.at(it->op);
        HoldV2Opcode code = HoldV2Opcode::read;
        switch (it->kind) {
            case Kind::read:
                code = HoldV2Opcode::read;
                break;
            case Kind::write:
                code = HoldV2Opcode::write;
                break;
            case Kind::discard:
                code = HoldV2Opcode::discard;
                break;
            case Kind::write_zeroes:
                code = HoldV2Opcode::write_zeroes;
                break;
        }
        auto h = header(code);
        h.request_id = it->request_id;
        h.lba = it->lba;
        h.blocks = it->blocks;
        h.group_id = _groups[it->group].group_id;
        h.term = _groups[it->group].term;
        proto::HoldV2Payload payload;
        if (it->kind == Kind::write) {
            payload = proto::BlockData{
                .block_size = bs,
                .crcs = std::span{op.crcs}.subspan(
                    it->first_block * proto::hold_block_crc_size,
                    std::size_t{it->blocks} * proto::hold_block_crc_size),
                .data = op.in.subspan(it->first_block * bs, std::size_t{it->blocks} * bs)};
        }
        auto frame = proto::encode_hold_v2_frame({.header = h, .payload = payload});
        if (!frame) {
            complete(it->op, std::unexpected(BackendError::io));
            return;  // `it` is gone; the next pump continues
        }
        if (!in_flight_on(s)) {
            s.last_heard = now;  // waiting starts now
        }
        _out.push_back({.session = s.id, .frame = std::move(*frame)});
        it->sent_on = s.id;
        s.last_sent = now;
        ++in_flight;
    }
}

// ---- sessions ----------------------------------------------------------------

auto KholdInitiatorCore::targets(Clock::time_point now) const -> std::vector<HoldTarget> {
    std::vector<HoldTarget> out;
    if (!_layout || _fenced || _stale || suspended()) {
        return out;
    }
    for (const auto& [server, s] : _sessions) {
        if (s.state == State::down && now < s.connect_at) {
            continue;
        }
        out.push_back(
            {.server_id = server, .endpoint = s.endpoint, .port = s.port, .session = s.id});
    }
    return out;
}

auto KholdInitiatorCore::send_hello(Session& s) -> void {
    auto h = header(HoldV2Opcode::hello);
    h.request_id = _next_request++;
    auto frame = proto::encode_hold_v2_frame(
        {.header = h, .payload = proto::HoldV2Hello{.role = proto::HoldV2Role::initiator}});
    if (frame) {
        _out.push_back({.session = s.id, .frame = std::move(*frame)});
    }
}

auto KholdInitiatorCore::connected(std::uint64_t session, Clock::time_point now) -> void {
    Session* s = session_of(session);
    if (s == nullptr || s->state != State::down || !_layout || _fenced) {
        return;
    }
    s->state = State::hello;
    s->last_heard = now;
    s->last_sent = now;
    s->ping_out = false;
    send_hello(*s);
    run_completions();
}

auto KholdInitiatorCore::disconnected(std::uint64_t session, Clock::time_point now) -> void {
    Session* s = session_of(session);
    if (s == nullptr) {
        return;
    }
    // A refused or lost connection: whatever it led is tried elsewhere.
    const auto server = s->server;
    drop_session(*s, now);
    rotate_from(server);
    pump(now);
    run_completions();
}

auto KholdInitiatorCore::drop_session(Session& s, Clock::time_point now) -> void {
    for (auto& p : _parts) {
        if (p.sent_on == s.id) {
            p.sent_on = 0;  // resent, in order, on whichever session leads it next
        }
    }
    std::erase_if(_out, [&](const SessionFrame& f) { return f.session == s.id; });
    _cooldown[s.server] = now + _config.retry_backoff;
    _sessions.erase(s.server);  // `s` is gone; plan_sessions opens a new one if needed
}

auto KholdInitiatorCore::drop_all(Clock::time_point now) -> void {
    while (!_sessions.empty()) {
        drop_session(_sessions.begin()->second, now);
    }
    _cooldown.clear();  // nothing failed: the next sessions open at once
}

auto KholdInitiatorCore::on_frame(std::uint64_t session, const proto::HoldV2Frame& f,
                                  Clock::time_point now) -> void {
    Session* s = session_of(session);
    if (s == nullptr || s->state == State::down || !proto::is_response(f.header) || !_layout) {
        return;
    }
    s->last_heard = now;
    switch (f.header.opcode) {
        case HoldV2Opcode::hello_ok:
            on_hello(*s, f, now);
            break;
        case HoldV2Opcode::redirect:
            on_redirect(*s, f, now);
            break;
        case HoldV2Opcode::ping:
            s->ping_out = false;
            break;
        case HoldV2Opcode::read:
        case HoldV2Opcode::write:
        case HoldV2Opcode::discard:
        case HoldV2Opcode::write_zeroes: {
            if (s->state != State::open) {
                break;
            }
            const auto id = s->id;
            const auto it = std::ranges::find_if(_parts, [&](const Part& p) {
                return p.sent_on == id && p.request_id == f.header.request_id;
            });
            if (it != _parts.end()) {
                on_reply(it, *s, f, now);
            }
            break;
        }
        default:
            break;
    }
    pump(now);
    run_completions();
}

auto KholdInitiatorCore::on_hello(Session& s, const proto::HoldV2Frame& f, Clock::time_point now)
    -> void {
    if (s.state != State::hello) {
        return;
    }
    switch (f.header.status) {
        case HoldV2Status::ok: {
            const auto* ok = std::get_if<proto::HoldV2HelloOk>(&f.payload);
            const auto& l = *_layout;
            if (ok == nullptr || ok->block_size != l.block_size ||
                ok->stripe_unit != l.stripe_unit || ok->stripe_width != l.groups.size()) {
                // Not the volume the layout describes: try again later.
                drop_session(s, now);
                return;
            }
            s.state = State::open;
            return;
        }
        case HoldV2Status::stale_epoch:
            if (f.header.epoch > _layout->epoch) {
                _stale = true;  // helm will bring the newer layout
                drop_all(now);
            } else {
                drop_session(s, now);  // the node is behind: again after a backoff
            }
            return;
        case HoldV2Status::fenced:
            fence();
            return;
        default:
            drop_session(s, now);
            return;
    }
}

auto KholdInitiatorCore::resend_group_on(std::size_t group, const Session& s,
                                         Clock::time_point not_before) -> void {
    for (auto& p : _parts) {
        if (p.group == group && p.sent_on == s.id) {
            p.sent_on = 0;
            p.not_before = not_before;
        }
    }
}

auto KholdInitiatorCore::on_redirect(Session& s, const proto::HoldV2Frame& f, Clock::time_point now)
    -> void {
    const auto index = group_index(f.header.group_id);
    if (!index) {
        return;  // not a group of this layout
    }
    Group& g = _groups[*index];
    const auto* r = std::get_if<proto::HoldV2Redirect>(&f.payload);
    const auto& lg = _layout->groups[*index];
    const bool split_layout = !_layout->gateways.empty();
    Clock::time_point not_before = now;
    if (split_layout) {
        // The gateway forwards to the leader itself; a redirect from it
        // means the group is between leaders.
        not_before = now + _config.retry_backoff;
    } else if (r != nullptr && r->leader_server != 0 && is_data_member(lg, r->leader_server) &&
               r->leader_term >= g.term) {
        g.leader = r->leader_server;
        g.term = r->leader_term;
    } else if (r != nullptr && r->leader_server != 0 && r->leader_term < g.term &&
               is_data_member(lg, r->leader_server)) {
        // An older view than ours: keep our leader, resend there.
        if (g.leader == s.server) {
            rotate(g, *index);
        }
    } else {
        // Leader unknown, or a server outside the group's layout: never
        // followed. Try the next member once an election had time.
        if (g.leader == s.server) {
            rotate(g, *index);
        }
        not_before = now + _config.retry_backoff;
    }
    resend_group_on(*index, s, not_before);
}

auto KholdInitiatorCore::on_reply(std::deque<Part>::iterator it, Session& s,
                                  const proto::HoldV2Frame& f, Clock::time_point now) -> void {
    const std::uint32_t bs = _layout->block_size;
    Group& g = _groups[it->group];
    switch (f.header.status) {
        case HoldV2Status::ok: {
            if (_layout->gateways.empty() && f.header.term > g.term && g.leader == s.server) {
                g.term = f.header.term;
            }
            if (it->kind != Kind::read) {
                part_done(it);
                return;
            }
            const auto* d = std::get_if<proto::BlockData>(&f.payload);
            bool good = d != nullptr && d->block_size == bs && f.header.blocks == it->blocks &&
                        f.header.lba == it->lba && d->data.size() == std::size_t{it->blocks} * bs;
            for (std::size_t b = 0; good && b < it->blocks; ++b) {
                const auto block = d->data.subspan(b * bs, bs);
                const auto crc = proto::block_crc(*d, b);
                good = crc32c::of(block) == crc || (crc == 0 && all_zero(block));
            }
            if (!good) {
                fault(InitiatorFault::checksum, s.server);
                if (it->retries < read_retries) {
                    ++it->retries;
                    it->sent_on = 0;
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
        case HoldV2Status::not_leader:  // carried by a redirect; not a block reply
        case HoldV2Status::unknown_group:
            if (_layout->gateways.empty() && g.leader == s.server) {
                rotate(g, it->group);
            }
            it->sent_on = 0;
            it->not_before = now + _config.retry_backoff;
            return;
        case HoldV2Status::throttled:
        case HoldV2Status::repairing:
            it->sent_on = 0;
            it->not_before = now + _config.retry_backoff;
            return;
        case HoldV2Status::io_suspended:
            it->sent_on = 0;
            it->not_before = now + (_config.retry_backoff * suspended_backoff_factor);
            return;
        case HoldV2Status::checksum:
            if (it->retries < write_retries) {
                ++it->retries;
                it->sent_on = 0;
            } else {
                complete(it->op, std::unexpected(BackendError::io));
            }
            return;
        case HoldV2Status::stale_epoch:
            if (f.header.epoch > _layout->epoch) {
                _stale = true;  // helm will bring the newer layout
                drop_all(now);
            } else {
                it->sent_on = 0;  // sent before the layout moved on: again, at its epoch
            }
            return;
        case HoldV2Status::fenced:
            fence();
            return;
        case HoldV2Status::range:
            complete(it->op, std::unexpected(BackendError::out_of_range));
            return;
        case HoldV2Status::io_error:
            fault(InitiatorFault::media_error, s.server);
            complete(it->op, std::unexpected(BackendError::io));
            return;
        default:  // no_space, read_only, not_hydrated, bad_request, unknown_volume
            complete(it->op, std::unexpected(BackendError::io));
            return;
    }
}

auto KholdInitiatorCore::part_done(std::deque<Part>::iterator it) -> void {
    const auto id = it->op;
    _parts.erase(it);
    auto op = _ops.find(id);
    if (op != _ops.end() && --op->second.parts_left == 0) {
        complete(id, {});
    }
}

auto KholdInitiatorCore::complete(std::uint64_t id, BackendResult r) -> void {
    const auto it = _ops.find(id);
    if (it == _ops.end()) {
        return;
    }
    _ready.emplace_back(std::move(it->second.done), r);
    _ops.erase(it);
    std::erase_if(_parts, [id](const Part& p) { return p.op == id; });
}

auto KholdInitiatorCore::fail_all(BackendError e) -> void {
    std::vector<std::uint64_t> ids;
    for (const auto& [id, op] : _ops) {
        ids.push_back(id);
    }
    for (const auto id : ids) {
        complete(id, std::unexpected(e));
    }
}

auto KholdInitiatorCore::fence() -> void {
    if (!_fenced) {
        fault(InitiatorFault::fenced, 0);
    }
    _fenced = true;
    fail_all(BackendError::io);
    _sessions.clear();
    _out.clear();
}

// ---- time --------------------------------------------------------------------

auto KholdInitiatorCore::tick(Clock::time_point now) -> void {
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
    // Sessions that went quiet with something outstanding.
    std::vector<std::uint64_t> lost;
    for (const auto& [server, s] : _sessions) {
        if (s.state != State::down && (in_flight_on(s) || s.state == State::hello) &&
            now - s.last_heard >= _config.leader_timeout) {
            lost.push_back(server);
        }
    }
    for (const auto server : lost) {
        fault(InitiatorFault::primary_timeout, server);
        drop_session(_sessions.at(server), now);
        rotate_from(server);
    }
    if (_layout && !_fenced) {
        for (auto& [server, s] : _sessions) {
            if (s.state == State::open && !in_flight_on(s) &&
                now - std::max(s.last_heard, s.last_sent) >= _config.ping_interval) {
                auto h = header(HoldV2Opcode::ping);
                h.request_id = _next_request++;
                if (auto frame =
                        proto::encode_hold_v2_frame({.header = h, .payload = std::monostate{}})) {
                    _out.push_back({.session = s.id, .frame = std::move(*frame)});
                    s.ping_out = true;
                    s.last_heard = now;
                    s.last_sent = now;
                }
            }
        }
    }
    pump(now);
    run_completions();
}

auto KholdInitiatorCore::next_wake(Clock::time_point now) const
    -> std::optional<Clock::time_point> {
    std::optional<Clock::time_point> wake;
    const auto at = [&](Clock::time_point t) { wake = wake ? std::min(*wake, t) : t; };
    for (const auto& [id, op] : _ops) {
        if (op.deadline != Clock::time_point::max()) {
            at(op.deadline);
        }
    }
    for (const auto& [server, s] : _sessions) {
        if (s.state != State::down && (in_flight_on(s) || s.state == State::hello)) {
            at(s.last_heard + _config.leader_timeout);
        }
        if (s.state == State::open && !in_flight_on(s)) {
            at(std::max(s.last_heard, s.last_sent) + _config.ping_interval);
        }
        if (s.state == State::down && s.connect_at > now && !_stale) {
            at(s.connect_at);
        }
    }
    bool unsent = false;
    for (const auto& p : _parts) {
        if (p.sent_on == 0) {
            unsent = true;
            if (p.not_before > now) {
                at(p.not_before);
            }
        }
    }
    if (unsent) {
        // A server cooling down after a failure gets its session then.
        for (const auto& [server, t] : _cooldown) {
            if (t > now) {
                at(t);
            }
        }
        if (qos_wait() > Clock::duration::zero()) {
            at(now + qos_wait());
        }
    }
    return wake;
}

auto KholdInitiatorCore::take_output() -> std::vector<SessionFrame> {
    return std::exchange(_out, {});
}

auto KholdInitiatorCore::take_faults() -> std::vector<FaultEvent> {
    return std::exchange(_faults, {});
}

auto KholdInitiatorCore::run_completions() -> void {
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
