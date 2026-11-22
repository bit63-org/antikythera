// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/server/server.hpp"

#include <algorithm>
#include <utility>

#include "common/crc32c.hpp"

namespace ak::hold {

namespace {

using proto::HoldOpcode;
using proto::HoldStatus;

auto find_member(const proto::ReplicaConfig& c, std::uint64_t server_id)
    -> const proto::ReplicaMember* {
    const auto it = std::ranges::find(c.members, server_id, &proto::ReplicaMember::server_id);
    return it == c.members.end() ? nullptr : &*it;
}

auto find_attachment(const proto::ReplicaConfig& c, std::uint64_t attachment_id)
    -> const proto::VolumeAttachment* {
    const auto it =
        std::ranges::find(c.attachments, attachment_id, &proto::VolumeAttachment::attachment_id);
    return it == c.attachments.end() ? nullptr : &*it;
}

auto is_plain_write(const proto::HoldHeader& h) noexcept -> bool {
    return h.opcode == HoldOpcode::write && (h.flags & proto::hold_flags::hydrate) == 0;
}

auto status_of(store::StoreError e) noexcept -> HoldStatus {
    switch (e) {
        case store::StoreError::bad_request:
            return HoldStatus::range;
        case store::StoreError::bad_crc:
            return HoldStatus::checksum;
        case store::StoreError::not_hydrated:
            return HoldStatus::not_hydrated;
        case store::StoreError::ring_full:
            return HoldStatus::io_suspended;
        default:
            return HoldStatus::io_error;
    }
}

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto overlaps(const proto::HoldHeader& a, const proto::HoldHeader& b) noexcept -> bool {
    return a.lba < b.lba + b.blocks && b.lba < a.lba + a.blocks;
}

// Members whose REPL_ACK a write waits for, and that can repair a read.
auto in_sync(proto::ReplicaRole r) noexcept -> bool {
    return r == proto::ReplicaRole::secondary || r == proto::ReplicaRole::leaving;
}

auto crc_bytes(std::span<const std::uint32_t> crcs) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(crcs.size() * proto::hold_block_crc_size);
    wire::Writer w{out};
    for (const auto c : crcs) {
        w.le32(c);
    }
    return out;
}

}  // namespace

auto to_string(ConfigError e) noexcept -> const char* {
    switch (e) {
        case ConfigError::wrong_server:
            return "wrong_server";
        case ConfigError::stale:
            return "stale";
        case ConfigError::mismatch:
            return "mismatch";
        case ConfigError::store:
            return "store";
    }
    return "unknown";
}

HoldServer::HoldServer(store::FileLayer& files, ServerConfig config, SessionSink& sink)
    : _files{&files}, _config{std::move(config)}, _sink{&sink} {}

// ---- volumes ---------------------------------------------------------------

auto HoldServer::ensure_replica(Volume& v, const proto::ReplicaMember& me)
    -> std::expected<void, ConfigError> {
    const auto& c = v.config;
    if (v.store && v.store->meta().replica_gen == me.replica_gen) {
        return {};
    }
    v.store.reset();
    const auto dir = _config.data_dir / store::replica_dir_name(c.volume_id, me.replica_gen);
    auto s = _files->exists(dir) ? store::ReplicaStore::open(*_files, dir)
                                 : store::ReplicaStore::create(
                                       *_files, dir,
                                       store::ReplicaMeta{.volume_id = c.volume_id,
                                                          .lineage_id = c.lineage_id,
                                                          .replica_gen = me.replica_gen,
                                                          .epoch = c.epoch,
                                                          .role = me.role,
                                                          .capacity_blocks = c.capacity_blocks,
                                                          .block_size = c.block_size,
                                                          .chunk_shift = _config.chunk_shift,
                                                          .source = c.source,
                                                          .header_seq = 1});
    if (!s) {
        return std::unexpected(ConfigError::store);
    }
    const auto& m = (*s)->meta();
    if (m.volume_id != c.volume_id || m.lineage_id != c.lineage_id ||
        m.block_size != c.block_size || m.capacity_blocks != c.capacity_blocks) {
        return std::unexpected(ConfigError::mismatch);
    }
    if (m.epoch > c.epoch) {
        return std::unexpected(ConfigError::stale);
    }
    v.store = std::move(*s);
    return {};
}

auto HoldServer::apply_config(const proto::ReplicaConfig& c, Clock::time_point now)
    -> std::expected<void, ConfigError> {
    _now = now;
    if (c.server_id != _config.server_id) {
        return std::unexpected(ConfigError::wrong_server);
    }
    auto found = _volumes.find(c.volume_id);
    if (found != _volumes.end()) {
        const auto& old = found->second.config;
        if (c.epoch < old.epoch) {
            return std::unexpected(ConfigError::stale);
        }
        if (c.epoch == old.epoch) {
            return {};
        }
        // Growing a volume is a later task (design "Resize").
        if (c.lineage_id != old.lineage_id || c.block_size != old.block_size ||
            c.capacity_blocks != old.capacity_blocks) {
            return std::unexpected(ConfigError::mismatch);
        }
    }
    const bool was_primary = found != _volumes.end() && is_primary(found->second);
    const std::uint64_t old_last = was_primary ? found->second.store->last_seq() : 0;
    // Build the new state aside, so a refused config changes nothing.
    Volume next;
    if (found != _volumes.end()) {
        auto& old = found->second;
        next.store = std::move(old.store);
        next.queue = std::move(old.queue);
        next.parked = std::move(old.parked);
        next.limiter = old.limiter;
        next.links = std::move(old.links);
        next.replicating = std::move(old.replicating);
        next.repairs = std::move(old.repairs);
        next.next_request = old.next_request;
        next.committed = old.committed;
        next.seq_floor = old.seq_floor;
        next.reconcile = std::move(old.reconcile);
        next.lease_asked = old.lease_asked;
        next.lease_until = old.lease_until;
    }
    next.heard = now;  // a new epoch: the primary gets primary_timeout to speak
    next.config = c;
    const auto restore = [&] {
        if (found != _volumes.end()) {
            auto& old = found->second;
            old.store = std::move(next.store);
            old.queue = std::move(next.queue);
            old.parked = std::move(next.parked);
            old.links = std::move(next.links);
            old.replicating = std::move(next.replicating);
            old.repairs = std::move(next.repairs);
            old.reconcile = std::move(next.reconcile);
        }
    };
    if (const auto* me = find_member(c, _config.server_id); me != nullptr) {
        if (auto r = ensure_replica(next, *me); !r) {
            restore();
            return r;
        }
        if (next.store->meta().epoch < c.epoch || next.store->meta().role != me->role) {
            if (!next.store->set_epoch(c.epoch, me->role)) {
                next.store.reset();
                restore();
                return std::unexpected(ConfigError::store);
            }
        }
    } else {
        next.store.reset();  // no longer a member: the replica stays until deleted
    }
    if (found == _volumes.end() || found->second.config.qos != c.qos) {
        next.limiter = VolumeLimiter{c.qos, now};
    }
    // A lone primary acknowledged every write it holds (or never did).
    if (next.store && single_replica_primary(next)) {
        next.store->set_commit(next.store->last_seq());
    }
    auto& v = _volumes.insert_or_assign(c.volume_id, std::move(next)).first->second;
    if (is_primary(v)) {
        if (!was_primary) {
            v.lease_asked.reset();
            v.lease_until = {};
            if (!single_replica_primary(v)) {
                start_reconcile(v, now);
            } else {
                v.committed = v.store->last_seq();
            }
        }
        sync_links(v, now);  // members added, removed or moved
        advance(v);          // a removed member no longer holds writes up
        if (v.reconcile) {
            finish_reconcile(v);  // a removed member no longer owes INTENTS
        }
    } else {
        abandon(v);
        if (was_primary) {
            _reports.emplace_back(proto::DemotionConfirmed{
                .volume_id = c.volume_id, .epoch = c.epoch, .last_seq = old_last, .slot = 0});
        }
    }
    return {};
}

auto HoldServer::single_replica_primary(const Volume& v) const -> bool {
    const auto* p = proto::primary_member(v.config);
    return v.config.members.size() == 1 && p != nullptr && p->server_id == _config.server_id;
}

auto HoldServer::is_primary(const Volume& v) const -> bool {
    const auto* p = proto::primary_member(v.config);
    return v.store && p != nullptr && p->server_id == _config.server_id;
}

auto HoldServer::epoch(std::uint64_t volume_id) const -> std::optional<std::uint64_t> {
    const auto it = _volumes.find(volume_id);
    if (it == _volumes.end()) {
        return std::nullopt;
    }
    return it->second.config.epoch;
}

auto HoldServer::replica(std::uint64_t volume_id) -> store::ReplicaStore* {
    const auto it = _volumes.find(volume_id);
    return it == _volumes.end() ? nullptr : it->second.store.get();
}

auto HoldServer::queued(std::uint64_t volume_id) const -> std::size_t {
    const auto it = _volumes.find(volume_id);
    return it == _volumes.end() ? 0 : it->second.queue.size();
}

auto HoldServer::replicating(std::uint64_t volume_id) const -> std::size_t {
    const auto it = _volumes.find(volume_id);
    return it == _volumes.end() ? 0 : it->second.replicating.size();
}

// ---- sessions --------------------------------------------------------------

auto HoldServer::open_session(std::uint64_t peer_server_id) -> SessionId {
    const SessionId id = _next_session++;
    _sessions.emplace(id, Session{.peer = peer_server_id});
    return id;
}

auto HoldServer::close_session(SessionId id) -> void {
    _sessions.erase(id);
    for (auto& [vid, v] : _volumes) {
        std::erase_if(v.queue, [id](const Request& r) { return r.session == id; });
        std::erase_if(v.parked, [id](const Request& r) { return r.session == id; });
        for (auto& [sid, l] : v.links) {
            if (l.session != id) {
                continue;
            }
            l.state = Link::State::down;
            l.session = 0;
            l.backoff = true;
            for (auto it = v.repairs.begin(); it != v.repairs.end();) {
                if (it->second.member == sid) {
                    auto rep = std::move(it->second);
                    it = v.repairs.erase(it);
                    finish_repair(v, rep, nullptr);
                } else {
                    ++it;
                }
            }
        }
    }
}

auto HoldServer::connected(SessionId id, Clock::time_point now) -> void {
    static_cast<void>(now);
    const auto sit = _sessions.find(id);
    if (sit == _sessions.end() || !sit->second.outbound) {
        return;
    }
    const auto vit = _volumes.find(sit->second.volume_id);
    if (vit == _volumes.end()) {
        return;
    }
    Volume& v = vit->second;
    const auto lit = v.links.find(sit->second.peer);
    const auto* me = find_member(v.config, _config.server_id);
    if (lit == v.links.end() || lit->second.session != id || me == nullptr) {
        return;
    }
    lit->second.state = Link::State::hello;
    proto::HoldHeader h;
    h.opcode = HoldOpcode::hello;
    h.request_id = v.next_request++;
    h.volume_id = v.config.volume_id;
    h.epoch = v.config.epoch;
    send_link(v, lit->second,
              {.header = h,
               .payload = proto::HoldHello{.role = proto::HoldPeerRole::peer,
                                           .replica_gen = me->replica_gen}});
}

auto HoldServer::check(const Session& s, const proto::HoldHeader& h) const -> Verdict {
    const bool initiator = s.role == proto::HoldPeerRole::initiator;
    if (!s.open || h.volume_id != s.volume_id || h.attachment_id != s.attachment_id ||
        (initiator && h.generation != s.generation)) {
        return {.status = HoldStatus::bad_request};
    }
    const auto it = _volumes.find(h.volume_id);
    if (it == _volumes.end()) {
        return {.status = HoldStatus::unknown_volume};
    }
    const Volume& v = it->second;
    const auto& c = v.config;
    if (h.epoch < c.epoch) {
        return {.status = HoldStatus::stale_epoch};
    }
    if (h.epoch > c.epoch) {
        return {.status = HoldStatus::not_primary, .redirect = true};
    }
    if (!initiator) {
        const auto* peer = find_member(c, s.peer);
        if (peer == nullptr || peer->replica_gen != s.generation) {
            return {.status = HoldStatus::fenced};
        }
        if (find_member(c, _config.server_id) == nullptr) {
            return {.status = HoldStatus::unknown_volume};
        }
        if (h.opcode == HoldOpcode::hello || h.opcode == HoldOpcode::ping) {
            return {};
        }
        // Replication and repair reads come from this epoch's primary only.
        const auto* primary = proto::primary_member(c);
        if (primary == nullptr || primary->server_id != s.peer ||
            primary->server_id == _config.server_id) {
            return {.status = HoldStatus::not_primary};
        }
        if (!v.store) {
            return {.status = HoldStatus::io_error};
        }
        if (proto::is_block_opcode(h.opcode) && h.lba + h.blocks > c.capacity_blocks) {
            return {.status = HoldStatus::range};
        }
        return {};
    }
    const auto* att = find_attachment(c, s.attachment_id);
    if (att == nullptr || att->generation != s.generation || att->server_id != s.peer) {
        return {.status = HoldStatus::fenced};
    }
    if ((c.flags & proto::replica_flags::io_suspended) != 0) {
        return {.status = HoldStatus::io_suspended};
    }
    const auto* primary = proto::primary_member(c);
    if (primary == nullptr || primary->server_id != _config.server_id) {
        return {.status = HoldStatus::not_primary, .redirect = true};
    }
    if (!v.store) {
        return {.status = HoldStatus::io_error};
    }
    if (proto::is_block_opcode(h.opcode) && h.lba + h.blocks > c.capacity_blocks) {
        return {.status = HoldStatus::range};
    }
    if (h.opcode == HoldOpcode::write && att->mode == proto::AttachMode::ro) {
        return {.status = HoldStatus::read_only};
    }
    return {};
}

auto HoldServer::check_hello(const Session& s, const proto::HoldHeader& h,
                             const proto::HoldHello& hello) const -> Verdict {
    if (s.open) {
        return {.status = HoldStatus::bad_request};
    }
    const bool initiator = hello.role == proto::HoldPeerRole::initiator;
    if (initiator != (h.attachment_id != 0) || initiator != (hello.replica_gen == 0)) {
        return {.status = HoldStatus::bad_request};
    }
    Session as = s;
    as.open = true;
    as.role = hello.role;
    as.volume_id = h.volume_id;
    as.attachment_id = h.attachment_id;
    as.generation = initiator ? h.generation : hello.replica_gen;
    return check(as, h);
}

auto HoldServer::hello(SessionId id, Session& s, const proto::HoldFrame& f) -> void {
    const auto* hello = std::get_if<proto::HoldHello>(&f.payload);
    if (hello == nullptr) {
        respond(id, f.header, HoldStatus::bad_request);
        return;
    }
    const auto verdict = check_hello(s, f.header, *hello);
    if (verdict.status != HoldStatus::ok) {
        refuse(id, f.header, verdict);
        return;
    }
    s.open = true;
    s.role = hello->role;
    s.volume_id = f.header.volume_id;
    s.attachment_id = f.header.attachment_id;
    s.generation =
        s.role == proto::HoldPeerRole::initiator ? f.header.generation : hello->replica_gen;
    const Volume& v = _volumes.at(s.volume_id);
    respond(id, f.header, HoldStatus::ok,
            proto::HoldHelloOk{.block_size = v.config.block_size,
                               .capacity_blocks = v.config.capacity_blocks,
                               .commit_seq = v.store ? v.store->commit_seq() : 0});
}

auto HoldServer::on_frame(SessionId id, const proto::HoldFrame& f, Clock::time_point now) -> void {
    _now = now;
    const auto sit = _sessions.find(id);
    if (sit == _sessions.end()) {
        return;
    }
    if (sit->second.outbound) {
        on_link_frame(sit->second, id, f, now);
        return;
    }
    if (proto::is_response(f.header)) {
        return;  // nothing is asked of a peer over an inbound session
    }
    ++_stats.requests;
    Session& s = sit->second;
    const auto& h = f.header;
    if (h.opcode == HoldOpcode::hello) {
        hello(id, s, f);
        return;
    }
    const auto verdict = check(s, h);
    if (verdict.status != HoldStatus::ok) {
        if (const auto* w = std::get_if<proto::ReplWrite>(&f.payload); w != nullptr) {
            respond(id, h, verdict.status, proto::ReplAck{.seq = w->seq});
        } else {
            refuse(id, h, verdict);
        }
        return;
    }
    Volume& v = _volumes.at(h.volume_id);
    const bool initiator = s.role == proto::HoldPeerRole::initiator;
    if (const auto* p = proto::primary_member(v.config);
        !initiator && p != nullptr && p->server_id == s.peer) {
        v.heard = now;
    }
    Request r{
        .session = id, .header = h, .data = {}, .crcs = {}, .block_size = v.config.block_size};
    switch (h.opcode) {
        case HoldOpcode::ping:
            if (const auto* p = std::get_if<proto::HoldPing>(&f.payload);
                p != nullptr && !initiator && v.store) {
                v.store->set_commit(p->commit_seq);  // the primary's commit point
            }
            respond(id, h, HoldStatus::ok,
                    proto::HoldPing{.commit_seq = v.store ? v.store->commit_seq() : 0});
            return;
        case HoldOpcode::read:  // from a peer: the primary repairing a block
            break;
        case HoldOpcode::intents: {  // from a peer: a new primary reconciling
            if (initiator || !v.store) {
                respond(id, h, HoldStatus::bad_request);
                return;
            }
            proto::HoldIntents out;
            for (const auto& i : v.store->intents()) {
                out.entries.push_back({.seq = i.seq, .lba = i.lba, .blocks = i.blocks});
            }
            respond(id, h, HoldStatus::ok, std::move(out));
            return;
        }
        case HoldOpcode::flush:
            if (!initiator) {
                respond(id, h, HoldStatus::bad_request);
                return;
            }
            break;
        case HoldOpcode::write: {
            const auto* d = std::get_if<proto::BlockData>(&f.payload);
            if (!initiator || d == nullptr || d->block_size != v.config.block_size) {
                respond(id, h, HoldStatus::bad_request);
                return;
            }
            if (proto::first_bad_block(*d) != h.blocks) {
                ++_stats.checksum;
                respond(id, h, HoldStatus::checksum);
                return;
            }
            r.data.assign(d->data.begin(), d->data.end());
            r.crcs.resize(h.blocks);
            for (std::size_t i = 0; i < h.blocks; ++i) {
                r.crcs[i] = proto::block_crc(*d, i);
            }
            break;
        }
        case HoldOpcode::repl_write: {
            const auto* w = std::get_if<proto::ReplWrite>(&f.payload);
            if (initiator || w == nullptr || w->op != proto::ReplOp::write || w->seq == 0 ||
                w->data.block_size != v.config.block_size) {
                respond(id, h, HoldStatus::bad_request,
                        proto::ReplAck{.seq = w != nullptr ? w->seq : 0});
                return;
            }
            if (proto::first_bad_block(w->data) != h.blocks) {
                ++_stats.checksum;
                respond(id, h, HoldStatus::checksum, proto::ReplAck{.seq = w->seq});
                return;
            }
            r.data.assign(w->data.data.begin(), w->data.data.end());
            r.crcs.resize(h.blocks);
            for (std::size_t i = 0; i < h.blocks; ++i) {
                r.crcs[i] = proto::block_crc(w->data, i);
            }
            r.seq = w->seq;
            r.commit_seq = w->commit_seq;
            break;
        }
        default:  // write_zeroes, discard and the replication opcodes come later
            respond(id, h, HoldStatus::bad_request);
            return;
    }
    if (v.queue.size() >= _config.max_queue) {
        ++_stats.throttled;
        respond(id, h, HoldStatus::throttled);
        return;
    }
    v.queue.push_back(std::move(r));
}

// ---- serving ---------------------------------------------------------------

auto HoldServer::run(Clock::time_point now) -> void {
    _now = now;
    if (_volumes.empty()) {
        return;
    }
    std::vector<Volume*> order;
    order.reserve(_volumes.size());
    for (auto& [id, v] : _volumes) {
        order.push_back(&v);
    }
    std::ranges::rotate(order, order.begin() + static_cast<std::ptrdiff_t>(_rr % order.size()));
    ++_rr;
    for (auto* v : order) {
        v->held = false;
        if (is_primary(*v)) {
            sync_links(*v, now);
        }
        watch(*v, now);
    }
    for (;;) {
        std::size_t progress = 0;
        for (auto* v : order) {
            progress += serve(*v, _config.quantum, now);
        }
        if (progress == 0) {
            return;
        }
    }
}

auto HoldServer::serve(Volume& v, std::size_t budget, Clock::time_point now) -> std::size_t {
    std::size_t served = 0;
    std::vector<Request> batch;
    std::size_t batch_bytes = 0;
    const auto flush_batch = [&] {
        if (!batch.empty()) {
            commit(v, batch);
            batch_bytes = 0;
        }
    };
    if (v.reconcile) {
        v.held = !v.queue.empty();  // until every member has answered INTENTS
        return 0;
    }
    while (served < budget && !v.queue.empty()) {
        Request& r = v.queue.front();
        const auto sit = _sessions.find(r.session);
        if (r.session != 0 && sit == _sessions.end()) {
            v.queue.pop_front();
            continue;
        }
        if (r.session == 0 && !is_primary(v)) {
            v.queue.pop_front();  // a reconcile write of a role since lost
            continue;
        }
        if (const auto verdict = r.session == 0 ? Verdict{} : check(sit->second, r.header);
            verdict.status != HoldStatus::ok) {
            if (r.header.opcode == HoldOpcode::repl_write) {
                respond(r.session, r.header, verdict.status, proto::ReplAck{.seq = r.seq});
            } else {
                refuse(r.session, r.header, verdict);
            }
            v.queue.pop_front();
            ++served;
            continue;
        }
        const bool repl = r.header.opcode == HoldOpcode::repl_write;
        const bool plain = is_plain_write(r.header) || repl;
        const std::uint64_t bytes = r.header.opcode == HoldOpcode::flush
                                        ? 0
                                        : std::uint64_t{r.header.blocks} * r.block_size;
        if (!plain || batch.size() >= _config.max_batch_writes ||
            batch_bytes + bytes > _config.max_batch_bytes) {
            flush_batch();  // order: what came before runs first
        }
        if (r.header.opcode == HoldOpcode::read && held_back(v, r, now)) {
            v.parked.push_back(std::move(r));  // later requests go on without it
            v.queue.pop_front();
            continue;
        }
        if (held_back(v, r, now) ||
            (plain && !repl && !v.links.empty() &&
             v.replicating.size() + batch.size() >= _config.max_replicating)) {
            flush_batch();
            v.held = true;  // until a member answers
            break;
        }
        // The primary already shaped what it replicates, and its own
        // reconcile writes are not the guest's.
        if (bytes != 0 && !repl && r.session != 0 && !v.limiter.admit(bytes, now)) {
            break;
        }
        Request taken = std::move(r);
        v.queue.pop_front();
        ++served;
        if (plain) {
            batch_bytes += bytes;
            batch.push_back(std::move(taken));
        } else {
            execute(v, taken);
        }
    }
    flush_batch();
    return served;
}

auto HoldServer::commit(Volume& v, std::vector<Request>& batch) -> void {
    if (batch.front().header.opcode == HoldOpcode::repl_write) {
        commit_replicas(v, batch);
        return;
    }
    std::vector<store::ReplicaStore::Write> writes;
    writes.reserve(batch.size());
    std::uint64_t seq = std::max(v.store->last_seq(), v.seq_floor);
    for (const auto& r : batch) {
        writes.push_back({.seq = ++seq, .lba = r.header.lba, .data = r.data, .crcs = r.crcs});
    }
    auto status = HoldStatus::ok;
    if (auto res = v.store->write(writes); res) {
        ++_stats.batches;
        _stats.writes += batch.size();
        if (!v.links.empty()) {
            // Answered once every member holds them (advance).
            const std::uint64_t first = seq - batch.size() + 1;
            for (std::size_t i = 0; i < batch.size(); ++i) {
                v.replicating.push_back(
                    {.request = std::move(batch[i]), .seq = first + i, .at = _now});
            }
            for (auto& [id, l] : v.links) {
                if (l.state == Link::State::open) {
                    for (auto it = v.replicating.end() - static_cast<std::ptrdiff_t>(batch.size());
                         it != v.replicating.end(); ++it) {
                        send_repl(v, l, *it);
                    }
                }
            }
            batch.clear();
            advance(v);
            return;
        }
        v.store->set_commit(seq);
        v.committed = seq;
    } else {
        status = status_of(res.error());
        if (res.error() == store::StoreError::io) {
            ++_stats.io_errors;
            v.store.reset();  // a failed replica is reopened by the next config
        }
    }
    for (const auto& r : batch) {
        respond(r.session, r.header, status);
    }
    batch.clear();
}

auto HoldServer::execute(Volume& v, Request& r) -> void {
    const auto fail = [&](store::StoreError e) {
        if (e == store::StoreError::io) {
            ++_stats.io_errors;
            v.store.reset();
        }
        respond(r.session, r.header, status_of(e));
    };
    switch (r.header.opcode) {
        case HoldOpcode::read: {
            std::vector<std::byte> data(std::size_t{r.header.blocks} * r.block_size);
            std::vector<std::uint32_t> crcs(r.header.blocks);
            auto bad = v.store->read(r.header.lba, data, crcs);
            if (!bad) {
                fail(bad.error());
                return;
            }
            if (!bad->empty()) {
                _stats.checksum += bad->size();
                if (start_repair(v, r, *bad)) {
                    return;
                }
                _stats.unrepairable += bad->size();
                respond(r.session, r.header, HoldStatus::io_error);
                return;
            }
            const auto crc = crc_bytes(crcs);
            respond(r.session, r.header, HoldStatus::ok,
                    proto::BlockData{.block_size = r.block_size, .crcs = crc, .data = data});
            return;
        }
        case HoldOpcode::write: {  // hydrate
            if (auto n = v.store->hydrate(r.header.lba, r.data, r.crcs); !n) {
                fail(n.error());
                return;
            }
            respond(r.session, r.header, HoldStatus::ok);
            return;
        }
        case HoldOpcode::flush:
            if (auto f = v.store->flush(); !f) {
                fail(f.error());
                return;
            }
            respond(r.session, r.header, HoldStatus::ok);
            return;
        default:
            respond(r.session, r.header, HoldStatus::bad_request);
            return;
    }
}

auto HoldServer::next_wake(Clock::time_point now) const -> std::optional<Clock::time_point> {
    std::optional<Clock::time_point> wake;
    const auto at = [&](Clock::time_point t) { wake = wake ? std::min(*wake, t) : t; };
    for (const auto& [id, v] : _volumes) {
        if (!v.queue.empty() && !v.held) {
            at(now + v.limiter.wait());
        }
        for (const auto& [sid, l] : v.links) {
            if (l.state == Link::State::down) {
                at(l.backoff ? now : std::max(now, l.redial_at));
            } else if (l.state == Link::State::open) {
                at(std::max(now, l.next_ping));
            }
            const bool reported = std::ranges::contains(v.timeout_reported, sid);
            if (!reported && !v.replicating.empty() && l.acked < v.replicating.front().seq) {
                at(std::max(now, v.replicating.front().at + _config.member_timeout));
            }
            if (!reported && v.reconcile && !l.intents_answered) {
                at(std::max(now, v.reconcile->started + _config.member_timeout));
            }
        }
        if (const auto* p = proto::primary_member(v.config);
            p != nullptr && v.store && p->server_id != _config.server_id && !v.primary_reported) {
            at(std::max(now, v.heard + _config.primary_timeout));
        }
    }
    if (_next_status) {
        at(std::max(now, *_next_status));  // the caller takes reports
    }
    return wake;
}

// ---- replication -----------------------------------------------------------

auto HoldServer::held_back(const Volume& v, const Request& r, Clock::time_point now) const -> bool {
    const auto& h = r.header;
    if (h.opcode == HoldOpcode::read) {
        // Not without a lease (another primary may be serving), nor before
        // an overlapping write is answered: it might still be rolled back.
        return !lease_valid(v, now) ||
               std::ranges::any_of(v.replicating, [&](const Replicating& w) {
                   return overlaps(w.request.header, h);
               });
    }
    if (h.opcode == HoldOpcode::write) {
        // Not under a repair, which would write the older copy back over it.
        return std::ranges::any_of(
            v.repairs, [&](const auto& kv) { return overlaps(kv.second.request.header, h); });
    }
    return false;
}

auto HoldServer::sync_links(Volume& v, Clock::time_point now) -> void {
    const auto& c = v.config;
    if (!is_primary(v)) {
        abandon(v);
        return;
    }
    for (auto it = v.links.begin(); it != v.links.end();) {
        const auto* m = find_member(c, it->first);
        if (m == nullptr || m->replica_gen != it->second.member.replica_gen ||
            m->endpoint != it->second.member.endpoint || m->port != it->second.member.port) {
            drop_link(v, it->second, now);
            it = v.links.erase(it);
        } else {
            it->second.member.role = m->role;
            ++it;
        }
    }
    for (const auto& m : c.members) {
        if (m.server_id == _config.server_id) {
            continue;
        }
        auto [it, added] = v.links.try_emplace(m.server_id, Link{.member = m});
        Link& l = it->second;
        if (l.state == Link::State::open && now >= l.next_ping) {
            l.next_ping = now + _config.ping_interval;
            proto::HoldHeader h;
            h.opcode = HoldOpcode::ping;
            h.request_id = v.next_request++;
            h.volume_id = c.volume_id;
            h.epoch = c.epoch;
            send_link(v, l, {.header = h, .payload = proto::HoldPing{.commit_seq = v.committed}});
        }
        if (l.backoff) {
            l.backoff = false;
            l.redial_at = now + _config.redial_backoff;
        }
        if (l.state != Link::State::down || now < l.redial_at) {
            continue;
        }
        const SessionId id = _next_session++;
        _sessions.emplace(id, Session{.peer = m.server_id,
                                      .open = false,
                                      .role = proto::HoldPeerRole::peer,
                                      .volume_id = c.volume_id,
                                      .attachment_id = 0,
                                      .generation = m.replica_gen,
                                      .outbound = true});
        l.session = id;
        l.state = Link::State::dialing;
        _sink->dial(id, m.server_id, m.endpoint, m.port);
    }
}

auto HoldServer::drop_link(Volume& v, Link& l, Clock::time_point now) -> void {
    if (l.session != 0) {
        const SessionId id = l.session;
        _sessions.erase(id);
        l.session = 0;
        _sink->hang_up(id);
    }
    l.state = Link::State::down;
    l.backoff = false;
    l.redial_at = now + _config.redial_backoff;
    for (auto it = v.repairs.begin(); it != v.repairs.end();) {
        if (it->second.member == l.member.server_id) {
            auto rep = std::move(it->second);
            it = v.repairs.erase(it);
            finish_repair(v, rep, nullptr);
        } else {
            ++it;
        }
    }
}

auto HoldServer::send_link(Volume& v, Link& l, proto::HoldFrame f) -> void {
    static_cast<void>(v);
    if (auto frame = proto::encode_hold_frame(f); frame && l.session != 0) {
        _sink->send(l.session, std::move(*frame));
    }
}

auto HoldServer::send_repl(Volume& v, Link& l, const Replicating& w) -> void {
    const auto& r = w.request;
    proto::HoldHeader h;
    h.opcode = HoldOpcode::repl_write;
    h.request_id = w.seq;
    h.volume_id = v.config.volume_id;
    h.epoch = v.config.epoch;
    h.lba = r.header.lba;
    h.blocks = r.header.blocks;
    const auto crcs = crc_bytes(r.crcs);
    send_link(v, l,
              {.header = h,
               .payload = proto::ReplWrite{
                   .seq = w.seq,
                   .commit_seq = std::min(v.committed, w.seq - 1),
                   .op = proto::ReplOp::write,
                   .data = {.block_size = r.block_size, .crcs = crcs, .data = r.data}}});
}

auto HoldServer::on_link_frame(Session& s, SessionId id, const proto::HoldFrame& f,
                               Clock::time_point now) -> void {
    if (!proto::is_response(f.header)) {
        return;
    }
    const auto vit = _volumes.find(s.volume_id);
    if (vit == _volumes.end()) {
        return;
    }
    Volume& v = vit->second;
    const auto lit = v.links.find(s.peer);
    if (lit == v.links.end() || lit->second.session != id) {
        return;
    }
    Link& l = lit->second;
    const bool ok = f.header.status == HoldStatus::ok;
    switch (f.header.opcode) {
        case HoldOpcode::hello_ok:
            if (!ok || l.state != Link::State::hello) {
                drop_link(v, l, now);  // the member is at another epoch: retry later
                return;
            }
            s.open = true;
            l.state = Link::State::open;
            l.next_ping = now + _config.ping_interval;
            if (const auto* ok_ = std::get_if<proto::HoldHelloOk>(&f.payload)) {
                l.commit_seen = ok_->commit_seq;
            }
            if (v.reconcile && !l.intents_answered) {
                ask_intents(v, l);
            }
            for (const auto& w : v.replicating) {
                if (w.seq > l.acked) {
                    send_repl(v, l, w);  // in order, what it may not have
                }
            }
            return;
        case HoldOpcode::repl_ack: {
            const auto* ack = std::get_if<proto::ReplAck>(&f.payload);
            if (!ok || ack == nullptr || l.state != Link::State::open) {
                drop_link(v, l, now);  // resent on the next session
                return;
            }
            l.acked = std::max(l.acked, ack->seq);
            advance(v);
            return;
        }
        case HoldOpcode::ping:
            return;
        case HoldOpcode::intents: {
            const auto* in = std::get_if<proto::HoldIntents>(&f.payload);
            if (!ok || in == nullptr || !v.reconcile || l.intents_answered ||
                f.header.request_id != l.intents_asked) {
                drop_link(v, l, now);  // asked again on the next session
                return;
            }
            l.intents_answered = true;
            auto& rec = *v.reconcile;
            rec.commit = std::max(rec.commit, l.commit_seen);
            for (const auto& i : in->entries) {
                rec.base = std::max(rec.base, i.seq);
                rec.extents.push_back(i);
            }
            finish_reconcile(v);
            return;
        }
        case HoldOpcode::read: {
            const auto rit = v.repairs.find(f.header.request_id);
            if (rit != v.repairs.end() && rit->second.member == l.member.server_id) {
                auto rep = std::move(rit->second);
                v.repairs.erase(rit);
                finish_repair(v, rep, &f);
            }
            return;
        }
        default:
            drop_link(v, l, now);
            return;
    }
}

auto HoldServer::advance(Volume& v) -> void {
    std::uint64_t done = 0;
    while (!v.replicating.empty()) {
        auto& w = v.replicating.front();
        const bool everywhere =
            std::ranges::all_of(v.links, [&](const auto& kv) { return kv.second.acked >= w.seq; });
        if (!everywhere) {
            break;
        }
        respond(w.request.session, w.request.header, HoldStatus::ok);
        ++_stats.replicated;
        done = w.seq;
        v.replicating.pop_front();
    }
    if (done != 0) {
        v.committed = done;
        if (v.store) {
            v.store->set_commit(done);
        }
        unpark(v);
    }
}

auto HoldServer::unpark(Volume& v) -> void {
    // Back to the front, in order; run() parks any still held back.
    v.queue.insert(v.queue.begin(), std::make_move_iterator(v.parked.begin()),
                   std::make_move_iterator(v.parked.end()));
    v.parked.clear();
}

auto HoldServer::abandon(Volume& v) -> void {
    // No longer the primary: the initiators resend to the one that is.
    for (auto& w : v.replicating) {
        refuse(w.request.session, w.request.header,
               {.status = HoldStatus::not_primary, .redirect = true});
    }
    v.replicating.clear();
    v.reconcile.reset();
    v.lease_asked.reset();
    v.lease_until = {};
    for (auto& [id, rep] : v.repairs) {
        respond(rep.request.session, rep.request.header, HoldStatus::io_error);
    }
    v.repairs.clear();
    unpark(v);  // the fencing checks refuse them
    for (auto& [id, l] : v.links) {
        if (l.session != 0) {
            _sessions.erase(l.session);
            _sink->hang_up(l.session);
        }
    }
    v.links.clear();
}

auto HoldServer::commit_replicas(Volume& v, std::vector<Request>& batch) -> void {
    std::uint64_t commit = 0;
    for (const auto& r : batch) {
        commit = std::max(commit, r.commit_seq);
    }
    v.store->set_commit(commit);
    const auto* me = find_member(v.config, _config.server_id);
    const bool joining = me != nullptr && me->role == proto::ReplicaRole::joining;
    std::vector<HoldStatus> status(batch.size(), HoldStatus::ok);
    std::vector<store::ReplicaStore::Write> writes;
    std::vector<std::size_t> written;
    std::vector<store::ReplicaStore::Write> again;
    std::vector<std::size_t> rewritten;
    std::uint64_t last = v.store->last_seq();
    for (std::size_t i = 0; i < batch.size(); ++i) {
        const auto& r = batch[i];
        if (r.seq <= last) {
            // A resend. Above the commit point it may be one a crash tore
            // here (still in the ring): write it again; else it is durable.
            if (r.seq > v.store->commit_seq() && r.seq <= v.store->last_seq()) {
                again.push_back(
                    {.seq = r.seq, .lba = r.header.lba, .data = r.data, .crcs = r.crcs});
                rewritten.push_back(i);
            }
            continue;
        }
        // A gap means writes this replica never saw, except on a session's
        // first REPL_WRITE: a primary that has just taken the role numbers
        // its writes above every seq any replica holds, and one that only
        // reconnected resends from this replica's last acknowledgement.
        const auto sit = _sessions.find(r.session);
        const bool first = sit != _sessions.end() && !sit->second.replicated;
        if (!joining && r.seq != last + 1 && !first) {
            status[i] = HoldStatus::bad_request;
            continue;
        }
        if (sit != _sessions.end()) {
            sit->second.replicated = true;
        }
        writes.push_back({.seq = r.seq, .lba = r.header.lba, .data = r.data, .crcs = r.crcs});
        written.push_back(i);
        last = r.seq;
    }
    if (!again.empty()) {
        if (auto res = v.store->rewrite(again); !res) {
            for (const auto i : rewritten) {
                status[i] = status_of(res.error());
            }
            for (const auto i : written) {
                status[i] = status_of(res.error());  // not after a failed rewrite
            }
            writes.clear();
            if (res.error() == store::StoreError::io) {
                ++_stats.io_errors;
                v.store.reset();
            }
        }
    }
    if (!writes.empty()) {
        if (auto res = v.store->write(writes); res) {
            ++_stats.batches;
            _stats.writes += writes.size();
        } else {
            for (const auto i : written) {
                status[i] = status_of(res.error());
            }
            if (res.error() == store::StoreError::io) {
                ++_stats.io_errors;
                v.store.reset();
            }
        }
    }
    for (std::size_t i = 0; i < batch.size(); ++i) {
        respond(batch[i].session, batch[i].header, status[i], proto::ReplAck{.seq = batch[i].seq});
    }
    batch.clear();
}

auto HoldServer::start_repair(Volume& v, Request& r, std::vector<std::uint64_t> bad) -> bool {
    if (!is_primary(v)) {
        return false;
    }
    const auto it = std::ranges::find_if(v.links, [](const auto& kv) {
        return kv.second.state == Link::State::open && in_sync(kv.second.member.role);
    });
    if (it == v.links.end()) {
        return false;
    }
    proto::HoldHeader h;
    h.opcode = HoldOpcode::read;
    h.request_id = v.next_request++;
    h.volume_id = v.config.volume_id;
    h.epoch = v.config.epoch;
    h.lba = r.header.lba;
    h.blocks = r.header.blocks;
    v.repairs.emplace(h.request_id,
                      Repair{.request = std::move(r), .bad = std::move(bad), .member = it->first});
    send_link(v, it->second, {.header = h, .payload = {}});
    return true;
}

auto HoldServer::finish_repair(Volume& v, Repair& rep, const proto::HoldFrame* f) -> void {
    const auto& h = rep.request.header;
    const std::uint32_t bs = rep.request.block_size;
    const bool sourced = v.config.source.kind != proto::SourceKind::none;
    const auto* d = f != nullptr && f->header.status == HoldStatus::ok
                        ? std::get_if<proto::BlockData>(&f->payload)
                        : nullptr;
    bool good = d != nullptr && v.store && d->block_size == bs && f->header.blocks == h.blocks &&
                d->data.size() == std::size_t{h.blocks} * bs;
    for (std::size_t b = 0; good && b < h.blocks; ++b) {
        const auto block = d->data.subspan(b * bs, bs);
        const auto crc = proto::block_crc(*d, b);
        good = crc32c::of(block) == crc || (crc == 0 && !sourced && all_zero(block));
    }
    for (std::size_t i = 0; good && i < rep.bad.size(); ++i) {
        const auto b = rep.bad[i] - h.lba;
        auto r = v.store->repair(rep.bad[i], d->data.subspan(b * bs, bs), proto::block_crc(*d, b));
        if (!r) {
            good = false;
            if (r.error() == store::StoreError::io) {
                ++_stats.io_errors;
                v.store.reset();
            }
        }
    }
    unpark(v);  // writes held behind the repair go on
    if (!good) {
        _stats.unrepairable += rep.bad.size();
        respond(rep.request.session, h, HoldStatus::io_error);
        return;
    }
    _stats.repaired += rep.bad.size();
    respond(rep.request.session, h, HoldStatus::ok,
            proto::BlockData{.block_size = bs, .crcs = d->crcs, .data = d->data});
}

// ---- failover --------------------------------------------------------------

auto HoldServer::lease_valid(const Volume& v, Clock::time_point now) const -> bool {
    return !_config.leases || now < v.lease_until;
}

auto HoldServer::start_reconcile(Volume& v, Clock::time_point now) -> void {
    Reconcile rec{.started = now,
                  .extents = {},
                  .base = v.store->last_seq(),
                  .commit = v.store->commit_seq()};
    for (const auto& i : v.store->intents()) {
        rec.extents.push_back({.seq = i.seq, .lba = i.lba, .blocks = i.blocks});
    }
    v.reconcile = std::move(rec);
    for (auto& [id, l] : v.links) {
        l.intents_answered = false;
        if (l.state == Link::State::open) {
            ask_intents(v, l);
        }
    }
}

auto HoldServer::ask_intents(Volume& v, Link& l) -> void {
    proto::HoldHeader h;
    h.opcode = HoldOpcode::intents;
    h.request_id = v.next_request++;
    h.volume_id = v.config.volume_id;
    h.epoch = v.config.epoch;
    l.intents_asked = h.request_id;
    send_link(v, l, {.header = h, .payload = {}});
}

auto HoldServer::finish_reconcile(Volume& v) -> void {
    if (!v.reconcile || !v.store) {
        return;
    }
    for (const auto& m : v.config.members) {
        if (m.server_id == _config.server_id) {
            continue;
        }
        const auto it = v.links.find(m.server_id);
        if (it == v.links.end() || !it->second.intents_answered) {
            return;
        }
    }
    auto rec = std::move(*v.reconcile);
    v.reconcile.reset();
    v.store->set_commit(rec.commit);
    v.committed = v.store->commit_seq();
    v.seq_floor = std::max(v.seq_floor, rec.base);
    // The union of the extents, merged and cut to what one write carries.
    std::ranges::sort(rec.extents, {}, &proto::HoldIntent::lba);
    const std::uint32_t bs = v.config.block_size;
    const std::uint64_t most =
        std::min<std::uint64_t>(proto::max_hold_blocks, proto::max_hold_data_bytes / bs);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;  // [first, end)
    for (const auto& e : rec.extents) {
        const std::uint64_t end = std::min(e.lba + e.blocks, v.config.capacity_blocks);
        if (e.lba >= end) {
            continue;
        }
        if (!spans.empty() && e.lba <= spans.back().second) {
            spans.back().second = std::max(spans.back().second, end);
        } else {
            spans.emplace_back(e.lba, end);
        }
    }
    std::vector<Request> writes;
    for (const auto& [first, end] : spans) {
        for (std::uint64_t lba = first; lba < end; lba += most) {
            const auto blocks = static_cast<std::uint32_t>(std::min(most, end - lba));
            Request r;
            r.header.opcode = HoldOpcode::write;
            r.header.volume_id = v.config.volume_id;
            r.header.epoch = v.config.epoch;
            r.header.lba = lba;
            r.header.blocks = blocks;
            r.block_size = bs;
            r.data.resize(std::size_t{blocks} * bs);
            r.crcs.resize(blocks);
            if (auto bad = v.store->read(lba, r.data, r.crcs); !bad) {
                ++_stats.io_errors;
                v.store.reset();  // a failed replica is reopened by the next config
                return;
            }
            for (std::size_t b = 0; b < blocks; ++b) {
                r.crcs[b] = crc32c::of(std::span{r.data}.subspan(b * bs, bs));
            }
            writes.push_back(std::move(r));
        }
    }
    _stats.reconciled += writes.size();
    // Ahead of everything the initiators sent meanwhile.
    v.queue.insert(v.queue.begin(), std::make_move_iterator(writes.begin()),
                   std::make_move_iterator(writes.end()));
}

auto HoldServer::watch(Volume& v, Clock::time_point now) -> void {
    if (is_primary(v)) {
        for (const auto& [sid, l] : v.links) {
            if (std::ranges::contains(v.timeout_reported, sid)) {
                continue;
            }
            const bool write_late = !v.replicating.empty() && l.acked < v.replicating.front().seq &&
                                    now - v.replicating.front().at >= _config.member_timeout;
            const bool intents_late = v.reconcile && !l.intents_answered &&
                                      now - v.reconcile->started >= _config.member_timeout;
            if (write_late || intents_late) {
                report_timeout(v, proto::VolumeFaultKind::member_timeout, sid);
            }
        }
        return;
    }
    const auto* p = proto::primary_member(v.config);
    if (p != nullptr && v.store && p->server_id != _config.server_id && !v.primary_reported &&
        now - v.heard >= _config.primary_timeout) {
        report_timeout(v, proto::VolumeFaultKind::primary_timeout, p->server_id);
    }
}

auto HoldServer::report_timeout(Volume& v, proto::VolumeFaultKind kind, std::uint64_t suspect)
    -> void {
    if (kind == proto::VolumeFaultKind::member_timeout) {
        v.timeout_reported.push_back(suspect);
    } else {
        v.primary_reported = true;
    }
    _reports.emplace_back(proto::VolumeFault{.volume_id = v.config.volume_id,
                                             .epoch = v.config.epoch,
                                             .suspect = suspect,
                                             .kind = kind,
                                             .reporter = proto::FaultReporter::hold,
                                             .slot = 0});
}

auto HoldServer::take_reports(Clock::time_point now) -> std::vector<proto::ReportBody> {
    std::vector<proto::ReportBody> out;
    if (!_next_status || now >= *_next_status) {
        auto interval = _config.status_interval;
        proto::ReplicaStatus status;
        for (auto& [id, v] : _volumes) {
            const auto* me = find_member(v.config, _config.server_id);
            if (me == nullptr || !v.store) {
                continue;
            }
            const bool primary = is_primary(v);
            if (primary) {
                // This status is the lease request (design "Epochs, leases").
                if (!v.lease_asked) {
                    v.lease_asked = now;
                }
                interval = std::min(interval, std::chrono::milliseconds{v.config.lease_ms / 4});
            }
            const auto left =
                primary && now < v.lease_until
                    ? std::chrono::duration_cast<std::chrono::milliseconds>(v.lease_until - now)
                    : std::chrono::milliseconds{0};
            proto::ReplicaState state = proto::ReplicaState::in_sync;
            if (me->role == proto::ReplicaRole::joining) {
                state = proto::ReplicaState::joining;
            }
            status.entries.push_back(
                {.volume_id = id,
                 .epoch = v.config.epoch,
                 .replica_gen = me->replica_gen,
                 .slot = 0,
                 .role = me->role,
                 .state = state,
                 .last_seq = v.store->last_seq(),
                 .commit_seq = v.store->commit_seq(),
                 .synced_bytes = 0,
                 .total_bytes = 0,
                 .hydrated_bytes = 0,
                 .lease_remaining_ms = static_cast<std::uint32_t>(left.count()),
                 .checksum_errors = 0,
                 .checksum_repairs = 0,
                 .reads = 0,
                 .writes = 0,
                 .read_bytes = 0,
                 .write_bytes = 0,
                 .throttled_us = 0});
        }
        out.emplace_back(std::move(status));
        _next_status = now + std::max(interval, std::chrono::milliseconds{1});
    }
    for (auto& r : _reports) {
        out.push_back(std::move(r));
    }
    _reports.clear();
    return out;
}

auto HoldServer::grant_lease(std::uint64_t volume_id, std::uint64_t epoch, Clock::time_point now)
    -> void {
    _now = now;
    const auto it = _volumes.find(volume_id);
    if (it == _volumes.end()) {
        return;
    }
    Volume& v = it->second;
    if (epoch != v.config.epoch || !is_primary(v) || !v.lease_asked) {
        return;  // not for this role, or not asked since the last grant
    }
    // From when it asked: the controller counts from when it answered.
    v.lease_until =
        std::max(v.lease_until, *v.lease_asked + std::chrono::milliseconds{v.config.lease_ms});
    v.lease_asked.reset();
    unpark(v);  // reads held for the lease
}

auto HoldServer::has_lease(std::uint64_t volume_id, Clock::time_point now) const -> bool {
    const auto it = _volumes.find(volume_id);
    return it != _volumes.end() && is_primary(it->second) && lease_valid(it->second, now);
}

auto HoldServer::reconciling(std::uint64_t volume_id) const -> bool {
    const auto it = _volumes.find(volume_id);
    return it != _volumes.end() && it->second.reconcile.has_value();
}

// ---- responses -------------------------------------------------------------

auto HoldServer::respond(SessionId id, const proto::HoldHeader& req, HoldStatus status,
                         proto::HoldPayload payload) -> void {
    if (id == 0) {
        return;  // the server's own request
    }
    proto::HoldHeader h = req;
    h.flags = proto::hold_flags::response;
    h.status = status;
    h.payload_len = 0;
    if (const auto it = _volumes.find(req.volume_id); it != _volumes.end()) {
        h.epoch = it->second.config.epoch;
    }
    switch (req.opcode) {
        case HoldOpcode::hello:
            h.opcode = HoldOpcode::hello_ok;
            break;
        case HoldOpcode::repl_write:
            h.opcode = HoldOpcode::repl_ack;
            if (std::holds_alternative<std::monostate>(payload)) {
                payload = proto::ReplAck{.seq = req.request_id};  // the primary's seq
            }
            break;
        default:
            break;
    }
    if (!proto::is_block_opcode(h.opcode)) {
        h.blocks = 0;
        h.lba = 0;
    }
    if (status != HoldStatus::ok) {
        ++_stats.refused;
    }
    auto frame = proto::encode_hold_frame({.header = h, .payload = std::move(payload)});
    if (frame) {
        _sink->send(id, std::move(*frame));
    }
}

auto HoldServer::refuse(SessionId id, const proto::HoldHeader& req, Verdict v) -> void {
    if (id == 0) {
        return;
    }
    if (!v.redirect || req.opcode == HoldOpcode::repl_write) {
        respond(id, req, v.status);
        return;
    }
    proto::HoldHeader h = req;
    h.opcode = HoldOpcode::redirect;
    h.blocks = 0;
    h.lba = 0;
    proto::HoldRedirect r;
    if (const auto it = _volumes.find(req.volume_id); it != _volumes.end()) {
        if (const auto* p = proto::primary_member(it->second.config); p != nullptr) {
            r.primary_server = p->server_id;
        }
        r.primary_epoch = it->second.config.epoch;
    }
    h.flags = proto::hold_flags::response;
    h.status = v.status;
    h.epoch = r.primary_epoch != 0 ? r.primary_epoch : req.epoch;
    h.payload_len = 0;
    ++_stats.refused;
    auto frame = proto::encode_hold_frame({.header = h, .payload = r});
    if (frame) {
        _sink->send(id, std::move(*frame));
    }
}

}  // namespace ak::hold
