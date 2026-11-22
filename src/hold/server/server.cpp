// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/server/server.hpp"

#include <algorithm>
#include <utility>

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
    // Build the new state aside, so a refused config changes nothing.
    Volume next;
    if (found != _volumes.end()) {
        next.store = std::move(found->second.store);
        next.queue = std::move(found->second.queue);
        next.limiter = found->second.limiter;
    }
    next.config = c;
    const auto restore = [&] {
        if (found != _volumes.end()) {
            found->second.store = std::move(next.store);
            found->second.queue = std::move(next.queue);
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
    _volumes.insert_or_assign(c.volume_id, std::move(next));
    return {};
}

auto HoldServer::single_replica_primary(const Volume& v) const -> bool {
    const auto* p = proto::primary_member(v.config);
    return v.config.members.size() == 1 && p != nullptr && p->server_id == _config.server_id;
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
    }
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
    if (h.opcode == HoldOpcode::write) {
        if (att->mode == proto::AttachMode::ro) {
            return {.status = HoldStatus::read_only};
        }
        if (!single_replica_primary(v)) {
            return {.status = HoldStatus::io_suspended};  // until replication (task 8)
        }
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
    static_cast<void>(now);
    const auto sit = _sessions.find(id);
    if (sit == _sessions.end() || proto::is_response(f.header)) {
        return;  // this role sends no requests yet (replication is task 8)
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
        refuse(id, h, verdict);
        return;
    }
    Volume& v = _volumes.at(h.volume_id);
    const bool initiator = s.role == proto::HoldPeerRole::initiator;
    Request r{
        .session = id, .header = h, .data = {}, .crcs = {}, .block_size = v.config.block_size};
    switch (h.opcode) {
        case HoldOpcode::ping:
            respond(id, h, HoldStatus::ok,
                    proto::HoldPing{.commit_seq = v.store ? v.store->commit_seq() : 0});
            return;
        case HoldOpcode::read:
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
            respond(id, h, HoldStatus::bad_request,
                    proto::ReplAck{.seq = w != nullptr ? w->seq : 0});
            return;
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
    while (served < budget && !v.queue.empty()) {
        Request& r = v.queue.front();
        const auto sit = _sessions.find(r.session);
        if (sit == _sessions.end()) {
            v.queue.pop_front();
            continue;
        }
        if (const auto verdict = check(sit->second, r.header); verdict.status != HoldStatus::ok) {
            refuse(r.session, r.header, verdict);
            v.queue.pop_front();
            ++served;
            continue;
        }
        const bool plain = is_plain_write(r.header);
        const std::uint64_t bytes = r.header.opcode == HoldOpcode::flush
                                        ? 0
                                        : std::uint64_t{r.header.blocks} * r.block_size;
        if (!plain || batch.size() >= _config.max_batch_writes ||
            batch_bytes + bytes > _config.max_batch_bytes) {
            flush_batch();  // order: what came before runs first
        }
        if (bytes != 0 && !v.limiter.admit(bytes, now)) {
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
    std::vector<store::ReplicaStore::Write> writes;
    writes.reserve(batch.size());
    std::uint64_t seq = v.store->last_seq();
    for (const auto& r : batch) {
        writes.push_back({.seq = ++seq, .lba = r.header.lba, .data = r.data, .crcs = r.crcs});
    }
    auto status = HoldStatus::ok;
    if (auto res = v.store->write(writes); res) {
        v.store->set_commit(seq);
        ++_stats.batches;
        _stats.writes += batch.size();
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
    for (const auto& [id, v] : _volumes) {
        if (!v.queue.empty()) {
            const auto at = now + v.limiter.wait();
            wake = wake ? std::min(*wake, at) : at;
        }
    }
    return wake;
}

// ---- responses -------------------------------------------------------------

auto HoldServer::respond(SessionId id, const proto::HoldHeader& req, HoldStatus status,
                         proto::HoldPayload payload) -> void {
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
    if (!v.redirect) {
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
