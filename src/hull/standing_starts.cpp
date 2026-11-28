// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/standing_starts.hpp"

#include <algorithm>
#include <utility>
#include <variant>

namespace ak::hull {

namespace mb = helm::mailbox;

// The mailbox carries what the standing-set codec allows.
static_assert(mb::max_standing_transfer == proto::max_standing_set_size);
static_assert(mb::max_standing_index == proto::max_standing_instances);
static_assert(proto::max_standing_command_body == mb::max_body);
static_assert(std::to_underlying(proto::StandingCommandType::create_vm) ==
              std::to_underlying(mb::Type::create_vm));
static_assert(std::to_underlying(proto::StandingCommandType::attach_device) ==
              std::to_underlying(mb::Type::attach_device));
static_assert(std::to_underlying(proto::StandingCommandType::attach_volume) ==
              std::to_underlying(mb::Type::attach_volume));

namespace {

// The VM a standing command acts on; nullopt for a type a standing start
// may not run (proto::decode_standing_set allows only these three).
auto vm_of(const mb::Body& body) -> std::optional<std::uint64_t> {
    if (const auto* c = std::get_if<mb::CreateVm>(&body)) {
        return c->vm_id;
    }
    if (const auto* a = std::get_if<mb::AttachVolume>(&body)) {
        return a->vm_id;
    }
    if (const auto* d = std::get_if<mb::AttachDevice>(&body)) {
        return d->vm_id;
    }
    return std::nullopt;
}

auto succeeded(mb::Status s) -> bool {
    return s == mb::Status::ok || s == mb::Status::accepted;
}

}  // namespace

auto StandingStarts::chunk(const mb::StandingChunk& c) -> mb::Status {
    if (!_open) {
        ++_stats.refused;
        return mb::Status::conflict;
    }
    ++_stats.chunks;
    if (c.offset == 0) {
        _buffer.clear();
        _buffer.reserve(c.total);
        _total = c.total;
    } else if (_total == 0 || c.total != _total || c.offset != _buffer.size()) {
        // A gap, a changed total or a continuation with nothing started.
        _buffer.clear();
        _total = 0;
        ++_stats.transfers_aborted;
        return mb::Status::malformed;
    }
    const auto bytes = c.chunk_bytes();
    _buffer.insert(_buffer.end(), bytes.begin(), bytes.end());
    if (_buffer.size() < _total) {
        return mb::Status::ok;
    }
    return accept_transfer();
}

auto StandingStarts::accept_transfer() -> mb::Status {
    std::vector<std::byte> frame = std::exchange(_buffer, {});
    _total = 0;
    auto set = proto::decode_standing_set(frame);
    if (!set) {
        ++_stats.sets_refused;
        return mb::Status::malformed;
    }
    // The server is inside the signed bytes; check it before the signature,
    // as authenticate() does for a slot.
    if (set->server_id != _server_id) {
        ++_stats.sets_refused;
        return mb::Status::wrong_server;
    }
    const auto signed_bytes = proto::standing_set_signed_bytes(frame);
    if (auto ok = _verifier->verify(signed_bytes, set->signature, set->key_id); !ok) {
        ++_stats.sets_refused;
        return ok.error() == VerifyError::crypto_failure ? mb::Status::internal_error
                                                         : mb::Status::bad_signature;
    }
    _set = std::move(*set);
    ++_stats.sets_accepted;
    return mb::Status::ok;
}

auto StandingStarts::start(const mb::StandingStart& s, CommandHandler& handler) -> mb::Status {
    if (!_open || !_set || _set->generation != s.generation || s.index >= _set->instances.size()) {
        ++_stats.refused;
        return !_open || !_set || _set->generation != s.generation ? mb::Status::conflict
                                                                   : mb::Status::malformed;
    }
    const auto& in = _set->instances[s.index];
    if (_started.contains(in.vm_id)) {
        ++_stats.refused;
        return mb::Status::conflict;
    }
    const auto status = run(*_set, in, handler);
    if (succeeded(status)) {
        _started.insert(in.vm_id);
        ++_stats.started;
    } else {
        ++_stats.failed;
    }
    return status;
}

auto StandingStarts::run(const proto::StandingSet& set, const proto::StandingInstance& in,
                         CommandHandler& handler) -> mb::Status {
    bool created = false;
    // Undoes a partial start so a retry finds no VM. The volumes are the
    // instance's own and outlive it.
    auto fail = [&](mb::Status status) {
        if (created) {
            mb::Message destroy{};
            destroy.header = {.type = mb::Type::destroy_vm,
                              .seq = 0,
                              .body_len = 0,
                              .key_id = set.key_id,
                              .server_id = set.server_id};
            (void)handler.handle(destroy,
                                 mb::DestroyVm{.vm_id = in.vm_id, .persist_volumes = true});
        }
        return status;
    };
    for (const auto& c : in.commands) {
        // The command as hull would have copied it out of a signed slot,
        // with no sequence number: a standing start consumes none.
        mb::Message msg{};
        msg.header = {.type = static_cast<mb::Type>(std::to_underlying(c.type)),
                      .seq = 0,
                      .body_len = static_cast<std::uint16_t>(c.body.size()),
                      .key_id = set.key_id,
                      .server_id = set.server_id};
        std::ranges::copy(c.body, msg.body.begin());  // at most max_body bytes
        auto body = mb::decode_body(msg);
        if (!body || vm_of(*body) != in.vm_id) {
            return fail(mb::Status::malformed);
        }
        const auto outcome = handler.handle(msg, *body);
        if (!succeeded(outcome.status)) {
            return fail(outcome.status);
        }
        created = created || std::holds_alternative<mb::CreateVm>(*body);
    }
    return mb::Status::ok;
}

auto StandingStarts::close() noexcept -> void {
    if (!_open) {
        return;
    }
    _open = false;
    _buffer = {};
    _total = 0;
    _set.reset();
}

}  // namespace ak::hull
