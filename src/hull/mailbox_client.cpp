// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/mailbox_client.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <variant>

#include "common/wire.hpp"

namespace ak::hull {

namespace {

namespace mb = helm::mailbox;

constexpr std::size_t word = sizeof(std::uint32_t);
constexpr std::size_t header_type_offset = 0x06;
constexpr std::size_t header_seq_offset = 0x08;

auto takes_payload(mb::Type t) -> bool {
    return t == mb::Type::list_vms || t == mb::Type::vm_status;
}

// The type and sequence number a slot claims, read straight from their fixed
// offsets: used only to address a `malformed` reply to a slot that did not
// decode, never to act on it. Empty if the type is not a known command.
struct Claimed {
    mb::Type type;
    std::uint64_t seq;
};

auto known_command(std::uint16_t raw) -> std::optional<mb::Type> {
    using enum mb::Type;
    static constexpr std::array commands{
        create_vm,     destroy_vm,      list_vms,       vm_status,      attach_device,
        detach_device, create_volume,   delete_volume,  attach_volume,  detach_volume,
        rewrap_volume, withdraw_detach, create_network, delete_network, gpu_vf_config};
    const auto* const it = std::ranges::find(commands, static_cast<mb::Type>(raw));
    if (it == commands.end()) {
        return std::nullopt;
    }
    return *it;
}

auto claimed(const mb::Slot& slot) -> std::optional<Claimed> {
    wire::Reader type_reader{std::span{slot}.subspan(header_type_offset)};
    wire::Reader seq_reader{std::span{slot}.subspan(header_seq_offset)};
    const auto raw_type = type_reader.le16();
    const auto seq = seq_reader.le64();
    if (!raw_type || !seq) {
        return std::nullopt;
    }
    const auto type = known_command(*raw_type);
    if (!type) {
        return std::nullopt;
    }
    return Claimed{.type = *type, .seq = *seq};
}

auto status_for(AuthFailure f) -> mb::Status {
    switch (f) {
        case AuthFailure::malformed:
        case AuthFailure::not_a_command:
            return mb::Status::malformed;
        case AuthFailure::unknown_key:
        case AuthFailure::bad_signature:
            return mb::Status::bad_signature;
        case AuthFailure::crypto_failure:
            return mb::Status::internal_error;
        case AuthFailure::replayed:
            return mb::Status::stale_sequence;
        case AuthFailure::wrong_server:
            return mb::Status::wrong_server;
    }
    return mb::Status::internal_error;
}

auto is_event(mb::Type t) -> bool {
    return t == mb::Type::vm_exited || t == mb::Type::device_released ||
           t == mb::Type::host_fault || t == mb::Type::scrub_done;
}

}  // namespace

auto to_string(AttachError e) noexcept -> const char* {
    switch (e) {
        case AttachError::bad_magic:
            return "bad_magic";
        case AttachError::bad_version:
            return "bad_version";
    }
    return "unknown";
}

auto MailboxClient::attach() -> std::expected<void, AttachError> {
    if (_mmio->read32(mb::reg::magic) != mb::magic) {
        return std::unexpected(AttachError::bad_magic);
    }
    if (_mmio->read32(mb::reg::version) != mb::protocol_version) {
        return std::unexpected(AttachError::bad_version);
    }
    _last_doorbell = _mmio->read32(mb::reg::cmd_doorbell);
    return {};
}

auto MailboxClient::copy_command_slot() -> mb::Slot {
    mb::Slot slot{};
    for (std::size_t off = 0; off < mb::slot_size; off += word) {
        const std::uint32_t v = _mmio->read32(mb::reg::cmd_slot + off);
        wire::SpanWriter w{std::span{slot}.subspan(off, word)};
        (void)w.write(v, wire::Order::little);
    }
    return slot;
}

auto MailboxClient::service() -> bool {
    const std::uint32_t doorbell = _mmio->read32(mb::reg::cmd_doorbell);
    if (doorbell == _last_doorbell) {
        ++_stats.spurious;
        return false;
    }
    _last_doorbell = doorbell;
    const mb::Slot slot = copy_command_slot();  // the only read of the slot

    const auto msg = authenticate(slot, _server_id, *_verifier, *_sequence);
    if (!msg) {
        const auto status = status_for(msg.error().failure);
        if (status == mb::Status::bad_signature) {
            ++_stats.bad_signature;
        } else if (status == mb::Status::stale_sequence) {
            ++_stats.replayed;
        } else if (status == mb::Status::wrong_server) {
            ++_stats.wrong_server;
        } else {
            ++_stats.malformed;
        }
        const auto who = claimed(slot);
        if (!who) {
            ++_stats.unanswerable;
            return true;
        }
        respond(who->seq, who->type, {.status = status, .payload = {}});
        return true;
    }

    const auto body = mb::decode_body(*msg);
    if (!body) {
        const bool reserved = body.error() == mb::BodyError::reserved_type;
        ++(reserved ? _stats.unsupported : _stats.malformed);
        respond(
            msg->header.seq, msg->header.type,
            {.status = reserved ? mb::Status::unsupported : mb::Status::malformed, .payload = {}});
        return true;
    }

    ++_stats.commands;
    respond(msg->header.seq, msg->header.type, _handler->handle(*msg, *body));
    return true;
}

auto MailboxClient::respond(std::uint64_t in_reply_to, mb::Type command,
                            const CommandOutcome& outcome) -> void {
    mb::Response rsp{.in_reply_to = in_reply_to, .command = command, .status = outcome.status};
    if (!outcome.payload.empty()) {
        // A payload the protocol cannot carry is the handler's bug: report
        // it rather than send something helm would reject as a stray.
        if (outcome.status != mb::Status::ok || !takes_payload(command) ||
            outcome.payload.size() > mb::max_response_payload) {
            rsp.status = mb::Status::internal_error;
        } else {
            rsp.payload_len = static_cast<std::uint8_t>(outcome.payload.size());
            std::ranges::copy(outcome.payload, rsp.payload.begin());
        }
    }
    write_slot(mb::reg::rsp_slot, mb::reg::rsp_doorbell, rsp);
}

auto MailboxClient::send_event(const mb::Body& body) -> bool {
    if (!is_event(mb::type_of(body))) {
        return false;
    }
    ++_stats.events;
    write_slot(mb::reg::evt_slot, mb::reg::evt_doorbell, body);
    return true;
}

auto MailboxClient::write_slot(std::size_t base, std::size_t doorbell, const mb::Body& body)
    -> void {
    const auto bytes = mb::encode_body(body);
    const std::array<std::byte, mb::signature_size> unsigned_sig{};
    const auto slot = mb::encode({.type = mb::type_of(body),
                                  .seq = _next_seq++,
                                  .body_len = static_cast<std::uint16_t>(bytes.size()),
                                  .key_id = mb::no_key_id},
                                 bytes, unsigned_sig);
    if (!slot) {
        return;  // unreachable: every body we build fits a slot
    }
    // Every byte of the slot is written, so nothing from an earlier message
    // survives past body_len (helm Requirement 1.4), then the doorbell.
    for (std::size_t off = 0; off < mb::slot_size; off += word) {
        wire::Reader r{std::span{*slot}.subspan(off, word)};
        _mmio->write32(base + off, r.le32().value_or(0));
    }
    _mmio->write32(doorbell, 1);
}

}  // namespace ak::hull
