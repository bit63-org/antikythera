// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MailboxClient: the agent's end of the control mailbox
// (.kiro/specs/hull-host-agent/ task 4, Requirements 3 and 4).
//
// It sees BAR0 only through an MmioWindow of aligned 32-bit accesses
// (VfioMailbox maps the real one; tests and the fuzzer substitute memory or
// helm's MailboxDevice). On every interrupt, or whenever the agent's loop
// calls service(), it:
//
//   1. reads CMD_DOORBELL and stops if it has not changed since the last
//      command it took (a spurious or repeated interrupt);
//   2. copies CMD_SLOT out once, with 64 32-bit reads, into a local Slot
//      (3.4) -- nothing is ever parsed in place in device memory;
//   3. authenticates the copy (decode, signature, sequence; command_auth.hpp),
//      or, for helm's own STANDING_CHUNK and STANDING_START, decodes it and
//      checks the server it names (StandingStarts verifies the controller's
//      signature over the set they carry);
//   4. decodes and validates the body;
//   5. hands the command to the CommandHandler, and
//   6. writes exactly one response into RSP_SLOT with 32-bit writes, then
//      rings RSP_DOORBELL.
//
// Rejections answer too (malformed, wrong_server, bad_signature,
// stale_sequence, unsupported), so helm's router never waits out its timeout on a command
// hull refused. The exception is a slot so broken that it names no command
// type: there is nothing a response could name, so it is only counted.
//
// The doorbell baseline is the value the doorbell holds at attach(): a
// command already in CMD_SLOT before the agent looked is never acted on
// (after an agent restart it may be one the previous run already executed,
// and the sequence floor may not survive the restart). helm's router times
// it out and the controller retries with a new sequence number.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <vector>

#include "helm/mailbox.hpp"
#include "hull/command_auth.hpp"
#include "hull/sequence_tracker.hpp"
#include "hull/signature_verifier.hpp"

namespace ak::hull {

class StandingStarts;

// Aligned 32-bit MMIO into the mailbox's BAR0. Offsets are byte offsets
// that are multiples of four and inside helm::mailbox::reg::bar0_size.
class MmioWindow {
public:
    MmioWindow() = default;
    MmioWindow(const MmioWindow&) = delete;
    auto operator=(const MmioWindow&) -> MmioWindow& = delete;
    MmioWindow(MmioWindow&&) = delete;
    auto operator=(MmioWindow&&) -> MmioWindow& = delete;
    virtual ~MmioWindow() = default;

    [[nodiscard]] virtual auto read32(std::size_t offset) -> std::uint32_t = 0;
    virtual auto write32(std::size_t offset, std::uint32_t value) -> void = 0;
};

// What the agent did with an authenticated, well-formed command.
struct CommandOutcome {
    helm::mailbox::Status status{helm::mailbox::Status::ok};
    // Only on an ok reply to LIST_VMS or VM_STATUS (mailbox.hpp, Response).
    std::vector<std::byte> payload;
};

class CommandHandler {
public:
    CommandHandler() = default;
    CommandHandler(const CommandHandler&) = delete;
    auto operator=(const CommandHandler&) -> CommandHandler& = delete;
    CommandHandler(CommandHandler&&) = delete;
    auto operator=(CommandHandler&&) -> CommandHandler& = delete;
    virtual ~CommandHandler() = default;

    // `body` is decode_body(msg), already validated. Long operations answer
    // `accepted` and report completion later with MailboxClient::send_event.
    virtual auto handle(const helm::mailbox::Message& msg, const helm::mailbox::Body& body)
        -> CommandOutcome = 0;
};

enum class AttachError : std::uint8_t {
    bad_magic,    // BAR0 does not hold a mailbox (wrong function, or not yet up)
    bad_version,  // the device speaks another protocol version
};

[[nodiscard]] auto to_string(AttachError e) noexcept -> const char*;

struct MailboxClientStats {
    std::uint64_t commands{0};  // reached the handler
    std::uint64_t malformed{0};
    std::uint64_t bad_signature{0};
    std::uint64_t replayed{0};
    std::uint64_t wrong_server{0};
    std::uint64_t unsupported{0};
    std::uint64_t unanswerable{0};  // no command type to answer for
    std::uint64_t spurious{0};      // service() with an unchanged doorbell
    std::uint64_t events{0};
};

class MailboxClient {
public:
    // `server_id` is this server's provisioned identity (mailbox protocol
    // v3): commands naming another server are refused with wrong_server.
    MailboxClient(MmioWindow& mmio, helm::mailbox::ServerId server_id,
                  const SignatureVerifier& verifier, SequenceTracker& sequence,
                  CommandHandler& handler) noexcept
        : _mmio{&mmio},
          _server_id{server_id},
          _verifier{&verifier},
          _sequence{&sequence},
          _handler{&handler} {}

    // Where helm's STANDING_CHUNK and STANDING_START go (not owned). With
    // none they are answered `unsupported`. The first signed command
    // accepted closes it (StandingStarts::close).
    auto set_standing_starts(StandingStarts* standing) noexcept -> void { _standing = standing; }

    // Checks MAGIC and VERSION and takes the doorbell baseline.
    [[nodiscard]] auto attach() -> std::expected<void, AttachError>;

    // Takes at most one new command; true if there was one (answered or
    // counted). Call it on every MSI-X interrupt; calling it without one is
    // harmless.
    auto service() -> bool;

    // Writes an event into EVT_SLOT and rings EVT_DOORBELL. False if `body`
    // is not an event.
    auto send_event(const helm::mailbox::Body& body) -> bool;

    [[nodiscard]] auto stats() const noexcept -> const MailboxClientStats& { return _stats; }

private:
    auto copy_command_slot() -> helm::mailbox::Slot;
    auto service_helm_command(const helm::mailbox::Message& msg) -> void;
    auto respond(std::uint64_t in_reply_to, helm::mailbox::Type command,
                 const CommandOutcome& outcome) -> void;
    auto write_slot(std::size_t base, std::size_t doorbell, const helm::mailbox::Body& body)
        -> void;

    MmioWindow* _mmio;
    helm::mailbox::ServerId _server_id;
    const SignatureVerifier* _verifier;
    SequenceTracker* _sequence;
    CommandHandler* _handler;
    StandingStarts* _standing{nullptr};
    std::uint32_t _last_doorbell{0};
    std::uint64_t _next_seq{1};  // header seq of hull's responses and events
    MailboxClientStats _stats;
};

}  // namespace ak::hull
