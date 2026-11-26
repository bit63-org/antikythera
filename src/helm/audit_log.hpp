// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AuditLog: helm's append-only record of every command it relays and every
// key operation it performs (.kiro/specs/helm-control-plane/ Requirement
// 9.3, design "Audit log").
//
// One record per line, ASCII, fields in a fixed order and printed only
// when set:
//
//   n=<index> t=<unix ms> ev=<event> [seq=<u64>] [cmd=0x<type>]
//   [status=<u16>] [vm=<u64>] [vol=<u64>] [fn=<slot>.<function>]
//   [count=<u64>] h=<sha256 hex>
//
// The records form a hash chain: h is SHA-256 over the previous record's h
// (32 zero bytes for record 0) followed by this line's text up to and
// excluding " h=". Editing, dropping or reordering a record breaks every
// h after it, so the log is tamper-evident as well as append-only (the
// file is opened O_APPEND and never rewritten).
//
// AuditRecord holds identifiers only: VM, volume and function IDs, command
// sequence numbers and statuses. There is no field that can carry key
// material, so none can reach the log (Requirement 9.3: key IDs only,
// never material).
//
// verify_audit_log() is the reader. It treats the text as untrusted (an
// operator may hand it a copied file): strict parse, canonical form (each
// line must be exactly what the writer would print for the record it
// parses to), consecutive indices from 0, and every hash. AuditLog runs
// it when it opens an existing file, so a helm restart continues the same
// chain, and refuses a file that does not verify.
//
// Not thread-safe; it belongs to helm's event-loop thread.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "helm/device_pool.hpp"
#include "helm/secure_element.hpp"

namespace ak::helm {

// Values are part of the log format: append, never renumber or rename.
enum class AuditEvent : std::uint8_t {
    command_received,  // a controller envelope was accepted for routing
    command_refused,   // helm answered it without relaying it to hull
    command_relayed,   // written to the mailbox
    command_outcome,   // hull answered (status is hull's)
    command_timed_out,
    late_response,  // hull answered after the command had timed out
    vm_key_created,
    vm_key_destroyed,  // count = volumes crypto-erased with it
    volume_key_created,
    volume_key_delivered,
    volume_key_dropped,
    volume_key_rewrapped,  // vm = the new owner
    volume_key_destroyed,
    volume_key_delivery_failed,  // ATTACH_VOLUME succeeded but the key did not reach the role
    eject_requested,             // cooperative detach: the guest was asked to release the function
    eject_released,              // the guest released it (helm may now relay the detach)
    detach_busy,                 // the guest did not release it by the command's timeout
    detach_withdrawn,            // WITHDRAW_DETACH cleared a pending eject request
    conversion_started,    // CONVERT_VOLUME: both keys went to the storage role (volume = local)
    conversion_failed,     // the copy did not start, failed or was lost (status = the failure)
    conversion_completed,  // the copy is durable on the target (count = bytes written)
};

[[nodiscard]] auto to_string(AuditEvent e) noexcept -> const char*;

struct AuditRecord {
    AuditEvent event{AuditEvent::command_received};
    std::uint64_t seq{0};                 // command sequence number; 0 = not printed
    std::uint16_t command{0};             // mailbox message type; 0 = not printed
    std::optional<std::uint16_t> status;  // mailbox::Status value
    std::uint64_t vm{0};                  // 0 = not printed (IDs are never zero)
    std::uint64_t volume{0};
    std::optional<FunctionId> function;
    std::optional<std::uint64_t> count;

    // Builders, so a call site names only the fields it sets.
    [[nodiscard]] static constexpr auto of(AuditEvent e) noexcept -> AuditRecord {
        AuditRecord r;
        r.event = e;
        return r;
    }
    [[nodiscard]] constexpr auto with_seq(std::uint64_t v) const noexcept -> AuditRecord {
        auto r = *this;
        r.seq = v;
        return r;
    }
    [[nodiscard]] constexpr auto with_command(std::uint16_t v) const noexcept -> AuditRecord {
        auto r = *this;
        r.command = v;
        return r;
    }
    [[nodiscard]] constexpr auto with_status(std::uint16_t v) const noexcept -> AuditRecord {
        auto r = *this;
        r.status = v;
        return r;
    }
    [[nodiscard]] constexpr auto with_vm(std::uint64_t v) const noexcept -> AuditRecord {
        auto r = *this;
        r.vm = v;
        return r;
    }
    [[nodiscard]] constexpr auto with_volume(std::uint64_t v) const noexcept -> AuditRecord {
        auto r = *this;
        r.volume = v;
        return r;
    }
    [[nodiscard]] constexpr auto with_function(FunctionId v) const noexcept -> AuditRecord {
        auto r = *this;
        r.function = v;
        return r;
    }
    [[nodiscard]] constexpr auto with_count(std::uint64_t v) const noexcept -> AuditRecord {
        auto r = *this;
        r.count = v;
        return r;
    }

    friend auto operator==(const AuditRecord&, const AuditRecord&) -> bool = default;
};

inline constexpr std::size_t audit_hash_size = 32;
using AuditHash = std::array<std::byte, audit_hash_size>;

// Where a chain ends: the next record gets index `next_index` and chains
// from `last_hash`.
struct AuditTail {
    std::uint64_t next_index{0};
    AuditHash last_hash{};

    friend auto operator==(const AuditTail&, const AuditTail&) -> bool = default;
};

enum class AuditErrc : std::uint8_t {
    bad_line,     // a line does not parse, or is not in canonical form
    bad_index,    // indices are not 0, 1, 2, ...
    bad_hash,     // a record's hash does not chain
    torn_tail,    // the text does not end with a newline (interrupted write)
    io,           // the file could not be opened, read or written
    unsafe_file,  // a symlink, not a regular file, or group/other permissions
};

[[nodiscard]] auto to_string(AuditErrc e) noexcept -> const char*;

struct AuditError {
    AuditErrc code{AuditErrc::io};
    std::uint64_t line{0};  // 1-based line of the failure, 0 if none
    int sys_errno{0};       // for io

    friend auto operator==(const AuditError&, const AuditError&) -> bool = default;
};

// One line (with its trailing newline) for `record`, given the chain so far.
[[nodiscard]] auto format_audit_line(const AuditTail& tail, std::int64_t unix_ms,
                                     const AuditRecord& record) -> std::string;

// Verifies a whole log. Empty text is a valid, empty log.
[[nodiscard]] auto verify_audit_log(std::string_view text) -> std::expected<AuditTail, AuditError>;

class AuditLog {
public:
    using WallClock = std::function<std::int64_t()>;  // unix time in ms

    struct Options {
        // fdatasync after every record. Commands are rare; losing the last
        // records in a crash is worse than the latency.
        bool sync{true};
        WallClock clock;  // empty: the system clock
    };

    // Opens (creating 0600 if absent) and verifies `path`. Refuses a
    // symlink, a non-regular file, a file with group or other permission
    // bits, and a file that does not verify.
    [[nodiscard]] static auto open(const std::string& path, Options options)
        -> std::expected<AuditLog, AuditError>;

    AuditLog(const AuditLog&) = delete;
    auto operator=(const AuditLog&) -> AuditLog& = delete;
    AuditLog(AuditLog&& other) noexcept;
    auto operator=(AuditLog&& other) noexcept -> AuditLog&;
    ~AuditLog();

    // Appends one record (one write, then fdatasync if configured). On
    // failure the chain does not advance and the caller decides whether to
    // go on; a write that failed part way leaves a line that verification
    // will report, which is the evidence it should leave.
    auto append(const AuditRecord& record) -> std::expected<void, AuditError>;

    [[nodiscard]] auto tail() const noexcept -> const AuditTail& { return _tail; }

private:
    AuditLog(int fd, AuditTail tail, Options options) noexcept;

    int _fd{-1};
    AuditTail _tail;
    Options _options;
};

}  // namespace ak::helm
