// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ControllerLink record framing (.kiro/specs/controller-interface/
// Requirement 2, design "ControllerLink"). The mTLS stream between the
// controller and one helm is a sequence of records:
//
//   0x00  length    u32  payload bytes after this 8-byte header
//   0x04  type      u16  RecordType
//   0x06  reserved  u16  zero
//   0x08  payload
//
//   type          direction            payload
//   hello         helm -> controller   server_id u64 | boot_id u64; first on
//                                      every connection
//   envelope      controller -> helm   an Envelope (envelope.hpp)
//   map_update    controller -> helm   a MapUpdate (map_update.hpp)
//   group_policy  controller -> helm   a GroupPolicy (group_policy.hpp)
//   report        helm -> controller   a Report (report.hpp)
//   report_ack    controller -> helm   server_id u64 | report_seq u64: every
//                                      report up to report_seq is processed
//   tunnel_peers  controller -> helm   a TunnelPeers frame (tunnel_peers.hpp)
//
// Report sequence numbers restart when helm reboots, so they are only
// meaningful together with the boot ID: hello names it before any report,
// and every report and ack on the connection belongs to that boot. The
// controller drops a report whose (boot_id, report_seq) it has already
// processed, which makes helm's replay after a reconnect idempotent.
//
// The framing only delimits; the receiver decodes each payload with its own
// strict decoder and refuses a record that arrived in the wrong direction.
// A record longer than max_record_payload ends the connection before its
// payload is buffered, so a peer cannot make the other side allocate more
// than one maximum-size frame.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/envelope.hpp"
#include "proto/group_policy.hpp"
#include "proto/map_update.hpp"
#include "proto/report.hpp"
#include "proto/tunnel_peers.hpp"

namespace ak::proto {

inline constexpr std::size_t record_header_size = 8;
inline constexpr std::size_t report_ack_size = 16;
inline constexpr std::size_t hello_size = 16;
inline constexpr std::size_t max_record_payload =
    std::max({envelope_size, max_map_update_size, max_report_size, report_ack_size, hello_size,
              group_policy_size, max_tunnel_peers_size});

// Values are part of the wire protocol: never renumber.
enum class RecordType : std::uint16_t {
    envelope = 1,
    map_update = 2,
    report = 3,
    report_ack = 4,
    hello = 5,
    group_policy = 6,
    tunnel_peers = 7,
};

struct Record {
    RecordType type{RecordType::envelope};
    std::vector<std::byte> payload;
    friend auto operator==(const Record&, const Record&) -> bool = default;
};

struct Hello {
    std::uint64_t server_id{0};
    std::uint64_t boot_id{0};
    friend auto operator==(const Hello&, const Hello&) -> bool = default;
};

struct ReportAck {
    std::uint64_t server_id{0};
    std::uint64_t report_seq{0};
    friend auto operator==(const ReportAck&, const ReportAck&) -> bool = default;
};

namespace detail {

[[nodiscard]] constexpr auto known(RecordType t) noexcept -> bool {
    return t >= RecordType::envelope && t <= RecordType::tunnel_peers;
}

}  // namespace detail

// Frames one record. Fails for an unknown type or an oversized payload.
[[nodiscard]] inline auto encode_record(RecordType type, std::span<const std::byte> payload)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (!detail::known(type)) {
        return std::unexpected(DecodeError::bad_record_type);
    }
    if (payload.size() > max_record_payload) {
        return std::unexpected(DecodeError::record_too_large);
    }
    std::vector<std::byte> out;
    out.reserve(record_header_size + payload.size());
    wire::Writer w{out};
    w.le32(static_cast<std::uint32_t>(payload.size()));
    w.le16(static_cast<std::uint16_t>(type));
    w.le16(0);
    w.bytes(payload);
    return out;
}

[[nodiscard]] inline auto encode_report_ack(const ReportAck& ack)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (ack.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (ack.report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    std::vector<std::byte> out;
    wire::Writer w{out};
    w.le64(ack.server_id);
    w.le64(ack.report_seq);
    return out;
}

[[nodiscard]] inline auto decode_report_ack(std::span<const std::byte> bytes) noexcept
    -> std::expected<ReportAck, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto report_seq = r.le64();
    if (!server_id || !report_seq) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (*report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    return ReportAck{.server_id = *server_id, .report_seq = *report_seq};
}

[[nodiscard]] inline auto encode_hello(const Hello& hello)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (hello.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (hello.boot_id == 0) {
        return std::unexpected(DecodeError::bad_boot_id);
    }
    std::vector<std::byte> out;
    wire::Writer w{out};
    w.le64(hello.server_id);
    w.le64(hello.boot_id);
    return out;
}

[[nodiscard]] inline auto decode_hello(std::span<const std::byte> bytes) noexcept
    -> std::expected<Hello, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto boot_id = r.le64();
    if (!server_id || !boot_id) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (*boot_id == 0) {
        return std::unexpected(DecodeError::bad_boot_id);
    }
    return Hello{.server_id = *server_id, .boot_id = *boot_id};
}

// Incremental record parser for a byte stream. Feed it whatever the socket
// returned, then call next() until it yields nothing. After any error the
// stream is out of sync and the connection must be closed; the decoder
// keeps returning that error.
class RecordDecoder {
public:
    auto feed(std::span<const std::byte> bytes) -> void {
        if (!_error) {
            _buffer.insert(_buffer.end(), bytes.begin(), bytes.end());
        }
    }

    // A complete record, std::nullopt when more bytes are needed, or the
    // error that broke the stream.
    [[nodiscard]] auto next() -> std::expected<std::optional<Record>, DecodeError> {
        if (_error) {
            return std::unexpected(*_error);
        }
        const auto avail = std::span<const std::byte>{_buffer}.subspan(_start);
        wire::Reader r{avail};
        auto length = r.le32();
        auto type = r.le16();
        auto reserved = r.le16();
        if (!length || !type || !reserved) {
            return std::optional<Record>{};
        }
        if (*reserved != 0) {
            return fail(DecodeError::reserved_not_zero);
        }
        if (!detail::known(static_cast<RecordType>(*type))) {
            return fail(DecodeError::bad_record_type);
        }
        if (*length > max_record_payload) {
            return fail(DecodeError::record_too_large);
        }
        auto payload = r.bytes(*length);
        if (!payload) {
            return std::optional<Record>{};
        }
        Record rec{.type = static_cast<RecordType>(*type),
                   .payload = {payload->begin(), payload->end()}};
        _start += record_header_size + *length;
        compact();
        return std::optional<Record>{std::move(rec)};
    }

    // Bytes received but not yet returned as a record.
    [[nodiscard]] auto buffered() const noexcept -> std::size_t { return _buffer.size() - _start; }

private:
    auto fail(DecodeError e) -> std::expected<std::optional<Record>, DecodeError> {
        _error = e;
        _buffer.clear();
        _start = 0;
        return std::unexpected(e);
    }

    // Drops consumed bytes once they are at least half the buffer, so
    // compaction is amortized O(1) per byte.
    auto compact() -> void {
        if (_start == _buffer.size()) {
            _buffer.clear();
            _start = 0;
        } else if (_start * 2 >= _buffer.size()) {
            _buffer.erase(_buffer.begin(), _buffer.begin() + static_cast<std::ptrdiff_t>(_start));
            _start = 0;
        }
    }

    std::vector<std::byte> _buffer;
    std::size_t _start{0};
    std::optional<DecodeError> _error;
};

}  // namespace ak::proto
