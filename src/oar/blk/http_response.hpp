// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The head of an HTTP/1.1 response from an object store
// (.kiro/specs/oar-blk-data-plane/ Requirements 8.9 and 8.11): status line
// and the few headers S3ObjectStore relies on. The store is untrusted, so
// this parser is strict and fuzzed (fuzz/fuzz_http_response.cpp):
//
//   - the head is at most max_response_head bytes and ends at the first
//     CRLF CRLF; bare LF line endings and obsolete line folding are refused;
//   - the status line is "HTTP/1.x NNN reason";
//   - Content-Length is decimal digits only, at most once (a repeat with
//     the same value is tolerated, as RFC 9110 allows);
//   - Content-Range is "bytes first-last/total" or "bytes first-last/*";
//   - any Transfer-Encoding is refused: bodies must be length-delimited;
//   - "Connection: close" is noted so the connection is not reused.
//
// Header names compare case-insensitively; other headers are skipped but
// must still be well-formed ("name: value", name a token).

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

namespace ak::oar::blk {

inline constexpr std::size_t max_response_head = 16U * 1024U;

struct ContentRange {
    std::uint64_t first{0};
    std::uint64_t last{0};               // inclusive
    std::optional<std::uint64_t> total;  // "*" when unknown

    friend auto operator==(const ContentRange&, const ContentRange&) -> bool = default;
};

struct ResponseHead {
    unsigned status{0};
    std::optional<std::uint64_t> content_length;
    std::optional<ContentRange> content_range;
    bool close{false};          // Connection: close, or HTTP/1.0
    std::size_t head_bytes{0};  // up to and including the blank line
};

enum class HttpError : std::uint8_t {
    incomplete,  // no blank line yet: read more
    too_large,   // no blank line within max_response_head
    bad_status_line,
    bad_header,          // malformed line, bare LF, folding, bad name
    bad_content_length,  // not digits, overflow, or two different values
    bad_content_range,
    transfer_encoding,  // chunked or any other coding
};

[[nodiscard]] auto to_string(HttpError e) noexcept -> const char*;

// Parses the head at the start of `bytes` (more may follow: the body).
[[nodiscard]] auto parse_response_head(std::span<const std::byte> bytes)
    -> std::expected<ResponseHead, HttpError>;

[[nodiscard]] auto parse_content_range(std::string_view value)
    -> std::expected<ContentRange, HttpError>;

}  // namespace ak::oar::blk
