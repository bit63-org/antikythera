// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/http_response.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include "common/wire.hpp"

namespace ak::oar::blk {

namespace {

namespace wire = ak::wire;

constexpr std::array<std::byte, 4> blank_line{std::byte{'\r'}, std::byte{'\n'}, std::byte{'\r'},
                                              std::byte{'\n'}};
constexpr unsigned ten = 10;

auto view(std::span<const std::byte> b) -> std::string_view {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

auto lower(char c) -> char {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() &&
           std::ranges::equal(a, b, [](char x, char y) { return lower(x) == lower(y); });
}

auto is_digit(char c) -> bool {
    return c >= '0' && c <= '9';
}

// RFC 9110 tchar.
auto is_token_char(char c) -> bool {
    static constexpr std::string_view extra = "!#$%&'*+-.^_`|~";
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           extra.find(c) != std::string_view::npos;
}

auto trim(std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

// Decimal digits only, no sign, no overflow.
auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    if (s.empty() || s.size() > std::numeric_limits<std::uint64_t>::digits10 + 1) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : s) {
        if (!is_digit(c)) {
            return std::nullopt;
        }
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (std::numeric_limits<std::uint64_t>::max() - d) / ten) {
            return std::nullopt;
        }
        v = (v * ten) + d;
    }
    return v;
}

// Next CRLF-terminated line from `r`, without the CRLF; a bare CR or LF
// is malformed.
auto next_line(wire::Reader& r) -> std::expected<std::string_view, HttpError> {
    const auto rest = r.rest();
    std::size_t n = 0;
    while (n < rest.size() && rest[n] != std::byte{'\r'} && rest[n] != std::byte{'\n'}) {
        ++n;
    }
    if (n + 1 >= rest.size() || rest[n] != std::byte{'\r'} || rest[n + 1] != std::byte{'\n'}) {
        return std::unexpected(HttpError::bad_header);
    }
    const auto line = r.bytes(n);
    if (!line || !r.skip(2)) {
        return std::unexpected(HttpError::bad_header);
    }
    return view(*line);
}

auto parse_status(std::string_view line, ResponseHead& head) -> bool {
    // "HTTP/1.x NNN" then optionally " reason".
    constexpr std::size_t prefix = 9;  // "HTTP/1.x "
    constexpr std::size_t code_end = prefix + 3;
    if (line.size() < code_end || line.substr(0, 7) != "HTTP/1." ||
        (line[7] != '0' && line[7] != '1') || line[8] != ' ' ||
        (line.size() > code_end && line[code_end] != ' ')) {
        return false;
    }
    const auto code = parse_u64(line.substr(prefix, 3));
    constexpr std::uint64_t min_status = 100;
    if (!code || *code < min_status) {
        return false;
    }
    head.status = static_cast<unsigned>(*code);
    head.close = line[7] == '0';
    return true;
}

}  // namespace

auto to_string(HttpError e) noexcept -> const char* {
    switch (e) {
        case HttpError::incomplete:
            return "incomplete";
        case HttpError::too_large:
            return "too_large";
        case HttpError::bad_status_line:
            return "bad_status_line";
        case HttpError::bad_header:
            return "bad_header";
        case HttpError::bad_content_length:
            return "bad_content_length";
        case HttpError::bad_content_range:
            return "bad_content_range";
        case HttpError::transfer_encoding:
            return "transfer_encoding";
    }
    return "unknown";
}

auto parse_content_range(std::string_view value) -> std::expected<ContentRange, HttpError> {
    constexpr std::string_view unit = "bytes ";
    if (value.substr(0, unit.size()) != unit) {
        return std::unexpected(HttpError::bad_content_range);
    }
    value.remove_prefix(unit.size());
    const auto dash = value.find('-');
    const auto slash = value.find('/');
    if (dash == std::string_view::npos || slash == std::string_view::npos || slash < dash) {
        return std::unexpected(HttpError::bad_content_range);
    }
    const auto first = parse_u64(value.substr(0, dash));
    const auto last = parse_u64(value.substr(dash + 1, slash - dash - 1));
    const std::string_view total_text = value.substr(slash + 1);
    if (!first || !last || *last < *first) {
        return std::unexpected(HttpError::bad_content_range);
    }
    ContentRange range{.first = *first, .last = *last, .total = std::nullopt};
    if (total_text != "*") {
        const auto total = parse_u64(total_text);
        if (!total || *last >= *total) {
            return std::unexpected(HttpError::bad_content_range);
        }
        range.total = total;
    }
    return range;
}

auto parse_response_head(std::span<const std::byte> bytes)
    -> std::expected<ResponseHead, HttpError> {
    const auto window = bytes.first(std::min(bytes.size(), max_response_head));
    const auto found = std::ranges::search(window, blank_line);
    if (found.empty()) {
        return std::unexpected(bytes.size() >= max_response_head ? HttpError::too_large
                                                                 : HttpError::incomplete);
    }
    ResponseHead head;
    head.head_bytes = static_cast<std::size_t>(found.begin() - window.begin()) + blank_line.size();
    // The lines, each with its CRLF, but not the final blank line's CRLF.
    wire::Reader r{window.first(head.head_bytes - 2)};
    const auto status = next_line(r);
    if (!status || !parse_status(*status, head)) {
        return std::unexpected(HttpError::bad_status_line);
    }
    while (r.remaining() > 0) {
        const auto line = next_line(r);
        if (!line) {
            return std::unexpected(line.error());
        }
        const auto colon = line->find(':');
        if (colon == 0 || colon == std::string_view::npos ||
            !std::ranges::all_of(line->substr(0, colon), is_token_char)) {
            return std::unexpected(HttpError::bad_header);  // also catches folding
        }
        const std::string_view name = line->substr(0, colon);
        const std::string_view value = trim(line->substr(colon + 1));
        if (iequals(name, "content-length")) {
            const auto len = parse_u64(value);
            if (!len || (head.content_length && *head.content_length != *len)) {
                return std::unexpected(HttpError::bad_content_length);
            }
            head.content_length = len;
        } else if (iequals(name, "content-range")) {
            if (head.content_range) {
                return std::unexpected(HttpError::bad_content_range);
            }
            const auto range = parse_content_range(value);
            if (!range) {
                return std::unexpected(range.error());
            }
            head.content_range = *range;
        } else if (iequals(name, "transfer-encoding")) {
            return std::unexpected(HttpError::transfer_encoding);
        } else if (iequals(name, "connection")) {
            if (iequals(value, "close")) {
                head.close = true;
            }
        }
    }
    return head;
}

}  // namespace ak::oar::blk
