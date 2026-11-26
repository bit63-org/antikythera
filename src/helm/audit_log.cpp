// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/audit_log.hpp"

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <limits>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace ak::helm {

namespace {

constexpr mode_t log_mode = 0600;
constexpr mode_t group_other_bits = 0077;
constexpr std::size_t hex_digits_per_byte = 2;
constexpr std::size_t hash_hex_size = audit_hash_size * hex_digits_per_byte;
constexpr std::size_t read_chunk = 64 * 1024;
constexpr unsigned function_slot_shift = 16;
constexpr std::uint32_t function_number_mask = 0xFFFF;
constexpr int hex_base = 16;
constexpr int decimal_base = 10;
constexpr unsigned nibble_bits = 4;
constexpr unsigned nibble_mask = 0x0F;
constexpr std::string_view hex_chars = "0123456789abcdef";
constexpr std::string_view hash_prefix = " h=";

constexpr std::array event_names{
    "command_received",     "command_refused",
    "command_relayed",      "command_outcome",
    "command_timed_out",    "late_response",
    "vm_key_created",       "vm_key_destroyed",
    "volume_key_created",   "volume_key_delivered",
    "volume_key_dropped",   "volume_key_rewrapped",
    "volume_key_destroyed", "volume_key_delivery_failed",
    "eject_requested",      "eject_released",
    "detach_busy",          "detach_withdrawn",
    "conversion_started",   "conversion_failed",
    "conversion_completed",
};
static_assert(event_names.size() == static_cast<std::size_t>(AuditEvent::conversion_completed) + 1,
              "event_names must list every AuditEvent");

auto append_uint(std::string& out, std::uint64_t v, int base = decimal_base) -> void {
    std::array<char, std::numeric_limits<std::uint64_t>::digits10 + 2> buf{};
    const auto res = std::to_chars(buf.data(), buf.data() + buf.size(), v, base);
    out.append(buf.data(), res.ptr);
}

auto append_hex(std::string& out, std::span<const std::byte> bytes) -> void {
    for (const auto b : bytes) {
        const auto v = std::to_integer<unsigned>(b);
        out.push_back(hex_chars[(v >> nibble_bits) & nibble_mask]);
        out.push_back(hex_chars[v & nibble_mask]);
    }
}

// The line up to, not including, " h=".
auto format_body(std::uint64_t index, std::int64_t unix_ms, const AuditRecord& r) -> std::string {
    std::string out;
    out += "n=";
    append_uint(out, index);
    out += " t=";
    if (unix_ms < 0) {
        out += '-';
        append_uint(out, static_cast<std::uint64_t>(-(unix_ms + 1)) + 1);
    } else {
        append_uint(out, static_cast<std::uint64_t>(unix_ms));
    }
    out += " ev=";
    out += to_string(r.event);
    if (r.seq != 0) {
        out += " seq=";
        append_uint(out, r.seq);
    }
    if (r.command != 0) {
        out += " cmd=0x";
        append_uint(out, r.command, hex_base);
    }
    if (r.status) {
        out += " status=";
        append_uint(out, *r.status);
    }
    if (r.vm != 0) {
        out += " vm=";
        append_uint(out, r.vm);
    }
    if (r.volume != 0) {
        out += " vol=";
        append_uint(out, r.volume);
    }
    if (r.function) {
        const auto raw = static_cast<std::uint32_t>(*r.function);
        out += " fn=";
        append_uint(out, raw >> function_slot_shift);
        out += '.';
        append_uint(out, raw & function_number_mask);
    }
    if (r.count) {
        out += " count=";
        append_uint(out, *r.count);
    }
    return out;
}

auto chain_hash(const AuditHash& prev, std::string_view body) -> std::optional<AuditHash> {
    std::vector<std::byte> input(prev.size() + body.size());
    std::ranges::copy(prev, input.begin());
    std::ranges::transform(body, input.begin() + static_cast<std::ptrdiff_t>(prev.size()),
                           [](char c) { return static_cast<std::byte>(c); });
    AuditHash out{};
    unsigned int len = 0;
    if (EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char*>(out.data()), &len,
                   EVP_sha256(), nullptr) != 1 ||
        len != out.size()) {
        return std::nullopt;
    }
    return out;
}

// ---- parsing ---------------------------------------------------------------

// Splits "key=value" off the front of `rest`; value runs to the next space.
struct Field {
    std::string_view key;
    std::string_view value;
};

auto next_field(std::string_view& rest) -> std::optional<Field> {
    if (rest.empty()) {
        return std::nullopt;
    }
    const auto end = rest.find(' ');
    const auto token = rest.substr(0, end);
    rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
    const auto eq = token.find('=');
    if (eq == std::string_view::npos || eq == 0) {
        return std::nullopt;
    }
    return Field{token.substr(0, eq), token.substr(eq + 1)};
}

template<typename T>
auto parse_uint(std::string_view s, int base = decimal_base) -> std::optional<T> {
    if (s.empty()) {
        return std::nullopt;
    }
    T v{};
    const auto res = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (res.ec != std::errc{} || res.ptr != s.data() + s.size()) {
        return std::nullopt;
    }
    return v;
}

auto parse_event(std::string_view s) -> std::optional<AuditEvent> {
    for (std::size_t i = 0; i < event_names.size(); ++i) {
        if (s == event_names.at(i)) {
            return static_cast<AuditEvent>(i);
        }
    }
    return std::nullopt;
}

struct ParsedLine {
    std::uint64_t index{0};
    std::int64_t unix_ms{0};
    AuditRecord record;
    AuditHash hash{};
    std::string_view body;  // the line up to " h="
};

auto parse_hash(std::string_view s) -> std::optional<AuditHash> {
    if (s.size() != hash_hex_size) {
        return std::nullopt;
    }
    AuditHash out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto v = parse_uint<std::uint8_t>(
            s.substr(i * hex_digits_per_byte, hex_digits_per_byte), hex_base);
        if (!v) {
            return std::nullopt;
        }
        out.at(i) = static_cast<std::byte>(*v);
    }
    return out;
}

// Parses the fields; canonical form is checked by the caller re-formatting.
auto parse_line(std::string_view line) -> std::optional<ParsedLine> {
    const auto h = line.rfind(hash_prefix);
    if (h == std::string_view::npos) {
        return std::nullopt;
    }
    ParsedLine out;
    out.body = line.substr(0, h);
    const auto hash = parse_hash(line.substr(h + hash_prefix.size()));
    if (!hash) {
        return std::nullopt;
    }
    out.hash = *hash;

    std::string_view rest = out.body;
    const auto n = next_field(rest);
    const auto t = next_field(rest);
    const auto ev = next_field(rest);
    if (!n || !t || !ev || n->key != "n" || t->key != "t" || ev->key != "ev") {
        return std::nullopt;
    }
    const auto index = parse_uint<std::uint64_t>(n->value);
    std::int64_t unix_ms = 0;
    {
        const auto& v = t->value;
        const auto res = std::from_chars(v.data(), v.data() + v.size(), unix_ms);
        if (v.empty() || res.ec != std::errc{} || res.ptr != v.data() + v.size()) {
            return std::nullopt;
        }
    }
    const auto event = parse_event(ev->value);
    if (!index || !event) {
        return std::nullopt;
    }
    out.index = *index;
    out.unix_ms = unix_ms;
    out.record.event = *event;

    while (auto f = next_field(rest)) {
        if (f->key == "seq") {
            auto v = parse_uint<std::uint64_t>(f->value);
            if (!v) {
                return std::nullopt;
            }
            out.record.seq = *v;
        } else if (f->key == "cmd") {
            if (!f->value.starts_with("0x")) {
                return std::nullopt;
            }
            auto v = parse_uint<std::uint16_t>(f->value.substr(2), hex_base);
            if (!v) {
                return std::nullopt;
            }
            out.record.command = *v;
        } else if (f->key == "status") {
            auto v = parse_uint<std::uint16_t>(f->value);
            if (!v) {
                return std::nullopt;
            }
            out.record.status = v;
        } else if (f->key == "vm") {
            auto v = parse_uint<std::uint64_t>(f->value);
            if (!v) {
                return std::nullopt;
            }
            out.record.vm = *v;
        } else if (f->key == "vol") {
            auto v = parse_uint<std::uint64_t>(f->value);
            if (!v) {
                return std::nullopt;
            }
            out.record.volume = *v;
        } else if (f->key == "fn") {
            const auto dot = f->value.find('.');
            if (dot == std::string_view::npos) {
                return std::nullopt;
            }
            auto slot = parse_uint<std::uint16_t>(f->value.substr(0, dot));
            auto number = parse_uint<std::uint16_t>(f->value.substr(dot + 1));
            if (!slot || !number) {
                return std::nullopt;
            }
            out.record.function =
                FunctionId{(static_cast<std::uint32_t>(*slot) << function_slot_shift) | *number};
        } else if (f->key == "count") {
            auto v = parse_uint<std::uint64_t>(f->value);
            if (!v) {
                return std::nullopt;
            }
            out.record.count = v;
        } else {
            return std::nullopt;
        }
    }
    return out;
}

auto write_all(int fd, std::string_view data) -> int {
    while (!data.empty()) {
        const auto n = ::write(fd, data.data(), data.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        data.remove_prefix(static_cast<std::size_t>(n));
    }
    return 0;
}

auto system_ms() -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

auto to_string(AuditEvent e) noexcept -> const char* {
    const auto i = static_cast<std::size_t>(e);
    return i < event_names.size() ? event_names.at(i) : "unknown";
}

auto to_string(AuditErrc e) noexcept -> const char* {
    switch (e) {
        case AuditErrc::bad_line:
            return "bad_line";
        case AuditErrc::bad_index:
            return "bad_index";
        case AuditErrc::bad_hash:
            return "bad_hash";
        case AuditErrc::torn_tail:
            return "torn_tail";
        case AuditErrc::io:
            return "io";
        case AuditErrc::unsafe_file:
            return "unsafe_file";
    }
    return "unknown";
}

auto format_audit_line(const AuditTail& tail, std::int64_t unix_ms, const AuditRecord& record)
    -> std::string {
    auto line = format_body(tail.next_index, unix_ms, record);
    // SHA-256 of a small buffer fails only if OpenSSL is broken; an all-zero
    // hash then makes the line fail verification rather than pass silently.
    const auto hash = chain_hash(tail.last_hash, line).value_or(AuditHash{});
    line += hash_prefix;
    append_hex(line, hash);
    line += '\n';
    return line;
}

auto verify_audit_log(std::string_view text) -> std::expected<AuditTail, AuditError> {
    AuditTail tail;
    std::uint64_t line_no = 0;
    while (!text.empty()) {
        ++line_no;
        const auto nl = text.find('\n');
        if (nl == std::string_view::npos) {
            return std::unexpected(AuditError{.code = AuditErrc::torn_tail, .line = line_no});
        }
        const auto line = text.substr(0, nl);
        text.remove_prefix(nl + 1);

        const auto parsed = parse_line(line);
        if (!parsed) {
            return std::unexpected(AuditError{.code = AuditErrc::bad_line, .line = line_no});
        }
        if (format_body(parsed->index, parsed->unix_ms, parsed->record) != parsed->body) {
            return std::unexpected(AuditError{.code = AuditErrc::bad_line, .line = line_no});
        }
        if (parsed->index != tail.next_index) {
            return std::unexpected(AuditError{.code = AuditErrc::bad_index, .line = line_no});
        }
        const auto want = chain_hash(tail.last_hash, parsed->body);
        if (!want || *want != parsed->hash) {
            return std::unexpected(AuditError{.code = AuditErrc::bad_hash, .line = line_no});
        }
        tail.next_index = parsed->index + 1;
        tail.last_hash = parsed->hash;
    }
    return tail;
}

AuditLog::AuditLog(int fd, AuditTail tail, Options options) noexcept
    : _fd{fd}, _tail{tail}, _options{std::move(options)} {
    if (!_options.clock) {
        _options.clock = system_ms;
    }
}

AuditLog::AuditLog(AuditLog&& other) noexcept
    : _fd{std::exchange(other._fd, -1)}, _tail{other._tail}, _options{std::move(other._options)} {}

auto AuditLog::operator=(AuditLog&& other) noexcept -> AuditLog& {
    if (this != &other) {
        if (_fd >= 0) {
            (void)::close(_fd);
        }
        _fd = std::exchange(other._fd, -1);
        _tail = other._tail;
        _options = std::move(other._options);
    }
    return *this;
}

AuditLog::~AuditLog() {
    if (_fd >= 0) {
        (void)::close(_fd);
    }
}

auto AuditLog::open(const std::string& path, Options options)
    -> std::expected<AuditLog, AuditError> {
    const int fd =
        ::open(path.c_str(), O_RDWR | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, log_mode);
    if (fd < 0) {
        const int err = errno;
        return std::unexpected(AuditError{
            .code = err == ELOOP ? AuditErrc::unsafe_file : AuditErrc::io, .sys_errno = err});
    }
    auto fail = [fd](AuditError e) {
        (void)::close(fd);
        return std::unexpected(e);
    };
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return fail(AuditError{.code = AuditErrc::io, .sys_errno = errno});
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & group_other_bits) != 0) {
        return fail(AuditError{.code = AuditErrc::unsafe_file});
    }

    std::string text;
    std::array<char, read_chunk> buf{};
    off_t offset = 0;
    for (;;) {
        const auto n = ::pread(fd, buf.data(), buf.size(), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return fail(AuditError{.code = AuditErrc::io, .sys_errno = errno});
        }
        if (n == 0) {
            break;
        }
        text.append(buf.data(), static_cast<std::size_t>(n));
        offset += n;
    }
    auto tail = verify_audit_log(text);
    if (!tail) {
        return fail(tail.error());
    }
    return AuditLog{fd, *tail, std::move(options)};
}

auto AuditLog::append(const AuditRecord& record) -> std::expected<void, AuditError> {
    if (_fd < 0) {
        return std::unexpected(AuditError{.code = AuditErrc::io, .sys_errno = EBADF});
    }
    const auto line = format_audit_line(_tail, _options.clock(), record);
    if (const int err = write_all(_fd, line); err != 0) {
        return std::unexpected(AuditError{.code = AuditErrc::io, .sys_errno = err});
    }
    if (_options.sync && ::fdatasync(_fd) != 0) {
        return std::unexpected(AuditError{.code = AuditErrc::io, .sys_errno = errno});
    }
    // The line is written; advance the chain to its hash (the last 64 hex
    // digits before the newline).
    const auto hash =
        parse_hash(std::string_view{line}.substr(line.size() - 1 - hash_hex_size, hash_hex_size));
    _tail.last_hash = hash.value_or(AuditHash{});
    ++_tail.next_index;
    return {};
}

}  // namespace ak::helm
