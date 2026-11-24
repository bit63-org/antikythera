// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/json.hpp"

#include <algorithm>
#include <charconv>

namespace ak::hull::json {

namespace {

class Parser {
public:
    explicit Parser(std::string_view text) noexcept : _s{text} {}

    auto document() -> std::expected<Value, JsonError> {
        skip_ws();
        auto v = value(0);
        if (!v) {
            return v;
        }
        skip_ws();
        if (_pos != _s.size()) {
            return std::unexpected(JsonError::trailing_data);
        }
        return v;
    }

private:
    [[nodiscard]] auto at_end() const noexcept -> bool { return _pos >= _s.size(); }
    [[nodiscard]] auto peek() const noexcept -> char { return at_end() ? '\0' : _s[_pos]; }

    auto skip_ws() noexcept -> void {
        while (!at_end()) {
            const char c = _s[_pos];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            ++_pos;
        }
    }

    auto literal(std::string_view word) noexcept -> bool {
        if (_s.substr(_pos, word.size()) != word) {
            return false;
        }
        _pos += word.size();
        return true;
    }

    auto value(std::size_t depth) -> std::expected<Value, JsonError> {
        if (depth >= max_depth) {
            return std::unexpected(JsonError::too_deep);
        }
        switch (peek()) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"': {
                auto s = string();
                if (!s) {
                    return std::unexpected(s.error());
                }
                return Value{std::move(*s)};
            }
            case 't':
                if (literal("true")) {
                    return Value{true};
                }
                return std::unexpected(JsonError::syntax);
            case 'f':
                if (literal("false")) {
                    return Value{false};
                }
                return std::unexpected(JsonError::syntax);
            case 'n':
                if (literal("null")) {
                    return Value{nullptr};
                }
                return std::unexpected(JsonError::syntax);
            default:
                if (peek() == '-' || (peek() >= '0' && peek() <= '9')) {
                    return number();
                }
                return std::unexpected(JsonError::syntax);
        }
    }

    auto object(std::size_t depth) -> std::expected<Value, JsonError> {
        ++_pos;  // '{'
        Object members;
        skip_ws();
        if (peek() == '}') {
            ++_pos;
            return Value{std::move(members)};
        }
        for (;;) {
            skip_ws();
            if (peek() != '"') {
                return std::unexpected(JsonError::syntax);
            }
            auto key = string();
            if (!key) {
                return std::unexpected(key.error());
            }
            if (std::ranges::any_of(members, [&](const Member& m) { return m.key == *key; })) {
                return std::unexpected(JsonError::duplicate_key);
            }
            skip_ws();
            if (peek() != ':') {
                return std::unexpected(JsonError::syntax);
            }
            ++_pos;
            skip_ws();
            auto v = value(depth + 1);
            if (!v) {
                return v;
            }
            members.push_back(Member{.key = std::move(*key), .value = std::move(*v)});
            skip_ws();
            if (peek() == ',') {
                ++_pos;
                continue;
            }
            if (peek() == '}') {
                ++_pos;
                return Value{std::move(members)};
            }
            return std::unexpected(JsonError::syntax);
        }
    }

    auto array(std::size_t depth) -> std::expected<Value, JsonError> {
        ++_pos;  // '['
        Array items;
        skip_ws();
        if (peek() == ']') {
            ++_pos;
            return Value{std::move(items)};
        }
        for (;;) {
            skip_ws();
            auto v = value(depth + 1);
            if (!v) {
                return v;
            }
            items.push_back(std::move(*v));
            skip_ws();
            if (peek() == ',') {
                ++_pos;
                continue;
            }
            if (peek() == ']') {
                ++_pos;
                return Value{std::move(items)};
            }
            return std::unexpected(JsonError::syntax);
        }
    }

    auto number() -> std::expected<Value, JsonError> {
        const std::size_t start = _pos;
        if (peek() == '-') {
            ++_pos;
        }
        if (peek() == '0') {
            ++_pos;
            if (peek() >= '0' && peek() <= '9') {
                return std::unexpected(JsonError::bad_number);
            }
        } else if (!digits()) {
            return std::unexpected(JsonError::bad_number);
        }
        if (peek() == '.') {
            ++_pos;
            if (!digits()) {
                return std::unexpected(JsonError::bad_number);
            }
        }
        if (peek() == 'e' || peek() == 'E') {
            ++_pos;
            if (peek() == '+' || peek() == '-') {
                ++_pos;
            }
            if (!digits()) {
                return std::unexpected(JsonError::bad_number);
            }
        }
        return Value{Number{std::string{_s.substr(start, _pos - start)}}};
    }

    auto digits() noexcept -> bool {
        const std::size_t start = _pos;
        while (peek() >= '0' && peek() <= '9') {
            ++_pos;
        }
        return _pos != start;
    }

    auto hex4() noexcept -> std::optional<std::uint32_t> {
        if (_s.size() - _pos < 4) {
            return std::nullopt;
        }
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = _s[_pos++];
            v <<= 4U;
            if (c >= '0' && c <= '9') {
                v |= static_cast<std::uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                v |= static_cast<std::uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                v |= static_cast<std::uint32_t>(c - 'A' + 10);
            } else {
                return std::nullopt;
            }
        }
        return v;
    }

    static auto put_utf8(std::string& out, std::uint32_t cp) -> void {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0U | (cp >> 6U)));
            out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0U | (cp >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
        } else {
            out.push_back(static_cast<char>(0xF0U | (cp >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
        }
    }

    // One raw (unescaped) UTF-8 sequence starting at _pos, copied to out.
    auto raw_utf8(std::string& out) noexcept -> bool {
        const auto b0 = static_cast<unsigned char>(_s[_pos]);
        std::size_t len = 0;
        std::uint32_t cp = 0;
        std::uint32_t min = 0;
        if (b0 < 0x80) {
            out.push_back(static_cast<char>(b0));
            ++_pos;
            return true;
        }
        if ((b0 & 0xE0U) == 0xC0U) {
            len = 2;
            cp = b0 & 0x1FU;
            min = 0x80;
        } else if ((b0 & 0xF0U) == 0xE0U) {
            len = 3;
            cp = b0 & 0x0FU;
            min = 0x800;
        } else if ((b0 & 0xF8U) == 0xF0U) {
            len = 4;
            cp = b0 & 0x07U;
            min = 0x10000;
        } else {
            return false;
        }
        if (_s.size() - _pos < len) {
            return false;
        }
        for (std::size_t i = 1; i < len; ++i) {
            const auto b = static_cast<unsigned char>(_s[_pos + i]);
            if ((b & 0xC0U) != 0x80U) {
                return false;
            }
            cp = (cp << 6U) | (b & 0x3FU);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        out.append(_s.substr(_pos, len));
        _pos += len;
        return true;
    }

    auto string() -> std::expected<std::string, JsonError> {
        ++_pos;  // '"'
        std::string out;
        for (;;) {
            if (at_end()) {
                return std::unexpected(JsonError::bad_string);
            }
            const char c = _s[_pos];
            if (c == '"') {
                ++_pos;
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                return std::unexpected(JsonError::bad_string);
            }
            if (c != '\\') {
                if (!raw_utf8(out)) {
                    return std::unexpected(JsonError::bad_string);
                }
                continue;
            }
            ++_pos;
            if (at_end()) {
                return std::unexpected(JsonError::bad_string);
            }
            const char e = _s[_pos++];
            switch (e) {
                case '"':
                case '\\':
                case '/':
                    out.push_back(e);
                    break;
                case 'b':
                    out.push_back('\b');
                    break;
                case 'f':
                    out.push_back('\f');
                    break;
                case 'n':
                    out.push_back('\n');
                    break;
                case 'r':
                    out.push_back('\r');
                    break;
                case 't':
                    out.push_back('\t');
                    break;
                case 'u': {
                    auto cp = hex4();
                    if (!cp) {
                        return std::unexpected(JsonError::bad_string);
                    }
                    if (*cp >= 0xDC00 && *cp <= 0xDFFF) {
                        return std::unexpected(JsonError::bad_string);  // lone low surrogate
                    }
                    if (*cp >= 0xD800 && *cp <= 0xDBFF) {
                        if (!literal("\\u")) {
                            return std::unexpected(JsonError::bad_string);
                        }
                        const auto lo = hex4();
                        if (!lo || *lo < 0xDC00 || *lo > 0xDFFF) {
                            return std::unexpected(JsonError::bad_string);
                        }
                        *cp = 0x10000 + ((*cp - 0xD800) << 10U) + (*lo - 0xDC00);
                    }
                    put_utf8(out, *cp);
                    break;
                }
                default:
                    return std::unexpected(JsonError::bad_string);
            }
        }
    }

    std::string_view _s;
    std::size_t _pos{0};
};

}  // namespace

auto to_string(JsonError e) noexcept -> const char* {
    switch (e) {
        case JsonError::too_large:
            return "too_large";
        case JsonError::too_deep:
            return "too_deep";
        case JsonError::syntax:
            return "syntax";
        case JsonError::bad_string:
            return "bad_string";
        case JsonError::bad_number:
            return "bad_number";
        case JsonError::duplicate_key:
            return "duplicate_key";
        case JsonError::trailing_data:
            return "trailing_data";
    }
    return "unknown";
}

auto Value::as_bool() const noexcept -> std::optional<bool> {
    if (const auto* b = std::get_if<bool>(&v)) {
        return *b;
    }
    return std::nullopt;
}

auto Value::as_u64() const noexcept -> std::optional<std::uint64_t> {
    const auto* n = std::get_if<Number>(&v);
    if (n == nullptr || n->text.empty() ||
        !std::ranges::all_of(n->text, [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    std::uint64_t out = 0;
    const auto* first = n->text.data();
    const auto* last = first + n->text.size();
    const auto [ptr, ec] = std::from_chars(first, last, out);
    if (ec != std::errc{} || ptr != last) {
        return std::nullopt;
    }
    return out;
}

auto Value::find(std::string_view key) const noexcept -> const Value* {
    const auto* obj = as_object();
    if (obj == nullptr) {
        return nullptr;
    }
    for (const auto& [k, val] : *obj) {
        if (k == key) {
            return &val;
        }
    }
    return nullptr;
}

auto parse(std::string_view text) -> std::expected<Value, JsonError> {
    if (text.size() > max_document) {
        return std::unexpected(JsonError::too_large);
    }
    return Parser{text}.document();
}

auto quote(std::string_view s) -> std::string {
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (u < 0x20) {
            out.append("\\u00");
            out.push_back(hex[u >> 4U]);
            out.push_back(hex[u & 0x0FU]);
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

}  // namespace ak::hull::json
