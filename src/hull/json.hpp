// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A strict, bounded JSON reader and the string escaping the agent's writers
// need (.kiro/specs/hull-host-agent/ task 8, Requirement 9.2).
//
// The agent talks JSON to exactly one peer: Cloud Hypervisor's API socket.
// That process runs a guest and is the agent's least trusted neighbour, so
// its replies are parsed as hostile input:
//
//   - documents larger than max_document bytes or nested deeper than
//     max_depth are refused before any allocation grows with them;
//   - RFC 8259 grammar only: no comments, no trailing commas, no leading
//     zeros, no NaN/Infinity, no bare control characters in strings;
//   - strings must be valid UTF-8, and escapes (including \uXXXX surrogate
//     pairs) must decode to valid scalar values;
//   - an object may not repeat a key, so there is never a question of
//     which of two values the agent believed;
//   - one value per document, surrounded only by JSON whitespace.
//
// Numbers are kept as their validated text: the agent only ever needs small
// unsigned integers out of them (as_u64), and keeping the text avoids
// rounding questions.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace ak::hull::json {

inline constexpr std::size_t max_document = 256U * 1024U;
inline constexpr std::size_t max_depth = 32;  // arrays and objects nested at most this deep

struct Value;
struct Member;
using Array = std::vector<Value>;
using Object = std::vector<Member>;  // in document order

struct Number {
    std::string text;  // grammar-checked
    friend auto operator==(const Number&, const Number&) -> bool = default;
};

struct Value {
    // No default member initializer: it would instantiate the variant while
    // Member is still incomplete. Default construction holds null anyway.
    std::variant<std::nullptr_t, bool, Number, std::string, Array, Object> v;

    [[nodiscard]] auto is_null() const noexcept -> bool {
        return std::holds_alternative<std::nullptr_t>(v);
    }
    [[nodiscard]] auto as_string() const noexcept -> const std::string* {
        return std::get_if<std::string>(&v);
    }
    [[nodiscard]] auto as_array() const noexcept -> const Array* { return std::get_if<Array>(&v); }
    [[nodiscard]] auto as_object() const noexcept -> const Object* {
        return std::get_if<Object>(&v);
    }
    [[nodiscard]] auto as_bool() const noexcept -> std::optional<bool>;
    // A non-negative integer without fraction or exponent that fits u64.
    [[nodiscard]] auto as_u64() const noexcept -> std::optional<std::uint64_t>;
    // The member `key` of an object, or nullptr (also when this is not one).
    [[nodiscard]] auto find(std::string_view key) const noexcept -> const Value*;

    friend auto operator==(const Value&, const Value&) -> bool = default;
};

struct Member {
    std::string key;
    Value value;
    friend auto operator==(const Member&, const Member&) -> bool = default;
};

enum class JsonError : std::uint8_t {
    too_large,      // more than max_document bytes
    too_deep,       // nesting beyond max_depth
    syntax,         // anything the grammar does not allow
    bad_string,     // control character, bad escape, invalid UTF-8
    bad_number,     // leading zero, missing digits, ...
    duplicate_key,  // an object names the same key twice
    trailing_data,  // something after the value
};

[[nodiscard]] auto to_string(JsonError e) noexcept -> const char*;

[[nodiscard]] auto parse(std::string_view text) -> std::expected<Value, JsonError>;

// `s` as a JSON string literal, quotes included. `s` must be valid UTF-8
// (everything the agent writes is: ASCII paths and identifiers); control
// characters, '"' and '\\' are escaped.
[[nodiscard]] auto quote(std::string_view s) -> std::string;

}  // namespace ak::hull::json
