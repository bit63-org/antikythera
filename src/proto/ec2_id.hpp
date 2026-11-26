// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// EC2 resource IDs from the 64-bit IDs antikythera carries
// (.kiro/specs/vpc-subnets-routing/ design "Metadata"; kythira
// ec2-compatible-api design "Identifiers"): the prefix, `0`, then the ID as
// 16 lower-case hex digits, so the result has EC2's 17-digit shape and
// decodes back to the same ID. Both repositories use this one definition.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ak::proto {

inline constexpr std::size_t ec2_id_digits = 17;

// `prefix` includes its hyphen, e.g. "subnet-".
[[nodiscard]] inline auto ec2_id(std::string_view prefix, std::uint64_t id) -> std::string {
    constexpr std::string_view hex = "0123456789abcdef";
    constexpr unsigned nibble_bits = 4;
    std::string out{prefix};
    out.push_back('0');
    for (unsigned shift = 64; shift > 0;) {
        shift -= nibble_bits;
        out.push_back(hex[(id >> shift) & 0xFU]);
    }
    return out;
}

// The ID `text` renders, if it is `prefix` followed by `0` and 16
// lower-case hex digits.
[[nodiscard]] inline auto parse_ec2_id(std::string_view prefix, std::string_view text) noexcept
    -> std::optional<std::uint64_t> {
    constexpr unsigned nibble_bits = 4;
    constexpr unsigned ten = 10;
    if (text.size() != prefix.size() + ec2_id_digits || !text.starts_with(prefix) ||
        text[prefix.size()] != '0') {
        return std::nullopt;
    }
    std::uint64_t id = 0;
    for (const char c : text.substr(prefix.size() + 1)) {
        unsigned v = 0;
        if (c >= '0' && c <= '9') {
            v = static_cast<unsigned>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v = static_cast<unsigned>(c - 'a') + ten;
        } else {
            return std::nullopt;
        }
        id = (id << nibble_bits) | v;
    }
    return id;
}

}  // namespace ak::proto
