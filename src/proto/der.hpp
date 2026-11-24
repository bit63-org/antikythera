// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Outer framing of DER certificates and certificate requests carried in
// controller frames (.kiro/specs/block-volume-service/ task 12,
// enrollment). src/proto/ does not parse X.509: the role that installs a
// certificate and the controller that signs a request parse them with a
// real X.509 library. These checks only make sure a field is what it
// claims to be at the outermost level, so neither side buffers or forwards
// arbitrary bytes: one or more DER SEQUENCEs (tag 0x30, definite length in
// its shortest form, at most three length octets), back to back, filling
// the field exactly.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "common/wire.hpp"
#include "proto/codec.hpp"

namespace ak::proto {

// Counts the DER SEQUENCEs that make up `bytes`, refusing an empty field,
// anything that is not a SEQUENCE, a non-minimal or indefinite length, a
// length past the end, or more than `max_count` of them.
[[nodiscard]] inline auto der_sequences(std::span<const std::byte> bytes,
                                        std::size_t max_count) noexcept
    -> std::expected<std::size_t, DecodeError> {
    wire::Reader r{bytes};
    std::size_t count = 0;
    while (r.remaining() != 0) {
        if (count == max_count) {
            return std::unexpected(DecodeError::bad_der);
        }
        auto tag = r.u8();
        auto first = r.u8();
        if (!tag || !first || *tag != 0x30) {
            return std::unexpected(DecodeError::bad_der);
        }
        std::size_t len = *first;
        if (*first >= 0x80) {
            const std::size_t octets = *first & 0x7FU;
            if (octets == 0 || octets > 3) {  // indefinite, or longer than 16 MiB
                return std::unexpected(DecodeError::bad_der);
            }
            len = 0;
            for (std::size_t i = 0; i < octets; ++i) {
                auto b = r.u8();
                if (!b || (i == 0 && *b == 0)) {  // a leading zero octet is not minimal
                    return std::unexpected(DecodeError::bad_der);
                }
                len = (len << 8U) | *b;
            }
            if (len < 0x80) {  // fits the short form
                return std::unexpected(DecodeError::bad_der);
            }
        }
        if (!r.bytes(len)) {
            return std::unexpected(DecodeError::bad_der);
        }
        ++count;
    }
    if (count == 0) {
        return std::unexpected(DecodeError::bad_der);
    }
    return count;
}

}  // namespace ak::proto
