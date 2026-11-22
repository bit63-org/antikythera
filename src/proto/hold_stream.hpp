// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Splits a TLS byte stream into whole hold frames (hold_wire.hpp), for
// both ends of a hold session: the hold node and oar-blk's initiator.

#include <cstddef>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include "proto/codec.hpp"
#include "proto/hold_wire.hpp"

namespace ak::proto {

// Checks each header as soon as it is complete, so a bad length is
// refused before anything is buffered for it.
class FrameAssembler {
public:
    auto feed(std::span<const std::byte> bytes) -> void {
        _buf.insert(_buf.end(), bytes.begin(), bytes.end());
    }

    // The next whole frame, nothing yet, or a header that does not decode.
    [[nodiscard]] auto next() -> std::expected<std::optional<std::vector<std::byte>>, DecodeError> {
        if (_buf.size() < hold_header_size) {
            return std::nullopt;
        }
        const auto header = decode_hold_header(std::span{_buf}.first(hold_header_size));
        if (!header) {
            return std::unexpected(header.error());
        }
        const std::size_t total = hold_header_size + header->payload_len;
        if (_buf.size() < total) {
            return std::nullopt;
        }
        const auto end = _buf.begin() + static_cast<std::ptrdiff_t>(total);
        std::vector<std::byte> frame{_buf.begin(), end};
        _buf.erase(_buf.begin(), end);
        return frame;
    }

    [[nodiscard]] auto buffered() const noexcept -> std::size_t { return _buf.size(); }

private:
    std::vector<std::byte> _buf;
};

}  // namespace ak::proto
