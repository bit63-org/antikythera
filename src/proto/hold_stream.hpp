// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Splits a TLS byte stream into whole hold frames, for both ends of a
// hold session: the hold node and oar-blk's initiator. An assembler is for
// one version, fixed when it is made (a session never changes version):
// version 1 (hold_wire.hpp, the default) or version 2 (hold_wire_v2.hpp,
// khold); a frame of the other version is a header that does not decode.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include "proto/codec.hpp"
#include "proto/hold_wire.hpp"
#include "proto/hold_wire_v2.hpp"

namespace ak::proto {

// Checks each header as soon as it is complete, so a bad length is
// refused before anything is buffered for it.
class FrameAssembler {
public:
    FrameAssembler() = default;
    // `version` is hold_version or hold_v2_version.
    explicit FrameAssembler(std::uint8_t version) noexcept : _version{version} {}

    auto feed(std::span<const std::byte> bytes) -> void {
        _buf.insert(_buf.end(), bytes.begin(), bytes.end());
    }

    // The next whole frame, nothing yet, or a header that does not decode.
    [[nodiscard]] auto next() -> std::expected<std::optional<std::vector<std::byte>>, DecodeError> {
        const bool v2 = _version == hold_v2_version;
        const std::size_t header_size = v2 ? hold_v2_header_size : hold_header_size;
        if (_buf.size() < header_size) {
            return std::nullopt;
        }
        const auto head = std::span{_buf}.first(header_size);
        std::size_t payload = 0;
        if (v2) {
            const auto header = decode_hold_v2_header(head);
            if (!header) {
                return std::unexpected(header.error());
            }
            payload = header->payload_len;
        } else {
            const auto header = decode_hold_header(head);
            if (!header) {
                return std::unexpected(header.error());
            }
            payload = header->payload_len;
        }
        const std::size_t total = header_size + payload;
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
    std::uint8_t _version{hold_version};
    std::vector<std::byte> _buf;
};

}  // namespace ak::proto
