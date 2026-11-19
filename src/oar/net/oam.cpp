// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/oam.hpp"

#include "common/wire.hpp"

namespace ak::oar::net::oam {

namespace {

constexpr std::uint8_t flag_oam = 0x80;  // Geneve byte 1: O bit; C and the rest clear
constexpr std::uint8_t first_byte = 0;   // Ver = 0, Opt Len = 0
constexpr std::uint16_t reserved = 0;

}  // namespace

auto to_string(OamError e) noexcept -> const char* {
    switch (e) {
        case OamError::not_oam:
            return "not_oam";
        case OamError::bad_protocol:
            return "bad_protocol";
        case OamError::nonzero_vni:
            return "nonzero_vni";
        case OamError::truncated:
            return "truncated";
        case OamError::bad_version:
            return "bad_version";
        case OamError::unknown_type:
            return "unknown_type";
        case OamError::trailing_bytes:
            return "trailing_bytes";
    }
    return "unknown";
}

auto encode(const Message& message) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(message_size);
    wire::Writer w{out};
    w.u8(first_byte);
    w.u8(flag_oam);
    w.be16(protocol);
    w.be32(0);  // VNI 0, reserved byte 0
    w.u8(version);
    w.u8(static_cast<std::uint8_t>(message.type));
    w.be16(reserved);
    w.be64(message.sequence);
    return out;
}

auto parse(const geneve::Packet& packet) noexcept -> std::expected<Message, OamError> {
    if (!packet.oam) {
        return std::unexpected(OamError::not_oam);
    }
    if (packet.protocol != protocol) {
        return std::unexpected(OamError::bad_protocol);
    }
    if (packet.vni != 0) {
        return std::unexpected(OamError::nonzero_vni);
    }
    wire::Reader r{packet.inner};
    auto ver = r.u8();
    auto type = r.u8();
    auto skipped = r.skip(sizeof(reserved));
    auto sequence = r.be64();
    if (!ver || !type || !skipped || !sequence) {
        return std::unexpected(OamError::truncated);
    }
    if (*ver != version) {
        return std::unexpected(OamError::bad_version);
    }
    if (*type != static_cast<std::uint8_t>(Type::keepalive)) {
        return std::unexpected(OamError::unknown_type);
    }
    if (r.remaining() != 0) {
        return std::unexpected(OamError::trailing_bytes);
    }
    return Message{.type = Type::keepalive, .sequence = *sequence};
}

}  // namespace ak::oar::net::oam
