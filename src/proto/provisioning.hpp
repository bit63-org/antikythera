// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Provisioning: the measured file helm puts beside hull's UKI in the boot
// function, telling one boot of the host who it is and where its replay
// protection starts (.kiro/specs/cold-start/ Requirement 6, task 3;
// design "Why a boot epoch").
//
// hull refuses a command whose sequence number is not above the last one
// it accepted, but it has no disk: every boot starts from nothing, so an
// envelope captured before a power cycle could be replayed after it. helm
// records the last sequence number it relayed in its sealed store before
// relaying each command, and passes it here as `sequence_floor`; hull
// accepts only sequence numbers above it. `boot_epoch` is the secure
// element's counter, advanced before every host boot, so each boot is
// numbered and two boots never share one.
//
// The file is measured with the rest of the boot function, so the host
// cannot pick its own floor without changing its measurement.
//
// Layout (little-endian, fixed 0x20 bytes):
//   0x00  magic           u32  'AKPV'
//   0x04  version         u16  frame format version (1)
//   0x06  reserved        u16  zero
//   0x08  server_id       u64  this server; non-zero
//   0x10  boot_epoch      u64  the secure element's boot counter; non-zero
//   0x18  sequence_floor  u64  last command sequence number helm relayed;
//                              0 if none ever was
//
// hull also still reads the older provisioning file that holds only the
// server ID in decimal (hull/host_setup.hpp); a file that starts with this
// magic is this frame.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"

namespace ak::proto {

inline constexpr std::uint32_t provisioning_magic = 0x5650'4B41;  // "AKPV" as little-endian bytes
inline constexpr std::uint16_t provisioning_version = 1;
inline constexpr std::size_t provisioning_size = 0x20;

struct Provisioning {
    std::uint64_t server_id{0};
    std::uint64_t boot_epoch{0};
    std::uint64_t sequence_floor{0};
    friend auto operator==(const Provisioning&, const Provisioning&) -> bool = default;
};

// Whether `bytes` claims to be a Provisioning frame (starts with its magic).
[[nodiscard]] inline auto is_provisioning_frame(std::span<const std::byte> bytes) noexcept -> bool {
    wire::Reader r{bytes};
    return r.le32().value_or(0) == provisioning_magic;
}

namespace detail {

[[nodiscard]] inline auto check_provisioning(const Provisioning& p) noexcept
    -> std::expected<void, DecodeError> {
    if (p.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (p.boot_epoch == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    return {};
}

}  // namespace detail

[[nodiscard]] inline auto decode_provisioning(std::span<const std::byte> bytes)
    -> std::expected<Provisioning, DecodeError> {
    if (bytes.size() < provisioning_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (bytes.size() > provisioning_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    // The length is exact, so these reads cannot fail.
    wire::Reader r{bytes};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    const bool zero = r.le16().value_or(1) == 0;
    Provisioning p;
    p.server_id = r.le64().value_or(0);
    p.boot_epoch = r.le64().value_or(0);
    p.sequence_floor = r.le64().value_or(0);
    if (magic != provisioning_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (version != provisioning_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = detail::check_provisioning(p); !ok) {
        return std::unexpected(ok.error());
    }
    return p;
}

[[nodiscard]] inline auto encode_provisioning(const Provisioning& p)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = detail::check_provisioning(p); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(provisioning_size);
    wire::Writer w{out};
    w.le32(provisioning_magic);
    w.le16(provisioning_version);
    w.le16(0);
    w.le64(p.server_id);
    w.le64(p.boot_epoch);
    w.le64(p.sequence_floor);
    return out;
}

}  // namespace ak::proto
