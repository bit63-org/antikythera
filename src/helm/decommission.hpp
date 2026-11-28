// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A decommission in progress, as helm keeps it in the sealed store
// (.kiro/specs/server-provisioning/ Requirement 5, task 5), so a server
// that loses power part-way resumes it at the next boot before doing
// anything else (5.5).
//
// The order of the work (design "Decommission order"):
//
//   keys      every VM key, then the secure element's master key: once
//             it is gone every volume on the server is unreadable, so an
//             interrupted decommission already leaves no readable data
//   media     each storage role sanitizes its drives (the oar sanitize
//             request) and helm reports every drive's result by serial
//   identity  helm reports identity_cleared, forgets its identity
//             baseline, and ak-helm removes its TLS keys and destroys
//             the sealed store (and this record with it)
//
// The object (`helm.decommission`, little-endian):
//
//   0  magic u32 ('AKDP') | 4  version u16 (1) | 6  phase u8 | 7  reserved u8
//   8  the controller's decommission frame [proto::decommission_size]
//
// The frame is kept whole so its signature is checked again on resume.

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include "proto/host_lifecycle.hpp"

namespace ak::helm {

inline constexpr std::string_view decommission_object = "helm.decommission";
inline constexpr std::uint32_t decommission_state_magic = 0x5044'4B41;  // "AKDP" as LE bytes
inline constexpr std::uint16_t decommission_state_version = 1;
inline constexpr std::size_t decommission_state_size = 8 + proto::decommission_size;

enum class DecommissionPhase : std::uint8_t {
    keys = 1,
    media = 2,
    identity = 3,
};

[[nodiscard]] auto to_string(DecommissionPhase p) noexcept -> const char*;

struct DecommissionState {
    DecommissionPhase phase{DecommissionPhase::keys};
    std::vector<std::byte> frame;  // exactly proto::decommission_size bytes
    friend auto operator==(const DecommissionState&, const DecommissionState&) -> bool = default;
};

enum class DecommissionStateError : std::uint8_t {
    wrong_size,
    bad_magic,
    bad_version,
    bad_phase,
    reserved_not_zero,
};

[[nodiscard]] auto encode_decommission_state(const DecommissionState& s)
    -> std::expected<std::vector<std::byte>, DecommissionStateError>;
[[nodiscard]] auto decode_decommission_state(std::span<const std::byte> bytes)
    -> std::expected<DecommissionState, DecommissionStateError>;

}  // namespace ak::helm
