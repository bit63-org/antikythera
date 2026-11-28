// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/decommission.hpp"

#include "common/wire.hpp"

namespace ak::helm {

namespace {

auto known(DecommissionPhase p) noexcept -> bool {
    return p >= DecommissionPhase::keys && p <= DecommissionPhase::identity;
}

}  // namespace

auto to_string(DecommissionPhase p) noexcept -> const char* {
    switch (p) {
        case DecommissionPhase::keys:
            return "keys";
        case DecommissionPhase::media:
            return "media";
        case DecommissionPhase::identity:
            return "identity";
    }
    return "unknown";
}

auto encode_decommission_state(const DecommissionState& s)
    -> std::expected<std::vector<std::byte>, DecommissionStateError> {
    if (!known(s.phase)) {
        return std::unexpected(DecommissionStateError::bad_phase);
    }
    if (s.frame.size() != proto::decommission_size) {
        return std::unexpected(DecommissionStateError::wrong_size);
    }
    std::vector<std::byte> out;
    out.reserve(decommission_state_size);
    wire::Writer w{out};
    w.le32(decommission_state_magic);
    w.le16(decommission_state_version);
    w.u8(static_cast<std::uint8_t>(s.phase));
    w.u8(0);
    w.bytes(s.frame);
    return out;
}

auto decode_decommission_state(std::span<const std::byte> bytes)
    -> std::expected<DecommissionState, DecommissionStateError> {
    if (bytes.size() != decommission_state_size) {
        return std::unexpected(DecommissionStateError::wrong_size);
    }
    wire::Reader r{bytes};
    if (r.le32().value_or(0) != decommission_state_magic) {
        return std::unexpected(DecommissionStateError::bad_magic);
    }
    if (r.le16().value_or(0) != decommission_state_version) {
        return std::unexpected(DecommissionStateError::bad_version);
    }
    DecommissionState s;
    s.phase = static_cast<DecommissionPhase>(r.u8().value_or(0));
    if (!known(s.phase)) {
        return std::unexpected(DecommissionStateError::bad_phase);
    }
    if (r.u8().value_or(1) != 0) {
        return std::unexpected(DecommissionStateError::reserved_not_zero);
    }
    const auto frame = r.bytes(proto::decommission_size).value_or(std::span<const std::byte>{});
    s.frame.assign(frame.begin(), frame.end());
    return s;
}

}  // namespace ak::helm
