// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Per-volume limits at the primary (.kiro/specs/block-volume-service/
// design "QoS and elasticity", Requirement 10.2). The initiator shapes the
// guest's traffic to the volume's limits; the primary enforces the same
// limits with 10 % slack, so a compromised initiator cannot take more than
// its volume's share, and a well-behaved one is never throttled by
// rounding or timing differences.
//
// Two token buckets per volume (common/token_bucket.hpp): I/Os, counted
// in 256 KiB units (a 1 MiB request is four), and MiB. Each refills at the
// baseline rate and holds up to the burst (both × 1.1).

#include <algorithm>
#include <chrono>
#include <cstdint>

#include "common/token_bucket.hpp"
#include "proto/replica_config.hpp"

namespace ak::hold {

inline constexpr std::uint64_t qos_io_unit = 256 * 1024;
inline constexpr double qos_slack = 1.1;

using ak::TokenBucket;

class VolumeLimiter {
public:
    using Clock = TokenBucket::Clock;

    VolumeLimiter() = default;
    VolumeLimiter(const proto::VolumeQos& q, Clock::time_point now) noexcept
        : _ios{q.iops * qos_slack, q.burst_iops * qos_slack, now},
          _mib{q.mib_per_s * qos_slack, q.burst_mib * qos_slack, now} {}

    [[nodiscard]] static auto io_units(std::uint64_t bytes) noexcept -> double {
        return static_cast<double>(
            std::max<std::uint64_t>(1, (bytes + qos_io_unit - 1) / qos_io_unit));
    }

    // Takes the cost of a request of `bytes` if the volume may start it.
    [[nodiscard]] auto admit(std::uint64_t bytes, Clock::time_point now) noexcept -> bool {
        _ios.refill(now);
        _mib.refill(now);
        if (!_ios.ready() || !_mib.ready()) {
            return false;
        }
        _ios.take(io_units(bytes));
        _mib.take(static_cast<double>(bytes) / (1024.0 * 1024.0));
        return true;
    }
    [[nodiscard]] auto wait() const noexcept -> Clock::duration {
        return std::max(_ios.wait(), _mib.wait());
    }

private:
    TokenBucket _ios;
    TokenBucket _mib;
};

}  // namespace ak::hold
