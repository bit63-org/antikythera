// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A token bucket for rate limits (.kiro/specs/block-volume-service/
// Requirement 10.2): refills at `rate` tokens per second up to `depth`.
// An operation may start whenever the bucket is not in debt and then
// takes its whole cost, so one larger than the depth still goes, and the
// debt it leaves delays the next. The initiator shapes a volume's traffic
// with it; the primary enforces the same limits with some slack.

#include <algorithm>
#include <chrono>

namespace ak {

class TokenBucket {
public:
    using Clock = std::chrono::steady_clock;

    TokenBucket() = default;
    TokenBucket(double rate_per_s, double depth, Clock::time_point now) noexcept
        : _rate{rate_per_s}, _depth{depth}, _tokens{depth}, _last{now} {}

    auto refill(Clock::time_point now) noexcept -> void {
        if (now > _last) {
            const double s = std::chrono::duration<double>(now - _last).count();
            _tokens = std::min(_depth, _tokens + (s * _rate));
            _last = now;
        }
    }
    [[nodiscard]] auto ready() const noexcept -> bool { return _tokens >= 0.0; }
    auto take(double n) noexcept -> void { _tokens -= n; }
    // How long after the last refill until ready() (zero if it is).
    [[nodiscard]] auto wait() const noexcept -> Clock::duration {
        if (_tokens >= 0.0 || _rate <= 0.0) {
            return Clock::duration::zero();
        }
        return std::chrono::ceil<Clock::duration>(std::chrono::duration<double>(-_tokens / _rate));
    }
    [[nodiscard]] auto tokens() const noexcept -> double { return _tokens; }

private:
    double _rate{0.0};
    double _depth{0.0};
    double _tokens{0.0};
    Clock::time_point _last{};
};

}  // namespace ak
