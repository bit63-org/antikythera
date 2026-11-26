// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/volume_copier.hpp"

#include <openssl/crypto.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

namespace ak::oar::blk {

namespace {

auto watch(int epoll, int fd) noexcept -> bool {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    return ::epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &ev) == 0;
}

auto wipe(std::vector<std::byte>& b) noexcept -> void {
    if (!b.empty()) {
        OPENSSL_cleanse(b.data(), b.size());
    }
}

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

}  // namespace

auto to_string(CopyError e) noexcept -> const char* {
    switch (e) {
        case CopyError::no_backend:
            return "no_backend";
        case CopyError::bad_block_size:
            return "bad_block_size";
        case CopyError::bad_region:
            return "bad_region";
        case CopyError::bad_capacity:
            return "bad_capacity";
        case CopyError::wake:
            return "wake";
    }
    return "unknown";
}

auto to_string(CopyState s) noexcept -> const char* {
    switch (s) {
        case CopyState::waiting_for_keys:
            return "waiting_for_keys";
        case CopyState::copying:
            return "copying";
        case CopyState::flushing:
            return "flushing";
        case CopyState::completed:
            return "completed";
        case CopyState::failed:
            return "failed";
    }
    return "unknown";
}

auto to_string(CopyFailure f) noexcept -> const char* {
    switch (f) {
        case CopyFailure::none:
            return "none";
        case CopyFailure::source_io:
            return "source_io";
        case CopyFailure::target_io:
            return "target_io";
        case CopyFailure::not_hydrated:
            return "not_hydrated";
        case CopyFailure::out_of_range:
            return "out_of_range";
        case CopyFailure::crypto:
            return "crypto";
    }
    return "unknown";
}

// ---- creation ------------------------------------------------------------------

auto VolumeCopier::create(CopyParams params)
    -> std::expected<std::unique_ptr<VolumeCopier>, CopyError> {
    if (!params.source || !params.target) {
        return std::unexpected(CopyError::no_backend);
    }
    const std::uint32_t lbs = params.logical_block_size;
    if (lbs != data_unit_512 && lbs != data_unit_4k) {
        return std::unexpected(CopyError::bad_block_size);
    }
    if (params.region_bytes == 0 || params.region_bytes % lbs != 0) {
        return std::unexpected(CopyError::bad_region);
    }
    const std::uint64_t size = params.source->size_bytes();
    if (size == 0 || size % lbs != 0 || params.target->size_bytes() < size) {
        return std::unexpected(CopyError::bad_capacity);
    }
    params.max_in_flight = std::max<std::size_t>(params.max_in_flight, 1);
    params.max_tries = std::max(params.max_tries, 1U);
    const int timer = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    const int epoll = ::epoll_create1(EPOLL_CLOEXEC);
    // Owned from here, so every failure below closes both.
    std::unique_ptr<VolumeCopier> c{new VolumeCopier(std::move(params), timer, epoll)};
    if (timer < 0 || epoll < 0 || !watch(epoll, timer)) {
        return std::unexpected(CopyError::wake);
    }
    for (const int fd : {c->_source->wake_fd(), c->_target->wake_fd()}) {
        if (fd >= 0 && !watch(epoll, fd)) {
            return std::unexpected(CopyError::wake);
        }
    }
    return c;
}

VolumeCopier::VolumeCopier(CopyParams params, int timer, int epoll) noexcept
    : _params{std::move(params)},
      _source{std::move(_params.source)},
      _target{std::move(_params.target)},
      _timer{timer},
      _epoll{epoll} {
    if (!_params.clock) {
        _params.clock = [] { return Clock::now(); };
    }
    // Bytes per second, with one region of burst at most.
    constexpr double mib = 1024.0 * 1024.0;
    _pace = TokenBucket{static_cast<double>(_params.mib_per_s) * mib,
                        static_cast<double>(_params.region_bytes), now()};
}

VolumeCopier::~VolumeCopier() {
    // The backends first: they drop completions that name this copier,
    // and touch no buffer once they are gone.
    _target.reset();
    _source.reset();
    for (auto& [id, r] : _active) {
        wipe(r.data);
    }
    if (_epoll >= 0) {
        ::close(_epoll);
    }
    if (_timer >= 0) {
        ::close(_timer);
    }
}

auto VolumeCopier::now() const -> Clock::time_point {
    return _params.clock();
}

auto VolumeCopier::regions() const noexcept -> std::uint64_t {
    const auto rb = _params.region_bytes;
    return (_progress.total_bytes + rb - 1) / rb;
}

auto VolumeCopier::region_length(std::uint64_t region) const noexcept -> std::uint64_t {
    return std::min(_params.region_bytes, _progress.total_bytes - (region * _params.region_bytes));
}

// ---- keys ------------------------------------------------------------------------

auto VolumeCopier::load_keys(XtsKey source_key, XtsKey target_key)
    -> std::expected<void, CopyKeyError> {
    if (_state != CopyState::waiting_for_keys) {
        return std::unexpected(CopyKeyError::occupied);
    }
    auto from = XtsCipher::create(source_key, _params.logical_block_size);
    auto to = XtsCipher::create(target_key, _params.logical_block_size);
    if (!from || !to) {
        return std::unexpected(CopyKeyError::rejected);
    }
    _from.emplace(std::move(*from));
    _to.emplace(std::move(*to));
    _progress.total_bytes = _source->size_bytes();
    _state = CopyState::copying;
    _pace.refill(now());
    return {};
}

// ---- copying a region ------------------------------------------------------------

auto VolumeCopier::pump(std::size_t& budget) -> void {
    const auto t = now();
    while (_state == CopyState::copying && budget > 0 && t >= _resume &&
           _active.size() < _params.max_in_flight) {
        if (_params.mib_per_s != 0) {
            _pace.refill(t);
            if (!_pace.ready()) {
                return;
            }
        }
        std::uint64_t region = 0;
        if (!_retry.empty()) {
            region = _retry.front();
            _retry.erase(_retry.begin());
            ++_progress.retries;
        } else if (_cursor < regions()) {
            region = _cursor++;
        } else {
            return;
        }
        if (_params.mib_per_s != 0) {
            _pace.take(static_cast<double>(region_length(region)));
        }
        --budget;
        start(region);
    }
}

auto VolumeCopier::start(std::uint64_t region) -> void {
    ++_tries[region];
    auto& r = _active[region];
    r = Region{};
    r.data.resize(region_length(region));
    // May complete inside the call (a FileBackend): nothing after it
    // touches `r`, which the completion may already have dropped.
    _source->submit_read(region * _params.region_bytes, r.data,
                         [this, region](BackendResult res) { on_read(region, res); });
}

auto VolumeCopier::on_read(std::uint64_t region, BackendResult res) -> void {
    const auto it = _active.find(region);
    if (it == _active.end()) {
        return;
    }
    Region& r = it->second;
    if (_state != CopyState::copying) {
        settle(region);  // the copy failed meanwhile
        return;
    }
    if (!res) {
        r.failed = true;
        r.error = res.error();
        settle(region);
        retry_or_fail(region, res.error(), CopyFailure::source_io);
        return;
    }
    const std::uint32_t bs = _params.logical_block_size;
    const std::uint64_t off = region * _params.region_bytes;
    const std::size_t blocks = r.data.size() / bs;
    // Runs of written blocks: [first, end) in blocks of this region.
    std::vector<std::pair<std::size_t, std::size_t>> runs;
    for (std::size_t b = 0; b < blocks;) {
        if (all_zero(std::span{r.data}.subspan(b * bs, bs))) {
            ++b;
            continue;
        }
        std::size_t e = b + 1;
        while (e < blocks && !all_zero(std::span{r.data}.subspan(e * bs, bs))) {
            ++e;
        }
        runs.emplace_back(b, e);
        b = e;
    }
    for (const auto& [b, e] : runs) {
        const auto part = std::span{r.data}.subspan(b * bs, (e - b) * bs);
        const std::uint64_t unit = (off / bs) + b;
        if (!_from->decrypt(unit, part, part) || !_to->encrypt(unit, part, part)) {
            settle(region);
            fail(CopyFailure::crypto);
            return;
        }
    }
    for (const auto& [b, e] : runs) {
        r.written += (e - b) * bs;
    }
    // One extra count while submitting: a write that completes inside its
    // submit must not settle the region before the rest are sent.
    r.pending = runs.size() + 1;
    for (const auto& [b, e] : runs) {
        _target->submit_write(off + (b * bs), std::span{r.data}.subspan(b * bs, (e - b) * bs),
                              [this, region](BackendResult w) { on_write(region, w); });
    }
    on_write(region, {});
}

auto VolumeCopier::on_write(std::uint64_t region, BackendResult res) -> void {
    const auto it = _active.find(region);
    if (it == _active.end()) {
        return;
    }
    Region& r = it->second;
    if (!res && !r.failed) {
        r.failed = true;
        r.error = res.error();
    }
    if (--r.pending > 0) {
        return;
    }
    const bool failed = r.failed;
    const BackendError error = r.error;
    if (!failed && _state == CopyState::copying) {
        _progress.done_bytes += r.data.size();
        _progress.written_bytes += r.written;
    }
    settle(region);
    if (failed && _state == CopyState::copying) {
        retry_or_fail(region, error, CopyFailure::target_io);
        return;
    }
    maybe_flush();
}

auto VolumeCopier::settle(std::uint64_t region) -> void {
    const auto it = _active.find(region);
    if (it == _active.end()) {
        return;
    }
    auto node = _active.extract(it);
    wipe(node.mapped().data);
}

auto VolumeCopier::retry_or_fail(std::uint64_t region, BackendError e, CopyFailure side) -> void {
    if (e == BackendError::not_hydrated) {
        fail(CopyFailure::not_hydrated);
        return;
    }
    if (e == BackendError::out_of_range) {
        fail(CopyFailure::out_of_range);
        return;
    }
    if (_tries[region] >= _params.max_tries) {
        fail(side);
        return;
    }
    _retry.push_back(region);
    _resume = now() + _params.retry_backoff;
}

auto VolumeCopier::fail(CopyFailure f) -> void {
    if (_state == CopyState::completed || _state == CopyState::failed) {
        return;
    }
    _state = CopyState::failed;
    _failure = f;
    _retry.clear();
    // Regions still in flight finish (their buffers stay until the
    // backends answer) and are dropped then.
    _from.reset();
    _to.reset();
}

auto VolumeCopier::maybe_flush() -> void {
    if (_state != CopyState::copying || _cursor < regions() || !_active.empty() ||
        !_retry.empty()) {
        return;
    }
    _state = CopyState::flushing;
    _from.reset();
    _to.reset();
    _target->submit_flush([this](BackendResult r) {
        if (_state != CopyState::flushing) {
            return;
        }
        if (r) {
            _state = CopyState::completed;
        } else {
            fail(CopyFailure::target_io);
        }
    });
}

// ---- driving ---------------------------------------------------------------------

auto VolumeCopier::arm() -> void {
    itimerspec spec{};
    const auto t = now();
    std::optional<Clock::time_point> wake;
    const bool more = !_retry.empty() || _cursor < regions();
    if (_state == CopyState::copying && more && _active.size() < _params.max_in_flight) {
        auto at = _resume;
        if (_params.mib_per_s != 0) {
            at = std::max(at, t + _pace.wait());
        }
        if (at > t) {
            wake = at;
        }
    }
    if (wake) {
        // Relative, so a test clock that is not steady_clock still works.
        const auto ns = std::max<std::int64_t>(
            1, std::chrono::duration_cast<std::chrono::nanoseconds>(*wake - t).count());
        spec.it_value.tv_sec = static_cast<time_t>(ns / 1'000'000'000);
        spec.it_value.tv_nsec = static_cast<long>(ns % 1'000'000'000);
    }
    static_cast<void>(::timerfd_settime(_timer, 0, &spec, nullptr));
}

auto VolumeCopier::poll() -> bool {
    std::uint64_t n = 0;
    [[maybe_unused]] const auto drained = ::read(_timer, &n, sizeof n);  // EAGAIN: not due
    static_cast<void>(_source->poll());
    static_cast<void>(_target->poll());
    std::size_t budget = _params.max_in_flight;
    pump(budget);
    maybe_flush();
    arm();
    // More to start right now: the budget ran out with room still free.
    const auto t = now();
    const bool more = !_retry.empty() || _cursor < regions();
    const bool paced = _params.mib_per_s != 0 && (_pace.refill(t), !_pace.ready());
    return _state == CopyState::copying && budget == 0 && more && t >= _resume && !paced &&
           _active.size() < _params.max_in_flight;
}

}  // namespace ak::oar::blk
