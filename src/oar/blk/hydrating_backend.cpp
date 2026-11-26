// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/hydrating_backend.hpp"

#include <openssl/crypto.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

namespace ak::oar::blk {

namespace {

constexpr double mib = 1024.0 * 1024.0;

auto close_fd(int& fd) noexcept -> void {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

auto drain(int fd) noexcept -> void {
    std::uint64_t n = 0;
    [[maybe_unused]] const auto r = ::read(fd, &n, sizeof n);  // EAGAIN: nothing
}

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

}  // namespace

auto to_string(HydratingError e) noexcept -> const char* {
    switch (e) {
        case HydratingError::no_image:
            return "no_image";
        case HydratingError::bad_block_size:
            return "bad_block_size";
        case HydratingError::bad_capacity:
            return "bad_capacity";
        case HydratingError::snapshot:
            return "snapshot";
        case HydratingError::wake:
            return "wake";
    }
    return "unknown";
}

auto to_string(HydratingKeyError e) noexcept -> const char* {
    switch (e) {
        case HydratingKeyError::occupied:
            return "occupied";
        case HydratingKeyError::rejected:
            return "rejected";
        case HydratingKeyError::missing_image_key:
            return "missing_image_key";
        case HydratingKeyError::unexpected_image_key:
            return "unexpected_image_key";
    }
    return "unknown";
}

// ---- descriptors -------------------------------------------------------------

HydratingBackend::Fds::~Fds() {
    close_fd(epoll);
    close_fd(timer);
    close_fd(inbox);
}

auto HydratingBackend::Fds::post(Arrival a) -> void {
    {
        const std::scoped_lock lock{mutex};
        arrivals.push_back(std::move(a));
    }
    const std::uint64_t one = 1;
    // EAGAIN only when the counter is saturated, which still wakes.
    [[maybe_unused]] const auto n = ::write(inbox, &one, sizeof one);
}

auto HydratingBackend::Fds::take() -> std::vector<Arrival> {
    drain(inbox);
    const std::scoped_lock lock{mutex};
    return std::exchange(arrivals, {});
}

// ---- creation ------------------------------------------------------------------

auto HydratingBackend::create(HydratingParams params)
    -> std::expected<std::unique_ptr<HydratingBackend>, HydratingError> {
    if (!params.volume || !params.image || params.fetcher == nullptr) {
        return std::unexpected(HydratingError::no_image);
    }
    const objstore::ImageManifest& m = params.image->manifest();
    if (m.chunked) {
        return std::unexpected(HydratingError::snapshot);
    }
    const std::uint32_t lbs = params.logical_block_size;
    if ((lbs != data_unit_512 && lbs != data_unit_4k) || m.image_bytes % lbs != 0 ||
        (m.encrypted && lbs != m.logical_block_size) || m.chunk_size() % lbs != 0) {
        return std::unexpected(HydratingError::bad_block_size);
    }
    // Before the route arrives the size is 0; the controller sized the
    // volume from the image, and the hold refuses what lies past its end.
    if (const auto size = params.volume->size_bytes();
        size != 0 && (size < m.image_bytes || size % lbs != 0)) {
        return std::unexpected(HydratingError::bad_capacity);
    }
    if (params.max_background == 0) {
        params.max_background = 1;
    }
    if (params.max_read_tries == 0) {
        params.max_read_tries = 1;
    }
    auto fds = std::make_shared<Fds>();
    fds->inbox = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    fds->timer = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    fds->epoll = ::epoll_create1(EPOLL_CLOEXEC);
    if (fds->inbox < 0 || fds->timer < 0 || fds->epoll < 0 || !watch(fds->epoll, fds->inbox) ||
        !watch(fds->epoll, fds->timer)) {
        return std::unexpected(HydratingError::wake);
    }
    if (const int inner = params.volume->wake_fd(); inner >= 0 && !watch(fds->epoll, inner)) {
        return std::unexpected(HydratingError::wake);
    }
    return std::unique_ptr<HydratingBackend>(
        new HydratingBackend(std::move(params), std::move(fds)));
}

HydratingBackend::HydratingBackend(HydratingParams params, std::shared_ptr<Fds> fds) noexcept
    : _params{std::move(params)}, _fds{std::move(fds)}, _inner{std::move(_params.volume)} {
    if (!_params.clock) {
        _params.clock = [] { return Clock::now(); };
    }
    // At most one region ahead of the pace: the walker never bursts.
    const double rate = static_cast<double>(_params.hydrate_mib_per_s);
    _pace = TokenBucket{rate, static_cast<double>(region_bytes()) / mib, now()};
}

HydratingBackend::~HydratingBackend() {
    _inner.reset();  // drops its completions, which name this backend
    for (auto& [id, g] : _regions) {
        wipe(g.data);
    }
}

auto HydratingBackend::now() const -> Clock::time_point {
    return _params.clock();
}

auto HydratingBackend::region_bytes() const noexcept -> std::uint64_t {
    return _params.image->manifest().chunk_size();
}

auto HydratingBackend::regions() const noexcept -> std::uint64_t {
    const auto rb = region_bytes();
    return (_inner->size_bytes() + rb - 1) / rb;
}

auto HydratingBackend::done() const noexcept -> bool {
    return regions() != 0 && _cursor >= regions() && _background == 0 && _retry.empty();
}

// ---- keys ------------------------------------------------------------------------

auto HydratingBackend::load_keys(XtsKey volume_key, std::optional<XtsKey> image_key)
    -> std::expected<void, HydratingKeyError> {
    if (_vol) {
        return std::unexpected(HydratingKeyError::occupied);
    }
    const objstore::ImageManifest& m = _params.image->manifest();
    if (m.encrypted && !image_key) {
        return std::unexpected(HydratingKeyError::missing_image_key);
    }
    if (!m.encrypted && image_key) {
        return std::unexpected(HydratingKeyError::unexpected_image_key);
    }
    auto vol = XtsCipher::create(volume_key, _params.logical_block_size);
    if (!vol) {
        return std::unexpected(HydratingKeyError::rejected);
    }
    if (image_key) {
        auto img = XtsCipher::create(*image_key, m.logical_block_size);
        if (!img) {
            return std::unexpected(HydratingKeyError::rejected);
        }
        _img.emplace(std::move(*img));
    }
    _vol.emplace(std::move(*vol));
    pump();
    arm();
    return {};
}

auto HydratingBackend::drop_keys() noexcept -> void {
    _vol.reset();
    _img.reset();
}

// ---- guest reads -------------------------------------------------------------------

auto HydratingBackend::submit_read(std::uint64_t offset, std::span<std::byte> out,
                                   BackendCompletion done) -> void {
    const auto id = _next_read++;
    _reads.emplace(id, Read{.offset = offset,
                            .out = out,
                            .done = std::move(done),
                            .tries = 0,
                            .waiting = 0,
                            .failed = false});
    send_read(id);
}

auto HydratingBackend::send_read(std::uint64_t id) -> void {
    auto& r = _reads.at(id);
    ++r.tries;
    _inner->submit_read(r.offset, r.out, [this, id](BackendResult res) { on_read(id, res); });
}

auto HydratingBackend::on_read(std::uint64_t id, BackendResult res) -> void {
    const auto it = _reads.find(id);
    if (it == _reads.end()) {
        return;
    }
    Read& r = it->second;
    const bool missing = !res && res.error() == BackendError::not_hydrated;
    if (missing) {
        ++_counters.not_hydrated;
    }
    if (missing && _vol && r.tries < _params.max_read_tries && !r.out.empty()) {
        // Hydrate every region the read touches, then read again. One
        // extra count keeps a region that completes at once from sending
        // the read before the rest have started.
        const auto rb = region_bytes();
        const std::uint64_t first = r.offset / rb;
        const std::uint64_t last = (r.offset + r.out.size() - 1) / rb;
        r.waiting = (last - first) + 2;
        r.failed = false;
        for (std::uint64_t g = first; g <= last; ++g) {
            hydrate(g, false, [this, id](bool ok) { read_region_done(id, ok); });
        }
        read_region_done(id, true);
        return;
    }
    // Detach before completing: the completion may submit again.
    auto node = _reads.extract(it);
    if (missing) {
        res = std::unexpected(BackendError::io);  // never past this backend
    }
    node.mapped().done(res);
}

auto HydratingBackend::read_region_done(std::uint64_t id, bool ok) -> void {
    const auto it = _reads.find(id);
    if (it == _reads.end()) {
        return;
    }
    Read& r = it->second;
    r.failed = r.failed || !ok;
    if (--r.waiting > 0) {
        return;
    }
    if (r.failed) {
        auto node = _reads.extract(it);
        node.mapped().done(std::unexpected(BackendError::io));
        return;
    }
    send_read(id);
}

// ---- hydrating a region ------------------------------------------------------------

auto HydratingBackend::hydrate(std::uint64_t region, bool background, Waiter w) -> void {
    if (const auto it = _regions.find(region); it != _regions.end()) {
        it->second.waiters.push_back(std::move(w));  // one hydration for everyone
        return;
    }
    const auto rb = region_bytes();
    const std::uint64_t size = _inner->size_bytes();
    const std::uint64_t off = region * rb;
    if (!_vol || off >= size) {
        w(false);
        return;
    }
    auto& g = _regions[region];
    g.waiters.push_back(std::move(w));
    g.data.assign(std::min(rb, size - off), std::byte{0});
    if (background) {
        ++_counters.background_regions;
    } else {
        ++_counters.demand_regions;
    }
    const objstore::ImageManifest& m = _params.image->manifest();
    const auto chunk = static_cast<std::uint32_t>(region);
    if (off >= m.image_bytes || region >= m.chunk_count() || m.is_hole(chunk)) {
        fill(region);  // zeros
        return;
    }
    const std::size_t n = std::min<std::uint64_t>(m.chunk_length(chunk), g.data.size());
    if (_params.image->read(chunk, 0, std::span{g.data}.first(n))) {
        fill(region);
        return;
    }
    ++_counters.fetches;
    // May run at once on this thread (a failure); the inbox takes it
    // either way, and poll() goes on with the region.
    _params.fetcher->fetch_async(_params.image, chunk,
                                 [fds = _fds, region](objstore::FetchResult r) {
                                     fds->post({.region = region, .result = std::move(r)});
                                 });
}

auto HydratingBackend::fill(std::uint64_t region) -> void {
    const auto it = _regions.find(region);
    if (it == _regions.end()) {
        return;
    }
    Region& g = it->second;
    const objstore::ImageManifest& m = _params.image->manifest();
    const std::uint64_t off = region * region_bytes();
    const std::uint32_t lbs = _params.logical_block_size;
    bool ok = _vol.has_value();
    // The image's part, decrypted with K_img (holes are plaintext zeros).
    if (ok && _img && off < m.image_bytes && !m.is_hole(static_cast<std::uint32_t>(region))) {
        const std::size_t n = std::min<std::uint64_t>(m.image_bytes - off, g.data.size());
        auto part = std::span{g.data}.first(n);
        ok = _img->decrypt(off / m.logical_block_size, part, part).has_value();
    }
    // Then all of it under K_vol, at each block's own number.
    if (ok) {
        ok = _vol->encrypt(off / lbs, g.data, g.data).has_value();
    }
    if (!ok) {
        finish(region, false);
        return;
    }
    g.writing = true;
    _inner->submit_hydrate(off, g.data,
                           [this, region](BackendResult r) { finish(region, r.has_value()); });
}

auto HydratingBackend::finish(std::uint64_t region, bool ok) -> void {
    const auto it = _regions.find(region);
    if (it == _regions.end()) {
        return;
    }
    auto node = _regions.extract(it);
    Region& g = node.mapped();
    if (ok) {
        _counters.hydrated_bytes += g.data.size();
    } else {
        ++_counters.failures;
    }
    wipe(g.data);
    for (auto& w : g.waiters) {
        w(ok);
    }
}

// ---- background walk ----------------------------------------------------------------

auto HydratingBackend::pump() -> void {
    if (!_vol || _params.hydrate_mib_per_s == 0) {
        return;
    }
    const auto t = now();
    if (t < _resume) {
        return;
    }
    const auto count = regions();
    const auto rb = region_bytes();
    while (_background < _params.max_background && _vol) {
        _pace.refill(t);
        if (!_pace.ready()) {
            return;
        }
        std::uint64_t region = 0;
        if (!_retry.empty()) {
            region = _retry.front();
            _retry.erase(_retry.begin());
        } else if (_cursor < count) {
            region = _cursor++;
        } else {
            return;
        }
        const std::uint64_t len = std::min(rb, _inner->size_bytes() - (region * rb));
        _pace.take(static_cast<double>(len) / mib);
        ++_background;
        probe(region);
    }
}

auto HydratingBackend::probe(std::uint64_t region) -> void {
    const auto rb = region_bytes();
    const std::uint64_t off = region * rb;
    auto& p = _probes[region];
    p.buffer.resize(std::min(rb, _inner->size_bytes() - off));
    _inner->submit_read(off, p.buffer, [this, region](BackendResult r) {
        _probes.erase(region);
        if (r) {
            ++_counters.skipped_regions;  // already whole
            background_done(region, true);
            return;
        }
        if (r.error() != BackendError::not_hydrated) {
            background_done(region, false);
            return;
        }
        hydrate(region, true, [this, region](bool ok) { background_done(region, ok); });
    });
}

auto HydratingBackend::background_done(std::uint64_t region, bool ok) -> void {
    --_background;
    if (!ok) {
        _retry.push_back(region);
        _resume = now() + _params.retry_backoff;
    }
}

auto HydratingBackend::arm() -> void {
    itimerspec spec{};
    const auto t = now();
    std::optional<Clock::time_point> wake;
    const bool more = !_retry.empty() || _cursor < regions();
    if (_vol && _params.hydrate_mib_per_s != 0 && more && _background < _params.max_background) {
        wake = std::max(_resume, t + _pace.wait());
    }
    if (wake) {
        // Relative, so a test clock that is not steady_clock still works.
        const auto ns = std::max<std::int64_t>(
            1, std::chrono::duration_cast<std::chrono::nanoseconds>(*wake - t).count());
        spec.it_value.tv_sec = static_cast<time_t>(ns / 1'000'000'000);
        spec.it_value.tv_nsec = static_cast<long>(ns % 1'000'000'000);
    }
    static_cast<void>(::timerfd_settime(_fds->timer, 0, &spec, nullptr));
}

auto HydratingBackend::poll() -> bool {
    drain(_fds->timer);
    for (auto& a : _fds->take()) {
        const auto it = _regions.find(a.region);
        if (it == _regions.end() || it->second.writing) {
            continue;
        }
        if (!a.result) {
            finish(a.region, false);
            continue;
        }
        Region& g = it->second;
        const auto& bytes = **a.result;
        std::copy_n(bytes.begin(), std::min(bytes.size(), g.data.size()), g.data.begin());
        fill(a.region);
    }
    static_cast<void>(_inner->poll());
    pump();
    arm();
    return !_reads.empty();
}

}  // namespace ak::oar::blk
