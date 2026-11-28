// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/bulk_fetch.hpp"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <format>
#include <utility>

#include "objstore/http_response.hpp"

namespace ak::oar::net {

namespace {

constexpr unsigned status_ok = 200;
constexpr std::size_t read_chunk = 16U * 1024U;
constexpr int traffic_class_cs6 = 0xC0;

auto failure_of(tls::Error e) noexcept -> FetchFailure {
    switch (e) {
        case tls::Error::resolve_failed:
        case tls::Error::connect_failed:
            return FetchFailure::connect;
        case tls::Error::handshake_failed:
        case tls::Error::bad_config:
            return FetchFailure::handshake;
        case tls::Error::timed_out:
            return FetchFailure::timed_out;
        case tls::Error::closed:
            return FetchFailure::closed;
        case tls::Error::io:
            return FetchFailure::io;
    }
    return FetchFailure::io;
}

// Marks the connection's packets CS6 (both families: the option for the
// other family fails harmlessly).
auto mark_control_class(int fd) noexcept -> void {
    const int tclass = traffic_class_cs6;
    static_cast<void>(::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof tclass));
    static_cast<void>(::setsockopt(fd, IPPROTO_IP, IP_TOS, &tclass, sizeof tclass));
}

// Reads at least one byte (or learns the peer closed) by the deadline.
auto read_wait(tls::Stream& s, std::span<std::byte> out, tls::Clock::time_point deadline)
    -> std::expected<std::size_t, FetchFailure> {
    while (true) {
        const auto n = s.read_some(out);
        if (!n) {
            return std::unexpected(failure_of(n.error()));
        }
        if (*n != 0) {
            return *n;
        }
        if (s.pending()) {
            continue;
        }
        const auto left =
            std::chrono::ceil<std::chrono::milliseconds>(deadline - tls::Clock::now());
        if (left.count() <= 0) {
            return std::unexpected(FetchFailure::timed_out);
        }
        pollfd p{.fd = s.fd(), .events = POLLIN, .revents = 0};
        const int r = ::poll(&p, 1, static_cast<int>(std::min<std::int64_t>(left.count(), 60'000)));
        if (r < 0 && errno != EINTR) {
            return std::unexpected(FetchFailure::io);
        }
    }
}

auto sha256(std::span<const std::byte> bytes) -> std::array<std::byte, proto::frame_digest_size> {
    std::array<std::byte, proto::frame_digest_size> out{};
    unsigned len = 0;
    static_cast<void>(EVP_Digest(bytes.data(), bytes.size(),
                                 reinterpret_cast<unsigned char*>(out.data()), &len, EVP_sha256(),
                                 nullptr));
    return out;
}

}  // namespace

auto to_string(FetchFailure f) noexcept -> const char* {
    switch (f) {
        case FetchFailure::connect:
            return "connect";
        case FetchFailure::handshake:
            return "handshake";
        case FetchFailure::timed_out:
            return "timed_out";
        case FetchFailure::closed:
            return "closed";
        case FetchFailure::http_status:
            return "http_status";
        case FetchFailure::bad_response:
            return "bad_response";
        case FetchFailure::size_mismatch:
            return "size_mismatch";
        case FetchFailure::digest_mismatch:
            return "digest_mismatch";
        case FetchFailure::io:
            return "io";
    }
    return "unknown";
}

auto digest_hex(std::span<const std::byte, proto::frame_digest_size> digest) -> std::string {
    std::string out;
    out.reserve(2 * digest.size());
    for (const auto b : digest) {
        out += std::format("{:02x}", std::to_integer<unsigned>(b));
    }
    return out;
}

auto frame_path(std::span<const std::byte, proto::frame_digest_size> digest) -> std::string {
    return "/v1/frames/" + digest_hex(digest);
}

// ---- TlsFrameSource --------------------------------------------------------------

auto TlsFrameSource::create(const tls::Config& config)
    -> std::expected<std::unique_ptr<TlsFrameSource>, tls::Error> {
    if (config.role != tls::Role::client) {
        return std::unexpected(tls::Error::bad_config);
    }
    auto probe = config;
    probe.peer_name = "frame-store";  // the context is made per endpoint; check the PEMs now
    if (auto ctx = tls::Context::create(probe); !ctx) {
        return std::unexpected(ctx.error());
    }
    return std::unique_ptr<TlsFrameSource>{new TlsFrameSource{config}};
}

auto TlsFrameSource::set_config(const tls::Config& config) -> std::expected<void, tls::Error> {
    if (config.role != tls::Role::client) {
        return std::unexpected(tls::Error::bad_config);
    }
    auto probe = config;
    probe.peer_name = "frame-store";
    if (auto ctx = tls::Context::create(probe); !ctx) {
        return std::unexpected(ctx.error());
    }
    const std::scoped_lock lock{_mutex};
    _config = config;
    return {};
}

auto TlsFrameSource::get(const FrameEndpoint& endpoint, std::string_view digest, std::uint32_t size,
                         tls::Clock::time_point deadline)
    -> std::expected<std::vector<std::byte>, FetchFailure> {
    auto cfg = [this] {
        const std::scoped_lock lock{_mutex};
        return _config;
    }();
    cfg.peer_name = endpoint.host;
    auto ctx = tls::Context::create(cfg);
    if (!ctx) {
        return std::unexpected(FetchFailure::handshake);
    }
    auto stream = tls::Stream::connect(*ctx, endpoint.host, endpoint.port, deadline);
    if (!stream) {
        return std::unexpected(failure_of(stream.error()));
    }
    mark_control_class(stream->fd());
    const auto request = std::format(
        "GET /v1/frames/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", digest,
        endpoint.host.find(':') == std::string::npos ? endpoint.host : "[" + endpoint.host + "]");
    if (auto w = stream->write_all(std::as_bytes(std::span{request}), deadline); !w) {
        return std::unexpected(failure_of(w.error()));
    }

    // The head, at most max_response_head bytes; what follows it is body.
    std::vector<std::byte> buf(read_chunk);
    std::size_t have = 0;
    std::expected<objstore::ResponseHead, objstore::HttpError> head =
        std::unexpected(objstore::HttpError::incomplete);
    while (true) {
        if (have == buf.size()) {
            if (buf.size() >= objstore::max_response_head + read_chunk) {
                return std::unexpected(FetchFailure::bad_response);
            }
            buf.resize(buf.size() + read_chunk);
        }
        const auto n = read_wait(*stream, std::span{buf}.subspan(have), deadline);
        if (!n) {
            return std::unexpected(n.error());
        }
        have += *n;
        head = objstore::parse_response_head(std::span{buf}.first(have));
        if (head || head.error() != objstore::HttpError::incomplete) {
            break;
        }
    }
    if (!head) {
        return std::unexpected(FetchFailure::bad_response);
    }
    if (head->status != status_ok) {
        return std::unexpected(FetchFailure::http_status);
    }
    if (!head->content_length || head->content_range) {
        return std::unexpected(FetchFailure::bad_response);
    }
    if (*head->content_length != size) {
        return std::unexpected(FetchFailure::size_mismatch);
    }
    const std::size_t extra = have - head->head_bytes;
    if (extra > size) {
        return std::unexpected(FetchFailure::bad_response);  // more than declared
    }
    std::vector<std::byte> body(size);
    std::copy_n(buf.begin() + static_cast<std::ptrdiff_t>(head->head_bytes), extra, body.begin());
    for (std::size_t done = extra; done < body.size();) {
        const auto n = read_wait(*stream, std::span{body}.subspan(done), deadline);
        if (!n) {
            return std::unexpected(n.error());
        }
        done += *n;
    }
    stream->close();
    return body;
}

// ---- BulkFetcher -----------------------------------------------------------------

BulkFetcher::BulkFetcher(FrameSource& source, BulkFetchConfig config)
    : _source{&source}, _config{std::move(config)} {
    _config.fallback_after = std::max<std::size_t>(_config.fallback_after, 1);
}

auto BulkFetcher::fetch(const proto::FrameNotice& notice) -> FetchResult {
    FetchResult result{.notice = notice,
                       .outcome = FetchOutcome::fallback,
                       .frame = {},
                       .last_failure = std::nullopt};
    const auto now = [this] { return _config.clock ? _config.clock() : tls::Clock::now(); };
    const auto started = now();
    const auto hex = digest_hex(notice.sha256);
    auto backoff = _config.backoff_initial;
    const auto& endpoints = _config.endpoints;
    for (std::size_t attempt = 0; attempt < _config.fallback_after && !endpoints.empty();
         ++attempt) {
        if (attempt != 0) {
            if (_config.sleep) {
                _config.sleep(backoff);
            } else {
                std::this_thread::sleep_for(backoff);
            }
            backoff = std::min(backoff * 2, _config.backoff_max);
        }
        if (_config.cancelled && _config.cancelled()) {
            break;
        }
        const auto& endpoint = endpoints[_next_endpoint % endpoints.size()];
        ++_next_endpoint;  // the next attempt, or the next notice, tries another store
        ++_counters.attempts;
        auto got =
            _source->get(endpoint, hex, notice.size, tls::Clock::now() + _config.attempt_timeout);
        if (got && got->size() != notice.size) {
            got = std::unexpected(FetchFailure::size_mismatch);
        }
        if (got && sha256(*got) != notice.sha256) {
            got = std::unexpected(FetchFailure::digest_mismatch);
        }
        if (!got) {
            result.last_failure = got.error();
            ++_counters.failures.at(static_cast<std::size_t>(got.error()));
            continue;
        }
        if (_config.verify && !_config.verify(notice.kind, *got)) {
            // The bytes are the ones announced: any store would serve them.
            ++_counters.rejected;
            result.outcome = FetchOutcome::rejected;
            return result;
        }
        const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(now() - started);
        ++_counters.fetched;
        _counters.bytes += got->size();
        _counters.fetch_ms += static_cast<std::uint64_t>(std::max<std::int64_t>(took.count(), 0));
        result.outcome = FetchOutcome::fetched;
        result.frame = std::move(*got);
        return result;
    }
    ++_counters.fallbacks;
    return result;
}

// ---- BulkWorker ------------------------------------------------------------------

auto BulkWorker::create(std::unique_ptr<FrameSource> source, BulkFetchConfig config)
    -> std::expected<std::unique_ptr<BulkWorker>, std::string> {
    if (!source) {
        return std::unexpected("no frame source");
    }
    const int fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(std::format("eventfd: {}", std::strerror(errno)));
    }
    return std::unique_ptr<BulkWorker>{new BulkWorker{std::move(source), std::move(config), fd}};
}

BulkWorker::BulkWorker(std::unique_ptr<FrameSource> source, BulkFetchConfig config, int event_fd)
    : _source{std::move(source)},
      _fetcher{*_source, with_stop_aware_sleep(std::move(config))},
      _event_fd{event_fd},
      _thread{[this](const std::stop_token& stop) { run(stop); }} {}

auto BulkWorker::with_stop_aware_sleep(BulkFetchConfig config) -> BulkFetchConfig {
    if (!config.cancelled) {
        config.cancelled = [this] { return _thread.get_stop_token().stop_requested(); };
    }
    if (!config.sleep) {
        // Backoff waits on the worker's own condition, so the destructor
        // ends one at once instead of after up to backoff_max.
        config.sleep = [this](std::chrono::milliseconds d) {
            std::unique_lock lock{_mutex};
            static_cast<void>(
                _wake.wait_for(lock, _thread.get_stop_token(), d, [] { return false; }));
        };
    }
    return config;
}

BulkWorker::~BulkWorker() {
    _thread.request_stop();
    _wake.notify_all();
    if (_thread.joinable()) {
        _thread.join();
    }
    ::close(_event_fd);
}

auto BulkWorker::submit(const proto::FrameNotice& notice) -> bool {
    {
        const std::scoped_lock lock{_mutex};
        if (_queue.size() >= max_queued) {
            return false;
        }
        _queue.push_back(notice);
    }
    _wake.notify_one();
    return true;
}

auto BulkWorker::take() -> std::vector<FetchResult> {
    std::uint64_t drained = 0;
    static_cast<void>(::read(_event_fd, &drained, sizeof drained));
    const std::scoped_lock lock{_mutex};
    return std::exchange(_done, {});
}

auto BulkWorker::counters() const -> BulkCounters {
    const std::scoped_lock lock{_mutex};
    return _snapshot;
}

auto BulkWorker::run(const std::stop_token& stop) -> void {
    while (true) {
        proto::FrameNotice notice;
        {
            std::unique_lock lock{_mutex};
            if (!_wake.wait(lock, stop, [this] { return !_queue.empty(); })) {
                return;  // stop requested
            }
            notice = _queue.front();
            _queue.pop_front();
        }
        auto result = _fetcher.fetch(notice);
        {
            const std::scoped_lock lock{_mutex};
            _done.push_back(std::move(result));
            _snapshot = _fetcher.counters();
        }
        const std::uint64_t one = 1;
        static_cast<void>(::write(_event_fd, &one, sizeof one));
    }
}

}  // namespace ak::oar::net
