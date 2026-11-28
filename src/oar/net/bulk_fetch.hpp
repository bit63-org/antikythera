// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// BulkFetcher: a network role's bulk channel (.kiro/specs/
// fleet-scale-networking/ Requirement 6, design "Bulk channel", task 12).
//
// The controller announces a large signed frame with a FrameNotice (kind,
// scope, sequence, size, SHA-256) and helm passes the notice down over
// OarLink. The role fetches the bytes from a frame store over its own
// Ethernet port, which is far faster than SMBus, and trusts neither the
// store nor the path:
//
//   1. GET /v1/frames/<sha256-hex> over HTTP/1.1 on TLS 1.3 with mutual
//      authentication: the role presents its role certificate
//      (task 10) and checks the store's against the role CA. The
//      response must be 200 with a Content-Length of exactly the
//      notice's size and no transfer coding (objstore/http_response.hpp,
//      the strict, fuzzed parser the S3 client uses).
//   2. The body's SHA-256 must equal the notice's digest.
//   3. Then `verify` (the frame's own decoder and signature check, per
//      kind) must accept it.
//
// A failed attempt (no connection, a TLS or HTTP failure, a short or
// wrong body) is retried on the next endpoint, with exponential backoff
// between attempts, up to `fallback_after` attempts; then the notice is
// handed back for OarLink delivery (fallback) and counted. A frame whose
// digest matches but which `verify` refuses is not retried anywhere:
// every store would serve the same bytes, so the controller announced a
// bad frame, and it is dropped and counted.
//
// The role only dials out, to the endpoints in its configuration
// (Requirement 6.5); it listens on nothing for this. The endpoint list
// needs no signature, since every frame is checked against the notice.
// Connections are marked CS6 (traffic class 0xC0), the control class.
//
// The fetch itself is synchronous (fetch()); BulkWorker runs it on a
// thread of its own so the data plane never waits on the network, and
// hands results back through an eventfd the role's poll loop watches.

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "proto/frame_notice.hpp"
#include "tls/tls.hpp"

namespace ak::oar::net {

struct FrameEndpoint {
    std::string host;  // an address or name the role's resolver knows
    std::uint16_t port{0};
    friend auto operator==(const FrameEndpoint&, const FrameEndpoint&) -> bool = default;
};

// Why one attempt failed. Values index BulkCounters::failures.
enum class FetchFailure : std::uint8_t {
    connect,          // no TCP connection (or the name did not resolve)
    handshake,        // TLS refused: certificates, names, versions
    timed_out,        // the attempt's deadline passed
    closed,           // the store hung up before the whole body arrived
    http_status,      // an answer other than 200
    bad_response,     // a head the parser refused, or no exact Content-Length
    size_mismatch,    // Content-Length is not the notice's size
    digest_mismatch,  // the body's SHA-256 is not the notice's
    io,               // any other socket or TLS error
};
inline constexpr std::size_t fetch_failure_count = 9;
[[nodiscard]] auto to_string(FetchFailure f) noexcept -> const char*;

// Where the bytes come from; TlsFrameSource in production, fakes in tests.
class FrameSource {
public:
    FrameSource() = default;
    FrameSource(const FrameSource&) = delete;
    auto operator=(const FrameSource&) -> FrameSource& = delete;
    FrameSource(FrameSource&&) = delete;
    auto operator=(FrameSource&&) -> FrameSource& = delete;
    virtual ~FrameSource() = default;

    // The frame named by `digest_hex` from `endpoint`, exactly `size`
    // bytes, or why not, by `deadline`. The digest is checked by the
    // caller, not here.
    [[nodiscard]] virtual auto get(const FrameEndpoint& endpoint, std::string_view digest_hex,
                                   std::uint32_t size, tls::Clock::time_point deadline)
        -> std::expected<std::vector<std::byte>, FetchFailure> = 0;
};

// HTTP/1.1 GET over ak::tls. The configuration must be a client's (the
// role certificate from enrollment); peer_name is set per endpoint.
class TlsFrameSource final : public FrameSource {
public:
    [[nodiscard]] static auto create(const tls::Config& config)
        -> std::expected<std::unique_ptr<TlsFrameSource>, tls::Error>;

    [[nodiscard]] auto get(const FrameEndpoint& endpoint, std::string_view digest_hex,
                           std::uint32_t size, tls::Clock::time_point deadline)
        -> std::expected<std::vector<std::byte>, FetchFailure> override;

    // Takes a renewed role certificate for the next connection; refused
    // (and the old one kept) if it is not a usable client configuration.
    auto set_config(const tls::Config& config) -> std::expected<void, tls::Error>;

private:
    explicit TlsFrameSource(tls::Config config) : _config{std::move(config)} {}
    std::mutex _mutex;
    tls::Config _config;  // guarded by _mutex
};

// The request target for a digest: /v1/frames/ and 64 lowercase hex digits.
[[nodiscard]] auto frame_path(std::span<const std::byte, proto::frame_digest_size> digest)
    -> std::string;
[[nodiscard]] auto digest_hex(std::span<const std::byte, proto::frame_digest_size> digest)
    -> std::string;

struct BulkFetchConfig {
    std::vector<FrameEndpoint> endpoints;
    // Attempts before the notice falls back to OarLink chunks.
    std::size_t fallback_after{4};
    std::chrono::milliseconds attempt_timeout{std::chrono::seconds{10}};
    std::chrono::milliseconds backoff_initial{std::chrono::milliseconds{100}};
    std::chrono::milliseconds backoff_max{std::chrono::seconds{2}};
    // The frame's own decoder and signature check; empty accepts any
    // frame whose digest matches.
    std::function<bool(proto::FrameKind, std::span<const std::byte>)> verify;
    // Waits between attempts; empty sleeps. Tests count instead.
    std::function<void(std::chrono::milliseconds)> sleep;
    // Measures fetch time; empty: steady_clock.
    std::function<tls::Clock::time_point()> clock;
    // True once the owner is shutting down: no further attempt starts and
    // the notice comes back as a fallback. Empty: never.
    std::function<bool()> cancelled;
};

// Requirement 6.6: bulk fetches by outcome, bytes and time, reported in
// the role's stream_status.
struct BulkCounters {
    std::uint64_t fetched{0};    // frames delivered
    std::uint64_t bytes{0};      // their bytes
    std::uint64_t fetch_ms{0};   // time spent fetching them, retries included
    std::uint64_t attempts{0};   // every attempt, failed or not
    std::uint64_t fallbacks{0};  // notices handed back for OarLink delivery
    std::uint64_t rejected{0};   // digest matched, verify refused: dropped
    std::array<std::uint64_t, fetch_failure_count> failures{};
};

enum class FetchOutcome : std::uint8_t {
    fetched,   // `frame` holds the verified bytes
    fallback,  // every attempt failed: deliver over OarLink instead
    rejected,  // the frame matched its digest but failed verify: dropped
};

struct FetchResult {
    proto::FrameNotice notice;
    FetchOutcome outcome{FetchOutcome::fallback};
    std::vector<std::byte> frame;
    std::optional<FetchFailure> last_failure;
};

class BulkFetcher {
public:
    // `source` must outlive the fetcher.
    BulkFetcher(FrameSource& source, BulkFetchConfig config);

    // Fetches one notice's frame, retrying as described above. Not
    // thread-safe: one caller at a time (BulkWorker's thread).
    auto fetch(const proto::FrameNotice& notice) -> FetchResult;

    [[nodiscard]] auto counters() const noexcept -> const BulkCounters& { return _counters; }

private:
    FrameSource* _source;
    BulkFetchConfig _config;
    BulkCounters _counters;
    std::size_t _next_endpoint{0};  // spreads first attempts over the stores
};

// Runs a BulkFetcher on its own thread: submit() queues a notice, the
// thread fetches it, and take() returns finished results. fd() is an
// eventfd that is readable while results wait, for the role's poll().
class BulkWorker {
public:
    [[nodiscard]] static auto create(std::unique_ptr<FrameSource> source, BulkFetchConfig config)
        -> std::expected<std::unique_ptr<BulkWorker>, std::string>;
    BulkWorker(const BulkWorker&) = delete;
    auto operator=(const BulkWorker&) -> BulkWorker& = delete;
    BulkWorker(BulkWorker&&) = delete;
    auto operator=(BulkWorker&&) -> BulkWorker& = delete;
    // Stops after the attempt in progress (a backoff wait ends at once);
    // queued notices are dropped.
    ~BulkWorker();

    // Queues a notice; false (and nothing queued) past max_queued.
    auto submit(const proto::FrameNotice& notice) -> bool;
    // Every finished result, oldest first.
    [[nodiscard]] auto take() -> std::vector<FetchResult>;
    [[nodiscard]] auto fd() const noexcept -> int { return _event_fd; }
    // A snapshot of the fetcher's counters.
    [[nodiscard]] auto counters() const -> BulkCounters;

    static constexpr std::size_t max_queued = 1024;

private:
    BulkWorker(std::unique_ptr<FrameSource> source, BulkFetchConfig config, int event_fd);
    auto run(const std::stop_token& stop) -> void;
    auto with_stop_aware_sleep(BulkFetchConfig config) -> BulkFetchConfig;

    std::unique_ptr<FrameSource> _source;
    BulkFetcher _fetcher;
    int _event_fd{-1};
    mutable std::mutex _mutex;
    std::condition_variable_any _wake;
    std::deque<proto::FrameNotice> _queue;  // guarded by _mutex
    std::vector<FetchResult> _done;         // guarded by _mutex
    BulkCounters _snapshot;                 // guarded by _mutex
    std::jthread _thread;                   // last: started once the rest exists
};

}  // namespace ak::oar::net
