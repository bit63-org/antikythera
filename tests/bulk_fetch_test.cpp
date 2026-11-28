// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/fleet-scale-networking/ Requirement 6, task 12: the network
// role's bulk channel. BulkFetcher against harbor's FrameStore over real
// mutual TLS on loopback (a cut transfer, a corrupted body, a wrong
// status, a store the role does not trust), its retry and fallback rules
// against a scripted source, BulkWorker's thread and eventfd, and the
// frame store's request parser.

#define BOOST_TEST_MODULE bulk_fetch_test
#include <boost/test/unit_test.hpp>

#include <poll.h>

#include <openssl/evp.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "harbor/frame_store.hpp"
#include "oar/net/bulk_fetch.hpp"
#include "proto/frame_notice.hpp"
#include "tls/tls.hpp"
#include "tls_test_support.hpp"

namespace net = ak::oar::net;
namespace proto = ak::proto;
namespace tls = ak::tls;
using ak::harbor::FrameRequestError;
using ak::harbor::FrameStore;
using ak::harbor::FrameStoreFault;
using namespace std::chrono_literals;

namespace {

constexpr unsigned unit_timeout_seconds = 60;
const std::string loopback = "127.0.0.1";

struct IgnoreSigpipe {
    IgnoreSigpipe() { (void)std::signal(SIGPIPE, SIG_IGN); }
};
const IgnoreSigpipe ignore_sigpipe;

auto bytes(std::string_view s) -> std::span<const std::byte> {
    return std::as_bytes(std::span{s});
}

auto frame_of(std::size_t size, std::uint8_t seed) -> std::vector<std::byte> {
    std::vector<std::byte> f(size);
    for (std::size_t i = 0; i < size; ++i) {
        f[i] = static_cast<std::byte>((i * 31U + seed) & 0xFFU);
    }
    return f;
}

auto notice_for(std::span<const std::byte> frame, std::uint64_t seq = 1) -> proto::FrameNotice {
    proto::FrameNotice n{.kind = proto::FrameKind::vpc_stream,
                         .vni_or_scope = 0x10,
                         .sequence_or_version = seq,
                         .size = static_cast<std::uint32_t>(frame.size()),
                         .sha256 = {}};
    unsigned len = 0;
    BOOST_REQUIRE(EVP_Digest(frame.data(), frame.size(),
                             reinterpret_cast<unsigned char*>(n.sha256.data()), &len, EVP_sha256(),
                             nullptr) == 1);
    return n;
}

// One CA issues the stores' certificates and the role's; a store checks
// the role's chain against it, the role the store's.
struct Pki {
    ak::test::TestCa ca{"role CA"};
    ak::test::Pem store = ca.issue("frame-store", "IP:127.0.0.1");
    ak::test::Pem role = ca.issue("oar-net", "IP:127.0.0.1");

    [[nodiscard]] auto store_config() const -> tls::Config {
        return {.role = tls::Role::server,
                .ca_pem = ca.cert_pem(),
                .cert_pem = store.cert,
                .key_pem = store.key,
                .peer_name = {}};
    }
    [[nodiscard]] auto role_config() const -> tls::Config {
        return {.role = tls::Role::client,
                .ca_pem = ca.cert_pem(),
                .cert_pem = role.cert,
                .key_pem = role.key,
                .peer_name = {}};
    }
};

auto start_store(const Pki& pki) -> std::unique_ptr<FrameStore> {
    auto s = FrameStore::create(pki.store_config(), loopback, 0);
    BOOST_REQUIRE_MESSAGE(s.has_value(), s.error());
    return std::move(*s);
}

auto endpoint(const FrameStore& s) -> net::FrameEndpoint {
    return {.host = loopback, .port = s.port()};
}

// Records backoff waits instead of sleeping.
struct Sleeps {
    std::vector<std::chrono::milliseconds> waits;
    auto fn() {
        return [this](std::chrono::milliseconds d) { waits.push_back(d); };
    }
};

auto config(std::vector<net::FrameEndpoint> endpoints, Sleeps& sleeps) -> net::BulkFetchConfig {
    net::BulkFetchConfig c;
    c.endpoints = std::move(endpoints);
    c.attempt_timeout = 10s;
    c.sleep = sleeps.fn();
    return c;
}

auto failures(const net::BulkCounters& c, net::FetchFailure f) -> std::uint64_t {
    return c.failures.at(static_cast<std::size_t>(f));
}

// A source that answers from a script, one entry per attempt, and
// records which endpoint each attempt went to.
class ScriptedSource final : public net::FrameSource {
public:
    std::deque<std::expected<std::vector<std::byte>, net::FetchFailure>> answers;
    std::vector<std::uint16_t> ports;
    std::vector<std::string> digests;
    std::atomic<std::size_t>* calls{nullptr};  // counted here too, if set

    auto get(const net::FrameEndpoint& e, std::string_view digest, std::uint32_t /*size*/,
             tls::Clock::time_point /*deadline*/)
        -> std::expected<std::vector<std::byte>, net::FetchFailure> override {
        if (calls != nullptr) {
            ++*calls;
        }
        ports.push_back(e.port);
        digests.emplace_back(digest);
        if (answers.empty()) {
            return std::unexpected(net::FetchFailure::connect);
        }
        auto a = std::move(answers.front());
        answers.pop_front();
        return a;
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(frame_paths_name_the_digest_in_lowercase_hex) {
    std::array<std::byte, proto::frame_digest_size> d{};
    d[0] = std::byte{0xAB};
    d[31] = std::byte{0x0F};
    const auto hex = net::digest_hex(d);
    BOOST_TEST(hex.size() == 64U);
    BOOST_TEST(hex.starts_with("ab00"));
    BOOST_TEST(hex.ends_with("000f"));
    BOOST_TEST(net::frame_path(d) == "/v1/frames/" + hex);
}

BOOST_AUTO_TEST_CASE(the_store_parses_only_frame_requests) {
    const std::string digest(64, 'a');
    const auto ok = ak::harbor::parse_frame_request(
        bytes("GET /v1/frames/" + digest + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
    BOOST_REQUIRE(ok.has_value());
    BOOST_TEST(*ok == digest);

    const auto err = [](std::string_view s) {
        const auto r = ak::harbor::parse_frame_request(bytes(s));
        BOOST_REQUIRE(!r.has_value());
        return r.error();
    };
    BOOST_TEST((err("GET /v1/frames/" + digest + " HTTP/1.1\r\nHost: x\r\n") ==
                FrameRequestError::incomplete));
    BOOST_TEST((err(std::string(ak::harbor::max_frame_request_head, 'x')) ==
                FrameRequestError::too_large));
    BOOST_TEST(
        (err("POST /v1/frames/" + digest + " HTTP/1.1\r\n\r\n") == FrameRequestError::bad_request));
    BOOST_TEST(
        (err("GET /v1/frames/" + digest + " HTTP/1.0\r\n\r\n") == FrameRequestError::bad_request));
    BOOST_TEST((err("GET /v1/frames/" + digest + " HTTP/1.1\r\nno colon\r\n\r\n") ==
                FrameRequestError::bad_request));
    BOOST_TEST(
        (err("GET  /v1/frames/" + digest + " HTTP/1.1\r\n\r\n") == FrameRequestError::bad_request));
    BOOST_TEST((err("GET /v1/lookup/1 HTTP/1.1\r\n\r\n") == FrameRequestError::not_found));
    BOOST_TEST((err("GET /v1/frames/" + std::string(64, 'A') + " HTTP/1.1\r\n\r\n") ==
                FrameRequestError::not_found));
    BOOST_TEST((err("GET /v1/frames/" + std::string(63, 'a') + " HTTP/1.1\r\n\r\n") ==
                FrameRequestError::not_found));
}

// Requirement 6.1-6.2: fetched over mutual TLS, checked against the notice.
BOOST_AUTO_TEST_CASE(a_frame_is_fetched_over_mutual_tls_and_checked,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Pki pki;
    auto store = start_store(pki);
    const auto frame = frame_of(200'000, 7);  // more than one TLS record and read chunk
    const auto n = notice_for(frame);
    BOOST_TEST(store->put(frame) == net::digest_hex(n.sha256));

    auto source = net::TlsFrameSource::create(pki.role_config());
    BOOST_REQUIRE(source.has_value());
    Sleeps sleeps;
    net::BulkFetcher fetcher{**source, config({endpoint(*store)}, sleeps)};
    const auto r = fetcher.fetch(n);
    BOOST_TEST((r.outcome == net::FetchOutcome::fetched));
    BOOST_TEST((r.frame == frame));
    BOOST_TEST((r.notice == n));
    BOOST_TEST(!r.last_failure.has_value());
    BOOST_TEST(fetcher.counters().fetched == 1U);
    BOOST_TEST(fetcher.counters().bytes == frame.size());
    BOOST_TEST(fetcher.counters().attempts == 1U);
    BOOST_TEST(sleeps.waits.empty());
    BOOST_TEST(store->served() == 1U);
}

// The channel cut mid-transfer: the attempt fails as closed and the next
// one, after a backoff, gets the whole frame.
BOOST_AUTO_TEST_CASE(a_transfer_cut_midway_is_retried,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Pki pki;
    auto store = start_store(pki);
    const auto frame = frame_of(100'000, 3);
    static_cast<void>(store->put(frame));
    store->set_fault({.cut_after = 40'000}, 1);

    auto source = net::TlsFrameSource::create(pki.role_config());
    BOOST_REQUIRE(source.has_value());
    Sleeps sleeps;
    net::BulkFetcher fetcher{**source, config({endpoint(*store)}, sleeps)};
    const auto r = fetcher.fetch(notice_for(frame));
    BOOST_TEST((r.outcome == net::FetchOutcome::fetched));
    BOOST_TEST((r.frame == frame));
    BOOST_TEST(fetcher.counters().attempts == 2U);
    BOOST_TEST(failures(fetcher.counters(), net::FetchFailure::closed) == 1U);
    BOOST_REQUIRE(sleeps.waits.size() == 1U);
    BOOST_TEST(sleeps.waits[0].count() == 100);
    BOOST_TEST(store->connections() == 2U);
}

// A body that is not the announced one is refused by digest, and the
// next attempt goes to the other store.
BOOST_AUTO_TEST_CASE(a_corrupted_body_fails_its_digest_and_the_next_store_serves,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Pki pki;
    auto bad = start_store(pki);
    auto good = start_store(pki);
    const auto frame = frame_of(5000, 9);
    static_cast<void>(bad->put(frame));
    static_cast<void>(good->put(frame));
    bad->set_fault({.cut_after = std::nullopt, .corrupt = true}, 10);

    auto source = net::TlsFrameSource::create(pki.role_config());
    BOOST_REQUIRE(source.has_value());
    Sleeps sleeps;
    net::BulkFetcher fetcher{**source, config({endpoint(*bad), endpoint(*good)}, sleeps)};
    const auto r = fetcher.fetch(notice_for(frame));
    BOOST_TEST((r.outcome == net::FetchOutcome::fetched));
    BOOST_TEST((r.frame == frame));
    BOOST_TEST(failures(fetcher.counters(), net::FetchFailure::digest_mismatch) == 1U);
    BOOST_TEST(good->served() == 1U);
}

// Wrong statuses, a size the notice did not announce, and a store the
// role does not trust each fail an attempt; past fallback_after the
// notice comes back for OarLink delivery, with backoff doubling up to
// its cap between attempts.
BOOST_AUTO_TEST_CASE(every_attempt_failing_falls_back_to_oarlink,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Pki pki;
    auto store = start_store(pki);
    const auto frame = frame_of(3000, 1);
    auto source = net::TlsFrameSource::create(pki.role_config());
    BOOST_REQUIRE(source.has_value());

    {  // not held: 404
        Sleeps sleeps;
        auto c = config({endpoint(*store)}, sleeps);
        c.fallback_after = 5;
        c.backoff_initial = 100ms;
        c.backoff_max = 300ms;
        net::BulkFetcher fetcher{**source, c};
        const auto r = fetcher.fetch(notice_for(frame));
        BOOST_TEST((r.outcome == net::FetchOutcome::fallback));
        BOOST_TEST((r.last_failure == net::FetchFailure::http_status));
        BOOST_TEST(r.frame.empty());
        BOOST_TEST(fetcher.counters().attempts == 5U);
        BOOST_TEST(fetcher.counters().fallbacks == 1U);
        BOOST_TEST(failures(fetcher.counters(), net::FetchFailure::http_status) == 5U);
        const std::vector<std::chrono::milliseconds> want{100ms, 200ms, 300ms, 300ms};
        BOOST_TEST((sleeps.waits == want));
    }
    static_cast<void>(store->put(frame));
    {  // a notice that announces another size
        Sleeps sleeps;
        auto c = config({endpoint(*store)}, sleeps);
        c.fallback_after = 1;
        net::BulkFetcher fetcher{**source, c};
        auto n = notice_for(frame);
        ++n.size;
        const auto r = fetcher.fetch(n);
        BOOST_TEST((r.outcome == net::FetchOutcome::fallback));
        BOOST_TEST((r.last_failure == net::FetchFailure::size_mismatch));
    }
    {  // the store answers 503
        store->set_fault({.cut_after = std::nullopt, .corrupt = false, .status = 503}, 1);
        Sleeps sleeps;
        auto c = config({endpoint(*store)}, sleeps);
        c.fallback_after = 1;
        net::BulkFetcher fetcher{**source, c};
        BOOST_TEST(
            (fetcher.fetch(notice_for(frame)).last_failure == net::FetchFailure::http_status));
    }
    {  // the store hangs up before the handshake
        store->set_fault({.cut_after = std::nullopt, .corrupt = false, .status = 0, .drop = true},
                         1);
        Sleeps sleeps;
        auto c = config({endpoint(*store)}, sleeps);
        c.fallback_after = 1;
        net::BulkFetcher fetcher{**source, c};
        const auto r = fetcher.fetch(notice_for(frame));
        BOOST_TEST((r.outcome == net::FetchOutcome::fallback));
        BOOST_TEST(r.last_failure.has_value());
    }
    {  // a store whose certificate another CA issued
        ak::test::TestCa rogue{"rogue CA"};
        const auto cert = rogue.issue("frame-store", "IP:127.0.0.1");
        auto impostor = FrameStore::create({.role = tls::Role::server,
                                            .ca_pem = pki.ca.cert_pem(),
                                            .cert_pem = cert.cert,
                                            .key_pem = cert.key,
                                            .peer_name = {}},
                                           loopback, 0);
        BOOST_REQUIRE(impostor.has_value());
        static_cast<void>((*impostor)->put(frame));
        Sleeps sleeps;
        auto c = config({endpoint(**impostor)}, sleeps);
        c.fallback_after = 1;
        net::BulkFetcher fetcher{**source, c};
        const auto r = fetcher.fetch(notice_for(frame));
        BOOST_TEST((r.outcome == net::FetchOutcome::fallback));
        BOOST_TEST((r.last_failure == net::FetchFailure::handshake));
        BOOST_TEST((*impostor)->served() == 0U);
    }
    {  // nothing listening
        Sleeps sleeps;
        std::uint16_t closed_port = 0;
        {
            auto l = tls::Listener::bind(loopback, 0);
            BOOST_REQUIRE(l.has_value());
            closed_port = l->port();
        }
        auto c = config({{.host = loopback, .port = closed_port}}, sleeps);
        c.fallback_after = 1;
        net::BulkFetcher fetcher{**source, c};
        BOOST_TEST((fetcher.fetch(notice_for(frame)).last_failure == net::FetchFailure::connect));
    }
}

// A store that does not trust the role's certificate refuses it.
BOOST_AUTO_TEST_CASE(a_store_refuses_a_role_it_does_not_trust,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Pki pki;
    auto store = start_store(pki);
    const auto frame = frame_of(1000, 2);
    static_cast<void>(store->put(frame));
    ak::test::TestCa rogue{"rogue CA"};
    const auto cert = rogue.issue("oar-net", "IP:127.0.0.1");
    auto role = pki.role_config();
    role.cert_pem = cert.cert;
    role.key_pem = cert.key;
    auto source = net::TlsFrameSource::create(role);
    BOOST_REQUIRE(source.has_value());
    Sleeps sleeps;
    auto c = config({endpoint(*store)}, sleeps);
    c.fallback_after = 1;
    net::BulkFetcher fetcher{**source, c};
    const auto r = fetcher.fetch(notice_for(frame));
    BOOST_TEST((r.outcome == net::FetchOutcome::fallback));
    BOOST_TEST(store->served() == 0U);

    // A renewed certificate the store trusts is used from the next fetch.
    BOOST_REQUIRE((*source)->set_config(pki.role_config()).has_value());
    BOOST_TEST((fetcher.fetch(notice_for(frame)).outcome == net::FetchOutcome::fetched));
    auto server_side = pki.store_config();
    BOOST_TEST(!(*source)->set_config(server_side).has_value());  // not a client's
    BOOST_TEST(!net::TlsFrameSource::create(server_side).has_value());
}

// A frame that matches its digest but fails verify is the controller's
// mistake: every store serves the same bytes, so it is dropped at once.
BOOST_AUTO_TEST_CASE(a_frame_verify_refuses_is_dropped_without_retrying) {
    ScriptedSource source;
    const auto frame = frame_of(64, 4);
    source.answers.emplace_back(frame);
    Sleeps sleeps;
    auto c = config({{.host = "a", .port = 1}, {.host = "b", .port = 2}}, sleeps);
    proto::FrameKind seen{};
    c.verify = [&seen](proto::FrameKind k, std::span<const std::byte> /*bytes*/) {
        seen = k;
        return false;
    };
    net::BulkFetcher fetcher{source, c};
    const auto n = notice_for(frame);
    const auto r = fetcher.fetch(n);
    BOOST_TEST((r.outcome == net::FetchOutcome::rejected));
    BOOST_TEST(r.frame.empty());
    BOOST_TEST((seen == proto::FrameKind::vpc_stream));
    BOOST_TEST(source.ports.size() == 1U);
    BOOST_TEST(source.digests.at(0) == net::digest_hex(n.sha256));
    BOOST_TEST(fetcher.counters().rejected == 1U);
    BOOST_TEST(fetcher.counters().fallbacks == 0U);
}

// Attempts rotate over the stores, and each notice starts on the store
// after the last one tried, spreading load.
BOOST_AUTO_TEST_CASE(attempts_rotate_over_the_stores) {
    ScriptedSource source;
    const auto frame = frame_of(64, 5);
    source.answers.emplace_back(std::unexpected(net::FetchFailure::timed_out));
    source.answers.emplace_back(std::unexpected(net::FetchFailure::io));
    source.answers.emplace_back(frame);
    source.answers.emplace_back(frame);
    Sleeps sleeps;
    auto c = config({{.host = "a", .port = 1}, {.host = "b", .port = 2}, {.host = "c", .port = 3}},
                    sleeps);
    net::BulkFetcher fetcher{source, c};
    BOOST_TEST((fetcher.fetch(notice_for(frame)).outcome == net::FetchOutcome::fetched));
    BOOST_TEST((fetcher.fetch(notice_for(frame, 2)).outcome == net::FetchOutcome::fetched));
    const std::vector<std::uint16_t> want{1, 2, 3, 1};
    BOOST_TEST((source.ports == want));
    BOOST_TEST(failures(fetcher.counters(), net::FetchFailure::timed_out) == 1U);
    BOOST_TEST(failures(fetcher.counters(), net::FetchFailure::io) == 1U);
    BOOST_TEST(fetcher.counters().fetched == 2U);

    // With no stores at all every notice falls back at once.
    net::BulkFetcher none{source, config({}, sleeps)};
    BOOST_TEST((none.fetch(notice_for(frame)).outcome == net::FetchOutcome::fallback));
    BOOST_TEST(none.counters().attempts == 0U);
}

// BulkWorker fetches on its own thread and signals through its eventfd.
BOOST_AUTO_TEST_CASE(the_worker_fetches_off_thread_and_signals_its_fd,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const Pki pki;
    auto store = start_store(pki);
    const auto a = frame_of(70'000, 11);
    const auto b = frame_of(900, 12);
    static_cast<void>(store->put(a));
    static_cast<void>(store->put(b));

    auto source = net::TlsFrameSource::create(pki.role_config());
    BOOST_REQUIRE(source.has_value());
    net::BulkFetchConfig c;
    c.endpoints = {endpoint(*store)};
    c.fallback_after = 1;
    auto worker = net::BulkWorker::create(std::move(*source), c);
    BOOST_REQUIRE(worker.has_value());
    auto& w = **worker;

    const auto missing = frame_of(10, 13);  // never put: falls back
    BOOST_TEST(w.submit(notice_for(a, 1)));
    BOOST_TEST(w.submit(notice_for(missing, 2)));
    BOOST_TEST(w.submit(notice_for(b, 3)));
    std::vector<net::FetchResult> got;
    const auto deadline = tls::Clock::now() + 30s;
    while (got.size() < 3 && tls::Clock::now() < deadline) {
        pollfd p{.fd = w.fd(), .events = POLLIN, .revents = 0};
        BOOST_REQUIRE(::poll(&p, 1, 1000) >= 0);
        for (auto& r : w.take()) {
            got.push_back(std::move(r));
        }
    }
    BOOST_REQUIRE(got.size() == 3U);
    BOOST_TEST((got[0].outcome == net::FetchOutcome::fetched));
    BOOST_TEST((got[0].frame == a));
    BOOST_TEST((got[1].outcome == net::FetchOutcome::fallback));
    BOOST_TEST(got[1].notice.sequence_or_version == 2U);
    BOOST_TEST((got[2].frame == b));
    const auto counters = w.counters();
    BOOST_TEST(counters.fetched == 2U);
    BOOST_TEST(counters.fallbacks == 1U);
    BOOST_TEST(counters.bytes == a.size() + b.size());

    // Nothing more waits: the eventfd is quiet.
    pollfd p{.fd = w.fd(), .events = POLLIN, .revents = 0};
    BOOST_TEST(::poll(&p, 1, 0) == 0);
}

// The destructor does not wait out a backoff.
BOOST_AUTO_TEST_CASE(stopping_the_worker_ends_a_backoff_at_once,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::atomic<std::size_t> calls{0};
    auto source = std::make_unique<ScriptedSource>();  // every attempt: connect
    source->calls = &calls;
    net::BulkFetchConfig c;
    c.endpoints = {{.host = "a", .port = 1}};
    c.fallback_after = 100;
    c.backoff_initial = 10s;
    c.backoff_max = 10s;
    auto worker = net::BulkWorker::create(std::move(source), c);
    BOOST_REQUIRE(worker.has_value());
    const auto frame = frame_of(10, 1);
    BOOST_TEST((*worker)->submit(notice_for(frame)));
    // Give the thread time to fail its first attempt and start waiting.
    const auto deadline = tls::Clock::now() + 5s;
    while (calls == 0 && tls::Clock::now() < deadline) {
        pollfd p{.fd = (*worker)->fd(), .events = POLLIN, .revents = 0};
        static_cast<void>(::poll(&p, 1, 10));
    }
    BOOST_REQUIRE(calls == 1U);
    const auto started = tls::Clock::now();
    worker->reset();
    BOOST_TEST((tls::Clock::now() - started < 5s));
    BOOST_TEST(calls == 1U);  // no attempt after the stop
}

BOOST_AUTO_TEST_CASE(the_worker_queue_is_bounded) {
    auto source = std::make_unique<ScriptedSource>();
    net::BulkFetchConfig c;  // no stores: each notice falls back at once
    auto worker = net::BulkWorker::create(std::move(source), c);
    BOOST_REQUIRE(worker.has_value());
    const auto frame = frame_of(10, 1);
    std::size_t accepted = 0;
    for (std::size_t i = 0; i < 4 * net::BulkWorker::max_queued; ++i) {
        accepted += (*worker)->submit(notice_for(frame, i + 1)) ? 1U : 0U;
    }
    // The thread drains as it goes, so at least max_queued fit, and the
    // queue never takes more than that beyond what was done.
    BOOST_TEST(accepted >= net::BulkWorker::max_queued);
    BOOST_TEST(net::to_string(net::FetchFailure::digest_mismatch) ==
               std::string{"digest_mismatch"});
}
