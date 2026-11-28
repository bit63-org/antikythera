// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 2: mutually authenticated
// TLS (ak::tls) and the ControllerLink over it, against an in-process
// controller on loopback with a throwaway PKI.

#define BOOST_TEST_MODULE controller_link_test
#include <boost/test/unit_test.hpp>

#include <poll.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <thread>
#include <vector>

#include "helm/controller_link.hpp"
#include "helm/mailbox.hpp"
#include "proto/link.hpp"
#include "tls/tls.hpp"
#include "tls_test_support.hpp"

namespace helm = ak::helm;
namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
namespace tls = ak::tls;
using namespace std::chrono_literals;
using proto::RecordType;

namespace {

constexpr unsigned link_timeout_seconds = 60;
constexpr std::uint64_t server = 0x5E'0001;
constexpr std::uint64_t boot = 0xB007;
constexpr proto::KeyId key = 3;
const std::string loopback = "127.0.0.1";

struct IgnoreSigpipe {
    IgnoreSigpipe() { (void)std::signal(SIGPIPE, SIG_IGN); }
};
const IgnoreSigpipe ignore_sigpipe;

auto soon(std::chrono::milliseconds d = 10s) -> tls::Clock::time_point {
    return tls::Clock::now() + d;
}

// The two PKIs of a deployment: kythira's CA issues the controller's
// certificate; the server CA issues helm's.
struct Pki {
    ak::test::TestCa controller_ca{"kythira test CA"};
    ak::test::TestCa server_ca{"antikythera server CA"};
    ak::test::Pem controller = controller_ca.issue("controller", "IP:127.0.0.1");
    ak::test::Pem helm_cert = server_ca.issue("server-5e0001", "DNS:server-5e0001");

    [[nodiscard]] auto controller_config() const -> tls::Config {
        return {.role = tls::Role::server,
                .ca_pem = server_ca.cert_pem(),
                .cert_pem = controller.cert,
                .key_pem = controller.key,
                .peer_name = ""};
    }
    [[nodiscard]] auto helm_config() const -> tls::Config {
        return {.role = tls::Role::client,
                .ca_pem = controller_ca.cert_pem(),
                .cert_pem = helm_cert.cert,
                .key_pem = helm_cert.key,
                .peer_name = loopback};
    }
};

// Reads records from a stream until `want` have arrived or the deadline.
auto read_records(tls::Stream& s, proto::RecordDecoder& d, std::size_t want,
                  tls::Clock::time_point deadline) -> std::vector<proto::Record> {
    std::vector<proto::Record> out;
    std::array<std::byte, 4096> buf{};
    while (out.size() < want && tls::Clock::now() < deadline) {
        if (!s.pending()) {
            pollfd p{.fd = s.fd(), .events = POLLIN, .revents = 0};
            (void)poll(&p, 1, 100);
        }
        auto got = s.read_some(buf);
        if (!got) {
            break;
        }
        d.feed(std::span{buf}.first(*got));
        for (;;) {
            auto r = d.next();
            if (!r || !r->has_value()) {
                break;
            }
            out.push_back(std::move(**r));
        }
    }
    return out;
}

auto report_of(const proto::Record& r) -> proto::Report {
    BOOST_REQUIRE((r.type == RecordType::report));
    auto rep = proto::decode_report(r.payload);
    BOOST_REQUIRE(rep.has_value());
    return *rep;
}

auto send(tls::Stream& s, RecordType t, std::span<const std::byte> payload) -> void {
    auto rec = proto::encode_record(t, payload);
    BOOST_REQUIRE(rec.has_value());
    BOOST_REQUIRE(s.write_all(*rec, soon()).has_value());
}

auto envelope_bytes(std::uint64_t seq) -> std::vector<std::byte> {
    const mb::Header h{.type = mb::Type::list_vms, .seq = seq, .key_id = key, .server_id = server};
    std::array<std::byte, mb::signature_size> sig{};
    auto slot = mb::encode(h, {}, sig);
    BOOST_REQUIRE(slot.has_value());
    auto env = proto::encode_envelope({.server_id = server, .key_id = key, .slot = *slot});
    BOOST_REQUIRE(env.has_value());
    return {env->begin(), env->end()};
}

struct WaitingSink final : helm::ControllerSink {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::uint64_t> seqs;

    auto on_envelope(const proto::Envelope& e) -> void override {
        const std::scoped_lock lock{mutex};
        seqs.push_back(proto::slot_seq(e.slot));
        cv.notify_all();
    }
    auto on_map_update(const proto::MapUpdate&, std::span<const std::byte>) -> void override {}

    auto wait_for(std::size_t n) -> bool {
        std::unique_lock lock{mutex};
        return cv.wait_for(lock, 10s, [&] { return seqs.size() >= n; });
    }
};

auto inventory() -> proto::Inventory {
    proto::Inventory inv;
    inv.boot_id = boot;
    inv.cores_total = 4;
    return inv;
}

// Runs a client handshake against a server context on loopback and
// returns both outcomes.
struct HandshakeResult {
    std::expected<void, tls::Error> client;
    std::expected<void, tls::Error> server;
};

auto handshake(const tls::Config& server_cfg, const tls::Config& client_cfg) -> HandshakeResult {
    auto server_ctx = tls::Context::create(server_cfg);
    auto client_ctx = tls::Context::create(client_cfg);
    BOOST_REQUIRE(server_ctx.has_value());
    BOOST_REQUIRE(client_ctx.has_value());
    auto listener = tls::Listener::bind(loopback, 0);
    BOOST_REQUIRE(listener.has_value());
    HandshakeResult result{};
    std::thread srv{[&] {
        auto fd = listener->accept_fd(soon());
        if (!fd) {
            result.server = std::unexpected(fd.error());
            return;
        }
        auto s = tls::Stream::accept(*server_ctx, *fd, soon(5s));
        if (!s) {
            result.server = std::unexpected(s.error());
            return;
        }
        // TLS 1.3 sends the client's certificate after the client's view
        // of the handshake completes; a byte round trip surfaces a
        // rejection on both sides.
        std::array<std::byte, 1> b{std::byte{1}};
        (void)s->write_all(b, soon(5s));
    }};
    auto c = tls::Stream::connect(*client_ctx, loopback, listener->port(), soon(5s));
    if (!c) {
        result.client = std::unexpected(c.error());
    } else {
        std::array<std::byte, 1> b{};
        const auto deadline = soon(5s);
        std::expected<std::size_t, tls::Error> got{0};
        while (got && *got == 0 && tls::Clock::now() < deadline) {
            pollfd p{.fd = c->fd(), .events = POLLIN, .revents = 0};
            (void)poll(&p, 1, 100);
            got = c->read_some(b);
        }
        if (!got) {
            result.client = std::unexpected(got.error());
        }
    }
    srv.join();
    return result;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(tls_policy, *boost::unit_test::timeout(link_timeout_seconds))

BOOST_AUTO_TEST_CASE(mutual_authentication_succeeds) {
    const Pki pki;
    const auto r = handshake(pki.controller_config(), pki.helm_config());
    BOOST_TEST(r.client.has_value());
    BOOST_TEST(r.server.has_value());
}

BOOST_AUTO_TEST_CASE(client_rejects_a_server_from_another_ca) {
    const Pki pki;
    ak::test::TestCa rogue{"rogue CA"};
    auto cfg = pki.controller_config();
    const auto impostor = rogue.issue("controller", "IP:127.0.0.1");
    cfg.cert_pem = impostor.cert;
    cfg.key_pem = impostor.key;
    const auto r = handshake(cfg, pki.helm_config());
    BOOST_TEST(!r.client.has_value());
}

BOOST_AUTO_TEST_CASE(client_rejects_a_server_with_the_wrong_name) {
    Pki pki;
    auto cfg = pki.controller_config();
    auto other = pki.controller_ca.issue("elsewhere", "IP:10.9.9.9");
    cfg.cert_pem = other.cert;
    cfg.key_pem = other.key;
    const auto r = handshake(cfg, pki.helm_config());
    BOOST_TEST(!r.client.has_value());
}

BOOST_AUTO_TEST_CASE(server_rejects_a_client_from_another_ca) {
    const Pki pki;
    ak::test::TestCa rogue{"rogue CA"};
    auto cfg = pki.helm_config();
    const auto impostor = rogue.issue("server-5e0001", "DNS:server-5e0001");
    cfg.cert_pem = impostor.cert;
    cfg.key_pem = impostor.key;
    const auto r = handshake(pki.controller_config(), cfg);
    BOOST_TEST(!r.server.has_value());
    BOOST_TEST(!r.client.has_value());
}

BOOST_AUTO_TEST_CASE(server_can_pin_the_client_name) {
    const Pki pki;
    auto cfg = pki.controller_config();
    cfg.peer_name = "server-5e0002";
    const auto r = handshake(cfg, pki.helm_config());
    BOOST_TEST(!r.server.has_value());
    cfg.peer_name = "server-5e0001";
    const auto ok = handshake(cfg, pki.helm_config());
    BOOST_TEST(ok.server.has_value());
}

// cold-start Requirement 7.2: certificates are checked at the time the
// configuration gives (helm: max(RTC, time floor)), not the system clock.
// The test certificates are valid from a minute ago for an hour.
BOOST_AUTO_TEST_CASE(certificates_are_checked_at_the_verification_time) {
    const Pki pki;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    auto at = [](std::int64_t t) {
        return std::function<std::optional<std::int64_t>()>{[t] { return std::optional{t}; }};
    };
    auto client = pki.helm_config();

    client.verification_time = at(now);
    BOOST_TEST(handshake(pki.controller_config(), client).client.has_value());
    // nullopt: the system clock.
    client.verification_time = [] { return std::optional<std::int64_t>{}; };
    BOOST_TEST(handshake(pki.controller_config(), client).client.has_value());

    // A floor past the server certificate's notAfter: expired.
    client.verification_time = at(now + 7200);
    BOOST_TEST(!handshake(pki.controller_config(), client).client.has_value());
    // A clock in the past (what a floor prevents): not yet valid.
    client.verification_time = at(now - 7200);
    BOOST_TEST(!handshake(pki.controller_config(), client).client.has_value());
}

BOOST_AUTO_TEST_CASE(bad_configuration_is_refused) {
    const Pki pki;
    auto cfg = pki.helm_config();
    cfg.peer_name = "";
    BOOST_TEST((tls::Context::create(cfg).error() == tls::Error::bad_config));
    cfg = pki.helm_config();
    cfg.key_pem = pki.controller.key;  // does not match the certificate
    BOOST_TEST((tls::Context::create(cfg).error() == tls::Error::bad_config));
    cfg = pki.helm_config();
    cfg.ca_pem = "not a certificate";
    BOOST_TEST((tls::Context::create(cfg).error() == tls::Error::bad_config));
}

BOOST_AUTO_TEST_CASE(connect_to_nothing_fails_promptly) {
    const Pki pki;
    auto ctx = tls::Context::create(pki.helm_config());
    BOOST_REQUIRE(ctx.has_value());
    std::uint16_t port = 0;
    {
        auto l = tls::Listener::bind(loopback, 0);
        BOOST_REQUIRE(l.has_value());
        port = l->port();
    }  // closed: nothing listens there now
    auto s = tls::Stream::connect(*ctx, loopback, port, soon(5s));
    BOOST_REQUIRE(!s.has_value());
    BOOST_TEST((s.error() == tls::Error::connect_failed));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(controller_link, *boost::unit_test::timeout(link_timeout_seconds))

BOOST_AUTO_TEST_CASE(registers_relays_and_reconciles_after_reconnect) {
    const Pki pki;
    auto server_ctx = tls::Context::create(pki.controller_config());
    BOOST_REQUIRE(server_ctx.has_value());
    auto listener = tls::Listener::bind(loopback, 0);
    BOOST_REQUIRE(listener.has_value());

    WaitingSink sink;
    helm::ControllerSession session{server, boot, inventory, sink};
    helm::LinkOptions opts{.host = loopback,
                           .port = listener->port(),
                           .tls = pki.helm_config(),
                           .min_backoff = 20ms,
                           .max_backoff = 100ms,
                           .io_timeout = 5s};
    auto link = helm::ControllerLink::create(opts, session);
    BOOST_REQUIRE(link.has_value());
    std::jthread runner{[&](const std::stop_token& st) { (*link)->run(st); }};

    // First connection: hello, inventory. Send a command, ack nothing.
    {
        auto fd = listener->accept_fd(soon());
        BOOST_REQUIRE(fd.has_value());
        auto s = tls::Stream::accept(*server_ctx, *fd, soon());
        BOOST_REQUIRE(s.has_value());
        proto::RecordDecoder d;
        auto recs = read_records(*s, d, 2, soon());
        BOOST_REQUIRE(recs.size() == 2U);
        BOOST_TEST((recs[0].type == RecordType::hello));
        BOOST_TEST(proto::decode_hello(recs[0].payload)->boot_id == boot);
        BOOST_TEST(report_of(recs[1]).report_seq == 1U);

        send(*s, RecordType::envelope, envelope_bytes(41));
        BOOST_REQUIRE(sink.wait_for(1));
        BOOST_TEST(sink.seqs[0] == 41U);

        // A report from another helm thread goes straight out.
        (void)(*link)->report(proto::CommandOutcome{
            .in_reply_to = 41, .command = 3, .status = proto::CommandStatus::ok, .payload = {}});
        recs = read_records(*s, d, 1, soon());
        BOOST_REQUIRE(recs.size() == 1U);
        BOOST_TEST(report_of(recs[0]).report_seq == 2U);
        auto ack = proto::encode_report_ack({.server_id = server, .report_seq = 1});
        send(*s, RecordType::report_ack, *ack);
        // Give the link a moment to process the ack before the drop.
        std::this_thread::sleep_for(100ms);
        s->close();  // the controller goes away
    }

    // Queued while disconnected.
    (void)(*link)->report(proto::VmExitedReport{
        .vm_id = 7, .exit_status = 0, .reason = proto::ExitReason::guest_shutdown});

    // Second connection: hello, unacked outcome (2), exit (3), inventory (4).
    {
        auto fd = listener->accept_fd(soon());
        BOOST_REQUIRE(fd.has_value());
        auto s = tls::Stream::accept(*server_ctx, *fd, soon());
        BOOST_REQUIRE(s.has_value());
        proto::RecordDecoder d;
        auto recs = read_records(*s, d, 4, soon());
        BOOST_REQUIRE(recs.size() == 4U);
        BOOST_TEST((recs[0].type == RecordType::hello));
        BOOST_TEST(report_of(recs[1]).report_seq == 2U);
        BOOST_TEST(report_of(recs[2]).report_seq == 3U);
        const auto inv = report_of(recs[3]);
        BOOST_TEST(inv.report_seq == 4U);
        BOOST_TEST(std::holds_alternative<proto::Inventory>(inv.body));

        // A protocol violation: the link drops and comes back.
        send(*s, RecordType::hello, *proto::encode_hello({.server_id = 1, .boot_id = 1}));
        auto fd2 = listener->accept_fd(soon());
        BOOST_REQUIRE(fd2.has_value());
        auto s2 = tls::Stream::accept(*server_ctx, *fd2, soon());
        BOOST_REQUIRE(s2.has_value());
        proto::RecordDecoder d2;
        // hello, the replay (2, 3; inventory 4 is superseded) and a fresh
        // inventory (5).
        recs = read_records(*s2, d2, 4, soon());
        BOOST_REQUIRE(recs.size() == 4U);
        BOOST_TEST((recs[0].type == RecordType::hello));
        BOOST_TEST(report_of(recs[1]).report_seq == 2U);
        BOOST_TEST(report_of(recs[3]).report_seq == 5U);
    }

    runner.request_stop();
    runner.join();
    const auto stats = (*link)->stats();
    BOOST_TEST(stats.connects == 3U);
    BOOST_TEST(stats.protocol_errors == 1U);
}

BOOST_AUTO_TEST_CASE(retries_until_the_controller_appears_and_stops_promptly) {
    const Pki pki;
    auto server_ctx = tls::Context::create(pki.controller_config());
    BOOST_REQUIRE(server_ctx.has_value());
    std::uint16_t port = 0;
    {
        auto probe = tls::Listener::bind(loopback, 0);
        BOOST_REQUIRE(probe.has_value());
        port = probe->port();
    }
    WaitingSink sink;
    helm::ControllerSession session{server, boot, inventory, sink};
    auto link = helm::ControllerLink::create({.host = loopback,
                                              .port = port,
                                              .tls = pki.helm_config(),
                                              .min_backoff = 20ms,
                                              .max_backoff = 50ms,
                                              .io_timeout = 5s},
                                             session);
    BOOST_REQUIRE(link.has_value());
    std::jthread runner{[&](const std::stop_token& st) { (*link)->run(st); }};
    std::this_thread::sleep_for(200ms);
    BOOST_TEST((*link)->stats().failures >= 2U);

    auto listener = tls::Listener::bind(loopback, port);
    BOOST_REQUIRE(listener.has_value());
    auto fd = listener->accept_fd(soon());
    BOOST_REQUIRE(fd.has_value());
    auto s = tls::Stream::accept(*server_ctx, *fd, soon());
    BOOST_REQUIRE(s.has_value());

    // Stop while connected and idle: run() must return without waiting
    // for the controller.
    const auto t0 = tls::Clock::now();
    runner.request_stop();
    runner.join();
    BOOST_TEST((tls::Clock::now() - t0 < 2s));
}

BOOST_AUTO_TEST_SUITE_END()
