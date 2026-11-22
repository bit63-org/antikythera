// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 7: the NetworkVolumeBackend
// against a hold node on loopback, over real TLS 1.3 with certificates
// from a throwaway CA. The backend holds requests until the route
// arrives, reaches the primary the route names, and talks to it only if
// its certificate names that server (Requirement 13.1).

#define BOOST_TEST_MODULE network_volume_test
#include <boost/test/unit_test.hpp>

#include <poll.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "hold/server/node.hpp"
#include "hold/store/file_layer.hpp"
#include "oar/blk/network_volume_backend.hpp"
#include "proto/replica_config.hpp"
#include "proto/server_identity.hpp"
#include "test_support.hpp"
#include "tls/tls.hpp"
#include "tls_test_support.hpp"

namespace {

namespace proto = ak::proto;
namespace tls = ak::tls;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using namespace ak::oar::blk;
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<std::byte>;

// A peer that hangs up must not kill the process: the roles' mains
// ignore SIGPIPE, and so do these tests.
struct IgnoreSigpipe {
    IgnoreSigpipe() { static_cast<void>(std::signal(SIGPIPE, SIG_IGN)); }
};
const IgnoreSigpipe ignore_sigpipe;

constexpr std::uint64_t hold_id = 1;
constexpr std::uint64_t compute_id = 2;
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;

auto uri(std::uint64_t id) -> std::string {
    return "URI:" + proto::server_uri(id);
}

auto config(std::uint64_t server, std::uint16_t port) -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.server_id = server;
    c.volume_id = vol;
    c.epoch = 1;
    c.lineage_id = 9;
    c.capacity_blocks = 1024;
    c.block_size = bs;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    proto::ReplicaMember m;
    m.server_id = hold_id;
    m.endpoint[10] = std::byte{0xFF};  // ::ffff:127.0.0.1
    m.endpoint[11] = std::byte{0xFF};
    m.endpoint[12] = std::byte{127};
    m.endpoint[15] = std::byte{1};
    m.port = port;
    m.role = proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    c.attachments = {{.attachment_id = att,
                      .server_id = compute_id,
                      .generation = 1,
                      .mode = proto::AttachMode::rw}};
    return c;
}

auto blocks_of(std::uint64_t tag, std::size_t n) -> Bytes {
    Bytes b(n * bs);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<std::byte>((tag * 31) + (i * 7) + 1);
    }
    return b;
}

// A hold node on 127.0.0.1, on its own thread, whose certificate names
// server `cert_id` (the real one is hold_id).
class Hold {
public:
    Hold(ak::test::TestCa& ca, std::uint64_t cert_id) {
        const auto pem = ca.issue("hold", "IP:127.0.0.1, " + uri(cert_id));
        auto node = ak::hold::Node::create(
            files, {.host = "127.0.0.1",
                    .port = 0,
                    .tls = {.role = tls::Role::server,
                            .ca_pem = ca.cert_pem(),
                            .cert_pem = pem.cert,
                            .key_pem = pem.key,
                            .peer_name = {}},
                    .server = {.server_id = hold_id, .data_dir = "/srv/hold", .leases = false},
                    .handshake_timeout = 2000ms,
                    .write_timeout = 2000ms});
        BOOST_TEST_REQUIRE(node.has_value());
        _node = std::move(*node);
        BOOST_TEST_REQUIRE(
            _node->server().apply_config(config(hold_id, port()), Clock::now()).has_value());
        _thread = std::thread{[this] {
            while (!_stop.load()) {
                _node->run_once(20ms);
            }
        }};
    }
    Hold(const Hold&) = delete;
    auto operator=(const Hold&) -> Hold& = delete;
    Hold(Hold&&) = delete;
    auto operator=(Hold&&) -> Hold& = delete;
    ~Hold() {
        _stop.store(true);
        _thread.join();
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return _node->port(); }

private:
    ak::hold::store::MemFiles files;
    std::unique_ptr<ak::hold::Node> _node;
    std::atomic<bool> _stop{false};
    std::thread _thread;
};

auto backend(ak::test::TestCa& ca, std::chrono::milliseconds request_timeout = 30s)
    -> std::unique_ptr<NetworkVolumeBackend> {
    const auto pem = ca.issue("compute", uri(compute_id));
    auto b = NetworkVolumeBackend::create(
        {.initiator = {.attachment_id = att, .request_timeout = request_timeout},
         .tls = {.role = tls::Role::client,
                 .ca_pem = ca.cert_pem(),
                 .cert_pem = pem.cert,
                 .key_pem = pem.key,
                 .peer_name = {}},
         .connect_timeout = 2000ms,
         .write_timeout = 2000ms});
    BOOST_TEST_REQUIRE(b.has_value());
    return std::move(*b);
}

// Runs the backend the way the role's loop does (wait on wake_fd, then
// poll) until `done` or the time is up.
auto run(NetworkVolumeBackend& b, const std::function<bool()>& done, Clock::duration limit = 10s)
    -> bool {
    const auto until = Clock::now() + limit;
    while (!done()) {
        if (Clock::now() >= until) {
            return false;
        }
        pollfd p{.fd = b.wake_fd(), .events = POLLIN, .revents = 0};
        static_cast<void>(::poll(&p, 1, 50));
        static_cast<void>(b.poll());
    }
    return true;
}

struct Done {
    std::optional<BackendResult> result;
    auto fn() -> BackendCompletion {
        return [this](BackendResult r) { result = r; };
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(serves_a_volume_over_tls, *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::test::TestCa ca{"storage CA"};
    Hold hold{ca, hold_id};
    auto b = backend(ca);
    BOOST_TEST(b->wake_fd() >= 0);
    BOOST_TEST(b->size_bytes() == 0U);

    // Submitted before the route: held, not failed.
    const auto data = blocks_of(1, 8);
    Done w;
    b->submit_write(16 * bs, data, w.fn());
    BOOST_TEST(!run(*b, [&] { return w.result.has_value(); }, 300ms));

    BOOST_TEST_REQUIRE(b->set_route(config(compute_id, hold.port())).has_value());
    BOOST_TEST(b->routed());
    BOOST_TEST(b->size_bytes() == 1024U * bs);
    BOOST_TEST_REQUIRE(run(*b, [&] { return w.result.has_value(); }));
    BOOST_TEST(w.result->has_value());
    BOOST_TEST(b->session_open());

    Bytes out(8 * bs);
    Done r;
    b->submit_read(16 * bs, out, r.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return r.result.has_value(); }));
    BOOST_TEST(r.result->has_value());
    BOOST_TEST(std::ranges::equal(out, data));

    Done f;
    b->submit_flush(f.fn());
    BOOST_TEST(f.result.has_value());
    BOOST_TEST(b->take_faults().empty());
    BOOST_TEST(!b->poll());  // nothing pending
}

BOOST_AUTO_TEST_CASE(talks_only_to_the_server_the_route_names,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::test::TestCa ca{"storage CA"};
    Hold hold{ca, 5};  // a valid certificate, but for server 5
    auto b = backend(ca, 1500ms);
    BOOST_TEST_REQUIRE(b->set_route(config(compute_id, hold.port())).has_value());
    const auto data = blocks_of(2, 1);
    Done w;
    b->submit_write(0, data, w.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return w.result.has_value(); }));
    BOOST_TEST(!w.result->has_value());  // failed at its deadline
    BOOST_TEST(!b->session_open());
}

BOOST_AUTO_TEST_CASE(fails_requests_when_no_primary_answers,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::test::TestCa ca{"storage CA"};
    std::uint16_t port = 0;
    {
        Hold gone{ca, hold_id};
        port = gone.port();
    }  // nothing listens there any more
    auto b = backend(ca, 1s);
    BOOST_TEST_REQUIRE(b->set_route(config(compute_id, port)).has_value());
    Bytes out(bs);
    Done r;
    b->submit_read(0, out, r.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return r.result.has_value(); }));
    BOOST_TEST((!r.result->has_value() && r.result->error() == BackendError::io));
}

BOOST_AUTO_TEST_CASE(drops_pending_requests_on_destruction,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::test::TestCa ca{"storage CA"};
    bool ran = false;
    Bytes out(bs);
    {
        auto b = backend(ca);
        b->submit_read(0, out, [&](BackendResult) { ran = true; });
        BOOST_TEST(b->poll());
    }
    BOOST_TEST(!ran);
}
