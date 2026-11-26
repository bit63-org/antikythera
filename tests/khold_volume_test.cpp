// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kythira .kiro/specs/khold-block-service/ task 16: the KholdVolumeBackend
// against fake khold nodes on loopback, over real TLS 1.3 with
// certificates from a throwaway CA and hold wire version 2. Each node
// leads the stripe groups the shared cluster state says it leads and
// redirects for the rest, so a striped write that starts at the wrong
// leader lands on the right one (Requirements 3.3, 11.3); discard frees
// blocks (4.2); and a node whose certificate names another server is
// never used (11.4, as hold's 13.1).

#define BOOST_TEST_MODULE khold_volume_test
#include <boost/test/unit_test.hpp>

#include <poll.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"
#include "oar/blk/khold_volume_backend.hpp"
#include "proto/hold_stream.hpp"
#include "proto/hold_wire_v2.hpp"
#include "proto/server_identity.hpp"
#include "proto/volume_layout.hpp"
#include "test_support.hpp"
#include "tls/tls.hpp"
#include "tls_test_support.hpp"

namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace {

namespace proto = ak::proto;
namespace tls = ak::tls;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using namespace ak::oar::blk;
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<std::byte>;
using proto::HoldV2Opcode;
using proto::HoldV2Status;

struct IgnoreSigpipe {
    IgnoreSigpipe() { static_cast<void>(std::signal(SIGPIPE, SIG_IGN)); }
};
const IgnoreSigpipe ignore_sigpipe;

constexpr std::uint64_t compute_id = 2;
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;
constexpr std::uint32_t su = 64 * 1024;  // 128 blocks
constexpr std::uint64_t capacity = 4096;
constexpr std::uint64_t group_base = 0x1000;

auto uri(std::uint64_t id) -> std::string {
    return "URI:" + proto::server_uri(id);
}

auto loopback() -> proto::StorageEndpoint {
    proto::StorageEndpoint e{};
    e[10] = std::byte{0xFF};  // ::ffff:127.0.0.1
    e[11] = std::byte{0xFF};
    e[12] = std::byte{127};
    e[15] = std::byte{1};
    return e;
}

auto blocks_of(std::uint64_t tag, std::size_t n) -> Bytes {
    Bytes b(n * bs);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<std::byte>((tag * 31) + (i * 7) + 1);
    }
    return b;
}

// What the fake nodes share: who leads each group, the volume's blocks,
// and what each server was asked.
struct Cluster {
    std::mutex mutex;
    std::map<std::uint64_t, std::uint64_t> leader;   // by group ID
    std::map<std::uint64_t, std::uint16_t> port;     // by server
    std::map<std::uint64_t, Bytes> blocks;           // by lba; absent: zeros
    std::map<std::uint64_t, std::size_t> redirects;  // by server
    std::map<std::uint64_t, std::size_t> served;     // block requests, by server
    proto::VolumeLayout l;
    Bytes read_data;
    Bytes read_crcs;

    auto answer(std::uint64_t server, const proto::HoldV2Frame& req) -> Bytes {
        const std::scoped_lock lock{mutex};
        const auto& h = req.header;
        proto::HoldV2Header r = h;
        r.flags = proto::hold_flags::response;
        r.status = HoldV2Status::ok;
        proto::HoldV2Payload p = std::monostate{};
        if (h.epoch != l.epoch) {
            r.status = HoldV2Status::stale_epoch;
            r.epoch = l.epoch;
        } else if (h.opcode == HoldV2Opcode::hello) {
            r.opcode = HoldV2Opcode::hello_ok;
            p = proto::HoldV2HelloOk{.block_size = bs,
                                     .capacity_blocks = l.capacity_blocks,
                                     .stripe_unit = l.stripe_unit,
                                     .stripe_width = static_cast<std::uint16_t>(l.groups.size())};
        } else if (h.opcode == HoldV2Opcode::ping) {
        } else if (leader[h.group_id] != server) {
            ++redirects[server];
            const auto to = leader[h.group_id];
            r.opcode = HoldV2Opcode::redirect;
            r.status = HoldV2Status::not_leader;
            r.lba = 0;
            r.blocks = 0;
            p = proto::HoldV2Redirect{
                .leader_server = to, .endpoint = loopback(), .port = port[to], .leader_term = 1};
        } else {
            ++served[server];
            r.term = 1;
            p = serve(req);
        }
        auto f = proto::encode_hold_v2_frame({.header = r, .payload = p});
        BOOST_TEST_REQUIRE(f.has_value());
        return *f;
    }

    auto serve(const proto::HoldV2Frame& req) -> proto::HoldV2Payload {
        const auto& h = req.header;
        switch (h.opcode) {
            case HoldV2Opcode::write: {
                const auto& d = std::get<proto::BlockData>(req.payload);
                for (std::uint32_t b = 0; b < h.blocks; ++b) {
                    const auto block = d.data.subspan(std::size_t{b} * bs, bs);
                    blocks[h.lba + b] = Bytes{block.begin(), block.end()};
                }
                return std::monostate{};
            }
            case HoldV2Opcode::discard:
            case HoldV2Opcode::write_zeroes:
                for (std::uint32_t b = 0; b < h.blocks; ++b) {
                    blocks.erase(h.lba + b);
                }
                return std::monostate{};
            case HoldV2Opcode::read: {
                // BlockData holds spans: the buffers outlive the encode.
                auto& data = read_data;
                auto& crcs = read_crcs;
                data.assign(std::size_t{h.blocks} * bs, std::byte{0});
                crcs.clear();
                ak::wire::Writer w{crcs};
                for (std::uint32_t b = 0; b < h.blocks; ++b) {
                    const auto it = blocks.find(h.lba + b);
                    if (it == blocks.end()) {
                        w.le32(0);
                        continue;
                    }
                    std::ranges::copy(it->second, data.begin() + static_cast<std::ptrdiff_t>(
                                                                     std::size_t{b} * bs));
                    w.le32(ak::crc32c::of(it->second));
                }
                return proto::BlockData{.block_size = bs, .crcs = crcs, .data = data};
            }
            default:
                return std::monostate{};
        }
    }
};

// A fake khold node on 127.0.0.1 serving `server` from the cluster, with
// a certificate that names `cert_id`. One thread accepts, one thread per
// connection serves it.
class Node {
public:
    Node(ak::test::TestCa& ca, Cluster& cluster, std::uint64_t server, std::uint64_t cert_id)
        : _cluster{cluster}, _server{server} {
        const auto pem = ca.issue("khold", "IP:127.0.0.1, " + uri(cert_id));
        auto ctx = tls::Context::create({.role = tls::Role::server,
                                         .ca_pem = ca.cert_pem(),
                                         .cert_pem = pem.cert,
                                         .key_pem = pem.key,
                                         .peer_name = {}});
        BOOST_TEST_REQUIRE(ctx.has_value());
        _ctx.emplace(std::move(*ctx));
        auto listener = tls::Listener::bind("127.0.0.1", 0);
        BOOST_TEST_REQUIRE(listener.has_value());
        _listener.emplace(std::move(*listener));
        _thread = std::thread{[this] { accept_loop(); }};
    }
    Node(const Node&) = delete;
    auto operator=(const Node&) -> Node& = delete;
    Node(Node&&) = delete;
    auto operator=(Node&&) -> Node& = delete;
    ~Node() {
        _stop.store(true);
        _thread.join();
        for (auto& t : _conns) {
            t.join();
        }
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return _listener->port(); }

private:
    auto accept_loop() -> void {
        while (!_stop.load()) {
            const auto fd = _listener->accept_fd(Clock::now() + 50ms);
            if (!fd) {
                continue;
            }
            auto s = tls::Stream::accept(*_ctx, *fd, Clock::now() + 2s);
            if (!s) {
                continue;
            }
            _conns.emplace_back([this, st = std::move(*s)]() mutable { serve(st); });
        }
    }

    auto serve(tls::Stream& s) -> void {
        proto::FrameAssembler in{proto::hold_v2_version};
        Bytes buf(64 * 1024);
        while (!_stop.load()) {
            const auto got = s.read_some(buf);
            if (!got) {
                break;
            }
            if (*got == 0) {
                if (!s.pending()) {
                    pollfd p{.fd = s.fd(), .events = POLLIN, .revents = 0};
                    static_cast<void>(::poll(&p, 1, 50));
                }
                continue;
            }
            in.feed(std::span{buf}.first(*got));
            for (;;) {
                auto f = in.next();
                if (!f || !f->has_value()) {
                    break;
                }
                const auto req = proto::decode_hold_v2_frame(**f);
                if (!req) {
                    continue;
                }
                const auto reply = _cluster.answer(_server, *req);
                if (!s.write_all(reply, Clock::now() + 2s)) {
                    s.close();
                    return;
                }
            }
        }
        s.close();
    }

    Cluster& _cluster;
    std::uint64_t _server;
    std::optional<tls::Context> _ctx;
    std::optional<tls::Listener> _listener;
    std::atomic<bool> _stop{false};
    std::thread _thread;
    std::vector<std::thread> _conns;
};

// Two groups, both with data members on servers 10 and 20 at their ports.
auto layout(const std::map<std::uint64_t, std::uint16_t>& ports) -> proto::VolumeLayout {
    proto::VolumeLayout l;
    l.key_id = 1;
    l.server_id = compute_id;
    l.volume_id = vol;
    l.epoch = 1;
    l.lineage_id = 9;
    l.capacity_blocks = capacity;
    l.block_size = bs;
    l.stripe_unit = su;
    l.commit_rule = proto::CommitRule::all_in_sync;
    l.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    l.timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900};
    for (std::uint64_t i = 0; i < 2; ++i) {
        proto::StripeGroup g{.group_id = group_base + i, .members = {}};
        for (const auto& [server, port] : ports) {
            g.members.push_back({.server_id = server,
                                 .endpoint = loopback(),
                                 .port = port,
                                 .kind = proto::MemberKind::data,
                                 .drive = 0});
        }
        l.groups.push_back(g);
    }
    l.attachments = {{.attachment_id = att,
                      .server_id = compute_id,
                      .generation = 1,
                      .mode = proto::AttachMode::rw}};
    return l;
}

auto backend(ak::test::TestCa& ca, std::chrono::milliseconds request_timeout = 30s)
    -> std::unique_ptr<KholdVolumeBackend> {
    const auto pem = ca.issue("compute", uri(compute_id));
    auto b = KholdVolumeBackend::create(
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

auto run(KholdVolumeBackend& b, const std::function<bool()>& done, Clock::duration limit = 10s)
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
    [[nodiscard]] auto ok() const -> bool { return result && result->has_value(); }
};

}  // namespace

BOOST_AUTO_TEST_CASE(stripes_a_volume_over_tls_and_follows_redirects,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::test::TestCa ca{"storage CA"};
    Cluster cluster;
    Node n10{ca, cluster, 10, 10};
    Node n20{ca, cluster, 20, 20};
    {
        const std::scoped_lock lock{cluster.mutex};
        cluster.port = {{10, n10.port()}, {20, n20.port()}};
        cluster.l = layout(cluster.port);
        // The initiator first guesses server 10 for group 0: it redirects.
        cluster.leader = {{group_base, 20}, {group_base + 1, 20}};
    }
    auto b = backend(ca);
    BOOST_TEST(b->size_bytes() == 0U);

    // Submitted before the layout: held, not failed.
    const auto data = blocks_of(1, 300);  // stripe units 0, 1 and 2
    Done w;
    b->submit_write(64 * bs, data, w.fn());
    BOOST_TEST(!run(*b, [&] { return w.result.has_value(); }, 200ms));

    BOOST_TEST_REQUIRE(b->set_layout(cluster.l).has_value());
    BOOST_TEST(b->size_bytes() == capacity * bs);
    BOOST_TEST_REQUIRE(run(*b, [&] { return w.result.has_value(); }));
    BOOST_TEST(w.ok());
    {
        const std::scoped_lock lock{cluster.mutex};
        BOOST_TEST(cluster.blocks.size() == 300U);
        BOOST_TEST((cluster.blocks[64] == Bytes{data.begin(), data.begin() + bs}));
        BOOST_TEST((cluster.blocks[363] == Bytes{data.end() - bs, data.end()}));
    }

    Bytes back(data.size());
    Done r;
    b->submit_read(64 * bs, back, r.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return r.result.has_value(); }));
    BOOST_TEST(r.ok());
    BOOST_TEST(back == data, boost::test_tools::per_element());

    // Discard the middle unit: it reads back as zeros, the rest stays.
    Done d;
    b->submit_discard(std::uint64_t{su}, su, d.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return d.result.has_value(); }));
    BOOST_TEST(d.ok());
    Done r2;
    std::ranges::fill(back, std::byte{0xAA});
    b->submit_read(64 * bs, back, r2.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return r2.result.has_value(); }));
    BOOST_TEST(r2.ok());
    const std::size_t before = su - (64 * bs);  // bytes of unit 0 written
    BOOST_TEST(std::ranges::equal(std::span{back}.first(before), std::span{data}.first(before)));
    BOOST_TEST(std::ranges::all_of(std::span{back}.subspan(before, su),
                                   [](std::byte x) { return x == std::byte{0}; }));
    BOOST_TEST(std::ranges::equal(std::span{back}.subspan(before + su),
                                  std::span{data}.subspan(before + su)));

    const std::scoped_lock lock{cluster.mutex};
    BOOST_TEST(cluster.redirects[10] >= 1U);
    BOOST_TEST(cluster.served[10] == 0U);
    BOOST_TEST(cluster.served[20] >= 4U);
    BOOST_TEST(b->take_faults().empty());
}

BOOST_AUTO_TEST_CASE(never_uses_a_node_whose_certificate_names_another_server,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::test::TestCa ca{"storage CA"};
    Cluster cluster;
    Node impostor{ca, cluster, 10, 55};  // the layout's server 10, by a certificate for 55
    {
        const std::scoped_lock lock{cluster.mutex};
        cluster.port = {{10, impostor.port()}};
        cluster.l = layout(cluster.port);
        cluster.leader = {{group_base, 10}, {group_base + 1, 10}};
    }
    auto b = backend(ca, 1500ms);
    BOOST_TEST_REQUIRE(b->set_layout(cluster.l).has_value());
    const auto data = blocks_of(2, 8);
    Done w;
    b->submit_write(0, data, w.fn());
    BOOST_TEST_REQUIRE(run(*b, [&] { return w.result.has_value(); }));
    BOOST_TEST(!w.ok());
    BOOST_TEST(b->sessions_open() == 0U);
    const std::scoped_lock lock{cluster.mutex};
    BOOST_TEST(cluster.served[10] == 0U);
    BOOST_TEST(cluster.blocks.empty());
}
