// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 6: a hold node on loopback,
// driven over real TLS 1.3 by clients holding certificates from a
// throwaway CA (Requirements 13.1, 13.2). The node takes the server ID
// from the client certificate's URI and nothing else: a client whose
// certificate names no server, or the wrong one, gets nothing done.

#define BOOST_TEST_MODULE hold_node_test
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "proto/server_identity.hpp"
#include "hold/server/node.hpp"
#include "hold/store/file_layer.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "test_support.hpp"
#include "tls/tls.hpp"
#include "tls_test_support.hpp"

namespace {

namespace proto = ak::proto;
namespace tls = ak::tls;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using ak::hold::Clock;
using Bytes = std::vector<std::byte>;

constexpr std::uint64_t hold_id = 1;
constexpr std::uint64_t compute_id = 2;
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;

auto config() -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.server_id = hold_id;
    c.volume_id = vol;
    c.epoch = 1;
    c.lineage_id = 9;
    c.capacity_blocks = 64;
    c.block_size = bs;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    proto::ReplicaMember m;
    m.server_id = hold_id;
    m.endpoint[15] = std::byte{1};
    m.port = 4430;
    m.role = proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    c.attachments = {{.attachment_id = att,
                      .server_id = compute_id,
                      .generation = 1,
                      .mode = proto::AttachMode::rw}};
    return c;
}

// A node on 127.0.0.1 running on its own thread.
class Rig {
public:
    Rig() {
        const auto pem = ca.issue("hold-1", "IP:127.0.0.1, " + uri(hold_id));
        auto node = ak::hold::Node::create(
            files, {.host = "127.0.0.1",
                    .port = 0,
                    .tls = {.role = tls::Role::server,
                            .ca_pem = ca.cert_pem(),
                            .cert_pem = pem.cert,
                            .key_pem = pem.key,
                            .peer_name = {}},
                    .server = {.server_id = hold_id, .data_dir = "/srv/hold"},
                    .handshake_timeout = 2000ms,
                    .write_timeout = 2000ms});
        BOOST_TEST_REQUIRE(node.has_value());
        _node = std::move(*node);
        BOOST_TEST_REQUIRE(_node->server().apply_config(config(), Clock::now()).has_value());
        _thread = std::thread{[this] {
            while (!_stop.load()) {
                _node->run_once(20ms);
            }
        }};
    }
    Rig(const Rig&) = delete;
    auto operator=(const Rig&) -> Rig& = delete;
    Rig(Rig&&) = delete;
    auto operator=(Rig&&) -> Rig& = delete;
    ~Rig() {
        _stop.store(true);
        _thread.join();
    }

    static auto uri(std::uint64_t id) -> std::string { return "URI:" + ak::proto::server_uri(id); }

    // A client presenting a certificate with these subjectAltNames.
    auto connect(const std::string& san) -> std::optional<tls::Stream> {
        const auto pem = ca.issue("client", san);
        auto ctx = tls::Context::create({.role = tls::Role::client,
                                         .ca_pem = ca.cert_pem(),
                                         .cert_pem = pem.cert,
                                         .key_pem = pem.key,
                                         .peer_name = "127.0.0.1"});
        BOOST_TEST_REQUIRE(ctx.has_value());
        _contexts.push_back(std::make_unique<tls::Context>(std::move(*ctx)));
        auto s =
            tls::Stream::connect(*_contexts.back(), "127.0.0.1", _node->port(), Clock::now() + 5s);
        if (!s) {
            return std::nullopt;
        }
        return std::move(*s);
    }

    [[nodiscard]] auto node() -> ak::hold::Node& { return *_node; }

    ak::test::TestCa ca{"storage CA"};

private:
    ak::hold::store::MemFiles files;
    std::unique_ptr<ak::hold::Node> _node;
    std::vector<std::unique_ptr<tls::Context>> _contexts;
    std::atomic<bool> _stop{false};
    std::thread _thread;
};

auto send(tls::Stream& s, const proto::HoldFrame& f) -> bool {
    const auto bytes = proto::encode_hold_frame(f);
    BOOST_TEST_REQUIRE(bytes.has_value());
    return s.write_all(*bytes, Clock::now() + 5s).has_value();
}

// The next frame from the node, or nothing if the connection ends first.
auto receive(tls::Stream& s, ak::hold::FrameAssembler& in) -> std::optional<Bytes> {
    const auto deadline = Clock::now() + 5s;
    std::array<std::byte, 4096> buf{};
    while (Clock::now() < deadline) {
        if (auto f = in.next(); f && f->has_value()) {
            return std::move(*f);
        }
        auto got = s.read_some(buf);
        if (!got) {
            return std::nullopt;
        }
        if (*got == 0) {
            std::this_thread::sleep_for(2ms);
            continue;
        }
        in.feed(std::span{buf}.first(*got));
    }
    return std::nullopt;
}

auto header(proto::HoldOpcode op, std::uint64_t id) -> proto::HoldHeader {
    proto::HoldHeader h;
    h.opcode = op;
    h.request_id = id;
    h.volume_id = vol;
    h.epoch = 1;
    h.attachment_id = att;
    h.generation = 1;
    return h;
}

auto hello(tls::Stream& s, ak::hold::FrameAssembler& in) -> std::optional<proto::HoldStatus> {
    if (!send(s, {.header = header(proto::HoldOpcode::hello, 1), .payload = proto::HoldHello{}})) {
        return std::nullopt;
    }
    const auto reply = receive(s, in);
    if (!reply) {
        return std::nullopt;
    }
    return proto::decode_hold_frame(*reply)->header.status;
}

}  // namespace

BOOST_AUTO_TEST_CASE(serves_an_attached_initiator, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto s = rig.connect(Rig::uri(compute_id));
    BOOST_TEST_REQUIRE(s.has_value());
    ak::hold::FrameAssembler in;
    BOOST_TEST((hello(*s, in) == proto::HoldStatus::ok));

    Bytes data(4 * bs);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(i * 13);
    }
    const auto crcs = proto::block_crcs(data, bs);
    auto w = header(proto::HoldOpcode::write, 2);
    w.lba = 8;
    w.blocks = 4;
    BOOST_TEST_REQUIRE(send(*s, {.header = w, .payload = proto::BlockData{bs, crcs, data}}));
    auto r = header(proto::HoldOpcode::read, 3);
    r.lba = 8;
    r.blocks = 4;
    BOOST_TEST_REQUIRE(send(*s, {.header = r, .payload = {}}));

    const auto wrote = receive(*s, in);
    BOOST_TEST_REQUIRE(wrote.has_value());
    const auto wf = proto::decode_hold_frame(*wrote);
    BOOST_TEST(wf->header.request_id == 2U);
    BOOST_TEST((wf->header.status == proto::HoldStatus::ok));
    const auto read = receive(*s, in);
    BOOST_TEST_REQUIRE(read.has_value());
    const auto rf = proto::decode_hold_frame(*read);
    BOOST_TEST_REQUIRE(rf.has_value());
    BOOST_TEST(rf->header.request_id == 3U);
    BOOST_TEST((rf->header.status == proto::HoldStatus::ok));
    const auto& d = std::get<proto::BlockData>(rf->payload);
    BOOST_TEST(std::ranges::equal(d.data, data));
    BOOST_TEST(std::ranges::equal(d.crcs, crcs));
}

BOOST_AUTO_TEST_CASE(knows_peers_only_by_their_certificate,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    // Another server: authenticated, but not the attached one.
    {
        auto s = rig.connect(Rig::uri(3));
        BOOST_TEST_REQUIRE(s.has_value());
        ak::hold::FrameAssembler in;
        BOOST_TEST((hello(*s, in) == proto::HoldStatus::fenced));
    }
    // No server URI, or two: the node hangs up before any frame.
    for (const auto* san :
         {"DNS:compute", "URI:urn:antikythera:server:2, URI:urn:antikythera:server:3"}) {
        BOOST_TEST_INFO(san);
        auto s = rig.connect(san);
        if (s) {  // the handshake may complete before the node checks the names
            ak::hold::FrameAssembler in;
            BOOST_TEST(!hello(*s, in).has_value());
        }
    }
    // A certificate from another CA does not get through the handshake.
    ak::test::TestCa rogue{"rogue CA"};
    const auto pem = rogue.issue("compute", Rig::uri(compute_id));
    auto ctx = tls::Context::create({.role = tls::Role::client,
                                     .ca_pem = rig.ca.cert_pem(),
                                     .cert_pem = pem.cert,
                                     .key_pem = pem.key,
                                     .peer_name = "127.0.0.1"});
    BOOST_TEST_REQUIRE(ctx.has_value());
    auto s = tls::Stream::connect(*ctx, "127.0.0.1", rig.node().port(), Clock::now() + 5s);
    if (s) {
        ak::hold::FrameAssembler in;
        BOOST_TEST(!hello(*s, in).has_value());
    }
}

BOOST_AUTO_TEST_CASE(hangs_up_on_garbage, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto s = rig.connect(Rig::uri(compute_id));
    BOOST_TEST_REQUIRE(s.has_value());
    const Bytes junk(proto::hold_header_size, std::byte{0x5A});
    BOOST_TEST_REQUIRE(s->write_all(junk, Clock::now() + 5s).has_value());
    ak::hold::FrameAssembler in;
    BOOST_TEST(!receive(*s, in).has_value());
}
