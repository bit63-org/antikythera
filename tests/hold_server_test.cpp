// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 6: the hold server's request
// handling over an in-memory replica. HELLO authorization against the
// ReplicaConfig (Requirement 13.2), epoch and generation fencing (6.2,
// 6.4), read-only attachments, READ/WRITE/FLUSH and group commit (1.5),
// per-volume QoS and fair queueing (10.2), config handling and restart.
// Also the server-ID identity parse and the frame assembler.

#define BOOST_TEST_MODULE hold_server_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <ostream>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/crc32c.hpp"
#include "proto/server_identity.hpp"
#include "hold/server/node.hpp"
#include "hold/server/qos.hpp"
#include "hold/server/server.hpp"
#include "hold/store/file_layer.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "test_support.hpp"

namespace ak::proto {
auto operator<<(std::ostream& os, HoldStatus s) -> std::ostream& {
    return os << static_cast<int>(s);
}
auto operator<<(std::ostream& os, HoldOpcode o) -> std::ostream& {
    return os << static_cast<int>(o);
}
}  // namespace ak::proto
namespace ak::hold {
auto operator<<(std::ostream& os, ConfigError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::hold
namespace ak::proto {
auto operator<<(std::ostream& os, IdentityError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::proto

namespace {

namespace proto = ak::proto;
namespace utf = boost::unit_test;
using namespace ak::hold;
using proto::HoldOpcode;
using proto::HoldStatus;
using proto::IdentityError;
using proto::parse_server_uri;
using proto::server_id_of;
using proto::server_uri;
using Bytes = std::vector<std::byte>;
using namespace std::chrono_literals;

constexpr std::uint64_t me = 1;
constexpr std::uint64_t compute = 2;  // the attached server
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;

const Clock::time_point t0{std::chrono::seconds{1000}};

auto member(std::uint64_t id, proto::ReplicaRole role, std::uint32_t gen = 1)
    -> proto::ReplicaMember {
    proto::ReplicaMember m;
    m.server_id = id;
    m.endpoint[15] = static_cast<std::byte>(id);
    m.port = 4430;
    m.role = role;
    m.replica_gen = gen;
    return m;
}

auto config(std::uint64_t epoch, std::uint64_t volume = vol) -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.server_id = me;
    c.volume_id = volume;
    c.epoch = epoch;
    c.lineage_id = 9;
    c.capacity_blocks = 64;
    c.block_size = bs;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    c.members = {member(me, proto::ReplicaRole::primary)};
    c.attachments = {{.attachment_id = att,
                      .server_id = compute,
                      .generation = 1,
                      .mode = proto::AttachMode::rw}};
    return c;
}

auto blocks_of(std::uint64_t tag, std::uint32_t n, std::uint32_t size = bs) -> Bytes {
    Bytes b(std::size_t{n} * size);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<std::byte>((tag * 31) + (i * 7) + 1);
    }
    return b;
}

// Records what the server sends, in order across sessions.
class Sink final : public SessionSink {
public:
    struct Sent {
        SessionId session;
        Bytes bytes;
    };
    auto send(SessionId session, Bytes frame) -> void override {
        _sent.push_back({session, std::move(frame)});
    }
    [[nodiscard]] auto count() const -> std::size_t { return _sent.size(); }
    [[nodiscard]] auto frame(std::size_t i) const -> proto::HoldFrame {
        auto f = proto::decode_hold_frame(_sent.at(i).bytes);
        BOOST_TEST_REQUIRE(f.has_value());
        return *f;
    }
    [[nodiscard]] auto last() const -> proto::HoldFrame { return frame(_sent.size() - 1); }
    [[nodiscard]] auto session(std::size_t i) const -> SessionId { return _sent.at(i).session; }
    auto clear() -> void { _sent.clear(); }

private:
    std::deque<Sent> _sent;
};

class Rig {
public:
    explicit Rig(ServerConfig cfg = {})
        : _cfg{fill(std::move(cfg))}, _server{_files, _cfg, _sink} {}

    [[nodiscard]] auto server() -> HoldServer& { return _server; }
    [[nodiscard]] auto sink() -> Sink& { return _sink; }
    [[nodiscard]] auto files() -> ak::hold::store::MemFiles& { return _files; }

    auto apply(const proto::ReplicaConfig& c) -> void {
        BOOST_TEST_REQUIRE(_server.apply_config(c, t0).has_value());
    }

    static auto header(HoldOpcode op, std::uint64_t epoch, std::uint64_t attachment = att,
                       std::uint32_t generation = 1, std::uint64_t volume = vol)
        -> proto::HoldHeader {
        proto::HoldHeader h;
        h.opcode = op;
        h.request_id = ++_next_request;
        h.volume_id = volume;
        h.epoch = epoch;
        h.attachment_id = attachment;
        h.generation = attachment == 0 ? 0 : generation;
        return h;
    }

    // Sends a frame and returns the status of the reply it produced at
    // once, or ok if it was queued.
    auto send(SessionId s, proto::HoldHeader h, proto::HoldPayload p = {}) -> HoldStatus {
        const auto before = _sink.count();
        _server.on_frame(s, {.header = h, .payload = std::move(p)}, t0);
        return _sink.count() == before ? HoldStatus::ok : _sink.last().header.status;
    }

    auto hello(SessionId s, std::uint64_t epoch = 1, std::uint64_t attachment = att,
               std::uint32_t generation = 1, std::uint64_t volume = vol) -> proto::HoldFrame {
        auto h = header(HoldOpcode::hello, epoch, attachment, generation, volume);
        _server.on_frame(
            s,
            {.header = h,
             .payload = proto::HoldHello{.role = proto::HoldPeerRole::initiator, .replica_gen = 0}},
            t0);
        return _sink.last();
    }

    auto peer_hello(SessionId s, std::uint32_t replica_gen, std::uint64_t epoch = 1)
        -> proto::HoldFrame {
        auto h = header(HoldOpcode::hello, epoch, 0, 0);
        _server.on_frame(s,
                         {.header = h,
                          .payload = proto::HoldHello{.role = proto::HoldPeerRole::peer,
                                                      .replica_gen = replica_gen}},
                         t0);
        return _sink.last();
    }

    // An initiator session past HELLO.
    auto session(std::uint64_t epoch = 1) -> SessionId {
        const auto s = _server.open_session(compute);
        const auto r = hello(s, epoch);
        BOOST_TEST_REQUIRE((r.header.status == HoldStatus::ok));
        return s;
    }

    auto write(SessionId s, std::uint64_t lba, const Bytes& data, std::uint64_t epoch = 1,
               std::uint16_t flags = 0) -> HoldStatus {
        auto h = header(HoldOpcode::write, epoch);
        h.flags = flags;
        h.lba = lba;
        h.blocks = static_cast<std::uint32_t>(data.size() / bs);
        _crcs.push_back(proto::block_crcs(data, bs));
        return send(s, h, proto::BlockData{.block_size = bs, .crcs = _crcs.back(), .data = data});
    }

    auto read(SessionId s, std::uint64_t lba, std::uint32_t blocks, std::uint64_t epoch = 1)
        -> HoldStatus {
        auto h = header(HoldOpcode::read, epoch);
        h.lba = lba;
        h.blocks = blocks;
        return send(s, h);
    }

    auto run(Clock::time_point now = t0) -> void { _server.run(now); }

    // The data of the last reply, which must be a successful read.
    auto read_data() -> Bytes {
        const auto f = _sink.last();
        BOOST_TEST_REQUIRE((f.header.opcode == HoldOpcode::read));
        BOOST_TEST_REQUIRE((f.header.status == HoldStatus::ok));
        const auto* d = std::get_if<proto::BlockData>(&f.payload);
        BOOST_TEST_REQUIRE(d != nullptr);
        for (std::size_t i = 0; i < f.header.blocks; ++i) {
            const auto block = d->data.subspan(i * bs, bs);
            const bool unwritten =
                proto::block_crc(*d, i) == 0 &&
                std::ranges::all_of(block, [](std::byte b) { return b == std::byte{0}; });
            BOOST_TEST((unwritten || ak::crc32c::of(block) == proto::block_crc(*d, i)));
        }
        return {d->data.begin(), d->data.end()};
    }

private:
    static auto fill(ServerConfig c) -> ServerConfig {
        c.server_id = me;
        c.data_dir = "/srv/hold";
        c.leases = false;  // failover is hold_replication_test's
        return c;
    }

    ak::hold::store::MemFiles _files;
    Sink _sink;
    ServerConfig _cfg;
    HoldServer _server;
    std::deque<Bytes> _crcs;
    static inline std::uint64_t _next_request = 0;
};

}  // namespace

// ---- identity and framing ------------------------------------------------------

BOOST_AUTO_TEST_SUITE(identity)

BOOST_AUTO_TEST_CASE(parses_server_uris, *utf::timeout(ak::test::unit_timeout_seconds)) {
    BOOST_TEST(server_uri(42) == "urn:antikythera:server:42");
    BOOST_TEST(parse_server_uri("urn:antikythera:server:42").value() == 42U);
    BOOST_TEST(parse_server_uri("urn:antikythera:server:18446744073709551615").value() ==
               UINT64_MAX);
    for (const auto* bad :
         {"urn:antikythera:server:", "urn:antikythera:server:0", "urn:antikythera:server:042",
          "urn:antikythera:server:-1", "urn:antikythera:server:+1", "urn:antikythera:server:1x",
          "urn:antikythera:server:18446744073709551616", "urn:antikythera:server:1 "}) {
        BOOST_TEST_INFO(bad);
        BOOST_TEST(parse_server_uri(bad).error() == IdentityError::malformed);
    }
    BOOST_TEST(parse_server_uri("https://example.com").error() == IdentityError::none);
    const std::vector<std::string> one{"spiffe://x", "urn:antikythera:server:5"};
    BOOST_TEST(server_id_of(one).value() == 5U);
    const std::vector<std::string> two{"urn:antikythera:server:5", "urn:antikythera:server:6"};
    BOOST_TEST(server_id_of(two).error() == IdentityError::ambiguous);
    const std::vector<std::string> none{"spiffe://x"};
    BOOST_TEST(server_id_of(none).error() == IdentityError::none);
    const std::vector<std::string> bad{"urn:antikythera:server:5", "urn:antikythera:server:x"};
    BOOST_TEST(server_id_of(bad).error() == IdentityError::malformed);
}

BOOST_AUTO_TEST_CASE(assembles_frames, *utf::timeout(ak::test::unit_timeout_seconds)) {
    auto h = Rig::header(HoldOpcode::ping, 1);
    const auto ping = *proto::encode_hold_frame({.header = h, .payload = proto::HoldPing{}});
    Bytes stream = ping;
    stream.insert(stream.end(), ping.begin(), ping.end());
    FrameAssembler a;
    for (std::size_t i = 0; i < stream.size(); ++i) {  // a byte at a time
        a.feed(std::span{stream}.subspan(i, 1));
        auto f = a.next();
        BOOST_TEST_REQUIRE(f.has_value());
        BOOST_TEST(f->has_value() == (i == ping.size() - 1 || i == stream.size() - 1));
        if (f->has_value()) {
            BOOST_TEST((**f == ping));
        }
    }
    BOOST_TEST(a.buffered() == 0U);
    Bytes junk(proto::hold_header_size, std::byte{0x41});
    a.feed(junk);
    BOOST_TEST(!a.next().has_value());
}

BOOST_AUTO_TEST_CASE(limits_volumes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    VolumeLimiter l{{.iops = 10, .mib_per_s = 1000, .burst_iops = 10, .burst_mib = 1000}, t0};
    int admitted = 0;
    while (l.admit(4096, t0)) {
        ++admitted;
    }
    BOOST_TEST(admitted == 12);  // a depth of 11 units, then one into debt
    BOOST_TEST(l.wait() > Clock::duration::zero());
    BOOST_TEST(l.wait() <= std::chrono::milliseconds{100});
    BOOST_TEST(l.admit(4096, t0 + l.wait()));
    BOOST_TEST(VolumeLimiter::io_units(1) == 1.0);
    BOOST_TEST(VolumeLimiter::io_units(256 * 1024) == 1.0);
    BOOST_TEST(VolumeLimiter::io_units((256 * 1024) + 1) == 2.0);
    BOOST_TEST(VolumeLimiter::io_units(4 << 20) == 16.0);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- HELLO -----------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(hello)

BOOST_AUTO_TEST_CASE(accepts_a_current_attachment, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.server().open_session(compute);
    const auto r = rig.hello(s);
    BOOST_TEST((r.header.opcode == HoldOpcode::hello_ok));
    BOOST_TEST((r.header.status == HoldStatus::ok));
    const auto* ok = std::get_if<proto::HoldHelloOk>(&r.payload);
    BOOST_TEST_REQUIRE(ok != nullptr);
    BOOST_TEST(ok->block_size == bs);
    BOOST_TEST(ok->capacity_blocks == 64U);
    BOOST_TEST(ok->commit_seq == 0U);
    BOOST_TEST((rig.hello(s).header.status == HoldStatus::bad_request));  // only once
}

BOOST_AUTO_TEST_CASE(refuses_what_the_config_does_not_allow,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(3));
    auto status = [&](std::uint64_t peer, std::uint64_t epoch, std::uint64_t attachment,
                      std::uint32_t generation, std::uint64_t volume = vol) {
        const auto s = rig.server().open_session(peer);
        return rig.hello(s, epoch, attachment, generation, volume).header.status;
    };
    BOOST_TEST((status(compute, 3, att, 1) == HoldStatus::ok));
    BOOST_TEST((status(compute, 3, att, 1, 8) == HoldStatus::unknown_volume));
    BOOST_TEST((status(compute, 2, att, 1) == HoldStatus::stale_epoch));
    BOOST_TEST((status(compute, 3, att + 1, 1) == HoldStatus::fenced));
    BOOST_TEST((status(compute, 3, att, 2) == HoldStatus::fenced));  // another generation
    BOOST_TEST((status(3, 3, att, 1) == HoldStatus::fenced));        // not the attached server
    // An initiator must not name a replica_gen.
    const auto s = rig.server().open_session(compute);
    auto h = Rig::header(HoldOpcode::hello, 3);
    rig.server().on_frame(
        s,
        {.header = h,
         .payload = proto::HoldHello{.role = proto::HoldPeerRole::initiator, .replica_gen = 1}},
        t0);
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::bad_request));
    // Nothing but HELLO before HELLO.
    const auto fresh = rig.server().open_session(compute);
    BOOST_TEST((rig.read(fresh, 0, 1, 3) == HoldStatus::bad_request));
}

BOOST_AUTO_TEST_CASE(redirects_to_the_primary, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(5);
    c.members = {member(me, proto::ReplicaRole::secondary), member(4, proto::ReplicaRole::primary)};
    rig.apply(c);
    const auto r = rig.hello(rig.server().open_session(compute), 5);
    BOOST_TEST((r.header.opcode == HoldOpcode::redirect));
    BOOST_TEST((r.header.status == HoldStatus::not_primary));
    const auto* to = std::get_if<proto::HoldRedirect>(&r.payload);
    BOOST_TEST_REQUIRE(to != nullptr);
    BOOST_TEST(to->primary_server == 4U);
    BOOST_TEST(to->primary_epoch == 5U);
    // An epoch this server has not seen yet: it says what it knows.
    const auto ahead = rig.hello(rig.server().open_session(compute), 6);
    BOOST_TEST((ahead.header.opcode == HoldOpcode::redirect));
    BOOST_TEST(std::get<proto::HoldRedirect>(ahead.payload).primary_epoch == 5U);
}

BOOST_AUTO_TEST_CASE(accepts_members_as_peers, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(2);
    c.members = {member(me, proto::ReplicaRole::primary),
                 member(4, proto::ReplicaRole::secondary, 3)};
    rig.apply(c);
    BOOST_TEST(
        (rig.peer_hello(rig.server().open_session(4), 3, 2).header.status == HoldStatus::ok));
    BOOST_TEST((rig.peer_hello(rig.server().open_session(4), 2, 2).header.status ==
                HoldStatus::fenced));  // a retired replica_gen
    BOOST_TEST((rig.peer_hello(rig.server().open_session(5), 3, 2).header.status ==
                HoldStatus::fenced));  // not a member
    // A peer names no attachment, and replicates only from the primary,
    // which this is.
    const auto p = rig.server().open_session(4);
    rig.peer_hello(p, 3, 2);
    BOOST_TEST((rig.read(p, 0, 1, 2) == HoldStatus::bad_request));
    auto h = Rig::header(HoldOpcode::repl_write, 2, 0, 0);
    h.lba = 0;
    h.blocks = 1;
    const auto data = blocks_of(1, 1);
    const auto crcs = proto::block_crcs(data, bs);
    rig.send(p, h,
             proto::ReplWrite{.seq = 9,
                              .commit_seq = 0,
                              .op = proto::ReplOp::write,
                              .data = {.block_size = bs, .crcs = crcs, .data = data}});
    const auto ack = rig.sink().last();
    BOOST_TEST((ack.header.opcode == HoldOpcode::repl_ack));
    BOOST_TEST((ack.header.status == HoldStatus::not_primary));
    BOOST_TEST(std::get<proto::ReplAck>(ack.payload).seq == 9U);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- the data path -----------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(data_path)

BOOST_AUTO_TEST_CASE(writes_reads_and_flushes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    const auto d = blocks_of(1, 3);
    BOOST_TEST((rig.write(s, 10, d) == HoldStatus::ok));
    BOOST_TEST(rig.server().queued(vol) == 1U);
    rig.run();
    BOOST_TEST((rig.sink().last().header.opcode == HoldOpcode::write));
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::ok));
    BOOST_TEST(rig.sink().last().header.lba == 10U);
    rig.read(s, 10, 3);
    rig.run();
    BOOST_TEST((rig.read_data() == d));
    rig.send(s, Rig::header(HoldOpcode::flush, 1));
    rig.run();
    BOOST_TEST((rig.sink().last().header.opcode == HoldOpcode::flush));
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::ok));
    // PING reports the commit point.
    rig.send(s, Rig::header(HoldOpcode::ping, 1), proto::HoldPing{});
    BOOST_TEST(std::get<proto::HoldPing>(rig.sink().last().payload).commit_seq == 1U);
    BOOST_TEST(rig.server().replica(vol)->last_seq() == 1U);
}

BOOST_AUTO_TEST_CASE(refuses_bad_requests, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    BOOST_TEST((rig.write(s, 63, blocks_of(1, 2)) == HoldStatus::range));
    BOOST_TEST((rig.read(s, 64, 1) == HoldStatus::range));
    {
        auto h = Rig::header(HoldOpcode::write, 1);
        h.blocks = 1;
        const auto d = blocks_of(1, 1);
        auto crcs = proto::block_crcs(d, bs);
        crcs[0] ^= std::byte{1};
        BOOST_TEST((rig.send(s, h, proto::BlockData{.block_size = bs, .crcs = crcs, .data = d}) ==
                    HoldStatus::checksum));
    }
    {
        auto h = Rig::header(HoldOpcode::write, 1);
        h.blocks = 1;
        const auto d = blocks_of(1, 1, 4096);  // the volume has 512-byte blocks
        const auto crcs = proto::block_crcs(d, 4096);
        BOOST_TEST((rig.send(s, h, proto::BlockData{.block_size = 4096, .crcs = crcs, .data = d}) ==
                    HoldStatus::bad_request));
    }
    {
        auto h = Rig::header(HoldOpcode::write_zeroes, 1);
        h.blocks = 1;
        BOOST_TEST((rig.send(s, h) == HoldStatus::bad_request));  // not yet
    }
    // A request must name the session's volume and attachment.
    BOOST_TEST(
        (rig.send(s, Rig::header(HoldOpcode::flush, 1, att, 1, 8)) == HoldStatus::bad_request));
    BOOST_TEST((rig.send(s, Rig::header(HoldOpcode::flush, 1, att, 2)) == HoldStatus::bad_request));
    BOOST_TEST(rig.server().queued(vol) == 0U);
    BOOST_TEST(rig.server().stats().checksum == 1U);
}

BOOST_AUTO_TEST_CASE(enforces_read_only, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(1);
    c.attachments[0].mode = proto::AttachMode::ro;
    rig.apply(c);
    const auto s = rig.session();
    BOOST_TEST((rig.write(s, 0, blocks_of(1, 1)) == HoldStatus::read_only));
    BOOST_TEST((rig.read(s, 0, 1) == HoldStatus::ok));
    rig.run();
    BOOST_TEST((rig.read_data() == Bytes(bs)));  // never written
}

BOOST_AUTO_TEST_CASE(group_commits_in_order, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    for (std::uint64_t i = 0; i < 10; ++i) {
        BOOST_TEST((rig.write(s, i % 3, blocks_of(i, 1)) == HoldStatus::ok));
    }
    rig.read(s, 0, 3);  // queued behind the writes: must see all of them
    rig.run();
    BOOST_TEST(rig.server().stats().batches == 1U);
    BOOST_TEST(rig.server().stats().writes == 10U);
    Bytes expect = blocks_of(9, 1);  // lba 0: writes 0, 3, 6, 9
    const auto b1 = blocks_of(7, 1);
    const auto b2 = blocks_of(8, 1);
    expect.insert(expect.end(), b1.begin(), b1.end());
    expect.insert(expect.end(), b2.begin(), b2.end());
    BOOST_TEST((rig.read_data() == expect));
    BOOST_TEST(rig.sink().count() == 1U + 10U + 1U);  // hello, writes, read
    for (std::size_t i = 1; i <= 10; ++i) {
        BOOST_TEST((rig.sink().frame(i).header.status == HoldStatus::ok));
    }
}

BOOST_AUTO_TEST_CASE(splits_batches_at_their_limits,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ServerConfig cfg;
    cfg.max_batch_writes = 4;
    Rig rig{cfg};
    rig.apply(config(1));
    const auto s = rig.session();
    for (std::uint64_t i = 0; i < 10; ++i) {
        rig.write(s, i, blocks_of(i, 1));
    }
    rig.run();
    BOOST_TEST(rig.server().stats().batches == 3U);
    BOOST_TEST(rig.server().replica(vol)->last_seq() == 10U);
}

BOOST_AUTO_TEST_CASE(hydrates_restored_volumes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(1);
    c.source = {.kind = proto::SourceKind::image,
                .store_id = 3,
                .hydrate_mib_per_s = 50,
                .manifest_name = {}};
    c.source.manifest_name[0] = std::byte{1};
    rig.apply(c);
    const auto s = rig.session();
    rig.read(s, 4, 1);
    rig.run();
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::not_hydrated));
    const auto image = blocks_of(5, 1);
    rig.write(s, 4, image, 1, proto::hold_flags::hydrate);
    rig.run();
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::ok));
    // A second fill does not overwrite what is there.
    const auto mine = blocks_of(6, 1);
    rig.write(s, 5, mine);
    rig.write(s, 4, blocks_of(7, 2), 1, proto::hold_flags::hydrate);
    rig.read(s, 4, 2);
    rig.run();
    auto expect = image;
    expect.insert(expect.end(), mine.begin(), mine.end());
    BOOST_TEST((rig.read_data() == expect));
}

BOOST_AUTO_TEST_CASE(fails_reads_of_corrupt_blocks, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    rig.write(s, 2, blocks_of(1, 2));
    rig.run();
    auto data = rig.files().open("/srv/hold/vol-7.1/data", false);
    BOOST_TEST_REQUIRE(data.has_value());
    BOOST_TEST_REQUIRE((*data)->pwrite((3 * bs) + 9, Bytes{std::byte{0xEE}}).has_value());
    rig.read(s, 2, 2);
    rig.run();
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::io_error));
    BOOST_TEST(rig.server().stats().checksum == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- fencing -------------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(fencing)

BOOST_AUTO_TEST_CASE(applies_to_queued_requests, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    rig.write(s, 0, blocks_of(1, 1));
    // The controller retires the attachment's generation before it runs.
    auto c = config(2);
    c.attachments[0].generation = 2;
    rig.apply(c);
    rig.run();
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::stale_epoch));
    BOOST_TEST(rig.server().replica(vol)->last_seq() == 0U);
    // At the new epoch, the old generation is fenced.
    BOOST_TEST((rig.write(s, 0, blocks_of(1, 1), 2) == HoldStatus::fenced));
    BOOST_TEST((rig.read(s, 0, 1, 2) == HoldStatus::fenced));
}

BOOST_AUTO_TEST_CASE(follows_the_epoch, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    auto c = config(2);
    c.attachments.push_back(
        {.attachment_id = att + 1, .server_id = 3, .generation = 1, .mode = proto::AttachMode::ro});
    rig.apply(c);
    BOOST_TEST((rig.write(s, 0, blocks_of(1, 1), 1) == HoldStatus::stale_epoch));
    BOOST_TEST((rig.write(s, 0, blocks_of(1, 1), 2) == HoldStatus::ok));  // same attachment
    rig.run();
    BOOST_TEST((rig.sink().last().header.status == HoldStatus::ok));
    BOOST_TEST(rig.server().replica(vol)->meta().epoch == 2U);
    // A request from an epoch not yet applied is redirected, not served.
    BOOST_TEST((rig.read(s, 0, 1, 3) == HoldStatus::not_primary));
    BOOST_TEST((rig.sink().last().header.opcode == HoldOpcode::redirect));
}

BOOST_AUTO_TEST_CASE(suspends_io, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    auto c = config(2);
    c.flags = proto::replica_flags::io_suspended;
    rig.apply(c);
    BOOST_TEST((rig.read(s, 0, 1, 2) == HoldStatus::io_suspended));
    BOOST_TEST((rig.write(s, 0, blocks_of(1, 1), 2) == HoldStatus::io_suspended));
}

BOOST_AUTO_TEST_CASE(redirects_after_a_handover, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    auto c = config(2);
    c.members = {member(me, proto::ReplicaRole::secondary), member(4, proto::ReplicaRole::primary)};
    rig.apply(c);
    BOOST_TEST((rig.read(s, 0, 1, 2) == HoldStatus::not_primary));
    BOOST_TEST(std::get<proto::HoldRedirect>(rig.sink().last().payload).primary_server == 4U);
    BOOST_TEST((rig.server().replica(vol)->meta().role == proto::ReplicaRole::secondary));
}

BOOST_AUTO_TEST_SUITE_END()

// ---- QoS -------------------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(qos)

BOOST_AUTO_TEST_CASE(holds_requests_over_the_limit, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(1);
    c.qos = {.iops = 10, .mib_per_s = 1000, .burst_iops = 10, .burst_mib = 1000};
    rig.apply(c);
    const auto s = rig.session();
    for (std::uint64_t i = 0; i < 30; ++i) {
        rig.write(s, i % 60, blocks_of(i, 1));
    }
    rig.run();
    BOOST_TEST(rig.server().stats().writes == 12U);  // 11 units of burst, one into debt
    BOOST_TEST(rig.server().queued(vol) == 18U);
    const auto wake = rig.server().next_wake(t0);
    BOOST_TEST_REQUIRE(wake.has_value());
    BOOST_TEST((*wake > t0));
    rig.run(t0 + 1s);  // 11 more units
    BOOST_TEST(rig.server().stats().writes == 23U);
    rig.run(t0 + 2s);
    BOOST_TEST(rig.server().stats().writes == 30U);
    BOOST_TEST(!rig.server().next_wake(t0 + 2s).has_value());
}

BOOST_AUTO_TEST_CASE(throttles_a_full_queue, *utf::timeout(ak::test::unit_timeout_seconds)) {
    ServerConfig cfg;
    cfg.max_queue = 4;
    Rig rig{cfg};
    rig.apply(config(1));
    const auto s = rig.session();
    for (std::uint64_t i = 0; i < 4; ++i) {
        BOOST_TEST((rig.write(s, i, blocks_of(i, 1)) == HoldStatus::ok));
    }
    BOOST_TEST((rig.write(s, 4, blocks_of(4, 1)) == HoldStatus::throttled));
    BOOST_TEST(rig.server().stats().throttled == 1U);
}

BOOST_AUTO_TEST_CASE(shares_between_volumes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    ServerConfig cfg;
    cfg.quantum = 4;
    Rig rig{cfg};
    rig.apply(config(1, 7));
    rig.apply(config(1, 8));
    const auto busy = rig.session();
    const auto quiet = rig.server().open_session(compute);
    BOOST_TEST_REQUIRE((rig.hello(quiet, 1, att, 1, 8).header.status == HoldStatus::ok));
    for (std::uint64_t i = 0; i < 100; ++i) {
        rig.read(busy, i % 64, 1);
    }
    auto h = Rig::header(HoldOpcode::read, 1, att, 1, 8);
    h.blocks = 1;
    rig.send(quiet, h);
    const auto before = rig.sink().count();
    rig.run();
    BOOST_TEST(rig.sink().count() == before + 101U);
    // The quiet volume's read went within the first round, not after 100.
    std::size_t at = 0;
    for (std::size_t i = before; i < rig.sink().count(); ++i) {
        if (rig.sink().session(i) == quiet) {
            at = i - before;
        }
    }
    BOOST_TEST(at <= 4U);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- configs and sessions ------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(configs)

BOOST_AUTO_TEST_CASE(refuses_configs_it_cannot_apply,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto other = config(1);
    other.server_id = 3;
    BOOST_TEST(rig.server().apply_config(other, t0).error() == ConfigError::wrong_server);
    rig.apply(config(2));
    BOOST_TEST(rig.server().apply_config(config(1), t0).error() == ConfigError::stale);
    BOOST_TEST(rig.server().apply_config(config(2), t0).has_value());  // again: a no-op
    auto grown = config(3);
    grown.capacity_blocks = 128;
    BOOST_TEST(rig.server().apply_config(grown, t0).error() == ConfigError::mismatch);
    BOOST_TEST(rig.server().epoch(vol).value() == 2U);
    // Not a member: no replica of its own, but the config still redirects.
    Rig other_rig;
    auto c = config(1);
    c.members = {member(4, proto::ReplicaRole::primary)};
    other_rig.apply(c);
    BOOST_TEST(other_rig.server().replica(vol) == nullptr);
    BOOST_TEST((other_rig.hello(other_rig.server().open_session(compute)).header.opcode ==
                HoldOpcode::redirect));
}

BOOST_AUTO_TEST_CASE(survives_a_restart, *utf::timeout(ak::test::unit_timeout_seconds)) {
    ak::hold::store::MemFiles files;
    Sink sink;
    ServerConfig cfg{.server_id = me, .data_dir = "/srv/hold"};
    cfg.leases = false;
    const auto d = blocks_of(3, 2);
    {
        HoldServer server{files, cfg, sink};
        BOOST_TEST_REQUIRE(server.apply_config(config(4), t0).has_value());
        const auto s = server.open_session(compute);
        auto h = Rig::header(HoldOpcode::hello, 4);
        server.on_frame(s, {.header = h, .payload = proto::HoldHello{}}, t0);
        auto w = Rig::header(HoldOpcode::write, 4);
        w.lba = 6;
        w.blocks = 2;
        const auto crcs = proto::block_crcs(d, bs);
        server.on_frame(s, {.header = w, .payload = proto::BlockData{bs, crcs, d}}, t0);
        server.run(t0);
    }
    HoldServer server{files, cfg, sink};
    BOOST_TEST(server.apply_config(config(3), t0).error() == ConfigError::stale);
    BOOST_TEST_REQUIRE(server.apply_config(config(5), t0).has_value());
    auto* replica = server.replica(vol);
    BOOST_TEST_REQUIRE(replica != nullptr);
    BOOST_TEST(replica->meta().epoch == 5U);
    BOOST_TEST(replica->last_seq() == 1U);
    BOOST_TEST(replica->commit_seq() == 1U);  // a lone primary takes writes again
    Bytes out(2 * bs);
    std::vector<std::uint32_t> crcs(2);
    BOOST_TEST(replica->read(6, out, crcs)->empty());
    BOOST_TEST((out == d));
}

BOOST_AUTO_TEST_CASE(drops_a_closed_session_s_requests,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto s = rig.session();
    rig.write(s, 0, blocks_of(1, 1));
    rig.write(s, 1, blocks_of(2, 1));
    const auto before = rig.sink().count();
    rig.server().close_session(s);
    BOOST_TEST(rig.server().queued(vol) == 0U);
    rig.run();
    BOOST_TEST(rig.sink().count() == before);
    BOOST_TEST(rig.server().replica(vol)->last_seq() == 0U);
}

BOOST_AUTO_TEST_SUITE_END()
