// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 8: replication between hold
// servers over an in-memory network. A write is answered once every
// member holds it (Requirements 1.5, 1.6); members apply writes in seq
// order from the primary of their own epoch only (6.2); the primary holds
// back overlapping reads and repairs a bad block from a member (5.4).

#define BOOST_TEST_MODULE hold_replication_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <utility>
#include <vector>

#include "common/crc32c.hpp"
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

namespace {

namespace proto = ak::proto;
namespace utf = boost::unit_test;
using namespace ak::hold;
using namespace std::chrono_literals;
using proto::HoldOpcode;
using proto::HoldStatus;
using Bytes = std::vector<std::byte>;

constexpr std::uint64_t compute = 9;  // the attached server
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;

const Clock::time_point t0{std::chrono::seconds{1000}};

auto member(std::uint64_t id, proto::ReplicaRole role) -> proto::ReplicaMember {
    proto::ReplicaMember m;
    m.server_id = id;
    m.endpoint[15] = static_cast<std::byte>(id);
    m.port = 4430;
    m.role = role;
    m.replica_gen = 1;
    return m;
}

// Primary 1 with secondaries 2 and 3, unless given other members.
auto config(std::uint64_t epoch, std::vector<proto::ReplicaMember> members = {})
    -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.volume_id = vol;
    c.epoch = epoch;
    c.lineage_id = 9;
    c.capacity_blocks = 256;
    c.block_size = bs;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    c.members = members.empty() ? std::vector{member(1, proto::ReplicaRole::primary),
                                              member(2, proto::ReplicaRole::secondary),
                                              member(3, proto::ReplicaRole::secondary)}
                                : std::move(members);
    c.attachments = {{.attachment_id = att,
                      .server_id = compute,
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

class Net;

class NetSink final : public SessionSink {
public:
    NetSink(Net& net, std::uint64_t id) : _net{&net}, _id{id} {}
    auto send(SessionId session, Bytes frame) -> void override;
    auto dial(SessionId session, std::uint64_t server_id, const proto::StorageEndpoint& endpoint,
              std::uint16_t port) -> void override;
    auto hang_up(SessionId session) -> void override;

private:
    Net* _net;
    std::uint64_t _id;
};

struct Server {
    Server(Net& net, std::uint64_t id, ServerConfig cfg)
        : sink{net, id}, hold{files, fill(id, std::move(cfg)), sink} {}
    static auto fill(std::uint64_t id, ServerConfig c) -> ServerConfig {
        c.server_id = id;
        c.data_dir = "/srv/hold";
        return c;
    }
    ak::hold::store::MemFiles files;
    NetSink sink;
    HoldServer hold;
    bool up{true};     // accepts connections
    bool mute{false};  // frames to it are lost
};

// Hold servers 1-3 and the sessions between them; the initiator's
// session to server 1 is the test's own end.
class Net {
public:
    explicit Net(ServerConfig cfg = {}) {
        for (std::uint64_t id = 1; id <= 3; ++id) {
            _servers[id] = std::make_unique<Server>(*this, id, cfg);
        }
    }

    auto server(std::uint64_t id) -> Server& { return *_servers.at(id); }
    auto hold(std::uint64_t id) -> HoldServer& { return server(id).hold; }

    // Applies `c` to each member's server.
    auto apply(const proto::ReplicaConfig& c) -> void {
        for (const auto& m : c.members) {
            apply_to(m.server_id, c);
        }
    }
    auto apply_to(std::uint64_t id, proto::ReplicaConfig c) -> void {
        c.server_id = id;
        BOOST_TEST_REQUIRE(hold(id).apply_config(c, now).has_value());
    }

    // An initiator session to `server` past HELLO.
    auto initiator(std::uint64_t server_id = 1, std::uint64_t epoch = 1) -> SessionId {
        const auto s = hold(server_id).open_session(compute);
        _clients.insert({server_id, s});
        hold(server_id).on_frame(
            s,
            {.header = header(HoldOpcode::hello, epoch),
             .payload = proto::HoldHello{.role = proto::HoldPeerRole::initiator, .replica_gen = 0}},
            now);
        step();
        BOOST_TEST_REQUIRE((last(s).header.status == HoldStatus::ok));
        return s;
    }

    static auto header(HoldOpcode op, std::uint64_t epoch = 1) -> proto::HoldHeader {
        proto::HoldHeader h;
        h.opcode = op;
        h.request_id = ++_next_request;
        h.volume_id = vol;
        h.epoch = epoch;
        h.attachment_id = att;
        h.generation = 1;
        return h;
    }

    // Returns the request ID; the reply lands in replies(s).
    auto write(SessionId s, std::uint64_t lba, const Bytes& data, std::uint64_t server_id = 1,
               std::uint64_t epoch = 1) -> std::uint64_t {
        auto h = header(HoldOpcode::write, epoch);
        h.lba = lba;
        h.blocks = static_cast<std::uint32_t>(data.size() / bs);
        const auto crcs = proto::block_crcs(data, bs);
        hold(server_id).on_frame(
            s,
            {.header = h,
             .payload = proto::BlockData{.block_size = bs, .crcs = crcs, .data = data}},
            now);
        step();
        return h.request_id;
    }
    auto read(SessionId s, std::uint64_t lba, std::uint32_t blocks, std::uint64_t server_id = 1)
        -> std::uint64_t {
        auto h = header(HoldOpcode::read);
        h.lba = lba;
        h.blocks = blocks;
        hold(server_id).on_frame(s, {.header = h, .payload = {}}, now);
        step();
        return h.request_id;
    }

    // The reply to `request` on client session `s`, if it came.
    auto reply(SessionId s, std::uint64_t request) -> const Bytes* {
        for (const auto& b : _inbox[s]) {
            if (proto::decode_hold_frame(b)->header.request_id == request) {
                return &b;
            }
        }
        return nullptr;
    }
    auto status(SessionId s, std::uint64_t request) -> std::optional<HoldStatus> {
        const auto* b = reply(s, request);
        if (b == nullptr) {
            return std::nullopt;
        }
        return proto::decode_hold_frame(*b)->header.status;
    }
    auto last(SessionId s) -> proto::HoldFrame {
        BOOST_TEST_REQUIRE(!_inbox[s].empty());
        return *proto::decode_hold_frame(_inbox[s].back());
    }
    auto read_data(SessionId s, std::uint64_t request) -> Bytes {
        const auto* b = reply(s, request);
        BOOST_TEST_REQUIRE(b != nullptr);
        const auto f = proto::decode_hold_frame(*b);
        BOOST_TEST_REQUIRE((f->header.status == HoldStatus::ok));
        const auto& d = std::get<proto::BlockData>(f->payload);
        return {d.data.begin(), d.data.end()};
    }

    // What a replica holds, read straight from its store.
    auto stored(std::uint64_t id, std::uint64_t lba, std::size_t blocks) -> Bytes {
        auto* r = hold(id).replica(vol);
        BOOST_TEST_REQUIRE(r != nullptr);
        Bytes out(blocks * bs);
        std::vector<std::uint32_t> crcs(blocks);
        BOOST_TEST_REQUIRE(r->read(lba, out, crcs).has_value());
        return out;
    }

    // Overwrites a block of a replica's data file behind its back.
    auto corrupt(std::uint64_t id, std::uint64_t lba) -> void {
        auto f = server(id).files.open(
            "/srv/hold/" + ak::hold::store::replica_dir_name(vol, 1) + "/data", false);
        BOOST_TEST_REQUIRE(f.has_value());
        const Bytes junk(bs, std::byte{0x66});
        BOOST_TEST_REQUIRE((*f)->pwrite(lba * bs, junk).has_value());
        BOOST_TEST_REQUIRE((*f)->sync().has_value());
    }

    // Moves frames, dials and hang-ups until nothing more happens.
    auto step() -> void {
        for (int guard = 0; guard < 10000; ++guard) {
            bool moved = false;
            for (auto& [id, s] : _servers) {
                s->hold.run(now);
            }
            while (!_dials.empty()) {
                moved = true;
                const auto d = _dials.front();
                _dials.pop_front();
                auto& target = server(d.to);
                if (!target.up) {
                    hold(d.from).close_session(d.session);
                    continue;
                }
                const auto peer = target.hold.open_session(d.from);
                _pipes[{d.from, d.session}] = {d.to, peer};
                _pipes[{d.to, peer}] = {d.from, d.session};
                ++dials;
                hold(d.from).connected(d.session, now);
            }
            while (!_hangups.empty()) {
                moved = true;
                const auto end = _hangups.front();
                _hangups.pop_front();
                cut_end(end);
            }
            while (!_frames.empty()) {
                moved = true;
                auto [from, bytes] = std::move(_frames.front());
                _frames.pop_front();
                if (_clients.contains(from)) {
                    _inbox[from.second].push_back(std::move(bytes));
                    continue;
                }
                const auto it = _pipes.find(from);
                if (it == _pipes.end()) {
                    continue;
                }
                const auto to = it->second;
                if (server(to.first).mute) {
                    continue;
                }
                const auto f = proto::decode_hold_frame(bytes);
                BOOST_TEST_REQUIRE(f.has_value());
                seen.push_back(f->header);
                hold(to.first).on_frame(to.second, *f, now);
            }
            if (!moved) {
                return;
            }
        }
        BOOST_FAIL("the network did not settle");
    }

    auto run_for(Clock::duration d) -> void {
        const auto until = now + d;
        while (true) {
            std::optional<Clock::time_point> wake;
            for (auto& [id, s] : _servers) {
                if (const auto w = s->hold.next_wake(now); w && *w > now) {
                    wake = wake ? std::min(*wake, *w) : *w;
                }
            }
            if (!wake || *wake > until) {
                break;
            }
            now = *wake;
            step();
        }
        now = until;
        step();
    }

    // Breaks every session to or from `id`, as when it crashes.
    auto cut(std::uint64_t id) -> void {
        std::vector<std::pair<std::uint64_t, SessionId>> ends;
        for (const auto& [end, other] : _pipes) {
            if (end.first == id) {
                ends.push_back(end);
            }
        }
        for (const auto& e : ends) {
            cut_end(e);
        }
        step();
    }

    [[nodiscard]] auto count(HoldOpcode op) const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count(seen, op, &proto::HoldHeader::opcode));
    }

    // NetSink's side.
    auto post(std::uint64_t from, SessionId s, Bytes frame) -> void {
        _frames.emplace_back(std::pair{from, s}, std::move(frame));
    }
    auto post_dial(std::uint64_t from, SessionId s, std::uint64_t to) -> void {
        _dials.push_back({.from = from, .session = s, .to = to});
    }
    auto post_hang_up(std::uint64_t from, SessionId s) -> void { _hangups.emplace_back(from, s); }

    Clock::time_point now{t0};
    std::vector<proto::HoldHeader> seen;  // frames between servers
    std::size_t dials{0};

private:
    using End = std::pair<std::uint64_t, SessionId>;
    struct Dial {
        std::uint64_t from{0};
        SessionId session{0};
        std::uint64_t to{0};
    };

    auto cut_end(End end) -> void {
        const auto it = _pipes.find(end);
        if (it == _pipes.end()) {
            return;
        }
        const auto other = it->second;
        _pipes.erase(it);
        _pipes.erase(other);
        hold(end.first).close_session(end.second);
        hold(other.first).close_session(other.second);
    }

    std::map<std::uint64_t, std::unique_ptr<Server>> _servers;
    std::map<End, End> _pipes;
    std::set<End> _clients;
    std::map<SessionId, std::vector<Bytes>> _inbox;
    std::deque<std::pair<End, Bytes>> _frames;
    std::deque<Dial> _dials;
    std::deque<End> _hangups;
    static inline std::uint64_t _next_request = 0;
};

auto NetSink::send(SessionId session, Bytes frame) -> void {
    _net->post(_id, session, std::move(frame));
}
auto NetSink::dial(SessionId session, std::uint64_t server_id,
                   const proto::StorageEndpoint& endpoint, std::uint16_t port) -> void {
    BOOST_TEST((endpoint[15] == static_cast<std::byte>(server_id)));
    BOOST_TEST(port == 4430);
    _net->post_dial(_id, session, server_id);
}
auto NetSink::hang_up(SessionId session) -> void {
    _net->post_hang_up(_id, session);
}

}  // namespace

BOOST_AUTO_TEST_CASE(replicates_writes_to_every_member,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    BOOST_TEST(net.dials == 2U);  // one session per member
    const auto s = net.initiator();
    const auto data = blocks_of(1, 4);
    const auto w = net.write(s, 10, data);
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
    BOOST_TEST(net.count(HoldOpcode::repl_write) == 2U);
    BOOST_TEST(net.hold(1).stats().replicated == 1U);
    for (const std::uint64_t id : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{3}}) {
        BOOST_TEST_INFO(id);
        BOOST_TEST(net.stored(id, 10, 4) == data);
        BOOST_TEST(net.hold(id).replica(vol)->last_seq() == 1U);
    }
    BOOST_TEST(net.hold(1).replica(vol)->commit_seq() == 1U);

    // The commit point rides on the next write, so members can trim.
    const auto w2 = net.write(s, 20, blocks_of(2, 1));
    BOOST_TEST((net.status(s, w2) == HoldStatus::ok));
    BOOST_TEST(net.hold(2).replica(vol)->commit_seq() == 1U);
    BOOST_TEST(net.hold(2).replica(vol)->last_seq() == 2U);

    const auto r = net.read(s, 10, 4);
    BOOST_TEST(net.read_data(s, r) == data);
}

BOOST_AUTO_TEST_CASE(waits_for_every_member, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.server(3).up = false;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto data = blocks_of(3, 2);
    const auto w = net.write(s, 0, data);
    BOOST_TEST(!net.status(s, w).has_value());  // member 3 does not have it
    BOOST_TEST(net.hold(1).replicating(vol) == 1U);
    BOOST_TEST(net.stored(2, 0, 2) == data);

    // A read of those blocks waits for the write; another read does not.
    const auto held = net.read(s, 1, 1);
    const auto other = net.read(s, 50, 1);
    BOOST_TEST(!net.status(s, held).has_value());
    BOOST_TEST((net.status(s, other) == HoldStatus::ok));

    // Member 3 comes back: the write reaches it and both answers go out.
    net.server(3).up = true;
    net.run_for(1s);
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
    BOOST_TEST((net.status(s, held) == HoldStatus::ok));
    BOOST_TEST(net.stored(3, 0, 2) == data);
}

BOOST_AUTO_TEST_CASE(resends_after_a_lost_session, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    // The members take the write but their answers are lost with the
    // sessions.
    net.server(1).mute = true;
    const auto data = blocks_of(4, 1);
    const auto w = net.write(s, 5, data);
    BOOST_TEST(!net.status(s, w).has_value());
    net.server(1).mute = false;
    BOOST_TEST(net.hold(2).replica(vol)->last_seq() == 1U);
    net.cut(1);
    net.run_for(1s);
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
    BOOST_TEST(net.count(HoldOpcode::repl_write) == 4U);     // sent, then resent
    BOOST_TEST(net.hold(2).replica(vol)->last_seq() == 1U);  // applied once
    BOOST_TEST(net.stored(2, 5, 1) == data);
}

BOOST_AUTO_TEST_CASE(applies_writes_in_seq_order, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    // Overlapping writes in one batch: every replica ends with the last.
    const auto first = blocks_of(5, 4);
    const auto second = blocks_of(6, 2);
    auto h1 = Net::header(HoldOpcode::write);
    h1.lba = 30;
    h1.blocks = 4;
    auto h2 = Net::header(HoldOpcode::write);
    h2.lba = 32;
    h2.blocks = 2;
    const auto c1 = proto::block_crcs(first, bs);
    const auto c2 = proto::block_crcs(second, bs);
    net.hold(1).on_frame(
        s, {.header = h1, .payload = proto::BlockData{.block_size = bs, .crcs = c1, .data = first}},
        net.now);
    net.hold(1).on_frame(
        s,
        {.header = h2, .payload = proto::BlockData{.block_size = bs, .crcs = c2, .data = second}},
        net.now);
    net.step();
    BOOST_TEST((net.status(s, h1.request_id) == HoldStatus::ok));
    BOOST_TEST((net.status(s, h2.request_id) == HoldStatus::ok));
    Bytes expect = first;
    std::ranges::copy(second, expect.begin() + 2 * bs);
    for (const std::uint64_t id : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{3}}) {
        BOOST_TEST_INFO(id);
        BOOST_TEST(net.stored(id, 30, 4) == expect);
    }
}

BOOST_AUTO_TEST_CASE(refuses_writes_out_of_order, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    // Straight to member 2, as server 1 (the primary): seq 1, then 3.
    auto& m = net.hold(2);
    const auto p = m.open_session(1);
    auto hello = Net::header(HoldOpcode::hello);
    hello.attachment_id = 0;
    hello.generation = 0;
    m.on_frame(p,
               {.header = hello,
                .payload = proto::HoldHello{.role = proto::HoldPeerRole::peer, .replica_gen = 1}},
               net.now);
    const auto data = blocks_of(7, 1);
    const auto crcs = proto::block_crcs(data, bs);
    const auto repl = [&](std::uint64_t seq) {
        auto h = Net::header(HoldOpcode::repl_write);
        h.attachment_id = 0;
        h.generation = 0;
        h.request_id = seq;
        h.lba = seq;
        h.blocks = 1;
        m.on_frame(
            p,
            {.header = h,
             .payload = proto::ReplWrite{.seq = seq,
                                         .commit_seq = 0,
                                         .op = proto::ReplOp::write,
                                         .data = {.block_size = bs, .crcs = crcs, .data = data}}},
            net.now);
        m.run(net.now);
    };
    repl(1);
    repl(3);  // seq 2 never came
    BOOST_TEST(m.replica(vol)->last_seq() == 1U);
    repl(2);
    BOOST_TEST(m.replica(vol)->last_seq() == 2U);
    repl(2);  // a resend: acknowledged, not written again
    BOOST_TEST(m.replica(vol)->last_seq() == 2U);
}

BOOST_AUTO_TEST_CASE(fences_a_deposed_primary, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    // The controller makes 2 primary at epoch 2; 1 has not heard yet.
    const auto next =
        config(2, {member(2, proto::ReplicaRole::primary), member(3, proto::ReplicaRole::secondary),
                   member(1, proto::ReplicaRole::secondary)});
    net.apply_to(2, next);
    net.apply_to(3, next);
    net.step();
    const auto data = blocks_of(8, 1);
    const auto w = net.write(s, 0, data);
    net.run_for(1s);
    // The members refuse the old epoch, so the write is never answered.
    BOOST_TEST(!net.status(s, w).has_value());
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == 0U);

    // 1 learns it was deposed: the initiator is sent to the new primary.
    net.apply_to(1, next);
    net.step();
    const auto f = net.last(s);
    BOOST_TEST((f.header.opcode == HoldOpcode::redirect));
    BOOST_TEST(f.header.request_id == w);
    BOOST_TEST(std::get<proto::HoldRedirect>(f.payload).primary_server == 2U);
    BOOST_TEST(net.hold(1).replicating(vol) == 0U);
}

BOOST_AUTO_TEST_CASE(stops_taking_writes_it_cannot_replicate,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ServerConfig cfg;
    cfg.max_replicating = 2;
    Net net{cfg};
    net.server(3).up = false;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    for (std::uint64_t i = 0; i < 3; ++i) {
        net.write(s, i, blocks_of(i, 1));
    }
    BOOST_TEST(net.hold(1).replicating(vol) == 2U);
    BOOST_TEST(net.hold(1).queued(vol) == 1U);
    // Held for a member, not for time: no busy wake.
    const auto wake = net.hold(1).next_wake(net.now);
    BOOST_TEST((!wake || *wake > net.now));
    net.server(3).up = true;
    net.run_for(1s);
    BOOST_TEST(net.hold(1).replicating(vol) == 0U);
    BOOST_TEST(net.hold(1).queued(vol) == 0U);
    BOOST_TEST(net.hold(1).stats().replicated == 3U);
}

BOOST_AUTO_TEST_CASE(repairs_a_bad_block_from_a_member,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto data = blocks_of(9, 4);
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 40, data)) == HoldStatus::ok));
    net.corrupt(1, 41);

    const auto r = net.read(s, 40, 4);
    BOOST_TEST(net.read_data(s, r) == data);
    BOOST_TEST(net.hold(1).stats().repaired == 1U);
    BOOST_TEST(net.stored(1, 40, 4) == data);  // written back
    const auto peer_reads = net.count(HoldOpcode::read);
    const auto again = net.read(s, 40, 4);
    BOOST_TEST(net.read_data(s, again) == data);
    BOOST_TEST(net.count(HoldOpcode::read) == peer_reads);  // served locally now

    // No good copy anywhere: the read fails.
    net.corrupt(1, 42);
    net.corrupt(2, 42);
    net.corrupt(3, 42);
    const auto bad = net.read(s, 42, 1);
    BOOST_TEST((net.status(s, bad) == HoldStatus::io_error));
    BOOST_TEST(net.hold(1).stats().unrepairable == 1U);
}

BOOST_AUTO_TEST_CASE(fails_a_read_with_no_member_to_ask,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 0, blocks_of(10, 1))) == HoldStatus::ok));
    net.server(2).up = false;
    net.server(3).up = false;
    net.cut(2);
    net.cut(3);
    net.corrupt(1, 0);
    const auto r = net.read(s, 0, 1);
    BOOST_TEST((net.status(s, r) == HoldStatus::io_error));
    BOOST_TEST(net.hold(1).stats().unrepairable == 1U);
}

BOOST_AUTO_TEST_CASE(follows_member_changes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.server(3).up = false;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto w = net.write(s, 0, blocks_of(11, 1));
    BOOST_TEST(!net.status(s, w).has_value());
    // The controller drops member 3 at epoch 2: the write is answered.
    const auto next = config(
        2, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)});
    net.apply(next);
    net.step();
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
    // Down to a lone primary: writes are answered at once.
    net.apply(config(3, {member(1, proto::ReplicaRole::primary)}));
    const auto s3 = net.initiator(1, 3);
    const auto w3 = net.write(s3, 1, blocks_of(12, 1), 1, 3);
    BOOST_TEST((net.status(s3, w3) == HoldStatus::ok));
}
