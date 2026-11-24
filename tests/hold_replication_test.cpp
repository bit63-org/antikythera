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
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <utility>
#include <variant>
#include <vector>

#include "common/crc32c.hpp"
#include "hold/server/server.hpp"
#include "hold/store/file_layer.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"
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
    bool up{true};       // accepts connections
    bool mute{false};    // frames to it are lost
    bool halted{false};  // never runs (with mute: hung)
};

// Failover is tested on its own: elsewhere a primary needs no lease.
auto no_leases() -> ServerConfig {
    ServerConfig c;
    c.leases = false;
    return c;
}

// Hold servers 1-3 and the sessions between them; the initiator's
// session to server 1 is the test's own end.
class Net {
public:
    explicit Net(ServerConfig cfg = no_leases()) {
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
    auto read(SessionId s, std::uint64_t lba, std::uint32_t blocks, std::uint64_t server_id = 1,
              std::uint64_t epoch = 1) -> std::uint64_t {
        auto h = header(HoldOpcode::read, epoch);
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
                if (!s->halted) {
                    s->hold.run(now);
                }
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
                if (s->halted) {
                    continue;
                }
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
    net.apply(config(1));
    net.step();  // the promotion's reconcile hears from every member
    net.server(3).up = false;
    net.cut(3);
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
    cfg.leases = false;
    Net net{cfg};
    net.apply(config(1));
    net.step();  // the promotion's reconcile hears from every member
    net.server(3).up = false;
    net.cut(3);
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

BOOST_AUTO_TEST_CASE(repairs_under_leases_one_block_at_a_time,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{ServerConfig{}};  // leases on: the members hold none
    net.apply(config(1));
    net.step();
    static_cast<void>(net.hold(1).take_reports(net.now));  // the lease request
    net.hold(1).grant_lease(vol, 1, net.now);
    const auto s = net.initiator();
    const auto data = blocks_of(11, 4);
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 40, data)) == HoldStatus::ok));
    // Bad here at 40 and 42; the member asked is bad at 41, in between.
    net.corrupt(1, 40);
    net.corrupt(1, 42);
    net.corrupt(2, 41);
    net.corrupt(3, 41);
    const auto r = net.read(s, 40, 4);
    BOOST_TEST(net.read_data(s, r) == data);
    BOOST_TEST(net.hold(1).stats().repaired == 2U);
    BOOST_TEST(net.stored(1, 40, 4) == data);
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
    net.apply(config(1));
    net.step();  // the promotion's reconcile hears from every member
    net.server(3).up = false;
    net.cut(3);
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

// ---- failover (task 10) ----------------------------------------------------

namespace {

auto faults(const std::vector<proto::ReportBody>& reports) -> std::vector<proto::VolumeFault> {
    std::vector<proto::VolumeFault> out;
    for (const auto& r : reports) {
        if (const auto* f = std::get_if<proto::VolumeFault>(&r)) {
            out.push_back(*f);
        }
    }
    return out;
}

auto status_of(const std::vector<proto::ReportBody>& reports)
    -> std::optional<proto::ReplicaStatusEntry> {
    for (const auto& r : reports) {
        if (const auto* s = std::get_if<proto::ReplicaStatus>(&r); s != nullptr) {
            for (const auto& e : s->entries) {
                if (e.volume_id == vol) {
                    return e;
                }
            }
        }
    }
    return std::nullopt;
}

// Server 1 hangs: it runs no more, and nothing reaches it.
auto hang(Net& net, std::uint64_t id) -> void {
    net.server(id).halted = true;
    net.server(id).mute = true;
    net.server(id).up = false;
}

// Epoch 2: server 2 primary, 3 its secondary; 1 is gone.
auto promoted() -> proto::ReplicaConfig {
    return config(
        2, {member(2, proto::ReplicaRole::primary), member(3, proto::ReplicaRole::secondary)});
}

}  // namespace

BOOST_AUTO_TEST_CASE(serves_reads_only_under_a_lease,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{ServerConfig{}};
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto data = blocks_of(1, 2);
    BOOST_TEST((net.status(s, net.write(s, 0, data)) == HoldStatus::ok));  // no lease needed
    const auto r = net.read(s, 0, 2);
    BOOST_TEST(!net.status(s, r).has_value());
    net.hold(1).grant_lease(vol, 1, net.now);  // never asked for: ignored
    net.step();
    BOOST_TEST(!net.status(s, r).has_value());

    // Its status is the lease request; a member's is only a status.
    const auto asked = net.now;
    const auto st = status_of(net.hold(1).take_reports(net.now));
    BOOST_TEST_REQUIRE(st.has_value());
    BOOST_TEST((st->role == proto::ReplicaRole::primary));
    BOOST_TEST(st->epoch == 1U);
    BOOST_TEST(st->last_seq == 1U);
    BOOST_TEST(st->lease_remaining_ms == 0U);
    const auto member_st = status_of(net.hold(2).take_reports(net.now));
    BOOST_TEST_REQUIRE(member_st.has_value());
    BOOST_TEST((member_st->role == proto::ReplicaRole::secondary));

    net.run_for(1s);
    net.hold(1).grant_lease(vol, 2, net.now);  // another epoch's
    net.step();
    BOOST_TEST(!net.status(s, r).has_value());
    net.hold(1).grant_lease(vol, 1, net.now);
    net.step();
    BOOST_TEST(net.read_data(s, r) == data);
    // It runs lease_ms from when it was asked for, not from the grant.
    BOOST_TEST(net.hold(1).has_lease(vol, asked + 3999ms));
    BOOST_TEST(!net.hold(1).has_lease(vol, asked + 4000ms));
    BOOST_TEST(!net.hold(2).has_lease(vol, net.now));
    net.run_for(3s);
    const auto late = net.read(s, 0, 2);
    BOOST_TEST(!net.status(s, late).has_value());
    // The next request and grant renew it.
    BOOST_TEST(status_of(net.hold(1).take_reports(net.now))->lease_remaining_ms == 0U);
    net.hold(1).grant_lease(vol, 1, net.now);
    net.step();
    BOOST_TEST(net.read_data(s, late) == data);
}

BOOST_AUTO_TEST_CASE(reports_a_member_that_stops_acknowledging,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    net.server(3).up = false;
    net.cut(3);
    const auto s = net.initiator();
    const auto w = net.write(s, 0, blocks_of(2, 1));
    net.run_for(1900ms);
    BOOST_TEST(faults(net.hold(1).take_reports(net.now)).empty());
    net.run_for(200ms);
    const auto f = faults(net.hold(1).take_reports(net.now));
    BOOST_TEST_REQUIRE(f.size() == 1U);
    BOOST_TEST((f[0].kind == proto::VolumeFaultKind::member_timeout));
    BOOST_TEST((f[0].reporter == proto::FaultReporter::hold));
    BOOST_TEST(f[0].suspect == 3U);
    BOOST_TEST(f[0].epoch == 1U);
    net.run_for(5s);
    BOOST_TEST(faults(net.hold(1).take_reports(net.now)).empty());  // once per epoch
    BOOST_TEST(!net.status(s, w).has_value());
    // The controller drops it: the write is answered.
    net.apply(config(
        2, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)}));
    net.step();
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
}

BOOST_AUTO_TEST_CASE(members_report_a_silent_primary,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    net.run_for(5s);  // idle, but the primary pings
    BOOST_TEST(faults(net.hold(2).take_reports(net.now)).empty());
    hang(net, 1);
    net.run_for(2500ms);
    for (const std::uint64_t id : {std::uint64_t{2}, std::uint64_t{3}}) {
        const auto f = faults(net.hold(id).take_reports(net.now));
        BOOST_TEST_REQUIRE(f.size() == 1U);
        BOOST_TEST((f[0].kind == proto::VolumeFaultKind::primary_timeout));
        BOOST_TEST(f[0].suspect == 1U);
    }
    net.run_for(5s);
    BOOST_TEST(faults(net.hold(2).take_reports(net.now)).empty());
}

BOOST_AUTO_TEST_CASE(confirms_its_demotion, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    BOOST_TEST((net.status(s, net.write(s, 0, blocks_of(3, 1))) == HoldStatus::ok));
    net.apply(
        config(2, {member(1, proto::ReplicaRole::leaving), member(2, proto::ReplicaRole::primary),
                   member(3, proto::ReplicaRole::secondary)}));
    net.step();
    const auto reports = net.hold(1).take_reports(net.now);
    const auto it = std::ranges::find_if(
        reports, [](const auto& r) { return std::holds_alternative<proto::DemotionConfirmed>(r); });
    BOOST_TEST_REQUIRE((it != reports.end()));
    const auto& d = std::get<proto::DemotionConfirmed>(*it);
    BOOST_TEST(d.volume_id == vol);
    BOOST_TEST(d.epoch == 2U);
    BOOST_TEST(d.last_seq == 1U);
    BOOST_TEST(!net.hold(1).has_lease(vol, net.now));
}

// A write only the old primary and server 2 hold when 1 hangs: the new
// primary keeps it and gives it to 3.
BOOST_AUTO_TEST_CASE(promotion_reconciles_from_the_new_primary,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto a = blocks_of(4, 1);
    const auto b = blocks_of(5, 1);
    BOOST_TEST((net.status(s, net.write(s, 0, a)) == HoldStatus::ok));
    net.server(3).up = false;
    net.cut(3);
    const auto w = net.write(s, 0, b);
    BOOST_TEST(!net.status(s, w).has_value());
    BOOST_TEST(net.stored(2, 0, 1) == b);
    BOOST_TEST(net.stored(3, 0, 1) == a);
    hang(net, 1);
    net.cut(1);

    // Promoted while 3 is still away: nothing is served until it answers.
    net.apply_to(2, promoted());
    net.apply_to(3, promoted());
    net.step();
    BOOST_TEST(net.hold(2).reconciling(vol));
    const auto s2 = net.initiator(2, 2);
    const auto w2 = net.write(s2, 8, blocks_of(6, 1), 2, 2);
    BOOST_TEST(!net.status(s2, w2).has_value());
    net.run_for(2100ms);
    const auto f = faults(net.hold(2).take_reports(net.now));
    BOOST_TEST_REQUIRE(f.size() == 1U);
    BOOST_TEST((f[0].kind == proto::VolumeFaultKind::member_timeout));
    BOOST_TEST(f[0].suspect == 3U);

    net.server(3).up = true;
    net.run_for(1s);
    BOOST_TEST(!net.hold(2).reconciling(vol));
    BOOST_TEST(net.hold(2).stats().reconciled == 1U);
    BOOST_TEST(net.stored(3, 0, 1) == b);
    BOOST_TEST((net.status(s2, w2) == HoldStatus::ok));
    BOOST_TEST(net.stored(3, 8, 1) == blocks_of(6, 1));
    BOOST_TEST(net.read_data(s2, net.read(s2, 0, 1, 2, 2)) == b);
    // Numbered above everything: seq 2 was the last either held.
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == 4U);
}

// A write only the old primary and server 3 hold: the new primary's
// older copy wins, so both replicas agree.
BOOST_AUTO_TEST_CASE(promotion_overrides_what_only_a_member_holds,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto a = blocks_of(7, 2);
    BOOST_TEST((net.status(s, net.write(s, 4, a)) == HoldStatus::ok));
    net.server(2).up = false;
    net.cut(2);
    net.write(s, 5, blocks_of(8, 1));
    BOOST_TEST(net.stored(3, 4, 2) != a);
    hang(net, 1);
    net.cut(1);
    net.server(2).up = true;
    net.apply_to(2, promoted());
    net.apply_to(3, promoted());
    net.step();
    BOOST_TEST(!net.hold(2).reconciling(vol));
    BOOST_TEST(net.stored(3, 4, 2) == a);
    BOOST_TEST(net.stored(2, 4, 2) == a);
}

// ---- resync and rebuild (task 11) ------------------------------------------

namespace {

// 8-block regions (4 KiB at 512-byte blocks): 32 of them in a volume.
constexpr std::uint64_t region = 8;

auto small_regions() -> ServerConfig {
    auto c = no_leases();
    c.chunk_shift = 12;
    return c;
}

// The regions SYNC_DATA carried (by first LBA), markers apart.
auto copied(const Net& net) -> std::multiset<std::uint64_t> {
    std::multiset<std::uint64_t> out;
    for (const auto& h : net.seen) {
        if (h.opcode == HoldOpcode::sync_data && (h.flags & proto::hold_flags::response) == 0 &&
            (h.flags & proto::hold_flags::last) == 0) {
            out.insert(h.lba / region);
        }
    }
    return out;
}

auto markers(const Net& net) -> std::size_t {
    return static_cast<std::size_t>(std::ranges::count_if(net.seen, [](const auto& h) {
        return h.opcode == HoldOpcode::sync_data && (h.flags & proto::hold_flags::last) != 0;
    }));
}

auto state_of(Net& net, std::uint64_t id) -> proto::ReplicaState {
    net.run_for(1s);  // a status is due
    const auto e = status_of(net.hold(id).take_reports(net.now));
    BOOST_TEST_REQUIRE(e.has_value());
    return e->state;
}

auto members_1_2(proto::ReplicaRole three = proto::ReplicaRole::joining)
    -> std::vector<proto::ReplicaMember> {
    return {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary),
            member(3, three)};
}

}  // namespace

BOOST_AUTO_TEST_CASE(rebuilds_a_new_member_from_written_regions,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    net.apply(config(
        1, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)}));
    net.step();
    const auto s = net.initiator();
    const auto a = blocks_of(1, 2);
    const auto b = blocks_of(2, 1);
    const auto c = blocks_of(3, 10);  // two regions
    BOOST_TEST((net.status(s, net.write(s, 1, a)) == HoldStatus::ok));
    BOOST_TEST((net.status(s, net.write(s, 100, b)) == HoldStatus::ok));
    BOOST_TEST((net.status(s, net.write(s, 200, c)) == HoldStatus::ok));

    // Member 3 joins: only the written regions are copied, then the marker.
    net.apply(config(2, members_1_2()));
    net.step();
    BOOST_TEST((copied(net) == std::multiset<std::uint64_t>{0, 12, 25, 26}));
    BOOST_TEST(markers(net) == 1U);
    BOOST_TEST(net.hold(1).stats().copied == 5U);
    BOOST_TEST(net.stored(3, 0, 256) == net.stored(1, 0, 256));
    BOOST_TEST((state_of(net, 3) == proto::ReplicaState::in_sync));

    // New writes reach it on the same stream; it takes up the primary's seq.
    const auto d = blocks_of(4, 1);
    const auto s2 = net.initiator(1, 2);
    BOOST_TEST((net.status(s2, net.write(s2, 101, d, 1, 2)) == HoldStatus::ok));
    BOOST_TEST(net.stored(3, 101, 1) == d);
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == net.hold(1).replica(vol)->last_seq());

    // The controller makes it a secondary; nothing more is copied.
    net.apply(config(3, members_1_2(proto::ReplicaRole::secondary)));
    net.run_for(2s);
    BOOST_TEST(net.hold(1).stats().copied == 5U);
}

BOOST_AUTO_TEST_CASE(resyncs_only_what_a_returning_member_missed,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    for (std::uint64_t r = 0; r < 32; ++r) {  // every region written, then committed
        BOOST_TEST((net.status(s, net.write(s, r * region, blocks_of(r, 1))) == HoldStatus::ok));
    }
    BOOST_TEST((net.status(s, net.write(s, 3, blocks_of(40, 1))) == HoldStatus::ok));
    BOOST_TEST((net.status(s, net.write(s, 4, blocks_of(41, 1))) == HoldStatus::ok));

    // Member 3 fails during a write to region 5, and is dropped.
    net.server(3).up = false;
    net.cut(3);
    const auto w = net.write(s, 5 * region, blocks_of(50, 1));
    net.apply(config(
        2, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)}));
    net.step();
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
    const auto s2 = net.initiator(1, 2);
    BOOST_TEST((net.status(s2, net.write(s2, (20 * region) + 3, blocks_of(51, 2), 1, 2)) ==
                HoldStatus::ok));

    // It comes back within the window: regions 5 and 20 are copied, and
    // region 0, where its last write before failing may still sit in its
    // intent ring; nothing else.
    net.server(3).up = true;
    net.apply(config(3, members_1_2()));
    net.step();
    const auto got = copied(net);
    BOOST_TEST(got.count(5) == 1U);
    BOOST_TEST(got.count(20) == 1U);
    BOOST_TEST(got.size() <= 3U);
    for (const auto r : got) {
        BOOST_TEST_INFO(r);
        BOOST_TEST((r == 0 || r == 5 || r == 20));
    }
    BOOST_TEST(markers(net) == 1U);
    BOOST_TEST(net.stored(3, 0, 256) == net.stored(1, 0, 256));
    BOOST_TEST((state_of(net, 3) == proto::ReplicaState::in_sync));

    // Its first write since rebases it onto the primary's stream.
    const auto s3 = net.initiator(1, 3);
    const auto d = blocks_of(52, 1);
    BOOST_TEST((net.status(s3, net.write(s3, 77, d, 1, 3)) == HoldStatus::ok));
    BOOST_TEST(net.stored(3, 77, 1) == d);
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == net.hold(1).replica(vol)->last_seq());
}

BOOST_AUTO_TEST_CASE(rebuilds_in_full_past_the_resync_window,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    auto c1 = config(1);
    c1.resync_window_s = 10;
    net.apply(c1);
    net.step();
    const auto s = net.initiator();
    for (std::uint64_t r = 0; r < 4; ++r) {
        BOOST_TEST((net.status(s, net.write(s, r * region, blocks_of(r, 1))) == HoldStatus::ok));
    }
    net.server(3).up = false;
    net.cut(3);
    auto c2 = config(
        2, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)});
    c2.resync_window_s = 10;
    net.apply(c2);
    net.run_for(11s);
    net.server(3).up = true;
    auto c3 = config(3, members_1_2());
    c3.resync_window_s = 10;
    net.apply(c3);
    net.step();
    BOOST_TEST((copied(net) == std::multiset<std::uint64_t>{0, 1, 2, 3}));
    BOOST_TEST((state_of(net, 3) == proto::ReplicaState::in_sync));
}

BOOST_AUTO_TEST_CASE(paces_a_copy_and_resumes_it_after_a_lost_session,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    auto cfg = small_regions();
    cfg.copy_bytes_per_s = region * bs;  // a region a second
    Net net{cfg};
    net.apply(config(
        1, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)}));
    net.step();
    const auto s = net.initiator();
    for (std::uint64_t r = 0; r < 6; ++r) {
        BOOST_TEST((net.status(s, net.write(s, r * region, blocks_of(r, 1))) == HoldStatus::ok));
    }
    net.apply(config(2, members_1_2()));
    net.step();
    BOOST_TEST(copied(net).size() <= 2U);  // the budget's burst
    net.run_for(2500ms);
    const auto before = copied(net).size();
    BOOST_TEST(before >= 3U);
    BOOST_TEST(before < 6U);
    BOOST_TEST((state_of(net, 3) == proto::ReplicaState::joining));

    // A write meanwhile goes to the member on the same stream.
    const auto d = blocks_of(9, 1);
    const auto s2 = net.initiator(1, 2);
    BOOST_TEST((net.status(s2, net.write(s2, 4 * region, d, 1, 2)) == HoldStatus::ok));

    // The session breaks: the copy goes on from what was not acknowledged.
    net.cut(3);
    net.run_for(10s);
    BOOST_TEST(markers(net) == 1U);
    BOOST_TEST(net.stored(3, 0, 256) == net.stored(1, 0, 256));
    BOOST_TEST(net.stored(3, 4 * region, 1) == d);
    BOOST_TEST((state_of(net, 3) == proto::ReplicaState::in_sync));
    // A new session from the primary sends the marker again; until then
    // the member is not in sync.
    net.cut(1);
    BOOST_TEST((status_of(net.hold(3).take_reports(net.now + 1s)).value().state ==
                proto::ReplicaState::joining));
    net.run_for(2s);
    BOOST_TEST(markers(net) == 2U);
    BOOST_TEST((state_of(net, 3) == proto::ReplicaState::in_sync));
}

BOOST_AUTO_TEST_CASE(a_joining_member_takes_up_a_lower_stream,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    // Server 3 holds a replica well ahead of the stream it joins.
    net.apply(config(
        1, {member(1, proto::ReplicaRole::primary), member(3, proto::ReplicaRole::secondary)}));
    net.step();
    const auto s = net.initiator();
    for (std::uint64_t i = 0; i < 10; ++i) {
        BOOST_TEST((net.status(s, net.write(s, 1, blocks_of(i, 1))) == HoldStatus::ok));
    }
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == 10U);
    net.apply(config(2, {member(2, proto::ReplicaRole::primary)}));
    const auto s2 = net.initiator(2, 2);
    const auto a = blocks_of(20, 1);
    BOOST_TEST((net.status(s2, net.write(s2, 1, a, 2, 2)) == HoldStatus::ok));
    net.apply(config(
        3, {member(2, proto::ReplicaRole::primary), member(3, proto::ReplicaRole::joining)}));
    net.step();
    const auto s3 = net.initiator(2, 3);
    const auto b = blocks_of(21, 1);
    BOOST_TEST((net.status(s3, net.write(s3, 9, b, 2, 3)) == HoldStatus::ok));
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == net.hold(2).replica(vol)->last_seq());
    BOOST_TEST(net.stored(3, 9, 1) == b);  // taken, not mistaken for a resend
    BOOST_TEST(net.stored(3, 1, 1) == a);  // copied
}

// ---- scrubbing (task 24) ---------------------------------------------------

namespace {

// A replica that joined by the copy alone (no write forwarded to it while
// it joined) holds no seq of its own. Made primary, it must still number
// its writes above what the members hold: numbered from 1, the members
// took them for resends of seqs they had and acknowledged them unwritten.
BOOST_AUTO_TEST_CASE(a_primary_that_joined_by_copy_numbers_above_the_members,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    net.apply(config(
        1, {member(1, proto::ReplicaRole::primary), member(2, proto::ReplicaRole::secondary)}));
    net.step();
    const auto s = net.initiator();
    for (std::uint64_t i = 0; i < 4; ++i) {
        BOOST_TEST((net.status(s, net.write(s, i, blocks_of(10 + i, 1))) == HoldStatus::ok));
    }
    net.run_for(3s);  // the commit point reaches the member
    net.apply(config(2, members_1_2()));
    net.step();
    BOOST_TEST(net.stored(3, 0, 4) == net.stored(1, 0, 4));
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == 0U);  // the copy carries no seq
    // A planned handover: 3 takes over, 1 leaves.
    net.apply(config(3, members_1_2(proto::ReplicaRole::secondary)));
    net.step();
    const auto handed = config(
        4, {member(2, proto::ReplicaRole::secondary), member(3, proto::ReplicaRole::primary)});
    net.apply_to(1, handed);
    net.apply(handed);
    net.run_for(1s);
    BOOST_REQUIRE(!net.hold(3).reconciling(vol));
    const auto s3 = net.initiator(3, 4);
    const auto c = blocks_of(20, 1);
    BOOST_TEST((net.status(s3, net.write(s3, 0, c, 3, 4)) == HoldStatus::ok));
    BOOST_TEST(net.stored(2, 0, 1) == c);
    BOOST_TEST(net.hold(3).replica(vol)->last_seq() == 5U);
    BOOST_TEST(net.hold(2).replica(vol)->last_seq() == 5U);
}

struct ScrubReports {
    std::vector<proto::OpOutcome> outcomes;
    std::vector<proto::VolumeFault> faults;
    std::optional<proto::ReplicaStatusEntry> status;
};

auto scrub_reports(HoldServer& hold, Clock::time_point now) -> ScrubReports {
    ScrubReports out;
    for (auto& r : hold.take_reports(now)) {
        if (const auto* o = std::get_if<proto::OpOutcome>(&r)) {
            out.outcomes.push_back(*o);
        } else if (const auto* f = std::get_if<proto::VolumeFault>(&r);
                   f != nullptr && f->kind == proto::VolumeFaultKind::checksum_unrepairable) {
            out.faults.push_back(*f);  // not the timeouts a cut session brings
        } else if (const auto* s = std::get_if<proto::ReplicaStatus>(&r);
                   s != nullptr && !s->entries.empty()) {
            out.status = s->entries.front();
        }
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(scrubs_repair_every_replica, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto a = blocks_of(1, 4);
    const auto b = blocks_of(2, 2);
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 40, a)) == HoldStatus::ok));
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 200, b)) == HoldStatus::ok));
    net.corrupt(1, 41);
    net.corrupt(2, 201);
    net.corrupt(3, 40);
    net.corrupt(3, 43);
    for (std::uint64_t id = 1; id <= 3; ++id) {
        static_cast<void>(scrub_reports(net.hold(id), net.now));
        net.hold(id).start_scrub(vol, 10 + id, 1, 0, net.now);
        BOOST_TEST(net.hold(id).scrubbing(vol));
    }
    net.run_for(2s);
    const std::array<std::uint64_t, 3> found{1, 1, 2};
    for (std::uint64_t id = 1; id <= 3; ++id) {
        BOOST_TEST(!net.hold(id).scrubbing(vol));
        BOOST_TEST(net.stored(id, 40, 4) == a);
        BOOST_TEST(net.stored(id, 200, 2) == b);
        net.now += 1s;
        const auto r = scrub_reports(net.hold(id), net.now);
        BOOST_TEST_REQUIRE(r.outcomes.size() == 1U);
        BOOST_TEST(r.outcomes[0].op_id == 10 + id);
        BOOST_TEST((r.outcomes[0].kind == proto::VolumeOpKind::scrub));
        BOOST_TEST((r.outcomes[0].status == proto::OpStatus::ok));
        BOOST_TEST(r.outcomes[0].detail == found.at(id - 1));
        BOOST_TEST(r.faults.empty());
        BOOST_TEST_REQUIRE(r.status.has_value());
        BOOST_TEST(r.status->checksum_errors == found.at(id - 1));
        BOOST_TEST(r.status->checksum_repairs == found.at(id - 1));
    }
    BOOST_TEST(net.hold(2).stats().scrubbed == 16U);  // the two regions written

    // A resend of a finished op is answered again; a running one is not.
    net.hold(2).start_scrub(vol, 12, 1, 0, net.now);
    auto again = scrub_reports(net.hold(2), net.now);
    BOOST_TEST_REQUIRE(again.outcomes.size() == 1U);
    BOOST_TEST(again.outcomes[0].detail == 1U);
    BOOST_TEST(!net.hold(2).scrubbing(vol));
}

BOOST_AUTO_TEST_CASE(scrubs_report_a_block_no_one_can_mend,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 8, blocks_of(3, 2))) == HoldStatus::ok));
    for (std::uint64_t id = 1; id <= 3; ++id) {
        net.corrupt(id, 9);
    }
    static_cast<void>(scrub_reports(net.hold(2), net.now));
    net.hold(2).start_scrub(vol, 5, 1, 0, net.now);
    net.run_for(1s);
    const auto r = scrub_reports(net.hold(2), net.now);
    BOOST_TEST_REQUIRE(r.outcomes.size() == 1U);
    BOOST_TEST((r.outcomes[0].status == proto::OpStatus::io_error));
    BOOST_TEST(r.outcomes[0].detail == 1U);
    BOOST_TEST_REQUIRE(r.faults.size() == 1U);
    BOOST_TEST((r.faults[0].kind == proto::VolumeFaultKind::checksum_unrepairable));
    BOOST_TEST(r.faults[0].suspect == 2U);
    BOOST_TEST(net.hold(2).stats().unrepairable == 1U);
    BOOST_TEST(net.hold(1).stats().unrepairable == 1U);  // asked server 3 for it too
}

BOOST_AUTO_TEST_CASE(scrubs_give_up_on_an_unreachable_primary,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    ServerConfig cfg = no_leases();
    cfg.scrub_timeout = 5s;
    Net net{cfg};
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 8, blocks_of(4, 1))) == HoldStatus::ok));
    net.corrupt(2, 8);
    net.server(2).up = false;  // the primary cannot reach it
    net.cut(2);
    static_cast<void>(scrub_reports(net.hold(2), net.now));
    net.hold(2).start_scrub(vol, 6, 1, 0, net.now);
    net.run_for(4s);
    BOOST_TEST(net.hold(2).scrubbing(vol));  // still asking
    net.run_for(2s);
    BOOST_TEST(!net.hold(2).scrubbing(vol));
    const auto r = scrub_reports(net.hold(2), net.now);
    BOOST_TEST_REQUIRE(r.outcomes.size() == 1U);
    BOOST_TEST((r.outcomes[0].status == proto::OpStatus::io_error));
    BOOST_TEST(r.faults.size() == 1U);
}

BOOST_AUTO_TEST_CASE(scrubs_resume_their_asks_on_a_new_session,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto a = blocks_of(5, 1);
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 8, a)) == HoldStatus::ok));
    net.corrupt(3, 8);
    net.server(1).mute = true;  // the ask is lost with its session
    net.hold(3).start_scrub(vol, 7, 1, 0, net.now);
    net.step();
    BOOST_TEST(net.hold(3).scrubbing(vol));
    net.server(1).mute = false;
    net.cut(3);  // the primary redials; the ask goes again on the new session
    net.run_for(2s);
    BOOST_TEST(!net.hold(3).scrubbing(vol));
    BOOST_TEST(net.stored(3, 8, 1) == a);
}

BOOST_AUTO_TEST_CASE(scrubs_end_when_the_replica_leaves,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net;
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 8, blocks_of(6, 1))) == HoldStatus::ok));
    net.corrupt(3, 8);
    net.server(1).mute = true;  // the ask stays unanswered
    net.hold(3).start_scrub(vol, 8, 1, 0, net.now);
    net.step();
    static_cast<void>(scrub_reports(net.hold(3), net.now));
    net.apply_to(3, config(2, {member(1, proto::ReplicaRole::primary),
                               member(2, proto::ReplicaRole::secondary)}));
    net.step();
    BOOST_TEST(!net.hold(3).scrubbing(vol));
    const auto r = scrub_reports(net.hold(3), net.now);
    BOOST_TEST_REQUIRE(r.outcomes.size() == 1U);
    BOOST_TEST((r.outcomes[0].status == proto::OpStatus::unknown_volume));
    BOOST_TEST(r.faults.empty());
}

BOOST_AUTO_TEST_CASE(primary_scrubs_wait_behind_unanswered_writes,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Net net{small_regions()};
    net.apply(config(1));
    net.step();
    const auto s = net.initiator();
    const auto a = blocks_of(7, 1);
    BOOST_TEST_REQUIRE((net.status(s, net.write(s, 41, a)) == HoldStatus::ok));
    net.corrupt(1, 41);
    net.server(3).mute = true;
    const auto w = net.write(s, 42, blocks_of(8, 1));  // same region, unanswered
    BOOST_TEST(!net.status(s, w).has_value());
    net.hold(1).start_scrub(vol, 9, 1, 0, net.now);
    net.step();
    BOOST_TEST(net.hold(1).scrubbing(vol));
    BOOST_TEST(net.hold(1).stats().scrubbed == 0U);
    net.server(3).mute = false;
    net.cut(3);  // resent on the next session, then answered
    net.run_for(2s);
    BOOST_TEST((net.status(s, w) == HoldStatus::ok));
    BOOST_TEST(!net.hold(1).scrubbing(vol));
    BOOST_TEST(net.stored(1, 41, 1) == a);
}
