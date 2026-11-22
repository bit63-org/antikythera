// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 9: the deterministic simulation
// (Requirement 15.1). The real master, three real hold servers over
// crash-model files and the real initiator run on one simulated clock,
// joined by a simulated network: each session is a pair of FIFO pipes
// with random latency, and configs travel from the master with their own
// delay. A seeded schedule crashes secondaries (power loss, then restart
// from what survived) and cuts sessions while a guest workload of
// overlapping reads and writes runs. Afterwards every operation must
// have completed, every read must be linearizable per block, and every
// replica must hold the same data.
//
// The primary is never crashed yet: replacing it needs leases, reports
// and intent reconcile (task 10), which will extend this harness.
//
// AK_SIM_SEED=<n> reruns one seed; AK_SIM_SEEDS=<n> sets how many seeds
// the run covers. ctest runs a short sweep; `ctest -C Nightly -L nightly`
// runs the long one.

#define BOOST_TEST_MODULE hold_sim_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "hold/master/master.hpp"
#include "hold/server/server.hpp"
#include "hold/store/file_layer.hpp"
#include "oar/blk/initiator.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "test_support.hpp"

namespace {

namespace proto = ak::proto;
namespace m = ak::hold::master;
namespace blk = ak::oar::blk;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using Clock = ak::hold::Clock;
using Bytes = std::vector<std::byte>;
using ak::hold::SessionId;

constexpr std::uint64_t compute = 100;  // the initiator's server
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 70;
constexpr std::uint32_t bs = 4096;
constexpr std::uint64_t blocks = 32;  // the range the workload touches
constexpr std::uint16_t port = 7300;
constexpr std::size_t max_outstanding = 4;

const Clock::time_point t0{std::chrono::seconds{1000}};

auto endpoint(std::uint64_t id) -> proto::StorageEndpoint {
    proto::StorageEndpoint e{};
    e[0] = std::byte{0xFD};
    e[15] = static_cast<std::byte>(id);
    return e;
}

auto env_number(const char* name) -> std::optional<std::uint64_t> {
    const char* v = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read before any thread
    if (v == nullptr || *v == '\0') {
        return std::nullopt;
    }
    return std::strtoull(v, nullptr, 10);
}

struct Params {
    Clock::duration workload{20s};  // faults and guest I/O stop after this
    Clock::duration settle{90s};    // then everything must finish within this
    Clock::duration max_latency{2ms};
    bool faults{true};
};

// One guest operation and what it saw.
struct Op {
    bool write{false};
    std::uint64_t lba{0};
    std::uint64_t n{0};
    Bytes buf;
    Clock::time_point invoked{};
    std::optional<Clock::time_point> completed;
    std::optional<blk::BackendResult> result;
};

// Block contents name the write that produced them: its op ID and the
// block's LBA, then filler derived from both.
auto stamp(std::span<std::byte> block, std::uint64_t op, std::uint64_t lba) -> void {
    std::uint64_t x = (op * 1'000'003) ^ (lba << 20U) ^ 0x9E37'79B9'7F4A'7C15ULL;
    for (std::size_t i = 0; i + sizeof x <= block.size(); i += sizeof x) {
        x ^= x << 13U;  // xorshift64
        x ^= x >> 7U;
        x ^= x << 17U;
        std::memcpy(block.data() + i, &x, sizeof x);
    }
    std::memcpy(block.data(), &op, sizeof op);
    std::memcpy(block.data() + sizeof op, &lba, sizeof lba);
}

// The write a block came from: 0 for a block never written, nullopt for
// contents no write produced.
auto writer_of(std::span<const std::byte> block, std::uint64_t lba)
    -> std::optional<std::uint64_t> {
    if (std::ranges::all_of(block, [](std::byte b) { return b == std::byte{0}; })) {
        return 0;
    }
    std::uint64_t op = 0;
    std::memcpy(&op, block.data(), sizeof op);
    Bytes expect(block.size());
    stamp(expect, op, lba);
    if (!std::ranges::equal(block, expect)) {
        return std::nullopt;
    }
    return op;
}

class World;

class HoldSink final : public ak::hold::SessionSink {
public:
    HoldSink(World& w, std::uint64_t id, std::uint32_t incarnation)
        : _w{&w}, _id{id}, _incarnation{incarnation} {}
    auto send(SessionId session, Bytes frame) -> void override;
    auto dial(SessionId session, std::uint64_t server_id, const proto::StorageEndpoint& endpoint,
              std::uint16_t port) -> void override;
    auto hang_up(SessionId session) -> void override;

private:
    World* _w;
    std::uint64_t _id;
    std::uint32_t _incarnation;
};

struct Hold {
    std::uint64_t id{0};
    ak::hold::store::MemFiles files;
    std::unique_ptr<HoldSink> sink;
    std::unique_ptr<ak::hold::HoldServer> server;
    std::optional<proto::ReplicaConfig> config;  // the newest delivered (helm keeps it)
    bool up{true};
    std::uint32_t incarnation{0};  // restarts: sessions of an earlier one are gone
    // What the replica's intent ring held when it reopened after a crash:
    // the extents whose checksums the crash may have left behind.
    std::vector<ak::hold::store::Intent> reopened;
};

class World final : public m::Transport {
    std::mt19937_64 _rng;
    Params _p;

public:
    World(std::uint64_t seed, Params p)
        : _rng{seed}, _p{p}, master{*this}, core{{.attachment_id = att}} {
        for (std::uint64_t id = 1; id <= 3; ++id) {
            auto& h = _holds[id];
            h.id = id;
            start(h);
            BOOST_TEST_REQUIRE(master
                                   .add_server({.server_id = id,
                                                .endpoint = endpoint(id),
                                                .port = port,
                                                .rack = static_cast<std::uint32_t>(id),
                                                .power = 0,
                                                .capacity_bytes = 1ULL << 30U},
                                               mnow())
                                   .has_value());
        }
        auto cls = m::provisioned_class();  // three replicas
        cls.qos = {
            .iops = 1'000'000, .mib_per_s = 100'000, .burst_iops = 1'000'000, .burst_mib = 100'000};
        BOOST_TEST_REQUIRE(master
                               .create_volume({.volume_id = vol,
                                               .lineage_id = vol,
                                               .capacity_blocks = 256,
                                               .block_size = bs,
                                               .volume_class = cls,
                                               .multi_attach = false,
                                               .source = {}},
                                              mnow())
                               .has_value());
        BOOST_TEST_REQUIRE(
            master.attach(vol, att, compute, proto::AttachMode::rw, mnow()).has_value());
    }
    World(const World&) = delete;
    auto operator=(const World&) -> World& = delete;
    World(World&&) = delete;
    auto operator=(World&&) -> World& = delete;
    ~World() override = default;

    // ---- m::Transport ---------------------------------------------------
    auto send_config(const proto::ReplicaConfig& c) -> void override {
        schedule(latency(), Deliver{.server = c.server_id, .config = c});
    }
    auto send_op(const proto::VolumeOp& op) -> void override { static_cast<void>(op); }
    auto grant_lease(std::uint64_t, std::uint64_t, std::uint64_t) -> void override {}
    auto sweep_lineage(std::uint64_t, std::span<const proto::ManifestName>) -> void override {}
    auto destroy_lineage_key(std::uint64_t) -> void override {}

    // ---- the network, from the holds' sinks ------------------------------
    struct End {
        std::uint64_t node{0};  // a hold's server ID, or `compute`
        std::uint32_t incarnation{0};
        SessionId session{0};
        friend auto operator<=>(const End&, const End&) = default;
    };

    auto send(End from, Bytes frame) -> void {
        const auto it = _peer.find(from);
        if (it == _peer.end()) {
            return;  // the session is gone
        }
        auto& last = _pipe_last[from];
        last = std::max(last, now + latency());  // TCP: in order
        schedule_at(last, Frame{.to = it->second, .bytes = std::move(frame)});
    }
    auto dial(End from, std::uint64_t to) -> void {
        schedule(latency(), Dial{.from = from, .to = to});
    }
    auto hang_up(End e) -> void {
        if (const auto it = _peer.find(e); it != _peer.end()) {
            const auto other = it->second;
            unlink(e);
            schedule(latency(), Closed{.end = other});
        }
        schedule(0ns, Closed{.end = e});
    }

    // ---- the run ----------------------------------------------------------
    auto run() -> void {
        const auto stop = t0 + _p.workload;
        auto next_report = t0;
        auto next_fault = t0 + 500ms;
        auto next_op = t0;
        while (now < stop + _p.settle) {
            const bool working = now < stop;
            if (now >= next_report) {
                report();
                next_report = now + 1s;
            }
            if (working && _p.faults && now >= next_fault) {
                fault();
                next_fault = now + std::chrono::milliseconds{200 + _rng() % 2000};
            }
            if (working && now >= next_op) {
                if (outstanding() < max_outstanding) {
                    submit();
                }
                next_op = now + std::chrono::microseconds{_rng() % 3000};
            }
            if (!working) {
                heal();
                if (outstanding() == 0 && quiet()) {
                    break;
                }
            }
            settle();
            // The next moment anything wants to happen.
            auto wake = next_report;
            if (working) {
                wake = std::min(wake, next_op);
                if (_p.faults) {
                    wake = std::min(wake, next_fault);
                }
            }
            if (!_events.empty()) {
                wake = std::min(wake, _events.begin()->first.first);
            }
            if (const auto w = core.next_wake(now)) {
                wake = std::min(wake, *w);
            }
            for (auto& [id, h] : _holds) {
                if (h.up) {
                    if (const auto w = h.server->next_wake(now)) {
                        wake = std::min(wake, *w);
                    }
                }
            }
            for (const auto& [id, at] : _restart) {
                wake = std::min(wake, at);
            }
            now = std::max(now + 1us, wake);
        }
    }

    // ---- checks -----------------------------------------------------------
    auto check() -> void {
        for (const auto& [id, op] : _ops) {
            BOOST_TEST_INFO("op " << id << (op.write ? " write" : " read") << " lba " << op.lba);
            BOOST_TEST_REQUIRE(op.result.has_value());  // nothing left hanging
            BOOST_TEST(op.result->has_value());         // and nothing failed
        }
        check_reads();
        check_replicas();
    }

    [[nodiscard]] auto ops() const -> std::size_t { return _ops.size(); }
    [[nodiscard]] auto crashes() const -> std::size_t { return _crashes; }
    [[nodiscard]] auto cuts() const -> std::size_t { return _cuts; }

    m::Master master;
    blk::InitiatorCore core;
    Clock::time_point now{t0};

private:
    struct Frame {
        End to;
        Bytes bytes;
    };
    struct Dial {
        End from;
        std::uint64_t to{0};
    };
    struct Closed {
        End end;
    };
    struct Deliver {
        std::uint64_t server{0};
        proto::ReplicaConfig config;
    };
    using Event = std::variant<Frame, Dial, Closed, Deliver>;

    [[nodiscard]] auto mnow() const -> m::Time {
        return std::chrono::duration_cast<m::Time>(now.time_since_epoch());
    }
    auto latency() -> Clock::duration {
        return std::chrono::microseconds{
            50 +
            (_rng() %
             static_cast<std::uint64_t>(
                 std::chrono::duration_cast<std::chrono::microseconds>(_p.max_latency).count()))};
    }
    auto schedule(Clock::duration after, Event e) -> void {
        schedule_at(now + after, std::move(e));
    }
    auto schedule_at(Clock::time_point at, Event e) -> void {
        _events.emplace(std::pair{at, _seq++}, std::move(e));
    }

    auto start(Hold& h) -> void {
        ++h.incarnation;
        h.sink = std::make_unique<HoldSink>(*this, h.id, h.incarnation);
        h.server = std::make_unique<ak::hold::HoldServer>(
            h.files, ak::hold::ServerConfig{.server_id = h.id, .data_dir = "/srv/hold"}, *h.sink);
        h.up = true;
        if (h.config) {
            static_cast<void>(h.server->apply_config(*h.config, now));
            if (const auto* r = h.server->replica(vol); r != nullptr) {
                std::ranges::copy(r->intents(), std::back_inserter(h.reopened));
            }
        }
    }

    auto link(End a, End b) -> void {
        _peer[a] = b;
        _peer[b] = a;
    }
    auto unlink(End e) -> void {
        if (const auto it = _peer.find(e); it != _peer.end()) {
            _peer.erase(it->second);
            _pipe_last.erase(it->second);
            _peer.erase(it);
            _pipe_last.erase(e);
        }
    }

    // Everything due now, then the roles, until nothing more happens now.
    auto settle() -> void {
        for (int guard = 0; guard < 100000; ++guard) {
            bool moved = false;
            for (auto it = _restart.begin(); it != _restart.end();) {
                if (it->second <= now) {
                    start(_holds.at(it->first));
                    it = _restart.erase(it);
                    moved = true;
                } else {
                    ++it;
                }
            }
            while (!_events.empty() && _events.begin()->first.first <= now) {
                auto e = std::move(_events.begin()->second);
                _events.erase(_events.begin());
                deliver(std::move(e));
                moved = true;
            }
            core.tick(now);
            moved = initiator_io() || moved;
            for (auto& [id, h] : _holds) {
                if (h.up) {
                    h.server->run(now);
                }
            }
            if (!moved && (_events.empty() || _events.begin()->first.first > now)) {
                return;
            }
        }
        BOOST_FAIL("the simulation did not settle at one instant");
    }

    auto deliver(Event e) -> void {
        if (auto* f = std::get_if<Frame>(&e)) {
            if (!_peer.contains(f->to)) {
                return;  // the session ended while the frame was in flight
            }
            const auto frame = proto::decode_hold_frame(f->bytes);
            BOOST_TEST_REQUIRE(frame.has_value());
            if (f->to.node == compute) {
                core.on_frame(f->to.session, *frame, now);
            } else if (auto* h = running(f->to)) {
                h->server->on_frame(f->to.session, *frame, now);
            }
        } else if (auto* d = std::get_if<Dial>(&e)) {
            if (d->from.node != compute && running(d->from) == nullptr) {
                return;  // the dialler crashed meanwhile
            }
            auto& target = _holds.at(d->to);
            if (!target.up) {
                closed(d->from);
                return;
            }
            const End there{.node = d->to,
                            .incarnation = target.incarnation,
                            .session = target.server->open_session(d->from.node)};
            link(d->from, there);
            if (d->from.node == compute) {
                core.connected(d->from.session, now);
            } else {
                running(d->from)->server->connected(d->from.session, now);
            }
        } else if (auto* c = std::get_if<Closed>(&e)) {
            unlink(c->end);
            closed(c->end);
        } else if (auto* cfg = std::get_if<Deliver>(&e)) {
            if (cfg->server == compute) {
                static_cast<void>(core.set_route(cfg->config, now));
                return;
            }
            auto& h = _holds.at(cfg->server);
            if (!h.config || h.config->epoch < cfg->config.epoch) {
                h.config = cfg->config;
            }
            if (h.up) {
                static_cast<void>(h.server->apply_config(cfg->config, now));
            }
        }
    }

    // The hold an end belongs to, if that incarnation is running.
    auto running(End e) -> Hold* {
        auto& h = _holds.at(e.node);
        return h.up && h.incarnation == e.incarnation ? &h : nullptr;
    }

    auto closed(End e) -> void {
        if (e.node == compute) {
            core.disconnected(e.session, now);
        } else if (auto* h = running(e)) {
            h->server->close_session(e.session);
        }
    }

    // The initiator's side of the network: the session it wants, and its
    // frames.
    auto initiator_io() -> bool {
        bool moved = false;
        const auto t = core.target(now);
        if (_initiator && (!t || t->session != _initiator->session)) {
            hang_up(*_initiator);
            _initiator.reset();
            moved = true;
        }
        if (t && !_initiator) {
            _initiator = End{.node = compute, .incarnation = 0, .session = t->session};
            BOOST_TEST((t->endpoint == endpoint(t->server_id)));
            dial(*_initiator, t->server_id);
            moved = true;
        }
        for (auto& f : core.take_output()) {
            moved = true;
            if (_initiator) {
                send(*_initiator, std::move(f));
            }
        }
        return moved;
    }

    // ---- faults -----------------------------------------------------------
    [[nodiscard]] auto primary() const -> std::uint64_t {
        const auto* v = master.volume(vol);
        for (const auto& mem : v->members) {
            if (mem.role == proto::ReplicaRole::primary) {
                return mem.server_id;
            }
        }
        return 0;
    }

    auto fault() -> void {
        if (_rng() % 2 == 0) {
            // Crash a secondary: its sessions drop, unsynced writes may be
            // lost, and it comes back from what its files kept.
            std::vector<std::uint64_t> candidates;
            for (auto& [id, h] : _holds) {
                if (h.up && id != primary()) {
                    candidates.push_back(id);
                }
            }
            if (candidates.empty()) {
                return;
            }
            auto& h = _holds.at(candidates[_rng() % candidates.size()]);
            std::vector<End> ends;
            for (const auto& [e, other] : _peer) {
                if (e.node == h.id && e.incarnation == h.incarnation) {
                    ends.push_back(e);
                }
            }
            for (const auto& e : ends) {
                const auto other = _peer.at(e);
                unlink(e);
                schedule(latency() * 10, Closed{.end = other});  // the peer notices later
            }
            h.up = false;
            h.server.reset();
            h.sink.reset();
            h.files.crash(_rng());
            _restart[h.id] = now + std::chrono::milliseconds{300 + _rng() % 3000};
            ++_crashes;
        } else if (!_peer.empty()) {
            // Cut one session.
            auto it = _peer.begin();
            std::advance(it, static_cast<std::ptrdiff_t>(_rng() % _peer.size()));
            const auto a = it->first;
            const auto b = it->second;
            unlink(a);
            schedule(latency(), Closed{.end = a});
            schedule(latency(), Closed{.end = b});
            ++_cuts;
        }
    }

    auto heal() -> void {
        for (auto& [id, at] : _restart) {
            at = std::min(at, now);
        }
    }

    [[nodiscard]] auto quiet() const -> bool {
        if (!_restart.empty()) {
            return false;
        }
        const auto p = primary();
        const auto& h = _holds.at(p);
        return h.up && h.server->replicating(vol) == 0 && h.server->queued(vol) == 0;
    }

    // What helm would report for each running hold every second.
    auto report() -> void {
        for (auto& [id, h] : _holds) {
            if (!h.up) {
                continue;
            }
            proto::ReplicaStatus status;
            if (const auto* r = h.server->replica(vol)) {
                const auto& meta = r->meta();
                status.entries.push_back({.volume_id = vol,
                                          .epoch = meta.epoch,
                                          .replica_gen = meta.replica_gen,
                                          .slot = 0,
                                          .role = meta.role,
                                          .state = proto::ReplicaState::in_sync,
                                          .last_seq = r->last_seq(),
                                          .commit_seq = r->commit_seq(),
                                          .synced_bytes = 0,
                                          .total_bytes = 0,
                                          .hydrated_bytes = 0,
                                          .lease_remaining_ms = 0});
            }
            master.on_report({.server_id = id, .report_seq = 0, .body = status}, mnow());
        }
        master.tick(mnow());
    }

    // ---- the guest ----------------------------------------------------------
    [[nodiscard]] auto outstanding() const -> std::size_t { return _outstanding; }

    auto submit() -> void {
        const auto id = _next_op++;
        auto& op = _ops[id];
        op.write = _rng() % 2 == 0;
        op.lba = _rng() % blocks;
        op.n = std::min<std::uint64_t>(1 + (_rng() % 4), blocks - op.lba);
        op.buf.resize(op.n * bs);
        op.invoked = now;
        ++_outstanding;
        auto done = [this, id](blk::BackendResult r) {
            auto& o = _ops.at(id);
            --_outstanding;
            o.result = r;
            o.completed = now;
        };
        if (op.write) {
            for (std::uint64_t b = 0; b < op.n; ++b) {
                stamp(std::span{op.buf}.subspan(b * bs, bs), id, op.lba + b);
            }
            core.submit_write(op.lba * bs, op.buf, std::move(done), now);
        } else {
            core.submit_read(op.lba * bs, op.buf, std::move(done), now);
        }
    }

    // Per block: a read returns a write that began before the read ended
    // and was not overwritten, entirely, before the read began; it returns
    // the initial zeros only if no write ended before it began.
    auto check_reads() -> void {
        struct W {
            std::uint64_t id;
            Clock::time_point begin;
            Clock::time_point end;
        };
        std::map<std::uint64_t, std::vector<W>> writes;  // by block
        std::map<std::uint64_t, W> by_id;
        for (const auto& [id, op] : _ops) {
            if (op.write) {
                for (std::uint64_t b = op.lba; b < op.lba + op.n; ++b) {
                    const W w{.id = id, .begin = op.invoked, .end = *op.completed};
                    writes[b].push_back(w);
                    by_id[(id << 8U) | b] = w;
                }
            }
        }
        for (const auto& [id, op] : _ops) {
            if (op.write) {
                continue;
            }
            for (std::uint64_t b = op.lba; b < op.lba + op.n; ++b) {
                const auto block = std::span{op.buf}.subspan((b - op.lba) * bs, bs);
                const auto got = writer_of(block, b);
                BOOST_TEST_INFO("read " << id << " block " << b);
                BOOST_TEST_REQUIRE(got.has_value());  // no torn or foreign data
                const auto& ws = writes[b];
                if (*got == 0) {
                    BOOST_TEST(
                        std::ranges::none_of(ws, [&](const W& w) { return w.end < op.invoked; }));
                    continue;
                }
                const auto it = by_id.find((*got << 8U) | b);
                BOOST_TEST_REQUIRE((it != by_id.end()));
                const auto& x = it->second;
                BOOST_TEST((x.begin < *op.completed));
                BOOST_TEST(std::ranges::none_of(
                    ws, [&](const W& w) { return x.end < w.begin && w.end < op.invoked; }));
            }
        }
    }

    // Every replica holds what the primary does. A member's checksums may
    // lag its data only inside extents its intent ring held when it
    // reopened after a crash (a crash can lose checksum updates the ring
    // covers): resync on return (task 11) rewrites those. The primary's
    // must all match.
    auto check_replicas() -> void {
        const auto p = primary();
        auto read_all = [&](std::uint64_t id) {
            auto* r = _holds.at(id).server->replica(vol);
            BOOST_TEST_REQUIRE(r != nullptr);
            Bytes out(blocks * bs);
            std::vector<std::uint32_t> crcs(blocks);
            auto bad = r->read(0, out, crcs);
            BOOST_TEST_REQUIRE(bad.has_value());
            const auto& reopened = _holds.at(id).reopened;
            for (const auto lba : *bad) {
                BOOST_TEST_INFO("bad block " << lba << " on " << id);
                BOOST_TEST(id != p);
                BOOST_TEST(std::ranges::any_of(reopened, [&](const auto& i) {
                    return i.lba <= lba && lba < i.lba + i.blocks;
                }));
            }
            return out;
        };
        const auto expect = read_all(p);
        for (auto& [id, h] : _holds) {
            if (id != p) {
                BOOST_TEST_INFO("replica on " << id);
                BOOST_TEST((read_all(id) == expect));
            }
        }
    }

    std::map<std::uint64_t, Hold> _holds;
    std::multimap<std::pair<Clock::time_point, std::uint64_t>, Event> _events;
    std::uint64_t _seq{0};
    std::map<End, End> _peer;
    std::map<End, Clock::time_point> _pipe_last;
    std::map<std::uint64_t, Clock::time_point> _restart;
    std::optional<End> _initiator;
    std::map<std::uint64_t, Op> _ops;
    std::size_t _outstanding = 0;
    std::uint64_t _next_op{1};
    std::size_t _crashes{0};
    std::size_t _cuts{0};
};

auto HoldSink::send(SessionId session, Bytes frame) -> void {
    _w->send({.node = _id, .incarnation = _incarnation, .session = session}, std::move(frame));
}
auto HoldSink::dial(SessionId session, std::uint64_t server_id,
                    const proto::StorageEndpoint& endpoint_, std::uint16_t port_) -> void {
    BOOST_TEST((endpoint_ == endpoint(server_id)));
    BOOST_TEST(port_ == port);
    _w->dial({.node = _id, .incarnation = _incarnation, .session = session}, server_id);
}
auto HoldSink::hang_up(SessionId session) -> void {
    _w->hang_up({.node = _id, .incarnation = _incarnation, .session = session});
}

auto run_seeds(std::uint64_t first, std::uint64_t count, Params p) -> void {
    if (const auto one = env_number("AK_SIM_SEED")) {
        first = *one;
        count = 1;
    } else if (const auto n = env_number("AK_SIM_SEEDS")) {
        count = *n;
    }
    for (std::uint64_t seed = first; seed < first + count; ++seed) {
        BOOST_TEST_CONTEXT("seed " << seed << " (rerun with AK_SIM_SEED=" << seed << ")") {
            World w{seed, p};
            w.run();
            w.check();
            BOOST_TEST_MESSAGE("seed " << seed << ": " << w.ops() << " ops, " << w.crashes()
                                       << " crashes, " << w.cuts() << " cuts");
        }
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(runs_without_faults, *utf::timeout(ak::test::unit_timeout_seconds)) {
    run_seeds(1, 1, {.workload = 5s, .settle = 30s, .max_latency = 2ms, .faults = false});
}

BOOST_AUTO_TEST_CASE(survives_secondary_crashes_and_cuts,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    run_seeds(100, 4, {.workload = 5s, .settle = 60s, .max_latency = 2ms, .faults = true});
}

// The nightly sweep (ctest -C Nightly -L nightly): many more seeds.
BOOST_AUTO_TEST_CASE(long_sweep, *utf::disabled()) {
    run_seeds(10'000, 500, {.workload = 60s, .settle = 120s, .max_latency = 5ms, .faults = true});
}
