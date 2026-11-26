// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 7: the initiator core driven on a
// simulated clock against in-process hold servers over in-memory replicas.
// Requests are held until the route arrives (Requirement 2.2), carry
// CRC32Cs both ways (1.1-1.3), follow epochs, redirects and a new primary
// (6.6), honour the volume's QoS limits (10.2) and fail by their deadline
// rather than hang.

#define BOOST_TEST_MODULE initiator_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <utility>
#include <vector>

#include "hold/server/server.hpp"
#include "hold/store/file_layer.hpp"
#include "oar/blk/initiator.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, RouteError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, InitiatorFault f) -> std::ostream& {
    return os << to_string(f);
}
auto operator<<(std::ostream& os, BackendError e) -> std::ostream& {
    return os << static_cast<int>(e);
}
}  // namespace ak::oar::blk
namespace ak::proto {
auto operator<<(std::ostream& os, HoldOpcode o) -> std::ostream& {
    return os << static_cast<int>(o);
}
}  // namespace ak::proto

namespace {

namespace proto = ak::proto;
namespace utf = boost::unit_test;
using namespace ak::oar::blk;
using namespace std::chrono_literals;
using Clock = InitiatorCore::Clock;
using Bytes = std::vector<std::byte>;
using proto::HoldOpcode;
using proto::HoldStatus;

constexpr std::uint64_t compute = 2;  // the initiator's own server
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;
constexpr std::uint64_t capacity = 8192;  // blocks: room for more than one part

const Clock::time_point t0{std::chrono::seconds{1000}};

auto member(std::uint64_t id, proto::ReplicaRole role = proto::ReplicaRole::primary)
    -> proto::ReplicaMember {
    proto::ReplicaMember m;
    m.server_id = id;
    m.endpoint[15] = static_cast<std::byte>(id);
    m.port = 4430;
    m.role = role;
    m.replica_gen = 1;
    return m;
}

auto config(std::uint64_t epoch, std::uint64_t primary = 1) -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.server_id = compute;
    c.volume_id = vol;
    c.epoch = epoch;
    c.lineage_id = 9;
    c.capacity_blocks = capacity;
    c.block_size = bs;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    c.members = {member(primary)};
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

// One request's outcome, filled in by its completion.
struct Done {
    std::optional<BackendResult> result;
    auto fn() -> BackendCompletion {
        return [this](BackendResult r) { result = r; };
    }
    [[nodiscard]] auto ok() const -> bool { return result && result->has_value(); }
    [[nodiscard]] auto failed(BackendError e) const -> bool {
        return result && !result->has_value() && result->error() == e;
    }
};

class Sink final : public ak::hold::SessionSink {
public:
    auto send(ak::hold::SessionId session, Bytes frame) -> void override {
        frames.emplace_back(session, std::move(frame));
    }
    std::vector<std::pair<ak::hold::SessionId, Bytes>> frames;
};

// A storage server the initiator can reach.
struct Server {
    explicit Server(std::uint64_t id)
        : hold{files, {.server_id = id, .data_dir = "/srv/hold", .leases = false}, sink} {}
    ak::hold::store::MemFiles files;
    Sink sink;
    ak::hold::HoldServer hold;
    bool reachable{true};  // a connection to it succeeds
    bool mute{false};      // it receives nothing (a hung primary)
};

// The initiator, the hold servers and the network between them, on a
// simulated clock. step() moves frames until nothing more happens.
class Rig {
public:
    explicit Rig(InitiatorConfig ic = {.attachment_id = att}) : core{ic} { server(1); }

    auto server(std::uint64_t id) -> Server& {
        auto& s = _servers[id];
        if (!s) {
            s = std::make_unique<Server>(id);
        }
        return *s;
    }

    // Applies `c` to every member server, then (unless `hold_only`) routes
    // the initiator.
    auto apply(const proto::ReplicaConfig& c, bool hold_only = false) -> void {
        for (const auto& m : c.members) {
            auto mine = c;
            mine.server_id = m.server_id;
            BOOST_TEST_REQUIRE(server(m.server_id).hold.apply_config(mine, now).has_value());
        }
        if (!hold_only) {
            BOOST_TEST_REQUIRE(core.set_route(c, now).has_value());
        }
        step();
    }

    auto step() -> void {
        for (int guard = 0; guard < 1000; ++guard) {
            bool moved = connect();
            for (auto& frame : core.take_output()) {
                moved = true;
                auto f = proto::decode_hold_frame(frame);
                BOOST_TEST_REQUIRE(f.has_value());
                sent.push_back(f->header);
                if (_link && !_link->server->mute) {
                    _link->server->hold.on_frame(_link->hold_session, *f, now);
                }
            }
            for (auto& [id, s] : _servers) {
                s->hold.run(now);
            }
            for (auto& [id, s] : _servers) {
                auto frames = std::exchange(s->sink.frames, {});
                for (auto& [session, bytes] : frames) {
                    if (!_link || _link->server != s.get() || session != _link->hold_session) {
                        continue;  // to a session the initiator has left
                    }
                    if (tamper && !tamper(bytes)) {
                        continue;
                    }
                    auto f = proto::decode_hold_frame(bytes);
                    BOOST_TEST_REQUIRE(f.has_value());
                    received.push_back(f->header);
                    moved = true;
                    core.on_frame(_link->session, *f, now);
                }
            }
            if (!moved) {
                return;
            }
        }
        BOOST_FAIL("the rig did not settle");
    }

    // Moves the clock to each wake the core asks for, up to `until`.
    auto run_until(Clock::time_point until) -> void {
        while (true) {
            const auto wake = core.next_wake(now);
            if (!wake || *wake > until) {
                break;
            }
            now = std::max(now, *wake);
            core.tick(now);
            step();
        }
        now = until;
        core.tick(now);
        step();
    }
    auto run_for(Clock::duration d) -> void { run_until(now + d); }

    [[nodiscard]] auto count(HoldOpcode op) const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count(sent, op, &proto::HoldHeader::opcode));
    }
    [[nodiscard]] auto linked_to() const -> std::uint64_t { return _link ? _link->server_id : 0; }
    // Drops the connection from the network's side.
    auto cut() -> void {
        if (_link) {
            const auto session = _link->session;
            _link->server->hold.close_session(_link->hold_session);
            _link.reset();
            core.disconnected(session, now);
        }
    }

    auto write(std::uint64_t lba, const Bytes& data, Done& d) -> void {
        core.submit_write(lba * bs, data, d.fn(), now);
        step();
    }
    auto read(std::uint64_t lba, Bytes& out, Done& d) -> void {
        core.submit_read(lba * bs, out, d.fn(), now);
        step();
    }

    InitiatorCore core;
    Clock::time_point now{t0};
    std::vector<proto::HoldHeader> sent;
    std::vector<proto::HoldHeader> received;
    // Sees each frame from a hold to the initiator; false drops it.
    std::function<bool(Bytes&)> tamper;
    std::uint64_t connects{0};

private:
    struct Link {
        std::uint64_t server_id{0};
        Server* server{nullptr};
        std::uint64_t session{0};
        ak::hold::SessionId hold_session{0};
    };

    // Opens or drops the session the core's target names.
    auto connect() -> bool {
        const auto t = core.target(now);
        if (_link && (!t || t->session != _link->session)) {
            _link->server->hold.close_session(_link->hold_session);
            _link.reset();
        }
        if (!t || _link) {
            return false;
        }
        auto& s = server(t->server_id);
        BOOST_TEST(t->port == 4430);
        BOOST_TEST((t->endpoint[15] == static_cast<std::byte>(t->server_id)));
        if (!s.reachable) {
            core.disconnected(t->session, now);
            return true;
        }
        ++connects;
        _link = Link{.server_id = t->server_id,
                     .server = &s,
                     .session = t->session,
                     .hold_session = s.hold.open_session(compute)};
        core.connected(t->session, now);
        return true;
    }

    std::map<std::uint64_t, std::unique_ptr<Server>> _servers;
    std::optional<Link> _link;
};

}  // namespace

BOOST_AUTO_TEST_CASE(holds_requests_until_the_route_arrives,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1), true);  // the hold has it; the initiator does not yet
    const auto data = blocks_of(1, 4);
    Done w;
    rig.write(8, data, w);
    BOOST_TEST(!rig.core.target(rig.now).has_value());
    // Far longer than any deadline: still held, not failed.
    rig.run_for(10min);
    BOOST_TEST(!w.result.has_value());
    BOOST_TEST(rig.core.pending() == 1U);

    rig.core.set_route(config(1), rig.now).value();
    rig.step();
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.core.session_open());
    BOOST_TEST(rig.core.capacity_bytes() == capacity * bs);
    BOOST_TEST(rig.count(HoldOpcode::hello) == 1U);
    // The deadline started with the route.
    Done r;
    Bytes out(4 * bs);
    rig.read(8, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST(std::ranges::equal(out, data));
}

BOOST_AUTO_TEST_CASE(writes_and_reads_back, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto data = blocks_of(2, 16);
    Done w;
    rig.write(100, data, w);
    BOOST_TEST(w.ok());
    // The hold checked every block's CRC32C and stored it.
    auto* replica = rig.server(1).hold.replica(vol);
    BOOST_TEST_REQUIRE(replica != nullptr);

    Bytes out(16 * bs);
    Done r;
    rig.read(100, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST(std::ranges::equal(out, data));

    // Never written: zeros, accepted with CRC 0.
    Bytes blank(2 * bs, std::byte{0xEE});
    Done z;
    rig.read(500, blank, z);
    BOOST_TEST(z.ok());
    BOOST_TEST(std::ranges::all_of(blank, [](std::byte b) { return b == std::byte{0}; }));

    Done f;
    rig.core.submit_flush(f.fn());
    BOOST_TEST(f.ok());
}

BOOST_AUTO_TEST_CASE(splits_large_requests, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const std::size_t n = proto::max_hold_blocks + 100;  // two parts
    const auto data = blocks_of(3, n);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.count(HoldOpcode::write) == 2U);
    BOOST_TEST(rig.sent.back().blocks == 100U);
    BOOST_TEST(rig.sent.back().lba == std::uint64_t{proto::max_hold_blocks});

    Bytes out(n * bs);
    Done r;
    rig.read(0, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST(rig.count(HoldOpcode::read) == 2U);
    BOOST_TEST(std::ranges::equal(out, data));
}

BOOST_AUTO_TEST_CASE(refuses_what_the_volume_cannot_take,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    Bytes buf(bs);
    Bytes odd(bs + 1);
    Done past;
    rig.read(capacity, buf, past);
    BOOST_TEST(past.failed(BackendError::out_of_range));
    Done unaligned;
    rig.core.submit_read(7, buf, unaligned.fn(), rig.now);
    BOOST_TEST(unaligned.failed(BackendError::out_of_range));
    Done partial;
    rig.core.submit_write(0, odd, partial.fn(), rig.now);
    BOOST_TEST(partial.failed(BackendError::out_of_range));
    BOOST_TEST(rig.count(HoldOpcode::read) == 0U);
    BOOST_TEST(rig.count(HoldOpcode::write) == 0U);
}

BOOST_AUTO_TEST_CASE(refuses_writes_on_a_read_only_attachment,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(1);
    c.attachments[0].mode = proto::AttachMode::ro;
    rig.apply(c);
    const auto data = blocks_of(4, 1);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(w.failed(BackendError::io));
    Bytes out(bs);
    Done r;
    rig.read(0, out, r);
    BOOST_TEST(r.ok());
}

BOOST_AUTO_TEST_CASE(retries_a_read_that_fails_its_checksum,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto data = blocks_of(5, 2);
    Done w;
    rig.write(10, data, w);
    BOOST_TEST_REQUIRE(w.ok());

    // The first read reply is corrupted on the way; the retry is not.
    int corrupt = 1;
    rig.tamper = [&](Bytes& b) {
        auto f = proto::decode_hold_frame(b);
        if (f && f->header.opcode == HoldOpcode::read && corrupt > 0) {
            --corrupt;
            b.back() ^= std::byte{0x01};
        }
        return true;
    };
    Bytes out(2 * bs);
    Done r;
    rig.read(10, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST(std::ranges::equal(out, data));
    BOOST_TEST(rig.count(HoldOpcode::read) == 2U);
    auto faults = rig.core.take_faults();
    BOOST_TEST(faults.size() == 1U);
    BOOST_TEST((faults.at(0).kind == InitiatorFault::checksum));
    BOOST_TEST(faults.at(0).server == 1U);  // the primary that answered
    BOOST_TEST(faults.at(0).epoch == 1U);

    // Corrupted every time: the guest gets an I/O error after one retry.
    corrupt = 100;
    Done bad;
    rig.read(10, out, bad);
    BOOST_TEST(bad.failed(BackendError::io));
    BOOST_TEST(rig.count(HoldOpcode::read) == 4U);
}

BOOST_AUTO_TEST_CASE(waits_for_a_newer_epoch, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    // The hold moves on to epoch 2 before helm brings it here.
    rig.apply(config(2), true);
    const auto data = blocks_of(6, 1);
    Done w;
    rig.write(3, data, w);
    BOOST_TEST(!w.result.has_value());
    BOOST_TEST(!rig.core.target(rig.now).has_value());  // nothing to do until the config
    rig.run_for(1s);
    BOOST_TEST(!w.result.has_value());

    rig.core.set_route(config(2), rig.now).value();
    rig.step();
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.sent.back().epoch == 2U);
    BOOST_TEST(rig.count(HoldOpcode::write) == 2U);  // resent at the new epoch
}

BOOST_AUTO_TEST_CASE(follows_a_new_primary, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    BOOST_TEST(rig.linked_to() == 1U);

    // Server 1 stops answering with a write outstanding.
    rig.server(1).mute = true;
    const auto data = blocks_of(7, 4);
    Done w;
    rig.write(20, data, w);
    BOOST_TEST(!w.result.has_value());
    rig.run_for(2s);
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(faults.size() == 1U);
    BOOST_TEST((faults.at(0).kind == InitiatorFault::primary_timeout));
    BOOST_TEST(faults.at(0).server == 1U);
    rig.server(1).reachable = false;
    rig.run_for(1s);  // retries against server 1 fail
    BOOST_TEST(!w.result.has_value());

    // The controller promotes server 3 at epoch 2: the write lands there.
    rig.apply(config(2, 3));
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.linked_to() == 3U);
    Bytes out(4 * bs);
    Done r;
    rig.read(20, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST(std::ranges::equal(out, data));
}

BOOST_AUTO_TEST_CASE(follows_a_redirect, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    // Server 3 has epoch 2 where server 1 is not the primary; the
    // initiator still thinks server 1 is, at epoch 1.
    auto old = config(1);
    BOOST_TEST_REQUIRE(rig.server(1)
                           .hold
                           .apply_config(
                               [&] {
                                   auto c = old;
                                   c.server_id = 1;
                                   return c;
                               }(),
                               rig.now)
                           .has_value());
    auto next = config(2, 3);  // server 1 is out (a lone new primary needs no reconcile)
    for (const std::uint64_t id : {std::uint64_t{1}, std::uint64_t{3}}) {
        auto c = next;
        c.server_id = id;
        BOOST_TEST_REQUIRE(rig.server(id).hold.apply_config(c, rig.now).has_value());
    }
    rig.core.set_route(old, rig.now).value();
    rig.step();
    // HELLO at epoch 1 to a hold at epoch 2: stale, wait for the config.
    BOOST_TEST(!rig.core.session_open());
    BOOST_TEST(!rig.core.target(rig.now).has_value());

    rig.core.set_route(next, rig.now).value();
    rig.step();
    BOOST_TEST(rig.core.session_open());
    BOOST_TEST(rig.linked_to() == 3U);

    // A REDIRECT to the same epoch (the hold is no longer primary but the
    // initiator has no newer config): back off and retry.
    const auto before = rig.connects;
    rig.tamper = [&](Bytes& b) {
        auto f = proto::decode_hold_frame(b);
        if (f && f->header.opcode == HoldOpcode::read) {
            auto h = f->header;
            h.opcode = HoldOpcode::redirect;
            h.status = HoldStatus::not_primary;
            h.blocks = 0;
            h.lba = 0;
            b = *proto::encode_hold_frame(
                {.header = h,
                 .payload = proto::HoldRedirect{.primary_server = 3, .primary_epoch = 2}});
            rig.tamper = nullptr;
        }
        return true;
    };
    Bytes out(bs);
    Done r;
    rig.read(0, out, r);
    BOOST_TEST(!r.result.has_value());
    rig.run_for(1s);
    BOOST_TEST(r.ok());
    BOOST_TEST(rig.connects == before + 1);
}

// A request sent just before helm brought a newer epoch comes back
// stale_epoch from a hold at that same epoch: resent, not a reason to wait
// for yet another config.
BOOST_AUTO_TEST_CASE(resends_what_an_older_epoch_sent,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto data = blocks_of(10, 1);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST_REQUIRE(w.ok());
    rig.tamper = [&](Bytes& b) {
        auto f = proto::decode_hold_frame(b);
        if (f && f->header.opcode == HoldOpcode::read) {
            auto h = f->header;
            h.status = HoldStatus::stale_epoch;  // its epoch is the route's: 1
            b = *proto::encode_hold_frame({.header = h, .payload = {}});
            rig.tamper = nullptr;
        }
        return true;
    };
    Bytes out(bs);
    Done r;
    rig.read(0, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST((out == data));
    BOOST_TEST(rig.core.session_open());
}

BOOST_AUTO_TEST_CASE(stops_when_fenced, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    // The attachment moves to generation 2 (attached elsewhere) at the
    // hold first: the next request is fenced.
    auto c = config(2);
    c.attachments[0].generation = 2;
    rig.apply(c, true);
    Done a;
    Done b;
    const auto data = blocks_of(8, 1);
    rig.core.submit_write(0, data, a.fn(), rig.now);
    rig.core.submit_write(bs, data, b.fn(), rig.now);
    rig.step();
    // Epoch 2 at the hold: first comes stale_epoch, then the config.
    rig.core.set_route(c, rig.now).value();
    rig.step();
    BOOST_TEST(rig.core.fenced());
    BOOST_TEST(a.failed(BackendError::io));
    BOOST_TEST(b.failed(BackendError::io));
    auto faults = rig.core.take_faults();
    BOOST_TEST((std::ranges::find(faults, InitiatorFault::fenced,
                                  &ak::oar::blk::FaultEvent::kind) != faults.end()));
    BOOST_TEST(!rig.core.target(rig.now).has_value());
    // Everything after fails too.
    Done later;
    rig.write(2, data, later);
    rig.run_for(1ms);
    BOOST_TEST(later.failed(BackendError::io));
}

BOOST_AUTO_TEST_CASE(stops_when_the_hold_fences_it, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    // The hold says fenced (it has retired the generation) before helm
    // brings the config that says so.
    rig.tamper = [](Bytes& b) {
        auto f = proto::decode_hold_frame(b);
        if (f && f->header.opcode == HoldOpcode::write) {
            auto h = f->header;
            h.status = HoldStatus::fenced;
            b = *proto::encode_hold_frame({.header = h, .payload = {}});
        }
        return true;
    };
    Done w;
    const auto data = blocks_of(9, 1);
    rig.write(0, data, w);
    BOOST_TEST(w.failed(BackendError::io));
    BOOST_TEST(rig.core.fenced());
}

BOOST_AUTO_TEST_CASE(fails_requests_at_their_deadline,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig{{.attachment_id = att, .request_timeout = 5s}};
    rig.apply(config(1));
    rig.server(1).reachable = false;
    rig.cut();
    const auto data = blocks_of(10, 1);
    Done w;
    rig.write(0, data, w);
    rig.run_for(4900ms);
    BOOST_TEST(!w.result.has_value());
    rig.run_for(200ms);
    BOOST_TEST(w.failed(BackendError::io));
    BOOST_TEST(rig.core.pending() == 0U);

    // I/O suspended by the controller: same, the guest never hangs.
    rig.server(1).reachable = true;
    auto c = config(2);
    c.flags = proto::replica_flags::io_suspended | proto::replica_flags::impaired;
    c.members.clear();
    BOOST_TEST_REQUIRE(rig.core.set_route(c, rig.now).has_value());
    Done s;
    rig.write(0, data, s);
    BOOST_TEST(!rig.core.target(rig.now).has_value());
    rig.run_for(6s);
    BOOST_TEST(s.failed(BackendError::io));
}

BOOST_AUTO_TEST_CASE(resends_after_a_lost_connection,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    // The replies are lost, then the connection drops.
    rig.tamper = [](Bytes&) { return false; };
    const auto data = blocks_of(11, 2);
    Done w;
    rig.write(30, data, w);
    BOOST_TEST(!w.result.has_value());
    rig.tamper = nullptr;
    rig.cut();
    rig.run_for(300ms);  // retry_backoff
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.count(HoldOpcode::write) == 2U);  // idempotent resend
    BOOST_TEST(rig.count(HoldOpcode::hello) == 2U);
}

BOOST_AUTO_TEST_CASE(retries_throttled_and_suspended_requests,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    // The first reply says throttled, the second io_suspended.
    std::vector<HoldStatus> answers{HoldStatus::throttled, HoldStatus::io_suspended};
    rig.tamper = [&](Bytes& b) {
        auto f = proto::decode_hold_frame(b);
        if (f && f->header.opcode == HoldOpcode::write && !answers.empty()) {
            auto h = f->header;
            h.status = answers.front();
            answers.erase(answers.begin());
            b = *proto::encode_hold_frame({.header = h, .payload = {}});
        }
        return true;
    };
    const auto data = blocks_of(12, 1);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(!w.result.has_value());
    rig.run_for(249ms);
    BOOST_TEST(rig.count(HoldOpcode::write) == 1U);
    rig.run_for(1ms);  // retry_backoff after throttled
    BOOST_TEST(rig.count(HoldOpcode::write) == 2U);
    BOOST_TEST(!w.result.has_value());
    rig.run_for(999ms);
    BOOST_TEST(!w.result.has_value());
    rig.run_for(1ms);  // four times that after io_suspended
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.count(HoldOpcode::write) == 3U);
}

BOOST_AUTO_TEST_CASE(gives_up_on_a_write_the_hold_keeps_refusing,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    rig.tamper = [](Bytes& b) {
        auto f = proto::decode_hold_frame(b);
        if (f && f->header.opcode == HoldOpcode::write) {
            auto h = f->header;
            h.status = HoldStatus::checksum;
            b = *proto::encode_hold_frame({.header = h, .payload = {}});
        }
        return true;
    };
    const auto data = blocks_of(13, 1);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(w.failed(BackendError::io));
    BOOST_TEST(rig.count(HoldOpcode::write) == 3U);  // the first and two retries
}

BOOST_AUTO_TEST_CASE(orders_overlapping_writes, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    // Hold every reply back so both writes would be in flight at once.
    std::vector<Bytes> held;
    rig.tamper = [&](Bytes& b) {
        held.push_back(b);
        return false;
    };
    const auto first = blocks_of(14, 4);
    const auto second = blocks_of(15, 2);
    const auto apart = blocks_of(16, 1);
    Done a;
    Done b;
    Done c;
    rig.write(40, first, a);
    rig.write(42, second, b);  // overlaps the first
    rig.write(50, apart, c);   // does not
    BOOST_TEST(rig.count(HoldOpcode::write) == 2U);
    BOOST_TEST(rig.sent.back().lba == 50U);

    // The first write is acknowledged: the second goes out.
    rig.tamper = nullptr;
    auto f = proto::decode_hold_frame(held.at(0));
    BOOST_TEST_REQUIRE(f.has_value());
    rig.core.on_frame(rig.core.target(rig.now)->session, *f, rig.now);
    rig.step();
    BOOST_TEST(a.ok());
    BOOST_TEST(rig.count(HoldOpcode::write) == 3U);
    BOOST_TEST(b.ok());

    Bytes out(4 * bs);
    Done r;
    rig.read(40, out, r);
    BOOST_TEST(std::ranges::equal(std::span{out}.first(2 * bs), std::span{first}.first(2 * bs)));
    BOOST_TEST(std::ranges::equal(std::span{out}.subspan(2 * bs), second));
}

BOOST_AUTO_TEST_CASE(keeps_to_the_qos_limits, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto c = config(1);
    c.qos = {.iops = 100, .mib_per_s = 1000, .burst_iops = 10, .burst_mib = 1000};
    rig.apply(c);
    const auto data = blocks_of(17, 1);
    std::vector<Done> done(30);
    for (std::size_t i = 0; i < done.size(); ++i) {
        rig.core.submit_write(i * bs, data, done[i].fn(), rig.now);
    }
    rig.step();
    // The burst, plus one that takes the bucket below zero.
    const auto burst = rig.count(HoldOpcode::write);
    BOOST_TEST(burst >= 10U);
    BOOST_TEST(burst <= 11U);
    rig.run_for(100ms);  // 100 IOPS: ten more
    BOOST_TEST(rig.count(HoldOpcode::write) >= burst + 9);
    BOOST_TEST(rig.count(HoldOpcode::write) <= burst + 11);
    rig.run_for(1s);
    BOOST_TEST(std::ranges::all_of(done, &Done::ok));
}

BOOST_AUTO_TEST_CASE(pings_an_idle_primary, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    rig.run_for(3500ms);
    BOOST_TEST(rig.count(HoldOpcode::ping) == 3U);
    BOOST_TEST(rig.core.take_faults().empty());
    BOOST_TEST(rig.connects == 1U);

    // An idle primary that stops answering PING is found out too.
    rig.server(1).mute = true;
    rig.run_for(3s);
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(!faults.empty());
    BOOST_TEST((faults.at(0).kind == InitiatorFault::primary_timeout));
    BOOST_TEST(rig.connects >= 2U);
}

BOOST_AUTO_TEST_CASE(lets_completions_submit_again, *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto data = blocks_of(18, 1);
    Bytes out(bs);
    Done inner;
    bool outer = false;
    rig.core.submit_write(
        0, data,
        [&](BackendResult r) {
            outer = r.has_value();
            rig.core.submit_read(0, out, inner.fn(), rig.now);
        },
        rig.now);
    rig.step();
    BOOST_TEST(outer);
    BOOST_TEST(inner.ok());
    BOOST_TEST(std::ranges::equal(out, data));
}

BOOST_AUTO_TEST_CASE(follows_a_resize_and_new_limits,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(1));
    const auto data = blocks_of(19, 2);
    Done before;
    rig.write(capacity, data, before);
    BOOST_TEST(before.failed(BackendError::out_of_range));
    // The resize epoch reaches the members first, then the initiator
    // (Requirement 10.3), with new QoS limits in the same config (10.4).
    auto grown = config(2);
    grown.capacity_blocks = 2 * capacity;
    grown.qos = {.iops = 100, .mib_per_s = 1000, .burst_iops = 10, .burst_mib = 1000};
    rig.apply(grown);
    BOOST_TEST(rig.core.capacity_bytes() == 2 * capacity * bs);
    Done after;
    rig.write(capacity, data, after);
    BOOST_TEST(after.ok());
    Bytes out(data.size());
    Done r;
    rig.read(capacity, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST(std::ranges::equal(out, data));
    // The tighter limits apply from the new epoch on.
    const auto one = blocks_of(20, 1);
    std::vector<Done> done(30);
    const auto sent = rig.count(HoldOpcode::write);
    for (std::size_t i = 0; i < done.size(); ++i) {
        rig.core.submit_write(i * bs, one, done[i].fn(), rig.now);
    }
    rig.step();
    BOOST_TEST(rig.count(HoldOpcode::write) - sent <= 11U);
    rig.run_for(1s);
    BOOST_TEST(std::ranges::all_of(done, &Done::ok));
}

BOOST_AUTO_TEST_CASE(refuses_routes_it_cannot_follow,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(config(2));
    auto other = config(3);
    other.volume_id = vol + 1;
    BOOST_TEST((rig.core.set_route(other, rig.now).error() == RouteError::wrong_volume));
    BOOST_TEST((rig.core.set_route(config(1), rig.now).error() == RouteError::stale));
    auto smaller = config(3);
    smaller.capacity_blocks /= 2;
    BOOST_TEST((rig.core.set_route(smaller, rig.now).error() == RouteError::mismatch));
    auto reblocked = config(3);
    reblocked.block_size = proto::block_size_4096;
    BOOST_TEST((rig.core.set_route(reblocked, rig.now).error() == RouteError::mismatch));
    BOOST_TEST(rig.core.set_route(config(2), rig.now).has_value());  // the same epoch again
    BOOST_TEST(!rig.core.fenced());
    BOOST_TEST(rig.connects == 1U);

    // A config without this attachment ends it.
    auto detached = config(3);
    detached.attachments.clear();
    BOOST_TEST(rig.core.set_route(detached, rig.now).has_value());
    BOOST_TEST(rig.core.fenced());
}

// Block-volume task 23: a volume restored from an image under another key.
auto image_config(std::uint64_t epoch, proto::AttachMode mode = proto::AttachMode::rw)
    -> proto::ReplicaConfig {
    auto c = config(epoch);
    c.source = {.kind = proto::SourceKind::image,
                .store_id = 3,
                .hydrate_mib_per_s = 50,
                .manifest_name = {}};
    c.source.manifest_name[0] = std::byte{1};
    c.attachments[0].mode = mode;
    return c;
}

BOOST_AUTO_TEST_CASE(reports_unhydrated_reads_and_sends_hydrate_writes,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(image_config(1));
    Bytes out(4 * bs);
    Done r0;
    rig.read(10, out, r0);
    BOOST_TEST(r0.failed(BackendError::not_hydrated));

    // The guest writes block 11; a hydrate write of 10-13 then fills the
    // rest, and the guest's block stays.
    const auto mine = blocks_of(1, 1);
    const auto image = blocks_of(2, 4);
    Done w;
    Done h;
    rig.write(11, mine, w);
    rig.core.submit_hydrate(10 * bs, image, h.fn(), rig.now);
    rig.step();
    BOOST_TEST(w.ok());
    BOOST_TEST(h.ok());
    const auto it = std::ranges::find_if(rig.sent, [](const proto::HoldHeader& hd) {
        return hd.opcode == HoldOpcode::write && (hd.flags & proto::hold_flags::hydrate) != 0;
    });
    BOOST_REQUIRE(it != rig.sent.end());
    BOOST_TEST(it->lba == 10U);
    Done r1;
    rig.read(10, out, r1);
    BOOST_TEST(r1.ok());
    auto expect = image;
    std::ranges::copy(mine, expect.begin() + bs);
    BOOST_TEST((out == expect));
}

BOOST_AUTO_TEST_CASE(hydrates_through_a_read_only_attachment,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    rig.apply(image_config(1, proto::AttachMode::ro));
    Done w;
    rig.write(4, blocks_of(1, 1), w);
    BOOST_TEST(w.failed(BackendError::io));  // refused before it leaves
    const auto image = blocks_of(3, 2);
    Done h;
    rig.core.submit_hydrate(4 * bs, image, h.fn(), rig.now);
    rig.step();
    BOOST_TEST(h.ok());
    Bytes out(2 * bs);
    Done r;
    rig.read(4, out, r);
    BOOST_TEST(r.ok());
    BOOST_TEST((out == image));
}
