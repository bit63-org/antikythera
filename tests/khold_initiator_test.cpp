// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kythira .kiro/specs/khold-block-service/ task 16: the khold initiator
// core against a fake khold cluster on a simulated clock. Each fake node
// leads the groups the cluster says it leads and redirects for the rest;
// the cluster keeps one block map per volume, so data written through one
// leader reads back through the next. Requirements 3.3 and 3.4
// (striping, ordering), 4.2 (discard, write-zeroes), 9.1 (failover by
// redirect and timeout), 9.9 (faults), 11.3 and 11.4 (layout-bound
// redirects, bounded sessions).

#define BOOST_TEST_MODULE khold_initiator_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <vector>

#include "common/crc32c.hpp"
#include "common/wire.hpp"
#include "oar/blk/khold_initiator.hpp"
#include "proto/hold_wire_v2.hpp"
#include "proto/volume_layout.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, RouteError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, InitiatorFault f) -> std::ostream& {
    return os << to_string(f);
}
}  // namespace ak::oar::blk
// Boost.Test's customization point for types it cannot print itself.
namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace {

namespace proto = ak::proto;
namespace utf = boost::unit_test;
using namespace ak::oar::blk;
using namespace std::chrono_literals;
using Clock = KholdInitiatorCore::Clock;
using Bytes = std::vector<std::byte>;
using proto::HoldV2Opcode;
using proto::HoldV2Status;

constexpr std::uint64_t compute = 2;  // the initiator's own server
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;
constexpr std::uint32_t su = 64 * 1024;         // stripe unit: 128 blocks
constexpr std::uint64_t unit_blocks = su / bs;  // 128
constexpr std::uint64_t capacity = 16 * 1024;   // blocks (8 MiB)
constexpr std::uint16_t port = 4430;
constexpr std::uint64_t outsider = 99;        // a server in no group
constexpr std::uint64_t group_base = 0x1000;  // group i is group_base + i

const Clock::time_point t0{std::chrono::seconds{1000}};

auto endpoint_of(std::uint64_t id) -> proto::StorageEndpoint {
    proto::StorageEndpoint e{};
    e[0] = std::byte{0xFD};  // unique local
    e[15] = static_cast<std::byte>(id);
    return e;
}

auto data_member(std::uint64_t id) -> proto::LayoutMember {
    return {.server_id = id,
            .endpoint = endpoint_of(id),
            .port = port,
            .kind = proto::MemberKind::data,
            .drive = 0};
}

auto witness(std::uint64_t id) -> proto::LayoutMember {
    auto m = data_member(id);
    m.kind = proto::MemberKind::witness;
    return m;
}

// `groups` stripe groups; group i has data members on servers
// 10 + i and 20 + i and a witness on 30 + i, unless `members` says
// otherwise.
auto layout(std::uint64_t epoch, std::size_t groups = 4,
            std::function<std::vector<proto::LayoutMember>(std::size_t)> members = {})
    -> proto::VolumeLayout {
    proto::VolumeLayout l;
    l.key_id = 1;
    l.server_id = compute;
    l.volume_id = vol;
    l.epoch = epoch;
    l.lineage_id = 9;
    l.capacity_blocks = capacity;
    l.block_size = bs;
    l.stripe_unit = su;
    l.commit_rule = proto::CommitRule::all_in_sync;
    l.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    l.timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900};
    for (std::size_t i = 0; i < groups; ++i) {
        proto::StripeGroup g{.group_id = group_base + i, .members = {}};
        if (members) {
            g.members = members(i);
        } else {
            g.members = {data_member(10 + i), data_member(20 + i), witness(30 + i)};
        }
        l.groups.push_back(g);
    }
    l.attachments = {{.attachment_id = att,
                      .server_id = compute,
                      .generation = 1,
                      .mode = proto::AttachMode::rw}};
    return l;
}

auto blocks_of(std::uint64_t tag, std::size_t n) -> Bytes {
    Bytes b(n * bs);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<std::byte>((tag * 31) + (i * 7) + 1);
    }
    return b;
}

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

// One request as a node saw it.
struct Seen {
    std::uint64_t server{0};
    HoldV2Opcode opcode{HoldV2Opcode::ping};
    std::uint64_t lba{0};
    std::uint32_t blocks{0};
    std::uint64_t group_id{0};
    std::uint64_t term{0};
    std::uint64_t epoch{0};
};

// The fake khold cluster: who leads which group at which term, the
// volume's blocks, and per-server behaviour.
struct Cluster {
    struct Lead {
        std::uint64_t leader{0};  // 0: no leader (election under way)
        std::uint64_t term{1};
    };
    std::map<std::uint64_t, Lead> leads;    // by group ID
    std::map<std::uint64_t, Bytes> blocks;  // by lba; absent: zeros
    std::set<std::uint64_t> unreachable;
    std::set<std::uint64_t> mute;
    std::uint64_t epoch{1};  // the nodes' layout epoch
    proto::VolumeLayout l;   // the nodes' layout
    // Per server, statuses to answer the next block requests with.
    std::map<std::uint64_t, std::vector<HoldV2Status>> scripted;
    // A redirect target to send instead of the real leader, per server.
    std::map<std::uint64_t, proto::HoldV2Redirect> lie;
    std::vector<Seen> seen;
    bool fenced{false};

    [[nodiscard]] auto group(std::uint64_t id) const -> const proto::StripeGroup* {
        const auto it = std::ranges::find(l.groups, id, &proto::StripeGroup::group_id);
        return it == l.groups.end() ? nullptr : &*it;
    }

    // The node on `server` answers one request.
    auto answer(std::uint64_t server, const proto::HoldV2Frame& req) -> std::optional<Bytes> {
        const auto& h = req.header;
        seen.push_back({.server = server,
                        .opcode = h.opcode,
                        .lba = h.lba,
                        .blocks = h.blocks,
                        .group_id = h.group_id,
                        .term = h.term,
                        .epoch = h.epoch});
        proto::HoldV2Header r = h;
        r.flags = proto::hold_flags::response;
        r.status = HoldV2Status::ok;
        if (h.epoch != epoch) {
            r.status = HoldV2Status::stale_epoch;
            r.epoch = std::max(h.epoch, epoch);
        } else if (fenced) {
            r.status = HoldV2Status::fenced;
        }
        if (h.opcode == HoldV2Opcode::hello) {
            r.opcode = HoldV2Opcode::hello_ok;
            if (r.status != HoldV2Status::ok) {
                return encode(r, std::monostate{});
            }
            return encode(r, proto::HoldV2HelloOk{
                                 .block_size = bs,
                                 .capacity_blocks = l.capacity_blocks,
                                 .stripe_unit = l.stripe_unit,
                                 .stripe_width = static_cast<std::uint16_t>(l.groups.size())});
        }
        if (h.opcode == HoldV2Opcode::ping) {
            return encode(r, std::monostate{});
        }
        if (r.status != HoldV2Status::ok) {
            return encode(r, std::monostate{});
        }
        const auto* g = group(h.group_id);
        const bool member =
            g != nullptr && std::ranges::find(g->members, server,
                                              &proto::LayoutMember::server_id) != g->members.end();
        if (!member) {
            r.status = HoldV2Status::unknown_group;
            return encode(r, std::monostate{});
        }
        const auto lead = leads[h.group_id];
        if (lead.leader != server || lie.contains(server)) {
            r.opcode = HoldV2Opcode::redirect;
            r.status = HoldV2Status::not_leader;
            r.lba = 0;
            r.blocks = 0;
            proto::HoldV2Redirect rd{};
            if (const auto it = lie.find(server); it != lie.end()) {
                rd = it->second;
            } else if (lead.leader != 0) {
                rd = {.leader_server = lead.leader,
                      .endpoint = endpoint_of(lead.leader),
                      .port = port,
                      .leader_term = lead.term};
            }
            return encode(r, rd);
        }
        r.term = lead.term;
        // A part must lie inside one stripe unit of its group.
        const std::uint64_t ub = l.stripe_unit / bs;
        const std::uint64_t unit = h.lba / ub;
        const auto index = static_cast<std::size_t>(g - l.groups.data());
        if (unit % l.groups.size() != index || (h.lba + h.blocks - 1) / ub != unit) {
            r.status = HoldV2Status::range;
            return encode(r, std::monostate{});
        }
        if (auto& s = scripted[server]; !s.empty()) {
            r.status = s.front();
            s.erase(s.begin());
            return encode(r, std::monostate{});
        }
        switch (h.opcode) {
            case HoldV2Opcode::write: {
                const auto& d = std::get<proto::BlockData>(req.payload);
                for (std::uint32_t b = 0; b < h.blocks; ++b) {
                    const auto block = d.data.subspan(std::size_t{b} * bs, bs);
                    blocks[h.lba + b] = Bytes{block.begin(), block.end()};
                }
                return encode(r, std::monostate{});
            }
            case HoldV2Opcode::discard:
            case HoldV2Opcode::write_zeroes:
                for (std::uint32_t b = 0; b < h.blocks; ++b) {
                    blocks.erase(h.lba + b);
                }
                return encode(r, std::monostate{});
            case HoldV2Opcode::read: {
                Bytes data(std::size_t{h.blocks} * bs);
                Bytes crcs;
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
                if (corrupt_reads > 0 && h.blocks > 0) {
                    --corrupt_reads;
                    data[0] ^= std::byte{0xFF};
                    if (blocks.find(h.lba) == blocks.end()) {
                        crcs[0] = std::byte{1};  // a zero block with a bad CRC
                    }
                }
                return encode(r, proto::BlockData{.block_size = bs, .crcs = crcs, .data = data});
            }
            default:
                return encode(r, std::monostate{});
        }
    }

    int corrupt_reads{0};

    static auto encode(const proto::HoldV2Header& h, const proto::HoldV2Payload& p)
        -> std::optional<Bytes> {
        auto f = proto::encode_hold_v2_frame({.header = h, .payload = p});
        BOOST_TEST_REQUIRE(f.has_value());
        return *f;
    }

    [[nodiscard]] auto count(HoldV2Opcode op) const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count(seen, op, &Seen::opcode));
    }
};

// The initiator and the cluster, on a simulated clock: step() moves frames
// until nothing more happens.
class Rig {
public:
    explicit Rig(KholdInitiatorConfig ic = {.attachment_id = att}) : core{ic} {}

    // Gives the cluster `l` (and leaders: data member `leader_index` of
    // each group at term 1), and unless `cluster_only` the initiator too.
    auto apply(const proto::VolumeLayout& l, bool cluster_only = false,
               std::size_t leader_index = 1) -> void {
        cluster.l = l;
        cluster.epoch = l.epoch;
        for (const auto& g : l.groups) {
            if (!cluster.leads.contains(g.group_id)) {
                std::vector<std::uint64_t> data;
                for (const auto& m : g.members) {
                    if (m.kind == proto::MemberKind::data) {
                        data.push_back(m.server_id);
                    }
                }
                cluster.leads[g.group_id] = {.leader = data[leader_index % data.size()], .term = 1};
            }
        }
        if (!cluster_only) {
            BOOST_TEST_REQUIRE(core.set_layout(l, now).has_value());
        }
        step();
    }

    auto step() -> void {
        for (int guard = 0; guard < 10000; ++guard) {
            bool moved = connect();
            for (auto& out : core.take_output()) {
                moved = true;
                const auto it = _links.find(out.session);
                BOOST_TEST_REQUIRE((it != _links.end()));
                auto f = proto::decode_hold_v2_frame(out.frame);
                BOOST_TEST_REQUIRE(f.has_value());
                if (cluster.mute.contains(it->second)) {
                    continue;
                }
                if (auto reply = cluster.answer(it->second, *f)) {
                    _inbox.emplace_back(out.session, std::move(*reply));
                }
            }
            auto inbox = std::exchange(_inbox, {});
            for (auto& [session, bytes] : inbox) {
                if (!_links.contains(session)) {
                    continue;  // a session the initiator has left
                }
                auto f = proto::decode_hold_v2_frame(bytes);
                BOOST_TEST_REQUIRE(f.has_value());
                moved = true;
                core.on_frame(session, *f, now);
            }
            if (!moved) {
                return;
            }
        }
        BOOST_FAIL("the rig did not settle");
    }

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

    // The data must outlive the write (the BlockBackend contract), and
    // callers pass temporaries: the rig keeps a copy.
    auto write(std::uint64_t lba, const Bytes& data, Done& d) -> void {
        core.submit_write(lba * bs, kept.emplace_back(data), d.fn(), now);
        step();
    }
    auto read(std::uint64_t lba, Bytes& out, Done& d) -> void {
        core.submit_read(lba * bs, out, d.fn(), now);
        step();
    }
    // Reads `n` blocks at `lba`, letting time run until done.
    auto read_back(std::uint64_t lba, std::size_t n) -> Bytes {
        Bytes out(n * bs);
        Done r;
        read(lba, out, r);
        for (int i = 0; i < 100 && !r.result; ++i) {
            run_for(100ms);
        }
        BOOST_TEST(r.ok());
        return out;
    }

    // Sessions open now, by server.
    [[nodiscard]] auto linked() const -> std::set<std::uint64_t> {
        std::set<std::uint64_t> out;
        for (const auto& [session, server] : _links) {
            out.insert(server);
        }
        return out;
    }

    std::deque<Bytes> kept;  // write data, alive as long as the core
    KholdInitiatorCore core;
    Cluster cluster;
    Clock::time_point now{t0};
    std::size_t connects{0};
    std::size_t max_links{0};

private:
    // Opens what targets() names and drops what it no longer names.
    auto connect() -> bool {
        const auto targets = core.targets(now);
        bool moved = false;
        std::erase_if(_links, [&](const auto& kv) {
            return std::ranges::find(targets, kv.first, &HoldTarget::session) == targets.end();
        });
        for (const auto& t : targets) {
            if (_links.contains(t.session) || _tried.contains(t.session)) {
                continue;
            }
            BOOST_TEST(t.port == port);
            BOOST_TEST((t.endpoint == endpoint_of(t.server_id)));
            _tried.insert(t.session);
            moved = true;
            if (cluster.unreachable.contains(t.server_id)) {
                core.disconnected(t.session, now);
                continue;
            }
            ++connects;
            _links[t.session] = t.server_id;
            max_links = std::max(max_links, _links.size());
            core.connected(t.session, now);
        }
        return moved;
    }

    std::map<std::uint64_t, std::uint64_t> _links;  // session -> server
    std::set<std::uint64_t> _tried;
    std::vector<std::pair<std::uint64_t, Bytes>> _inbox;
};

auto block_ops(const Cluster& c) -> std::vector<Seen> {
    std::vector<Seen> out;
    std::ranges::copy_if(c.seen, std::back_inserter(out),
                         [](const Seen& s) { return proto::is_block_opcode(s.opcode); });
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(khold_initiator, *utf::timeout(ak::test::unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(holds_requests_until_the_layout_arrives) {
    Rig rig;
    rig.apply(layout(1), true);  // the cluster has it; the initiator not yet
    const auto data = blocks_of(1, 4);
    Done w;
    rig.write(8, data, w);
    BOOST_TEST(rig.core.targets(rig.now).empty());
    rig.run_for(1h);  // held, not failed, however long
    BOOST_TEST(!w.result.has_value());

    BOOST_TEST_REQUIRE(rig.core.set_layout(layout(1), rig.now).has_value());
    rig.step();
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.core.capacity_bytes() == capacity * bs);
    BOOST_TEST(rig.read_back(8, 4) == data, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(splits_at_stripe_units_and_sends_each_part_to_its_group) {
    Rig rig;
    rig.apply(layout(1));
    // From the middle of unit 1 to the middle of unit 4: four parts, on
    // groups 1, 2, 3 and 0 (units 1, 2, 3, 4 of a 4-wide stripe).
    const std::uint64_t first = unit_blocks + 64;
    const std::size_t n = 3 * unit_blocks;
    const auto data = blocks_of(2, n);
    Done w;
    rig.write(first, data, w);
    BOOST_TEST_REQUIRE(w.ok());
    // Groups 0 and 2 first went to their first guess (data member 0),
    // which redirected; what the leaders took:
    std::vector<Seen> ops;
    std::ranges::copy_if(block_ops(rig.cluster), std::back_inserter(ops),
                         [](const Seen& s) { return s.server >= 20; });
    std::ranges::sort(ops, {}, &Seen::lba);
    BOOST_TEST_REQUIRE(ops.size() == 4U);
    const std::uint64_t want_lba[] = {first, 2 * unit_blocks, 3 * unit_blocks, 4 * unit_blocks};
    const std::uint32_t want_blocks[] = {64, 128, 128, 64};
    const std::uint64_t want_group[] = {1, 2, 3, 0};
    for (std::size_t i = 0; i < 4; ++i) {
        BOOST_TEST(ops[i].lba == want_lba[i]);
        BOOST_TEST(ops[i].blocks == want_blocks[i]);
        BOOST_TEST(ops[i].group_id == group_base + want_group[i]);
        BOOST_TEST((ops[i].opcode == HoldV2Opcode::write));
    }
    BOOST_TEST(rig.read_back(first, n) == data, boost::test_tools::per_element());
    // One session per leader; group i is led by data member 1 (server 20 + i).
    BOOST_TEST((rig.linked() == std::set<std::uint64_t>{20, 21, 22, 23}));
}

BOOST_AUTO_TEST_CASE(splits_at_the_part_size_inside_a_unit) {
    // A 4 MiB stripe unit and one group: parts split at the part size.
    Rig rig;
    auto l = layout(1, 1);
    l.stripe_unit = 4U << 20U;
    l.capacity_blocks = 32 * 1024;
    rig.apply(l, false, 0);  // the first guess leads: no redirects
    const std::size_t n = (5U << 20U) / bs;
    const auto data = blocks_of(3, n);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST_REQUIRE(w.ok());
    // max_hold_blocks (1 MiB of 512-byte blocks) per part: five parts.
    const auto ops = block_ops(rig.cluster);
    BOOST_TEST_REQUIRE(ops.size() == 5U);
    for (std::size_t i = 0; i < ops.size(); ++i) {
        BOOST_TEST(ops[i].blocks == proto::max_hold_blocks);
        BOOST_TEST(ops[i].lba == i * proto::max_hold_blocks);
    }
}

BOOST_AUTO_TEST_CASE(follows_a_redirect_to_a_member_of_the_group) {
    Rig rig;
    // The initiator first guesses data member 0; the cluster made member 1
    // the leader, at term 5.
    rig.apply(layout(1), true, 1);
    rig.cluster.leads[group_base].term = 5;
    BOOST_TEST_REQUIRE(rig.core.set_layout(layout(1), rig.now).has_value());
    BOOST_TEST(rig.core.leader_of(0) == 10U);
    const auto data = blocks_of(4, 8);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.core.leader_of(0) == 20U);
    const auto ops = block_ops(rig.cluster);
    BOOST_TEST_REQUIRE(ops.size() == 2U);
    BOOST_TEST(ops[0].server == 10U);  // redirected
    BOOST_TEST(ops[1].server == 20U);
    BOOST_TEST(ops[1].term == 5U);  // the redirect's term, carried from then on
    BOOST_TEST(rig.core.take_faults().empty());
}

BOOST_AUTO_TEST_CASE(never_follows_a_redirect_outside_the_layout) {
    Rig rig;
    rig.apply(layout(1, 1), true, 1);
    BOOST_TEST_REQUIRE(rig.core.set_layout(layout(1, 1), rig.now).has_value());
    // Server 10 (a compromised or confused member) points at a stranger.
    rig.cluster.lie[10] = {.leader_server = outsider,
                           .endpoint = endpoint_of(outsider),
                           .port = port,
                           .leader_term = 100};
    const auto data = blocks_of(5, 2);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(!w.result.has_value());  // waits out the backoff, never goes to 99
    rig.run_for(1s);
    BOOST_TEST(w.ok());
    for (const auto& s : rig.cluster.seen) {
        BOOST_TEST(s.server != outsider);
    }
    BOOST_TEST(rig.core.leader_of(0) == 20U);
    BOOST_TEST(!rig.linked().contains(outsider));
}

BOOST_AUTO_TEST_CASE(an_older_redirect_does_not_move_the_leader_back) {
    Rig rig;
    rig.apply(layout(1, 1), false, 0);
    Done w0;
    rig.write(0, blocks_of(6, 1), w0);
    BOOST_TEST_REQUIRE(w0.ok());
    // A new leader at term 7 answers; then a stale member claims an older
    // term for the old leader.
    rig.cluster.leads[group_base] = {.leader = 20, .term = 7};
    Done w1;
    rig.write(1, blocks_of(7, 1), w1);
    BOOST_TEST_REQUIRE(w1.ok());
    BOOST_TEST(rig.core.leader_of(0) == 20U);
    rig.cluster.lie[20] = {
        .leader_server = 10, .endpoint = endpoint_of(10), .port = port, .leader_term = 3};
    rig.cluster.leads[group_base] = {.leader = 0, .term = 7};
    Done w2;
    rig.write(2, blocks_of(8, 1), w2);
    BOOST_TEST(rig.core.leader_of(0) != 10U);  // term 3 < 7: not followed back
}

BOOST_AUTO_TEST_CASE(a_silent_leader_is_reported_and_its_groups_move_on) {
    Rig rig;
    rig.apply(layout(1, 2));
    Done w0;
    rig.write(0, blocks_of(9, 1), w0);
    BOOST_TEST_REQUIRE(w0.ok());
    BOOST_TEST(rig.core.leader_of(0) == 20U);

    // Server 20 hangs with a write outstanding; the group elects 10.
    rig.cluster.mute.insert(20);
    const auto data = blocks_of(10, 4);
    Done w;
    rig.write(4, data, w);
    BOOST_TEST(!w.result.has_value());
    rig.cluster.leads[group_base] = {.leader = 10, .term = 2};
    rig.run_for(2500ms);
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.core.leader_of(0) == 10U);
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(faults.size() == 1U);
    BOOST_TEST((faults[0].kind == InitiatorFault::primary_timeout));
    BOOST_TEST(faults[0].server == 20U);
    BOOST_TEST(faults[0].epoch == 1U);
    // Group 1 (led by 21) never paused.
    rig.cluster.mute.clear();
    BOOST_TEST(rig.read_back(4, 4) == data, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(an_unreachable_leader_is_skipped) {
    Rig rig;
    rig.apply(layout(1, 1), true, 1);
    rig.cluster.unreachable.insert(10);  // the first guess is down
    BOOST_TEST_REQUIRE(rig.core.set_layout(layout(1, 1), rig.now).has_value());
    const auto data = blocks_of(11, 3);
    Done w;
    rig.write(0, data, w);
    rig.run_for(1s);
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.core.leader_of(0) == 20U);
}

BOOST_AUTO_TEST_CASE(no_leader_anywhere_fails_at_the_deadline) {
    Rig rig{{.attachment_id = att, .request_timeout = 5s}};
    rig.apply(layout(1, 1));
    rig.cluster.leads[group_base] = {.leader = 0, .term = 2};  // an election that never ends
    Done w;
    rig.write(0, blocks_of(12, 1), w);
    rig.run_for(4s);
    BOOST_TEST(!w.result.has_value());
    rig.run_for(2s);
    BOOST_TEST(w.failed(BackendError::io));
    // The backoff kept it from spinning.
    BOOST_TEST(block_ops(rig.cluster).size() < 40U);
}

BOOST_AUTO_TEST_CASE(waits_for_a_newer_layout) {
    Rig rig;
    rig.apply(layout(1));
    rig.apply(layout(2), true);  // the cluster moves on first
    const auto data = blocks_of(13, 2);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST(!w.result.has_value());
    BOOST_TEST(rig.core.targets(rig.now).empty());  // nothing to do until helm's layout
    rig.run_for(1s);
    BOOST_TEST(!w.result.has_value());
    BOOST_TEST_REQUIRE(rig.core.set_layout(layout(2), rig.now).has_value());
    rig.step();
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.cluster.seen.back().epoch == 2U);
}

BOOST_AUTO_TEST_CASE(layout_changes_are_checked) {
    Rig rig;
    rig.apply(layout(3));
    BOOST_TEST(rig.core.set_layout(layout(2), rig.now).error() == RouteError::stale);
    BOOST_TEST(rig.core.set_layout(layout(3), rig.now).has_value());  // the same: nothing
    auto other = layout(4);
    other.volume_id = vol + 1;
    BOOST_TEST(rig.core.set_layout(other, rig.now).error() == RouteError::wrong_volume);
    auto restriped = layout(4);
    restriped.stripe_unit = 2 * su;
    BOOST_TEST(rig.core.set_layout(restriped, rig.now).error() == RouteError::mismatch);
    BOOST_TEST(rig.core.set_layout(layout(4, 2), rig.now).error() == RouteError::mismatch);
    auto smaller = layout(4);
    smaller.capacity_blocks = capacity / 2;
    BOOST_TEST(rig.core.set_layout(smaller, rig.now).error() == RouteError::mismatch);
    auto larger = layout(4);
    larger.capacity_blocks = 2 * capacity;
    rig.cluster.l = larger;
    rig.cluster.epoch = 4;
    BOOST_TEST(rig.core.set_layout(larger, rig.now).has_value());
    BOOST_TEST(rig.core.capacity_bytes() == 2 * capacity * bs);
}

BOOST_AUTO_TEST_CASE(a_member_change_reseeds_the_leader) {
    Rig rig;
    rig.apply(layout(1, 1));
    Done w0;
    rig.write(0, blocks_of(14, 1), w0);
    BOOST_TEST_REQUIRE(w0.ok());
    BOOST_TEST(rig.core.leader_of(0) == 20U);
    // Server 20 is replaced by 40, which now leads.
    const auto moved = layout(2, 1, [](std::size_t) {
        return std::vector{data_member(10), witness(30), data_member(40)};
    });
    rig.cluster.leads[group_base] = {.leader = 40, .term = 3};
    rig.apply(moved);
    BOOST_TEST(!rig.linked().contains(20));
    const auto data = blocks_of(15, 1);
    Done w;
    rig.write(1, data, w);
    rig.run_for(1s);
    BOOST_TEST(w.ok());
    BOOST_TEST(rig.core.leader_of(0) == 40U);
}

BOOST_AUTO_TEST_CASE(fencing_fails_everything) {
    Rig rig;
    rig.apply(layout(1));
    auto detached = layout(2);
    detached.attachments.clear();
    Done w;
    rig.cluster.mute.insert(20);  // so the write is still in flight
    rig.write(0, blocks_of(16, 1), w);
    BOOST_TEST_REQUIRE(rig.core.set_layout(detached, rig.now).has_value());
    BOOST_TEST(rig.core.fenced());
    BOOST_TEST(w.failed(BackendError::io));
    BOOST_TEST(rig.core.targets(rig.now).empty());
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(faults.size() == 1U);
    BOOST_TEST((faults[0].kind == InitiatorFault::fenced));
    Done later;
    rig.write(1, blocks_of(17, 1), later);
    rig.run_for(1ms);
    BOOST_TEST(later.failed(BackendError::io));
}

BOOST_AUTO_TEST_CASE(a_fenced_reply_fails_everything) {
    Rig rig;
    rig.apply(layout(1));
    rig.cluster.fenced = true;
    Done w;
    rig.write(0, blocks_of(18, 1), w);
    BOOST_TEST(w.failed(BackendError::io));
    BOOST_TEST(rig.core.fenced());
}

BOOST_AUTO_TEST_CASE(statuses_fail_retry_or_report) {
    Rig rig;
    rig.apply(layout(1, 1));
    const auto one = blocks_of(19, 1);
    // no_space and read_only: that request only.
    rig.cluster.scripted[20] = {HoldV2Status::no_space};
    Done a;
    rig.write(0, one, a);
    BOOST_TEST(a.failed(BackendError::io));
    Done b;
    rig.write(1, one, b);
    BOOST_TEST(b.ok());
    // repairing and throttled: resent after a backoff.
    rig.cluster.scripted[20] = {HoldV2Status::repairing, HoldV2Status::throttled};
    Done c;
    rig.write(2, one, c);
    BOOST_TEST(!c.result.has_value());
    rig.run_for(1s);
    BOOST_TEST(c.ok());
    // A write's checksum refusal: resent, twice at most.
    rig.cluster.scripted[20] = {HoldV2Status::checksum, HoldV2Status::checksum,
                                HoldV2Status::checksum};
    Done d;
    rig.write(3, one, d);
    BOOST_TEST(d.failed(BackendError::io));
    // io_error: a media error the node could not repair, reported.
    rig.cluster.scripted[20] = {HoldV2Status::io_error};
    Done e;
    rig.write(4, one, e);
    BOOST_TEST(e.failed(BackendError::io));
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(faults.size() == 1U);
    BOOST_TEST((faults[0].kind == InitiatorFault::media_error));
    BOOST_TEST(faults[0].server == 20U);
    // range: out of range.
    rig.cluster.scripted[20] = {HoldV2Status::range};
    Done f;
    rig.write(5, one, f);
    BOOST_TEST(f.failed(BackendError::out_of_range));
}

BOOST_AUTO_TEST_CASE(reads_are_checked_and_retried) {
    Rig rig;
    rig.apply(layout(1, 1));
    const auto data = blocks_of(20, 2);
    Done w;
    rig.write(10, data, w);
    BOOST_TEST_REQUIRE(w.ok());
    rig.cluster.corrupt_reads = 1;
    BOOST_TEST(rig.read_back(10, 2) == data, boost::test_tools::per_element());
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(faults.size() == 1U);
    BOOST_TEST((faults[0].kind == InitiatorFault::checksum));
    BOOST_TEST(faults[0].server == 20U);
    rig.cluster.corrupt_reads = 2;
    Bytes out(2 * bs);
    Done r;
    rig.read(10, out, r);
    BOOST_TEST(r.failed(BackendError::io));
}

BOOST_AUTO_TEST_CASE(discard_and_write_zeroes_free_blocks) {
    Rig rig;
    rig.apply(layout(1));
    const std::size_t n = 2 * unit_blocks;
    const auto data = blocks_of(21, n);
    Done w;
    rig.write(0, data, w);
    BOOST_TEST_REQUIRE(w.ok());
    Done d;
    rig.core.submit_discard(0, unit_blocks * bs, d.fn(), rig.now);
    Done z;
    rig.core.submit_write_zeroes((unit_blocks + 8) * bs, 8 * bs, z.fn(), rig.now);
    rig.step();
    BOOST_TEST(d.ok());
    BOOST_TEST(z.ok());
    BOOST_TEST(rig.cluster.count(HoldV2Opcode::discard) == 1U);
    BOOST_TEST(rig.cluster.count(HoldV2Opcode::write_zeroes) == 1U);
    auto want = data;
    std::fill_n(want.begin(), unit_blocks * bs, std::byte{0});
    std::fill_n(want.begin() + static_cast<std::ptrdiff_t>((unit_blocks + 8) * bs), 8 * bs,
                std::byte{0});
    BOOST_TEST(rig.read_back(0, n) == want, boost::test_tools::per_element());
    // A discard past the end, or not whole blocks: refused without I/O.
    Done bad;
    rig.core.submit_discard(capacity * bs, bs, bad.fn(), rig.now);
    BOOST_TEST(bad.failed(BackendError::out_of_range));
    Done odd;
    rig.core.submit_discard(0, 100, odd.fn(), rig.now);
    BOOST_TEST(odd.failed(BackendError::out_of_range));
}

BOOST_AUTO_TEST_CASE(read_only_attachments_refuse_changes) {
    Rig rig;
    auto l = layout(1);
    l.attachments[0].mode = proto::AttachMode::ro;
    rig.apply(l);
    Done w;
    rig.write(0, blocks_of(22, 1), w);
    BOOST_TEST(w.failed(BackendError::io));
    Done d;
    rig.core.submit_discard(0, bs, d.fn(), rig.now);
    BOOST_TEST(d.failed(BackendError::io));
    BOOST_TEST(block_ops(rig.cluster).empty());
}

BOOST_AUTO_TEST_CASE(overlapping_writes_go_out_in_order) {
    Rig rig;
    rig.apply(layout(1, 1));
    rig.cluster.mute.insert(20);
    Done a;
    Done b;
    Done c;
    const auto first = blocks_of(23, 4);
    const auto second = blocks_of(24, 4);
    rig.core.submit_write(0, first, a.fn(), rig.now);
    rig.core.submit_write(2 * bs, second, b.fn(), rig.now);    // overlaps the first
    rig.core.submit_write(100 * bs, second, c.fn(), rig.now);  // does not
    rig.step();
    const auto ops = block_ops(rig.cluster);
    BOOST_TEST_REQUIRE(ops.size() == 2U);
    BOOST_TEST(ops[0].lba == 0U);
    BOOST_TEST(ops[1].lba == 100U);  // the overlapping write waits
    rig.cluster.mute.clear();
    rig.run_for(3s);  // the silent session times out; everything is resent in order
    BOOST_TEST(a.ok());
    BOOST_TEST(b.ok());
    BOOST_TEST(c.ok());
    auto want = first;
    want.resize(6 * bs);
    std::ranges::copy(second, want.begin() + 2 * bs);
    BOOST_TEST(rig.read_back(0, 6) == want, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(sessions_are_bounded) {
    Rig rig{{.attachment_id = att, .max_sessions = 2}};
    rig.apply(layout(1, 4));
    // One write per group: four leaders, two sessions at a time.
    std::vector<Done> done(4);
    std::vector<Bytes> data;
    for (std::size_t g = 0; g < 4; ++g) {
        data.push_back(blocks_of(30 + g, 1));
    }
    for (std::size_t g = 0; g < 4; ++g) {
        rig.core.submit_write(g * unit_blocks * bs, data[g], done[g].fn(), rig.now);
    }
    rig.step();
    rig.run_for(1s);
    BOOST_TEST(std::ranges::all_of(done, &Done::ok));
    BOOST_TEST(rig.max_links <= 2U);
    for (std::size_t g = 0; g < 4; ++g) {
        BOOST_TEST(rig.read_back(g * unit_blocks, 1) == data[g], boost::test_tools::per_element());
    }
}

BOOST_AUTO_TEST_CASE(idle_sessions_are_pinged) {
    Rig rig;
    rig.apply(layout(1, 1));
    Done w;
    rig.write(0, blocks_of(40, 1), w);
    BOOST_TEST_REQUIRE(w.ok());
    rig.run_for(3500ms);
    BOOST_TEST(rig.cluster.count(HoldV2Opcode::ping) == 3U);
    BOOST_TEST(rig.core.take_faults().empty());
    rig.cluster.mute.insert(20);
    rig.run_for(4s);
    auto faults = rig.core.take_faults();
    BOOST_TEST_REQUIRE(!faults.empty());
    BOOST_TEST((faults[0].kind == InitiatorFault::primary_timeout));
    BOOST_TEST(faults[0].server == 20U);
}

BOOST_AUTO_TEST_CASE(io_suspended_layouts_hold_requests) {
    Rig rig{{.attachment_id = att, .request_timeout = 5s}};
    auto l = layout(1, 1);
    l.flags = proto::layout_flags::io_suspended | proto::layout_flags::impaired;
    rig.apply(l);
    Done w;
    rig.write(0, blocks_of(41, 1), w);
    BOOST_TEST(rig.core.targets(rig.now).empty());
    rig.run_for(2s);
    BOOST_TEST(!w.result.has_value());
    rig.apply(layout(2, 1));  // EnableVolumeIO
    BOOST_TEST(w.ok());
}

BOOST_AUTO_TEST_CASE(split_layouts_go_through_gateways) {
    Rig rig;
    auto l = layout(1, 2);
    l.gateways = {{.server_id = 50, .endpoint = endpoint_of(50), .port = port},
                  {.server_id = 51, .endpoint = endpoint_of(51), .port = port}};
    rig.apply(l);
    // The fake gateways answer as if they led every group they are asked about.
    for (const auto& g : l.groups) {
        rig.cluster.l.groups[g.group_id - group_base].members.push_back(data_member(50));
        rig.cluster.l.groups[g.group_id - group_base].members.push_back(data_member(51));
    }
    rig.cluster.leads[group_base] = {.leader = 50, .term = 1};
    rig.cluster.leads[group_base + 1] = {.leader = 51, .term = 1};
    Done a;
    Done b;
    rig.write(0, blocks_of(42, 1), a);
    rig.write(unit_blocks, blocks_of(43, 1), b);
    BOOST_TEST(a.ok());
    BOOST_TEST(b.ok());
    BOOST_TEST((rig.linked() == std::set<std::uint64_t>{50, 51}));
    // Gateway 50 dies: group 0 moves to gateway 51.
    rig.cluster.unreachable.insert(50);
    rig.cluster.mute.insert(50);
    rig.cluster.leads[group_base] = {.leader = 51, .term = 1};
    Done c;
    rig.write(1, blocks_of(44, 1), c);
    rig.run_for(3s);
    BOOST_TEST(c.ok());
    BOOST_TEST(!rig.linked().contains(50));
}

BOOST_AUTO_TEST_CASE(completions_may_submit_again) {
    Rig rig;
    rig.apply(layout(1, 1));
    const auto data = blocks_of(45, 1);
    std::vector<Done> done(5);
    std::size_t next = 0;
    std::function<void(BackendResult)> chain = [&](BackendResult r) {
        done[next].result = r;
        if (++next < done.size()) {
            rig.core.submit_write(next * bs, data, chain, rig.now);
        }
    };
    rig.core.submit_write(0, data, chain, rig.now);
    rig.step();
    BOOST_TEST(std::ranges::all_of(done, &Done::ok));
}

BOOST_AUTO_TEST_SUITE_END()
