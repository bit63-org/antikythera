// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirements 1.4, 2.3 and 3: the
// ControllerSession protocol, driven byte by byte with no network.

#define BOOST_TEST_MODULE controller_session_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "helm/controller_link.hpp"
#include "helm/mailbox.hpp"
#include "proto/link.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::LinkError;
using proto::RecordType;

namespace {

constexpr std::uint64_t server = 0x5E'0001;
constexpr std::uint64_t other_server = 0x5E'0002;
constexpr std::uint64_t boot = 0xB007;
constexpr proto::KeyId key = 3;

struct RecordingSink final : helm::ControllerSink {
    std::vector<proto::Envelope> envelopes;
    std::vector<std::pair<proto::MapUpdate, std::vector<std::byte>>> updates;

    auto on_envelope(const proto::Envelope& e) -> void override { envelopes.push_back(e); }
    auto on_map_update(const proto::MapUpdate& u, std::span<const std::byte> frame)
        -> void override {
        updates.emplace_back(u, std::vector<std::byte>{frame.begin(), frame.end()});
    }
};

struct Fixture {
    RecordingSink sink;
    int inventories = 0;
    helm::ControllerSession session{server, boot,
                                    [this] {
                                        ++inventories;
                                        proto::Inventory inv;
                                        inv.boot_id = 1;  // the session overrides it
                                        inv.cores_total = 8;
                                        inv.cores_free = static_cast<std::uint16_t>(inventories);
                                        return inv;
                                    },
                                    sink};
};

// Parses everything the session wrote into records.
auto records(std::vector<std::byte> bytes) -> std::vector<proto::Record> {
    proto::RecordDecoder d;
    d.feed(bytes);
    std::vector<proto::Record> out;
    for (;;) {
        auto r = d.next();
        BOOST_REQUIRE(r.has_value());
        if (!r->has_value()) {
            BOOST_TEST(d.buffered() == 0U);
            return out;
        }
        out.push_back(std::move(**r));
    }
}

auto as_report(const proto::Record& r) -> proto::Report {
    BOOST_REQUIRE((r.type == RecordType::report));
    auto rep = proto::decode_report(r.payload);
    BOOST_REQUIRE(rep.has_value());
    return *rep;
}

auto framed(RecordType t, const std::vector<std::byte>& payload) -> std::vector<std::byte> {
    auto b = proto::encode_record(t, payload);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto envelope_record(std::uint64_t to, std::uint64_t seq) -> std::vector<std::byte> {
    const mb::Header h{.type = mb::Type::list_vms, .seq = seq, .key_id = key};
    std::array<std::byte, mb::signature_size> sig{};
    auto slot = mb::encode(h, {}, sig);
    BOOST_REQUIRE(slot.has_value());
    auto env = proto::encode_envelope({.server_id = to, .key_id = key, .slot = *slot});
    BOOST_REQUIRE(env.has_value());
    return framed(RecordType::envelope, {env->begin(), env->end()});
}

auto map_update_record(std::uint64_t to) -> std::vector<std::byte> {
    proto::MapUpdate m{
        .server_id = to, .key_id = key, .vni = 5, .map_version = 1, .entries = {}, .signature = {}};
    auto b = proto::encode_map_update(m);
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::map_update, *b);
}

auto ack_record(std::uint64_t seq, std::uint64_t to = server) -> std::vector<std::byte> {
    auto b = proto::encode_report_ack({.server_id = to, .report_seq = seq});
    BOOST_REQUIRE(b.has_value());
    return framed(RecordType::report_ack, *b);
}

auto exited(std::uint64_t vm) -> proto::ReportBody {
    return proto::VmExitedReport{
        .vm_id = vm, .exit_status = 0, .reason = proto::ExitReason::guest_shutdown};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(controller_session, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_FIXTURE_TEST_CASE(registration_is_hello_then_inventory, Fixture) {
    session.on_connected();
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 2U);
    BOOST_REQUIRE((recs[0].type == RecordType::hello));
    auto hello = proto::decode_hello(recs[0].payload);
    BOOST_REQUIRE(hello.has_value());
    BOOST_TEST(hello->server_id == server);
    BOOST_TEST(hello->boot_id == boot);
    const auto inv = as_report(recs[1]);
    BOOST_TEST(inv.server_id == server);
    BOOST_TEST(inv.report_seq == 1U);
    BOOST_REQUIRE(std::holds_alternative<proto::Inventory>(inv.body));
    BOOST_TEST(std::get<proto::Inventory>(inv.body).boot_id == boot);
    BOOST_TEST(session.take_outbound().empty());
}

BOOST_FIXTURE_TEST_CASE(reports_go_out_immediately_when_connected, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    BOOST_TEST(session.report(exited(7)) == 2U);
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 1U);
    BOOST_TEST(as_report(recs[0]).report_seq == 2U);
}

BOOST_FIXTURE_TEST_CASE(reconnect_replays_unacked_then_fresh_inventory, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    (void)session.report(exited(7));  // seq 2
    (void)session.report(exited(8));  // seq 3
    BOOST_TEST(session.on_bytes(ack_record(2)).has_value());
    BOOST_TEST(session.last_acked() == 2U);
    session.on_disconnected();
    (void)session.report(exited(9));  // seq 4, queued while down
    BOOST_TEST(session.take_outbound().empty());

    session.on_connected();
    const auto recs = records(session.take_outbound());
    // hello, seq 3 and 4 (the inventory, seq 1, was acked by 2), then a
    // fresh inventory as seq 5.
    BOOST_REQUIRE(recs.size() == 4U);
    BOOST_TEST((recs[0].type == RecordType::hello));
    BOOST_TEST(as_report(recs[1]).report_seq == 3U);
    BOOST_TEST(as_report(recs[2]).report_seq == 4U);
    const auto inv = as_report(recs[3]);
    BOOST_TEST(inv.report_seq == 5U);
    BOOST_TEST(std::get<proto::Inventory>(inv.body).cores_free == 2U);
}

BOOST_FIXTURE_TEST_CASE(unacked_inventory_is_superseded_not_replayed, Fixture) {
    session.on_connected();  // inventory seq 1, never acked
    (void)session.take_outbound();
    session.on_disconnected();
    session.on_connected();
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == 2U);
    BOOST_TEST(as_report(recs[1]).report_seq == 2U);
    BOOST_TEST(session.pending_reports() == 1U);
}

BOOST_FIXTURE_TEST_CASE(acks_only_move_forward, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    (void)session.report(exited(7));
    (void)session.report(exited(8));
    BOOST_TEST(session.on_bytes(ack_record(3)).has_value());
    BOOST_TEST(session.pending_reports() == 0U);
    BOOST_TEST(session.on_bytes(ack_record(1)).has_value());  // late duplicate
    BOOST_TEST(session.last_acked() == 3U);
}

BOOST_FIXTURE_TEST_CASE(envelopes_and_updates_reach_the_sink_unmodified, Fixture) {
    session.on_connected();
    auto stream = envelope_record(server, 10);
    const auto upd = map_update_record(server);
    stream.insert(stream.end(), upd.begin(), upd.end());
    // Byte at a time: reassembly is the decoder's job.
    for (const auto b : stream) {
        BOOST_REQUIRE(session.on_bytes(std::span{&b, 1}).has_value());
    }
    BOOST_REQUIRE(sink.envelopes.size() == 1U);
    BOOST_TEST(proto::slot_seq(sink.envelopes[0].slot) == 10U);
    const auto env_bytes = proto::encode_envelope(sink.envelopes[0]);
    BOOST_TEST(std::ranges::equal(
        *env_bytes, std::span{stream}.subspan(proto::record_header_size, proto::envelope_size)));
    BOOST_REQUIRE(sink.updates.size() == 1U);
    BOOST_TEST(sink.updates[0].first.vni == 5U);
    BOOST_TEST(std::ranges::equal(sink.updates[0].second,
                                  std::span{upd}.subspan(proto::record_header_size)));
}

BOOST_FIXTURE_TEST_CASE(protocol_violations_end_the_connection, Fixture) {
    struct Case {
        std::vector<std::byte> bytes;
        LinkError want;
    };
    auto bad_envelope = envelope_record(server, 10);
    bad_envelope[proto::record_header_size] = std::byte{0};  // envelope magic
    auto report_payload =
        proto::encode_report({.server_id = server, .report_seq = 1, .body = exited(1)});
    auto hello_payload = proto::encode_hello({.server_id = server, .boot_id = 1});
    const Case cases[] = {
        {envelope_record(other_server, 10), LinkError::wrong_server},
        {map_update_record(other_server), LinkError::wrong_server},
        {bad_envelope, LinkError::bad_record},
        {framed(RecordType::report, *report_payload), LinkError::wrong_direction},
        {framed(RecordType::hello, *hello_payload), LinkError::wrong_direction},
        {ack_record(99), LinkError::bad_ack},
        {ack_record(1, other_server), LinkError::bad_ack},
        {ak::test::bytes_of(0, 0, 0, 0, 9, 0, 0, 0), LinkError::bad_record},
    };
    for (const auto& c : cases) {
        Fixture f;
        f.session.on_connected();
        auto r = f.session.on_bytes(c.bytes);
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == c.want));
        BOOST_TEST(f.sink.envelopes.empty());
        BOOST_TEST(f.sink.updates.empty());
    }
}

BOOST_FIXTURE_TEST_CASE(bytes_without_a_connection_are_refused, Fixture) {
    auto r = session.on_bytes(envelope_record(server, 1));
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error() == LinkError::not_connected));
    BOOST_TEST(sink.envelopes.empty());
}

BOOST_FIXTURE_TEST_CASE(a_new_connection_starts_a_fresh_stream, Fixture) {
    session.on_connected();
    const auto env = envelope_record(server, 1);
    // Half a record, then the connection drops.
    BOOST_TEST(session.on_bytes(std::span{env}.first(10)).has_value());
    session.on_disconnected();
    session.on_connected();
    BOOST_TEST(session.on_bytes(env).has_value());
    BOOST_TEST(sink.envelopes.size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(pending_reports_are_bounded, Fixture) {
    for (std::size_t i = 0; i < helm::max_pending_reports + 5; ++i) {
        (void)session.report(exited(i + 1));
    }
    BOOST_TEST(session.pending_reports() == helm::max_pending_reports);
    BOOST_TEST(session.dropped_reports() == 5U);
    session.on_connected();
    const auto recs = records(session.take_outbound());
    BOOST_REQUIRE(recs.size() == helm::max_pending_reports + 2);
    BOOST_TEST(as_report(recs[1]).report_seq == 6U);  // the oldest five went
}

BOOST_FIXTURE_TEST_CASE(invalid_reports_are_dropped_not_sent, Fixture) {
    session.on_connected();
    (void)session.take_outbound();
    (void)session.report(proto::VmExitedReport{});  // vm_id 0
    BOOST_TEST(session.take_outbound().empty());
    BOOST_TEST(session.dropped_reports() == 1U);
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {LinkError::bad_record, LinkError::wrong_direction, LinkError::wrong_server,
                   LinkError::bad_ack, LinkError::not_connected}) {
        BOOST_TEST(std::string_view{helm::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
