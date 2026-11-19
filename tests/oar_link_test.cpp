// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 5 and 7: OarLink and
// OarEndpoint over both bindings (InProcessBinding, SocketBinding), with
// timeouts, stale responses, noise on the segment, and chunked map updates.

#define BOOST_TEST_MODULE oar_link_test
#include <boost/test/unit_test.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "helm/oar_link.hpp"
#include "test_support.hpp"

namespace ak::helm {

struct ScopedKeyTestAccess {
    static auto make(std::span<const std::byte, volume_key_size> key) -> ScopedKey {
        return ScopedKey{key};
    }
};

}  // namespace ak::helm

namespace mctp = ak::helm::mctp;
namespace oar = ak::helm::oar;
using ak::helm::Binding;
using ak::helm::BindingError;
using ak::helm::CleaningAction;
using ak::helm::FunctionType;
using ak::helm::InProcessBinding;
using ak::helm::LinkAddress;
using ak::helm::LinkConfig;
using ak::helm::LinkErrc;
using ak::helm::OarEndpoint;
using ak::helm::OarHandler;
using ak::helm::OarLink;
using ak::helm::ScopedKey;
using ak::helm::ScopedKeyTestAccess;
using ak::helm::SocketBinding;
using ak::helm::SocketListener;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using namespace std::chrono_literals;

namespace {

constexpr LinkAddress helm_side{
    .local_addr = 0x08, .peer_addr = 0x10, .local_eid = 0x08, .peer_eid = 0x09};
constexpr std::uint8_t stranger_addr = 0x11;

constexpr auto short_timeout = 50ms;
constexpr auto long_timeout = 5s;
constexpr auto serve_poll = 10ms;

constexpr oar::FunctionNumber sample_fn = 3;
constexpr ak::helm::VmId sample_vm = 42;
constexpr ak::helm::VolumeId sample_volume = 77;
constexpr std::uint8_t key_fill = 0x5C;
constexpr std::uint16_t sample_fault = 12;
constexpr std::uint32_t sample_uptime = 3600;
constexpr std::size_t multi_chunk_frame = 10'000;  // three chunks
constexpr std::size_t big_mtu = mctp::max_packet_payload;
constexpr std::size_t tiny_capacity = 2;
constexpr std::size_t oversized_datagram = mctp::max_packet_size + 10;

auto config(std::chrono::milliseconds timeout = long_timeout, std::size_t mtu = mctp::baseline_mtu)
    -> LinkConfig {
    return {.address = helm_side, .mtu = mtu, .timeout = timeout};
}

auto oar_config(std::size_t mtu = mctp::baseline_mtu) -> LinkConfig {
    return {.address = helm_side.reversed(), .mtu = mtu, .timeout = long_timeout};
}

auto sample_key() -> std::array<std::byte, ak::helm::volume_key_size> {
    std::array<std::byte, ak::helm::volume_key_size> k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        k.at(i) = static_cast<std::byte>(key_fill ^ i);
    }
    return k;
}

auto pattern(std::size_t n) -> std::vector<std::byte> {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::byte>((i * 7) & 0xFF);
    }
    return v;
}

// A data-plane role that records what it was asked and answers with
// `status` (ok unless a test changes it).
class FakeOar final : public OarHandler {
public:
    oar::Status status{oar::Status::ok};
    std::optional<oar::PrepareFunction> prepared;
    std::optional<oar::CleanFunction> cleaned;
    std::optional<oar::DropKey> dropped;
    std::vector<std::byte> key;
    ak::helm::VolumeId key_volume{0};
    std::vector<std::vector<std::byte>> frames;

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        if (status != oar::Status::ok) {
            return std::unexpected(status);
        }
        return oar::Inventory{.role = oar::Role::blk,
                              .vtep = {},
                              .functions = {{.fn = 0, .type = FunctionType::blk_fn},
                                            {.fn = sample_fn, .type = FunctionType::blk_fn}}};
    }
    auto prepare_function(const oar::PrepareFunction& r) -> oar::Status override {
        prepared = r;
        return status;
    }
    auto clean_function(const oar::CleanFunction& r) -> oar::Status override {
        cleaned = r;
        return status;
    }
    auto deliver_key(const oar::DeliverKey& r) -> oar::Status override {
        key.assign(r.key.begin(), r.key.end());
        key_volume = r.volume_id;
        return status;
    }
    auto drop_key(const oar::DropKey& r) -> oar::Status override {
        dropped = r;
        return status;
    }
    auto map_update(std::span<const std::byte> frame) -> oar::Status override {
        frames.emplace_back(frame.begin(), frame.end());
        return status;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override {
        if (status != oar::Status::ok) {
            return std::unexpected(status);
        }
        return oar::Health{.state = oar::HealthState::degraded,
                           .fault_code = sample_fault,
                           .uptime_seconds = sample_uptime};
    }
};

// Serves `endpoint` on a thread until stopped or the peer disconnects.
class Server {
public:
    Server(OarEndpoint& endpoint, OarHandler& handler)
        : _thread{[&endpoint, &handler](const std::stop_token& stop) {
              while (!stop.stop_requested()) {
                  auto r = endpoint.serve_one(handler, serve_poll);
                  if (!r && r.error() != BindingError::timed_out) {
                      return;
                  }
              }
          }} {}

private:
    std::jthread _thread;
};

// Every operation once, against a FakeOar; the role's view is checked after
// the server stops so there is no race on the handler.
auto exercise(Binding& helm_binding, Binding& oar_binding, std::size_t mtu) -> void {
    FakeOar fake;
    OarEndpoint endpoint{oar_binding, oar_config(mtu)};
    OarLink link{helm_binding, config(long_timeout, mtu)};
    const auto key = sample_key();
    const auto frame = pattern(multi_chunk_frame);
    const oar::PrepareFunction prep{.fn = sample_fn,
                                    .type = FunctionType::blk_fn,
                                    .vm_id = sample_vm,
                                    .config = oar::BlkConfig{.volume_id = sample_volume}};
    {
        const Server server{endpoint, fake};

        auto inv = link.function_inventory();
        BOOST_REQUIRE(inv.has_value());
        BOOST_TEST((inv->role == oar::Role::blk));
        BOOST_TEST(inv->functions.size() == 2U);

        BOOST_TEST(link.prepare_function(prep).has_value());
        BOOST_TEST(
            link.deliver_key(sample_fn, sample_volume, ScopedKeyTestAccess::make(key)).has_value());
        BOOST_TEST(link.drop_key({.fn = sample_fn, .volume_id = sample_volume}).has_value());
        BOOST_TEST(link.clean_function({.fn = sample_fn, .action = CleaningAction::drop_volume_key})
                       .has_value());
        BOOST_TEST(link.map_update(frame).has_value());

        auto h = link.health();
        BOOST_REQUIRE(h.has_value());
        BOOST_TEST(h->fault_code == sample_fault);
        BOOST_TEST(h->uptime_seconds == sample_uptime);
    }
    BOOST_TEST((fake.prepared == prep));
    BOOST_TEST(std::ranges::equal(fake.key, key));
    BOOST_TEST(fake.key_volume == sample_volume);
    BOOST_TEST(fake.dropped.has_value());
    BOOST_TEST((fake.cleaned->action == CleaningAction::drop_volume_key));
    BOOST_REQUIRE(fake.frames.size() == 1U);
    BOOST_TEST((fake.frames[0] == frame));
    BOOST_TEST(link.stats().dropped_packets == 0U);
    BOOST_TEST(link.stats().dropped_messages == 0U);
}

// Sends one request message from helm's side by hand, for bodies OarLink
// would refuse to encode.
auto send_raw_request(Binding& b, mctp::VendorType type, std::span<const std::byte> body,
                      std::uint8_t tag) -> void {
    auto msg = mctp::encode_vendor({.type = type, .response = false}, body).value();
    const mctp::Route route{.dest_addr = helm_side.peer_addr,
                            .src_addr = helm_side.local_addr,
                            .dest_eid = helm_side.peer_eid,
                            .src_eid = helm_side.local_eid,
                            .tag_owner = true,
                            .tag = tag};
    const auto packets = mctp::fragment(route, msg).value();
    for (const auto& p : packets) {
        BOOST_REQUIRE(b.send(p).has_value());
    }
}

// Serves packets until one completes and answers a request.
auto serve_request(OarEndpoint& endpoint, OarHandler& handler) -> void {
    for (;;) {
        auto r = endpoint.serve_one(handler, long_timeout);
        BOOST_REQUIRE(r.has_value());
        if (*r) {
            return;
        }
    }
}

// Reads one single-packet response on helm's side and returns its status.
auto read_raw_status(Binding& b) -> oar::Status {
    auto raw = b.receive(long_timeout).value();
    auto packet = mctp::decode_packet(raw).value();
    auto vendor = mctp::decode_vendor(packet.payload()).value();
    BOOST_TEST(vendor.header.response);
    return oar::decode_response(vendor.body).value().status;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(oar_link, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(every_operation_in_process) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    exercise(*helm_b, *oar_b, mctp::baseline_mtu);
}

BOOST_AUTO_TEST_CASE(every_operation_over_socketpair) {
    auto pair = SocketBinding::make_pair();
    BOOST_REQUIRE(pair.has_value());
    exercise(*pair->first, *pair->second, mctp::baseline_mtu);
}

BOOST_AUTO_TEST_CASE(every_operation_large_mtu) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    exercise(*helm_b, *oar_b, big_mtu);
}

BOOST_AUTO_TEST_CASE(refusal_carries_status) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    fake.status = oar::Status::busy;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const Server server{endpoint, fake};

    auto r = link.drop_key({.fn = 1, .volume_id = sample_volume});
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error().code == LinkErrc::refused));
    BOOST_TEST((r.error().status == oar::Status::busy));
    auto inv = link.function_inventory();
    BOOST_TEST((inv.error().status == oar::Status::busy));
    auto h = link.health();
    BOOST_TEST((h.error().status == oar::Status::busy));
}

BOOST_AUTO_TEST_CASE(invalid_arguments_never_reach_the_wire) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    OarLink link{*helm_b, config(short_timeout)};
    BOOST_TEST((link.drop_key({.fn = 1, .volume_id = 0}).error().code == LinkErrc::bad_request));
    BOOST_TEST((link.map_update({}).error().code == LinkErrc::bad_request));
    const std::vector<std::byte> too_big(oar::max_map_frame + 1);
    BOOST_TEST((link.map_update(too_big).error().code == LinkErrc::bad_request));

    // A moved-from key holds nothing to deliver. Using it after the move is
    // the point of the check.
    auto key = ScopedKeyTestAccess::make(sample_key());
    auto taken = std::move(key);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    BOOST_TEST(!key.holds_key());
    BOOST_TEST(
        (link.deliver_key(1, sample_volume, std::move(key)).error().code == LinkErrc::bad_request));
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    BOOST_TEST((oar_b->receive(0ms).error() == BindingError::timed_out));
}

BOOST_AUTO_TEST_CASE(no_answer_times_out) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    OarLink link{*helm_b, config(short_timeout)};
    const auto start = std::chrono::steady_clock::now();
    BOOST_TEST((link.health().error().code == LinkErrc::timed_out));
    BOOST_TEST((std::chrono::steady_clock::now() - start >= short_timeout));
}

BOOST_AUTO_TEST_CASE(late_answer_is_not_taken_for_the_next) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config(short_timeout)};

    // Nobody serving: the drop_key request waits in the queue and times out.
    BOOST_TEST(
        (link.drop_key({.fn = 1, .volume_id = sample_volume}).error().code == LinkErrc::timed_out));
    // The role now answers it late, then answers health. health must see its
    // own answer, not drop_key's.
    {
        const Server server{endpoint, fake};
        auto h = link.health();
        BOOST_REQUIRE(h.has_value());
        BOOST_TEST(h->uptime_seconds == sample_uptime);
    }
    BOOST_TEST(link.stats().dropped_messages == 1U);
}

BOOST_AUTO_TEST_CASE(noise_on_the_segment_is_dropped) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    // Before the role starts, put junk in helm's receive queue: garbage, a
    // packet with a bad PEC, and a well-formed packet from another address.
    BOOST_REQUIRE(oar_b->send(bytes_of(1, 2, 3)).has_value());
    const mctp::TransportHeader h{.dest_eid = helm_side.local_eid,
                                  .src_eid = helm_side.peer_eid,
                                  .som = true,
                                  .eom = true,
                                  .seq = 0,
                                  .tag_owner = false,
                                  .tag = 0};
    auto pkt =
        mctp::encode_packet(helm_side.local_addr, helm_side.peer_addr, h, bytes_of(0x7E)).value();
    pkt.back() ^= std::byte{1};
    BOOST_REQUIRE(oar_b->send(pkt).has_value());
    auto stranger =
        mctp::encode_packet(helm_side.local_addr, stranger_addr, h, bytes_of(0x7E)).value();
    BOOST_REQUIRE(oar_b->send(stranger).has_value());

    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    {
        const Server server{endpoint, fake};
        BOOST_TEST(link.health().has_value());
    }
    BOOST_TEST(link.stats().dropped_packets == 3U);
}

BOOST_AUTO_TEST_CASE(endpoint_refuses_malformed_requests) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config()};

    send_raw_request(*helm_b, mctp::VendorType::health, bytes_of(1), 0);
    BOOST_TEST(endpoint.serve_one(fake, long_timeout).value());
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));

    send_raw_request(*helm_b, mctp::VendorType::clean_function, bytes_of(0, 0, 9, 0), 1);
    BOOST_TEST(endpoint.serve_one(fake, long_timeout).value());
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));
    BOOST_TEST(!fake.cleaned.has_value());

    // A response sent to the role is not a request: dropped, not answered.
    auto msg = mctp::encode_vendor({.type = mctp::VendorType::health, .response = true},
                                   oar::encode_response(oar::Status::ok).value())
                   .value();
    const mctp::Route route{.dest_addr = helm_side.peer_addr,
                            .src_addr = helm_side.local_addr,
                            .dest_eid = helm_side.peer_eid,
                            .src_eid = helm_side.local_eid,
                            .tag_owner = true,
                            .tag = 2};
    BOOST_REQUIRE(helm_b->send(mctp::fragment(route, msg).value().front()).has_value());
    BOOST_TEST(!endpoint.serve_one(fake, long_timeout).value());
    BOOST_TEST(endpoint.stats().dropped_messages == 1U);
    BOOST_TEST((helm_b->receive(0ms).error() == BindingError::timed_out));
}

BOOST_AUTO_TEST_CASE(map_transfer_must_be_contiguous) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config(big_mtu)};
    const auto data = pattern(oar::max_map_chunk);
    constexpr std::uint32_t total = oar::max_map_chunk * 2;

    // A continuation with no transfer started.
    auto body = oar::encode_map_chunk({.total = total, .offset = oar::max_map_chunk, .chunk = data})
                    .value();
    send_raw_request(*helm_b, mctp::VendorType::map_update, body, 0);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));

    // First chunk, then a second that claims a different total.
    body = oar::encode_map_chunk({.total = total, .offset = 0, .chunk = data}).value();
    send_raw_request(*helm_b, mctp::VendorType::map_update, body, 1);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::ok));
    body = oar::encode_map_chunk({.total = total + 1, .offset = oar::max_map_chunk, .chunk = data})
               .value();
    send_raw_request(*helm_b, mctp::VendorType::map_update, body, 2);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));
    BOOST_TEST(fake.frames.empty());
}

BOOST_AUTO_TEST_CASE(largest_map_frame) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config(big_mtu)};
    OarLink link{*helm_b, config(long_timeout, big_mtu)};
    const auto frame = pattern(oar::max_map_frame);
    {
        const Server server{endpoint, fake};
        BOOST_TEST(link.map_update(frame).has_value());
    }
    BOOST_REQUIRE(fake.frames.size() == 1U);
    BOOST_TEST((fake.frames[0] == frame));
}

BOOST_AUTO_TEST_CASE(map_apply_failure_is_reported) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    fake.status = oar::Status::failed;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const Server server{endpoint, fake};
    auto r = link.map_update(pattern(multi_chunk_frame));
    BOOST_TEST((r.error().code == LinkErrc::refused));
    BOOST_TEST((r.error().status == oar::Status::failed));
}

BOOST_AUTO_TEST_CASE(peer_gone_is_disconnected) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    OarLink link{*helm_b, config()};
    oar_b.reset();
    BOOST_TEST((link.health().error().code == LinkErrc::disconnected));

    auto pair = SocketBinding::make_pair().value();
    OarLink socket_link{*pair.first, config()};
    pair.second.reset();
    BOOST_TEST((socket_link.health().error().code == LinkErrc::disconnected));
}

BOOST_AUTO_TEST_CASE(peer_closing_mid_wait_is_disconnected) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    OarLink link{*helm_b, config()};
    std::jthread closer{[&oar_b] {
        // Wait for the request, then go away without answering.
        (void)oar_b->receive(long_timeout);
        oar_b.reset();
    }};
    BOOST_TEST((link.health().error().code == LinkErrc::disconnected));
}

BOOST_AUTO_TEST_CASE(in_process_queue_is_bounded) {
    auto [a, b] = InProcessBinding::make_pair(tiny_capacity);
    BOOST_TEST(a->send(bytes_of(1)).has_value());
    BOOST_TEST(a->send(bytes_of(2)).has_value());
    BOOST_TEST((a->send(bytes_of(3)).error() == BindingError::queue_full));
    BOOST_TEST((b->receive(0ms).value() == bytes_of(1)));
    BOOST_TEST(a->send(bytes_of(3)).has_value());
    const std::vector<std::byte> huge(mctp::max_packet_size + 1);
    BOOST_TEST((a->send(huge).error() == BindingError::oversized));
}

BOOST_AUTO_TEST_CASE(socket_drops_oversized_datagrams) {
    auto pair = SocketBinding::make_pair().value();
    const std::vector<std::byte> huge(oversized_datagram, std::byte{1});
    BOOST_REQUIRE(::send(pair.first->fd(), huge.data(), huge.size(), 0) ==
                  static_cast<ssize_t>(huge.size()));
    BOOST_TEST((pair.second->receive(long_timeout).error() == BindingError::oversized));
    BOOST_TEST((pair.first->send(huge).error() == BindingError::oversized));
    // The next datagram arrives intact.
    BOOST_REQUIRE(pair.first->send(bytes_of(9, 8)).has_value());
    BOOST_TEST((pair.second->receive(long_timeout).value() == bytes_of(9, 8)));
    BOOST_TEST((pair.second->receive(0ms).error() == BindingError::timed_out));
}

BOOST_AUTO_TEST_CASE(socket_listener_connects_a_slot) {
    char tmpl[] = "/tmp/ak-oar-link-XXXXXX";
    const char* dir = ::mkdtemp(tmpl);
    BOOST_REQUIRE(dir != nullptr);
    const std::filesystem::path path = std::filesystem::path{dir} / "slot0.sock";
    {
        auto listener = SocketListener::bind(path);
        BOOST_REQUIRE(listener.has_value());
        BOOST_TEST(std::filesystem::is_socket(path));
        // A path that exists is never replaced.
        BOOST_TEST((SocketListener::bind(path).error() == BindingError::io));
        BOOST_TEST(((*listener)->accept(0ms).error() == BindingError::timed_out));

        auto helm_b = SocketBinding::connect(path);
        BOOST_REQUIRE(helm_b.has_value());
        auto oar_b = (*listener)->accept(long_timeout);
        BOOST_REQUIRE(oar_b.has_value());

        FakeOar fake;
        OarEndpoint endpoint{**oar_b, oar_config()};
        OarLink link{**helm_b, config()};
        const Server server{endpoint, fake};
        BOOST_TEST(link.health().has_value());
    }
    BOOST_TEST(!std::filesystem::exists(path));
    BOOST_TEST((SocketBinding::connect(path).error() == BindingError::disconnected));
    std::filesystem::remove(dir);
}

BOOST_AUTO_TEST_CASE(names) {
    BOOST_TEST(std::string_view{ak::helm::to_string(LinkErrc::refused)} == "refused");
    BOOST_TEST(std::string_view{ak::helm::to_string(BindingError::queue_full)} == "queue_full");
    BOOST_TEST(helm_side.reversed().reversed().local_eid == helm_side.local_eid);
}

BOOST_AUTO_TEST_SUITE_END()
