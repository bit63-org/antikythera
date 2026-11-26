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
#include "proto/volume_layout.hpp"
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
constexpr std::uint64_t sample_sectors = 0x20'0000;
constexpr std::size_t wrapped_size = 95;
constexpr std::uint8_t rewrapped_fill = 0x7E;

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
    std::vector<std::vector<std::byte>> peer_frames;
    std::optional<ak::helm::VolumeId> created;
    std::uint64_t created_sectors{0};
    std::vector<std::byte> created_key;
    std::optional<oar::DeleteVolume> deleted;
    ak::helm::VmId rewrapped_owner{0};
    std::vector<std::byte> rewrapped_key;

    auto create_volume(const oar::CreateVolume& r) -> oar::Status override {
        created = r.volume_id;
        created_sectors = r.capacity_sectors;
        created_key.assign(r.wrapped_key.begin(), r.wrapped_key.end());
        return status;
    }
    auto delete_volume(const oar::DeleteVolume& r) -> oar::Status override {
        deleted = r;
        return status;
    }
    auto rewrap_volume(const oar::RewrapVolume& r) -> oar::Status override {
        rewrapped_owner = r.owner_vm;
        rewrapped_key.assign(r.wrapped_key.begin(), r.wrapped_key.end());
        return status;
    }

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
    auto tunnel_peers(std::span<const std::byte> frame) -> oar::Status override {
        peer_frames.emplace_back(frame.begin(), frame.end());
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
    auto peer_frame = pattern(multi_chunk_frame + 1);
    peer_frame[0] = std::byte{0xEE};
    const auto wrapped = pattern(wrapped_size);
    const std::vector<std::byte> rewrapped(wrapped_size, std::byte{rewrapped_fill});
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
        BOOST_TEST(link.tunnel_peers(peer_frame).has_value());
        BOOST_TEST(link.create_volume({.volume_id = sample_volume,
                                       .owner_vm = sample_vm,
                                       .capacity_sectors = sample_sectors,
                                       .block_size = oar::sector_size,
                                       .wrapped_key = wrapped})
                       .has_value());
        BOOST_TEST(link.rewrap_volume({.volume_id = sample_volume,
                                       .owner_vm = sample_vm + 1,
                                       .wrapped_key = rewrapped})
                       .has_value());
        BOOST_TEST(link.delete_volume({.volume_id = sample_volume}).has_value());

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
    BOOST_REQUIRE(fake.peer_frames.size() == 1U);
    BOOST_TEST((fake.peer_frames[0] == peer_frame));
    BOOST_TEST((fake.created == sample_volume));
    BOOST_TEST(fake.created_sectors == sample_sectors);
    BOOST_TEST((fake.created_key == wrapped));
    BOOST_TEST(fake.rewrapped_owner == sample_vm + 1);
    BOOST_TEST((fake.rewrapped_key == rewrapped));
    BOOST_TEST(fake.deleted->volume_id == sample_volume);
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
    BOOST_TEST((link.tunnel_peers({}).error().code == LinkErrc::bad_request));
    const std::vector<std::byte> too_many_peers(oar::max_tunnel_peers_frame + 1);
    BOOST_TEST((link.tunnel_peers(too_many_peers).error().code == LinkErrc::bad_request));

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

BOOST_AUTO_TEST_CASE(roles_without_a_volume_store_answer_unsupported) {
    // A handler that keeps the defaults (any role but storage).
    class NoStore final : public OarHandler {
    public:
        auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
            return std::unexpected(oar::Status::failed);
        }
        auto prepare_function(const oar::PrepareFunction&) -> oar::Status override {
            return oar::Status::ok;
        }
        auto clean_function(const oar::CleanFunction&) -> oar::Status override {
            return oar::Status::ok;
        }
        auto deliver_key(const oar::DeliverKey&) -> oar::Status override { return oar::Status::ok; }
        auto drop_key(const oar::DropKey&) -> oar::Status override { return oar::Status::ok; }
        auto map_update(std::span<const std::byte>) -> oar::Status override {
            return oar::Status::ok;
        }
        auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    };
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    NoStore role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    const auto body = oar::encode_delete_volume({.volume_id = sample_volume}).value();
    send_raw_request(*helm_b, mctp::VendorType::delete_volume, body, 0);
    serve_request(endpoint, role);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::unsupported));
    // Nor does it hold tunnel keys (only the network role does).
    std::array<std::byte, oar::set_tunnel_peer_size> peer{};
    peer.fill(std::byte{1});
    send_raw_request(*helm_b, mctp::VendorType::set_tunnel_peer, peer, 2);
    serve_request(endpoint, role);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::unsupported));
    send_raw_request(*helm_b, mctp::VendorType::set_tunnel_key,
                     std::span{peer}.first(oar::set_tunnel_key_size), 3);
    serve_request(endpoint, role);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::unsupported));
    send_raw_request(*helm_b, mctp::VendorType::remove_tunnel_peer,
                     std::span{peer}.first(oar::remove_tunnel_peer_size), 4);
    serve_request(endpoint, role);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::unsupported));
    const auto peers_body =
        oar::encode_map_chunk({.total = 3, .offset = 0, .chunk = std::span{peer}.first(3)}).value();
    send_raw_request(*helm_b, mctp::VendorType::tunnel_peers, peers_body, 5);
    serve_request(endpoint, role);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::unsupported));

    // A malformed volume body never reaches the handler.
    FakeOar fake;
    send_raw_request(*helm_b, mctp::VendorType::create_volume, bytes_of(1, 2, 3), 1);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));
    BOOST_TEST(!fake.created.has_value());
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

// A map_update transfer and a tunnel_peers transfer share the endpoint's
// reassembly buffer: a chunk of one type never continues the other.
BOOST_AUTO_TEST_CASE(frame_transfers_do_not_mix) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config(big_mtu)};
    const auto data = pattern(oar::max_map_chunk);
    constexpr std::uint32_t total = oar::max_map_chunk * 2;

    auto body = oar::encode_map_chunk({.total = total, .offset = 0, .chunk = data}).value();
    send_raw_request(*helm_b, mctp::VendorType::map_update, body, 0);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::ok));
    body = oar::encode_map_chunk({.total = total, .offset = oar::max_map_chunk, .chunk = data})
               .value();
    send_raw_request(*helm_b, mctp::VendorType::tunnel_peers, body, 1);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));
    BOOST_TEST(fake.frames.empty());
    BOOST_TEST(fake.peer_frames.empty());

    // A tunnel_peers transfer may not announce more than its own limit,
    // even though a MapUpdate of that size would be fine.
    body =
        oar::encode_map_chunk({.total = static_cast<std::uint32_t>(oar::max_tunnel_peers_frame + 1),
                               .offset = 0,
                               .chunk = data})
            .value();
    send_raw_request(*helm_b, mctp::VendorType::tunnel_peers, body, 2);
    serve_request(endpoint, fake);
    BOOST_TEST((read_raw_status(*helm_b) == oar::Status::bad_request));
    BOOST_TEST(fake.peer_frames.empty());
}

BOOST_AUTO_TEST_CASE(largest_tunnel_peers_frame) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint endpoint{*oar_b, oar_config(big_mtu)};
    OarLink link{*helm_b, config(long_timeout, big_mtu)};
    const auto frame = pattern(oar::max_tunnel_peers_frame);
    {
        const Server server{endpoint, fake};
        BOOST_TEST(link.tunnel_peers(frame).has_value());
    }
    BOOST_REQUIRE(fake.peer_frames.size() == 1U);
    BOOST_TEST((fake.peer_frames[0] == frame));
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

// A network role's group policy and meters (oar-net Requirement 10).
class MeterRole final : public OarHandler {
public:
    std::vector<std::vector<std::byte>> policies;
    std::vector<oar::UsageEntry> attached;
    std::vector<oar::UsageEntry> retired;  // returned by the next snapshot only
    int snapshots{0};

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return std::unexpected(oar::Status::failed);
    }
    auto prepare_function(const oar::PrepareFunction&) -> oar::Status override {
        return oar::Status::ok;
    }
    auto clean_function(const oar::CleanFunction&) -> oar::Status override {
        return oar::Status::ok;
    }
    auto deliver_key(const oar::DeliverKey&) -> oar::Status override { return oar::Status::ok; }
    auto drop_key(const oar::DropKey&) -> oar::Status override { return oar::Status::ok; }
    auto map_update(std::span<const std::byte>) -> oar::Status override { return oar::Status::ok; }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto group_policy(std::span<const std::byte> frame) -> oar::Status override {
        policies.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    std::vector<std::vector<std::byte>> vpc_configs;
    auto vpc_config(std::span<const std::byte> frame) -> oar::Status override {
        vpc_configs.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    auto group_usage(std::uint16_t cursor) -> std::expected<oar::UsagePage, oar::Status> override {
        return _pager.page(cursor, [this] {
            ++snapshots;
            auto all = attached;
            all.insert(all.end(), retired.begin(), retired.end());
            retired.clear();
            return all;
        });
    }
    std::vector<std::vector<std::byte>> records;
    auto instance_metadata(std::span<const std::byte> frame) -> oar::Status override {
        records.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    std::vector<std::vector<std::byte>> layouts;
    auto volume_layout(std::span<const std::byte> frame) -> oar::Status override {
        layouts.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    std::vector<std::vector<std::byte>> members;
    auto group_members(std::span<const std::byte> frame) -> oar::Status override {
        members.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    std::vector<oar::MembershipEntry> joins;
    std::uint32_t generation{0};
    int membership_snapshots{0};
    bool torn{false};  // later pages claim another generation
    auto group_membership(const oar::MembershipRequest& request)
        -> std::expected<oar::MembershipPage, oar::Status> override {
        auto page = _memberships.page(request, generation, [this] {
            ++membership_snapshots;
            return joins;
        });
        if (page && torn && request.cursor != 0) {
            ++page->generation;
        }
        return page;
    }

private:
    oar::UsagePager _pager;
    oar::MembershipPager _memberships;
};

auto meter(std::uint64_t nic, std::uint64_t attachment, bool detached = false) -> oar::UsageEntry {
    return {.nic_id = nic,
            .vni = 5,
            .detached = detached,
            .attachment = attachment,
            .frames = nic,
            .bytes = nic * 100,
            .replicas_remote = nic * 2,
            .replica_bytes_remote = nic * 200};
}

BOOST_AUTO_TEST_CASE(group_usage_reads_every_page) {
    constexpr std::uint64_t nics = 100;  // three pages
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    for (std::uint64_t n = nics; n >= 1; --n) {  // any order; the pager sorts
        role.attached.push_back(meter(n, n));
    }
    role.retired.push_back(meter(nics + 1, 1, true));
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    std::vector<oar::UsageEntry> first;
    std::vector<oar::UsageEntry> second;
    {
        const Server server{endpoint, role};
        auto got = link.group_usage();
        BOOST_REQUIRE(got.has_value());
        first = *got;
        got = link.group_usage();
        BOOST_REQUIRE(got.has_value());
        second = *got;
    }
    BOOST_REQUIRE(first.size() == nics + 1);
    BOOST_TEST(first.front().nic_id == 1U);
    BOOST_TEST(first.back().detached);
    BOOST_TEST((first[41] == meter(42, 42)));
    BOOST_TEST(second.size() == nics);  // the final reading was delivered once
    BOOST_TEST(role.snapshots == 2);
}

BOOST_AUTO_TEST_CASE(group_policy_is_forwarded_whole) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    // Version 1, and the largest version 2 frame, which takes several
    // chunks (vpc-subnets-routing task 12).
    const auto frame = pattern(oar::group_policy_frame_size);
    const auto largest = pattern(oar::max_group_policy_frame);
    BOOST_REQUIRE(largest.size() > oar::max_map_chunk);
    {
        const Server server{endpoint, role};
        BOOST_TEST(link.group_policy(frame).has_value());
        BOOST_TEST(link.group_policy(largest).has_value());
        BOOST_TEST(link.group_policy(pattern(oar::min_group_policy_v2_frame)).has_value());
        // Any other length never reaches the wire.
        for (const std::size_t bad : {std::size_t{10}, oar::min_group_policy_v2_frame - 1,
                                      oar::max_group_policy_frame + 1}) {
            BOOST_TEST((link.group_policy(pattern(bad)).error().code == LinkErrc::bad_request));
        }
    }
    BOOST_REQUIRE(role.policies.size() == 3U);
    BOOST_TEST(role.policies[0] == frame);
    BOOST_TEST(role.policies[1] == largest);
}

BOOST_AUTO_TEST_CASE(group_members_are_forwarded_in_chunks) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto small = pattern(200);
    const auto largest = pattern(oar::max_group_members_frame);  // about 19 chunks
    {
        const Server server{endpoint, role};
        BOOST_TEST(link.group_members(small).has_value());
        BOOST_TEST(link.group_members(largest).has_value());
        // Empty or too large never reaches the wire.
        BOOST_TEST((link.group_members({}).error().code == LinkErrc::bad_request));
        BOOST_TEST((link.group_members(pattern(oar::max_group_members_frame + 1)).error().code ==
                    LinkErrc::bad_request));
    }
    BOOST_REQUIRE(role.members.size() == 2U);
    BOOST_TEST(role.members[0] == small);
    BOOST_TEST(role.members[1] == largest);
}

// kythira khold-block-service Requirement 11.5: helm relays a khold
// volume's layout to the blk role byte for byte.
BOOST_AUTO_TEST_CASE(volume_layouts_are_forwarded_in_chunks) {
    static_assert(oar::max_volume_layout_frame == ak::proto::max_volume_layout_size);
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto small = pattern(300);
    const auto largest = pattern(oar::max_volume_layout_frame);
    {
        const Server server{endpoint, role};
        BOOST_TEST(link.volume_layout(small).has_value());
        BOOST_TEST(link.volume_layout(largest).has_value());
        BOOST_TEST((link.volume_layout({}).error().code == LinkErrc::bad_request));
        BOOST_TEST((link.volume_layout(pattern(oar::max_volume_layout_frame + 1)).error().code ==
                    LinkErrc::bad_request));
    }
    BOOST_REQUIRE(role.layouts.size() == 2U);
    BOOST_TEST(role.layouts[0] == small);
    BOOST_TEST(role.layouts[1] == largest);

    auto [helm_c, oar_c] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint other{*oar_c, oar_config()};
    OarLink other_link{*helm_c, config()};
    const Server server{other, fake};
    const auto refused = other_link.volume_layout(small);
    BOOST_REQUIRE(!refused.has_value());
    BOOST_TEST((refused.error().status == oar::Status::unsupported));
}

BOOST_AUTO_TEST_CASE(instance_metadata_is_forwarded_in_chunks) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto small = pattern(300);
    const auto largest = pattern(oar::max_instance_metadata_frame);  // five chunks
    {
        const Server server{endpoint, role};
        BOOST_TEST(link.instance_metadata(small).has_value());
        BOOST_TEST(link.instance_metadata(largest).has_value());
        BOOST_TEST((link.instance_metadata({}).error().code == LinkErrc::bad_request));
        BOOST_TEST(
            (link.instance_metadata(pattern(oar::max_instance_metadata_frame + 1)).error().code ==
             LinkErrc::bad_request));
    }
    BOOST_REQUIRE(role.records.size() == 2U);
    BOOST_TEST(role.records[0] == small);
    BOOST_TEST(role.records[1] == largest);

    // A role that keeps no records (the default) answers unsupported.
    auto [helm_c, oar_c] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint other{*oar_c, oar_config()};
    OarLink other_link{*helm_c, config()};
    const Server server{other, fake};
    const auto refused = other_link.instance_metadata(small);
    BOOST_REQUIRE(!refused.has_value());
    BOOST_TEST((refused.error().status == oar::Status::unsupported));
}

namespace {

auto joined(std::uint64_t nic, std::uint8_t last) -> oar::MembershipEntry {
    oar::MembershipEntry e{.nic_id = nic, .vni = 5, .ipv6 = false, .group = {}};
    e.group[0] = std::byte{239};
    e.group[3] = std::byte{last};
    return e;
}

}  // namespace

BOOST_AUTO_TEST_CASE(group_membership_reads_on_change_only) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    for (std::uint64_t n = 1; n <= 300; ++n) {  // three pages
        role.joins.push_back(joined(n, 1));
    }
    role.generation = 7;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const Server server{endpoint, role};

    auto read = link.group_membership(std::nullopt);
    BOOST_REQUIRE(read.has_value());
    BOOST_REQUIRE(read->has_value());
    BOOST_TEST((*read)->generation == 7U);
    BOOST_REQUIRE((*read)->entries.size() == 300U);
    BOOST_TEST(((*read)->entries[150] == joined(151, 1)));
    BOOST_TEST(role.membership_snapshots == 1);

    // The same generation: one small answer, no snapshot.
    read = link.group_membership(7);
    BOOST_REQUIRE(read.has_value());
    BOOST_TEST(!read->has_value());
    BOOST_TEST(role.membership_snapshots == 1);

    // A change is read whole; an empty list is a list.
    role.joins.clear();
    role.generation = 8;
    read = link.group_membership(7);
    BOOST_REQUIRE(read.has_value());
    BOOST_REQUIRE(read->has_value());
    BOOST_TEST((*read)->generation == 8U);
    BOOST_TEST((*read)->entries.empty());

    // Pages from different snapshots are refused.
    for (std::uint64_t n = 1; n <= 200; ++n) {
        role.joins.push_back(joined(n, 2));
    }
    role.generation = 9;
    role.torn = true;
    read = link.group_membership(8);
    BOOST_REQUIRE(!read.has_value());
    BOOST_TEST((read.error().code == LinkErrc::bad_response));
}

BOOST_AUTO_TEST_CASE(vpc_config_is_forwarded_whole_in_chunks) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    MeterRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto smallest = pattern(oar::min_vpc_config_frame);
    const auto largest = pattern(oar::max_vpc_config_frame);  // 35 chunks
    {
        const Server server{endpoint, role};
        BOOST_TEST(link.vpc_config(smallest).has_value());
        BOOST_TEST(link.vpc_config(largest).has_value());
        // Out of range never reaches the wire.
        BOOST_TEST(
            (link.vpc_config(std::span{smallest}.first(10)).error().code == LinkErrc::bad_request));
        BOOST_TEST((link.vpc_config(pattern(oar::max_vpc_config_frame + 1)).error().code ==
                    LinkErrc::bad_request));
    }
    BOOST_REQUIRE(role.vpc_configs.size() == 2U);
    BOOST_TEST(role.vpc_configs[0] == smallest);
    BOOST_TEST(role.vpc_configs[1] == largest);

    // A role that keeps no gateway (the default) answers unsupported.
    auto [helm_c, oar_c] = InProcessBinding::make_pair();
    FakeOar fake;
    OarEndpoint other{*oar_c, oar_config()};
    OarLink other_link{*helm_c, config()};
    const Server server{other, fake};
    const auto refused = other_link.vpc_config(smallest);
    BOOST_REQUIRE(!refused.has_value());
    BOOST_TEST((refused.error().status == oar::Status::unsupported));
}

BOOST_AUTO_TEST_CASE(roles_without_group_meters_answer_unsupported) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;  // keeps the defaults
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const Server server{endpoint, fake};
    const auto policy = link.group_policy(pattern(oar::group_policy_frame_size));
    BOOST_REQUIRE(!policy.has_value());
    BOOST_TEST((policy.error().status == oar::Status::unsupported));
    const auto usage = link.group_usage();
    BOOST_REQUIRE(!usage.has_value());
    BOOST_TEST((usage.error().status == oar::Status::unsupported));
    const auto members = link.group_members(pattern(100));
    BOOST_REQUIRE(!members.has_value());
    BOOST_TEST((members.error().status == oar::Status::unsupported));
    const auto joins = link.group_membership(std::nullopt);
    BOOST_REQUIRE(!joins.has_value());
    BOOST_TEST((joins.error().status == oar::Status::unsupported));
}

// A hold role: configs, ops and lease grants in, reports out.
class HoldRole final : public OarHandler {
public:
    std::vector<std::vector<std::byte>> configs;
    std::vector<std::vector<std::byte>> ops;
    std::vector<oar::LeaseGrant> grants;
    oar::ReportQueue reports;

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return oar::Inventory{.role = oar::Role::hold, .vtep = {}, .functions = {}};
    }
    auto prepare_function(const oar::PrepareFunction&) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto clean_function(const oar::CleanFunction&) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto deliver_key(const oar::DeliverKey&) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto drop_key(const oar::DropKey&) -> oar::Status override { return oar::Status::unsupported; }
    auto map_update(std::span<const std::byte>) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto replica_config(std::span<const std::byte> frame) -> oar::Status override {
        configs.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    auto volume_op(std::span<const std::byte> frame) -> oar::Status override {
        ops.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    auto lease_grant(const oar::LeaseGrant& g) -> oar::Status override {
        grants.push_back(g);
        return oar::Status::ok;
    }
    auto hold_reports(const oar::ReportRequest& r)
        -> std::expected<oar::ReportChunk, oar::Status> override {
        return reports.serve(r);
    }
    std::vector<std::byte> csr;
    std::vector<std::vector<std::byte>> chains;
    oar::Status install = oar::Status::ok;
    auto cert_request() -> std::expected<oar::CertAnswer, oar::Status> override {
        return oar::CertAnswer{.role = oar::Role::hold, .csr = csr};
    }
    auto role_certificate(std::span<const std::byte> chain) -> oar::Status override {
        chains.emplace_back(chain.begin(), chain.end());
        return install;
    }
};

BOOST_AUTO_TEST_CASE(hold_role_takes_configs_ops_and_grants) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    HoldRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto config_frame = pattern(oar::max_replica_config_frame);
    const auto op_frame = pattern(oar::volume_op_frame_size);
    {
        const Server server{endpoint, role};
        BOOST_TEST((link.function_inventory().value().role == oar::Role::hold));
        BOOST_TEST(link.replica_config(config_frame).has_value());
        BOOST_TEST(link.volume_op(op_frame).has_value());
        BOOST_TEST(link.lease_grant({.volume_id = 7, .epoch = 3}).has_value());
        BOOST_TEST((link.replica_config(std::span{config_frame}.first(10)).error().code ==
                    LinkErrc::bad_request));
        BOOST_TEST(
            (link.lease_grant({.volume_id = 7, .epoch = 0}).error().code == LinkErrc::bad_request));
    }
    BOOST_REQUIRE(role.configs.size() == 1U);
    BOOST_TEST(role.configs[0] == config_frame);
    BOOST_REQUIRE(role.ops.size() == 1U);
    BOOST_TEST(role.ops[0] == op_frame);
    BOOST_REQUIRE(role.grants.size() == 1U);
    BOOST_TEST((role.grants[0] == oar::LeaseGrant{.volume_id = 7, .epoch = 3}));
}

BOOST_AUTO_TEST_CASE(hold_reports_arrive_whole_and_once) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    HoldRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto big = pattern(3 * oar::max_report_chunk + 7);  // four chunks
    const auto small = pattern(40);
    BOOST_REQUIRE(role.reports.push(1000, big));
    BOOST_REQUIRE(role.reports.push(1001, small));
    BOOST_REQUIRE(role.reports.push(1002, small));
    {
        const Server server{endpoint, role};
        auto got = link.hold_reports(2);
        BOOST_REQUIRE(got.has_value());
        BOOST_REQUIRE(got->size() == 2U);
        BOOST_TEST((*got)[0] == big);
        BOOST_TEST((*got)[1] == small);
        got = link.hold_reports(8);  // acknowledges 1001, then takes 1002
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(got->size() == 1U);
        got = link.hold_reports(8);
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(got->empty());
    }
    BOOST_TEST(role.reports.size() == 0U);
}

BOOST_AUTO_TEST_CASE(enrollment_requests_and_certificates_cross_whole) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    HoldRole role;
    role.csr = pattern(oar::max_csr);
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const auto chain = pattern(oar::max_cert_chain);  // five chunks
    {
        const Server server{endpoint, role};
        auto asked = link.cert_request();
        BOOST_REQUIRE(asked.has_value());
        BOOST_TEST((asked->role == oar::Role::hold));
        BOOST_TEST(asked->csr == role.csr);
        BOOST_TEST(link.role_certificate(chain).has_value());
        BOOST_TEST(
            (link.role_certificate({}).error().code == LinkErrc::bad_request));  // never sent
        BOOST_TEST((link.role_certificate(pattern(oar::max_cert_chain + 1)).error().code ==
                    LinkErrc::bad_request));
    }
    BOOST_REQUIRE(role.chains.size() == 1U);
    BOOST_TEST(role.chains[0] == chain);

    // Nothing wanted, and a refused chain.
    role.csr.clear();
    role.install = oar::Status::failed;
    {
        const Server server{endpoint, role};
        auto asked = link.cert_request();
        BOOST_REQUIRE(asked.has_value());
        BOOST_TEST(asked->csr.empty());
        BOOST_TEST((link.role_certificate(pattern(10)).error().status == oar::Status::failed));
    }
}

BOOST_AUTO_TEST_CASE(roles_without_replicas_answer_unsupported) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    FakeOar fake;  // keeps the defaults
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const Server server{endpoint, fake};
    BOOST_TEST((link.replica_config(pattern(oar::min_replica_config_frame)).error().status ==
                oar::Status::unsupported));
    BOOST_TEST((link.volume_op(pattern(oar::volume_op_frame_size)).error().status ==
                oar::Status::unsupported));
    BOOST_TEST((link.lease_grant({.volume_id = 1, .epoch = 1}).error().status ==
                oar::Status::unsupported));
    BOOST_TEST((link.hold_reports(1).error().status == oar::Status::unsupported));
    BOOST_TEST((link.cert_request().error().status == oar::Status::unsupported));
    BOOST_TEST((link.role_certificate(pattern(10)).error().status == oar::Status::unsupported));
    BOOST_TEST((link.eject({.fn = 0, .op = oar::EjectOp::query}).error().status ==
                oar::Status::unsupported));
    BOOST_TEST((link.copy_volume({.op = oar::CopyOp::query,
                                  .direction = oar::CopyDirection::to_network,
                                  .mib_per_s = 0,
                                  .local_volume_id = 1,
                                  .network_volume_id = 2,
                                  .attachment_id = 3,
                                  .generation = 1,
                                  .local_key = std::nullopt,
                                  .network_key = std::nullopt})
                    .error()
                    .status == oar::Status::unsupported));
    BOOST_TEST((link.self_test().error().status == oar::Status::unsupported));
}

namespace {

// A khold role's self-test trigger (kythira khold-block-service task 17).
class SelfTestingRole final : public ak::helm::OarHandler {
public:
    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return oar::Inventory{.role = oar::Role::khold, .vtep = {}, .functions = {}};
    }
    auto prepare_function(const oar::PrepareFunction& /*r*/) -> oar::Status override {
        return oar::Status::unknown_function;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        return oar::Status::unknown_function;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::unknown_function;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override {
        return oar::Status::unknown_function;
    }
    auto map_update(std::span<const std::byte> /*f*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto self_test() -> oar::Status override {
        ++tests;
        return tests > 1 ? oar::Status::busy : oar::Status::ok;
    }
    int tests{0};
};

}  // namespace

BOOST_AUTO_TEST_CASE(self_test_requests_cross_and_carry_the_answer) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    SelfTestingRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    {
        const Server server{endpoint, role};
        BOOST_TEST((link.function_inventory().value().role == oar::Role::khold));
        BOOST_TEST(link.self_test().has_value());
        BOOST_TEST((link.self_test().error().status == oar::Status::busy));
    }
    BOOST_TEST(role.tests == 2);
}

namespace {

// A storage role's half of cooperative detach: one function, which the
// guest releases at once.
class EjectingRole final : public ak::helm::OarHandler {
public:
    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return oar::Inventory{.role = oar::Role::blk, .vtep = {}, .functions = {}};
    }
    auto prepare_function(const oar::PrepareFunction& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override { return oar::Status::ok; }
    auto map_update(std::span<const std::byte> /*f*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto eject(const oar::Eject& r) -> std::expected<oar::EjectState, oar::Status> override {
        seen.push_back(r);
        if (r.fn != 0) {
            return std::unexpected(oar::Status::unknown_function);
        }
        if (r.op == oar::EjectOp::request) {
            state = oar::EjectState::released;
        } else if (r.op == oar::EjectOp::cancel) {
            state = oar::EjectState::none;
        }
        return state;
    }
    oar::EjectState state{oar::EjectState::none};
    std::vector<oar::Eject> seen;
};

}  // namespace

BOOST_AUTO_TEST_CASE(eject_requests_and_answers_cross) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    EjectingRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    {
        const Server server{endpoint, role};
        BOOST_TEST(
            (link.eject({.fn = 0, .op = oar::EjectOp::query}).value() == oar::EjectState::none));
        BOOST_TEST((link.eject({.fn = 0, .op = oar::EjectOp::request}).value() ==
                    oar::EjectState::released));
        BOOST_TEST(
            (link.eject({.fn = 0, .op = oar::EjectOp::cancel}).value() == oar::EjectState::none));
        BOOST_TEST((link.eject({.fn = 9, .op = oar::EjectOp::query}).error().status ==
                    oar::Status::unknown_function));
        BOOST_TEST((link.eject({.fn = 0, .op = static_cast<oar::EjectOp>(7)}).error().code ==
                    LinkErrc::bad_request));  // never sent
    }
    BOOST_TEST(role.seen.size() == 4U);
}

namespace {

// A storage role's half of a conversion: remembers the keys of a start
// (copied, as the message is wiped after the call) and answers progress.
class CopyingRole final : public ak::helm::OarHandler {
public:
    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return oar::Inventory{.role = oar::Role::blk, .vtep = {}, .functions = {}};
    }
    auto prepare_function(const oar::PrepareFunction& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override { return oar::Status::ok; }
    auto map_update(std::span<const std::byte> /*f*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto copy_volume(const oar::CopyVolume& r)
        -> std::expected<oar::CopyAnswer, oar::Status> override {
        ops.push_back(r.op);
        if (r.local_volume_id == 99) {
            return std::unexpected(oar::Status::busy);
        }
        if (r.op == oar::CopyOp::start) {
            local_key.assign(r.local_key->begin(), r.local_key->end());
            network_key.assign(r.network_key->begin(), r.network_key->end());
        }
        return oar::CopyAnswer{.state = oar::CopyVolumeState::copying,
                               .failure = oar::CopyVolumeFailure::none,
                               .total_bytes = 8,
                               .done_bytes = 4,
                               .written_bytes = 2};
    }
    std::vector<oar::CopyOp> ops;
    std::vector<std::byte> local_key;
    std::vector<std::byte> network_key;
};

auto test_scoped_key(std::byte fill) -> ak::helm::ScopedKey {
    std::array<std::byte, ak::helm::volume_key_size> raw{};
    raw.fill(fill);
    return ScopedKeyTestAccess::make(raw);
}

}  // namespace

BOOST_AUTO_TEST_CASE(copy_volume_requests_and_answers_cross) {
    auto [helm_b, oar_b] = InProcessBinding::make_pair();
    CopyingRole role;
    OarEndpoint endpoint{*oar_b, oar_config()};
    OarLink link{*helm_b, config()};
    const oar::CopyVolume head{.op = oar::CopyOp::start,
                               .direction = oar::CopyDirection::to_network,
                               .mib_per_s = 0,
                               .local_volume_id = 1,
                               .network_volume_id = 2,
                               .attachment_id = 3,
                               .generation = 1,
                               .local_key = std::nullopt,
                               .network_key = std::nullopt};
    {
        const Server server{endpoint, role};
        const auto started =
            link.copy_volume(head, test_scoped_key(std::byte{1}), test_scoped_key(std::byte{2}));
        BOOST_REQUIRE(started.has_value());
        BOOST_TEST(started->done_bytes == 4U);
        BOOST_TEST((role.local_key == std::vector<std::byte>(64, std::byte{1})));
        BOOST_TEST((role.network_key == std::vector<std::byte>(64, std::byte{2})));
        auto q = head;
        q.op = oar::CopyOp::query;
        BOOST_TEST((link.copy_volume(q).value().state == oar::CopyVolumeState::copying));
        q.op = oar::CopyOp::release;
        BOOST_TEST(link.copy_volume(q).has_value());
        // A refusal carries its status; bad arguments never reach the wire.
        q.local_volume_id = 99;
        BOOST_TEST((link.copy_volume(q).error().status == oar::Status::busy));
        BOOST_TEST((link.copy_volume(head).error().code == LinkErrc::bad_request));  // no keys
        BOOST_TEST(
            (link.copy_volume(q, test_scoped_key(std::byte{1}), test_scoped_key(std::byte{2}))
                 .error()
                 .code == LinkErrc::bad_request));  // keys on a release
    }
    BOOST_TEST(role.ops.size() == 4U);
}

BOOST_AUTO_TEST_CASE(names) {
    BOOST_TEST(std::string_view{ak::helm::to_string(LinkErrc::refused)} == "refused");
    BOOST_TEST(std::string_view{ak::helm::to_string(BindingError::queue_full)} == "queue_full");
    BOOST_TEST(helm_side.reversed().reversed().local_eid == helm_side.local_eid);
}

BOOST_AUTO_TEST_SUITE_END()
