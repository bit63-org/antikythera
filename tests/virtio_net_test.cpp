// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 1 (virtio-net functions),
// 2.1-2.3 (identity from helm, VLAN tags as payload, source MAC check) and
// 8.2 (clean state on detach): VirtioNetFunction driven by a simulated
// guest driver through its BAR and rings.

#define BOOST_TEST_MODULE virtio_net_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <ostream>
#include <vector>

#include "oar/net/virtio_net.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

namespace ak::oar::net {
auto boost_test_print_type(std::ostream& os, RxResult r) -> std::ostream& {
    return os << to_string(r);
}
auto boost_test_print_type(std::ostream& os, NetConfigError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::net
namespace ak::oar::virtio {
auto boost_test_print_type(std::ostream& os, AccessError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::virtio

namespace net = ak::oar::net;
namespace virtio = ak::oar::virtio;
namespace layout = virtio::bar_layout;
using ak::test::Buffer;
using ak::test::unit_timeout_seconds;
using ak::test::width16;
using ak::test::width32;
using ak::test::width8;
using net::RxResult;
using virtio::AccessError;

namespace {

constexpr std::uint64_t nic_value = 0x0102'0304'0506'0708ULL;
constexpr std::uint16_t mtu = 1500;
constexpr std::uint16_t rx = net::virtio_net_rx_queue;
constexpr std::uint16_t tx = net::virtio_net_tx_queue;
constexpr std::uint32_t hdr = net::virtio_net_hdr_size;
constexpr std::uint16_t config_vector = net::virtio_net_num_queues;
constexpr std::uint8_t payload_fill = 0xAB;
constexpr std::size_t small_payload = 46;

const net::MacAddress nic_mac{std::byte{0x02}, std::byte{0x00}, std::byte{0x5E},
                              std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
const net::MacAddress peer_mac{std::byte{0x02}, std::byte{0x00}, std::byte{0x5E},
                               std::byte{0x40}, std::byte{0x50}, std::byte{0x60}};

constexpr std::uint64_t driver_features =
    virtio::feature_bit(virtio::feature_version_1) | virtio::feature_bit(net::virtio_net_f_mac) |
    virtio::feature_bit(net::virtio_net_f_mtu) | virtio::feature_bit(net::virtio_net_f_status);

auto identity() -> net::NicIdentity {
    return {.nic_id = net::geneve::NicId{nic_value}, .mac = nic_mac, .mtu = mtu};
}

// An Ethernet frame of `size` bytes from `src` to `dst`.
auto frame(const net::MacAddress& dst, const net::MacAddress& src, std::size_t size)
    -> std::vector<std::byte> {
    std::vector<std::byte> f(size, std::byte{payload_fill});
    std::copy(dst.begin(), dst.end(), f.begin());
    std::copy(src.begin(), src.end(), f.begin() + 6);
    f[12] = std::byte{0x08};  // IPv4 ethertype, for looks
    f[13] = std::byte{0x00};
    return f;
}

auto with_header(const std::vector<std::byte>& f) -> std::vector<std::byte> {
    std::vector<std::byte> out(hdr, std::byte{0});
    out.insert(out.end(), f.begin(), f.end());
    return out;
}

class RecordingSink final : public net::FrameSink {
public:
    auto transmit(const net::TxFrame& f) -> void override {
        sources.push_back(f.source);
        frames.emplace_back(f.frame.begin(), f.frame.end());
        if (on_transmit) {
            on_transmit();
        }
    }
    std::vector<net::geneve::NicId> sources;
    std::vector<std::vector<std::byte>> frames;
    std::function<void()> on_transmit;
};

struct Fixture {
    explicit Fixture(std::size_t tx_budget = 256) {
        auto f = net::VirtioNetFunction::create({.identity = identity(),
                                                 .queue_size = ak::test::test_queue_size,
                                                 .tx_budget = tx_budget},
                                                ram.memory(), irq, sink);
        BOOST_REQUIRE(f);
        fn = std::move(*f);
        driver = std::make_unique<ak::test::VirtioDriver>(ram, fn->pci());
    }

    auto up() -> void { BOOST_REQUIRE(driver->bring_up(driver_features, {rx, tx})); }

    // Posts a one-descriptor TX chain holding header + frame and kicks.
    auto send(const std::vector<std::byte>& bytes) -> std::uint16_t {
        std::vector<virtio::Gpa> gpas;
        const std::uint16_t head =
            driver->post(tx, {{.len = static_cast<std::uint32_t>(bytes.size())}}, &gpas);
        ram.put_bytes(gpas[0], bytes);
        BOOST_REQUIRE(driver->notify(tx));
        return head;
    }

    auto config(std::uint32_t off, std::size_t width) -> std::uint64_t {
        auto v = fn->pci().bar_read(layout::device_offset + off, width);
        BOOST_REQUIRE(v);
        return *v;
    }

    ak::test::GuestRam ram;
    ak::test::RecordingInterrupts irq;
    RecordingSink sink;
    std::unique_ptr<net::VirtioNetFunction> fn;
    std::unique_ptr<ak::test::VirtioDriver> driver;
};

struct SmallBudget : Fixture {
    SmallBudget() : Fixture(2) {}
};

}  // namespace

BOOST_AUTO_TEST_CASE(identity_is_validated, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto id = identity();
    BOOST_TEST(net::validate(id).has_value());
    id.nic_id = net::geneve::nic_invalid;
    BOOST_TEST(net::validate(id).error() == net::NetConfigError::invalid_nic_id);
    id.nic_id = net::geneve::nic_broadcast;
    BOOST_TEST(net::validate(id).error() == net::NetConfigError::invalid_nic_id);
    id = identity();
    id.mac[0] = std::byte{0x01};  // group address
    BOOST_TEST(net::validate(id).error() == net::NetConfigError::bad_mac);
    id.mac = {};
    BOOST_TEST(net::validate(id).error() == net::NetConfigError::bad_mac);
    id = identity();
    id.mtu = net::min_mtu - 1;
    BOOST_TEST(net::validate(id).error() == net::NetConfigError::bad_mtu);

    ak::test::GuestRam ram;
    ak::test::RecordingInterrupts irq;
    RecordingSink sink;
    auto bad_queue = net::VirtioNetFunction::create({.identity = identity(), .queue_size = 3},
                                                    ram.memory(), irq, sink);
    BOOST_TEST(bad_queue.error() == net::NetConfigError::bad_queue_size);
    auto bad_id = net::VirtioNetFunction::create({.identity = id}, ram.memory(), irq, sink);
    BOOST_TEST(bad_id.error() == net::NetConfigError::bad_mtu);
}

BOOST_FIXTURE_TEST_CASE(presents_a_modern_virtio_net_device, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto& id = fn->pci().identity();
    BOOST_TEST(id.device_id == 0x1041);
    BOOST_TEST(id.class_code == 0x02);
    BOOST_TEST(fn->pci().msix_vectors() == 3);
    // Offered features, read through the common configuration.
    namespace cc = virtio::common_cfg;
    BOOST_REQUIRE(driver->common_write(cc::device_feature_select, width32, 0));
    const auto low = *driver->common_read(cc::device_feature, width32);
    BOOST_REQUIRE(driver->common_write(cc::device_feature_select, width32, 1));
    const auto high = *driver->common_read(cc::device_feature, width32);
    const std::uint64_t offered = low | (high << 32U);
    BOOST_TEST((offered & virtio::feature_bit(virtio::feature_version_1)) != 0);
    BOOST_TEST((offered & virtio::feature_bit(net::virtio_net_f_mac)) != 0);
    BOOST_TEST((offered & virtio::feature_bit(net::virtio_net_f_mtu)) != 0);
    BOOST_TEST((offered & virtio::feature_bit(net::virtio_net_f_status)) != 0);
    BOOST_TEST(*driver->common_read(cc::num_queues, width16) == 2U);
}

BOOST_FIXTURE_TEST_CASE(config_carries_helm_identity, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (std::uint32_t i = 0; i < nic_mac.size(); ++i) {
        BOOST_TEST(config(net::net_cfg::mac + i, width8) ==
                   std::to_integer<std::uint64_t>(nic_mac[i]));
    }
    BOOST_TEST(config(net::net_cfg::status, width16) == net::virtio_net_s_link_up);
    BOOST_TEST(config(net::net_cfg::max_virtqueue_pairs, width16) == 1U);
    BOOST_TEST(config(net::net_cfg::mtu, width16) == mtu);
    BOOST_TEST(config(net::net_cfg::status, width32) == (net::virtio_net_s_link_up | (1U << 16U)));
    BOOST_TEST(fn->pci().bar_read(layout::device_offset, ak::test::width64).error() ==
               AccessError::bad_width);
    BOOST_TEST(fn->pci().bar_read(layout::device_offset + net::net_cfg::size, width8).error() ==
               AccessError::bad_offset);
}

BOOST_FIXTURE_TEST_CASE(guest_cannot_write_mac_or_mtu, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(
        fn->pci().bar_write(layout::device_offset + net::net_cfg::mac, width8, 0xFF).error() ==
        AccessError::read_only);
    BOOST_TEST(
        fn->pci().bar_write(layout::device_offset + net::net_cfg::mtu, width16, 9000).error() ==
        AccessError::read_only);
    BOOST_TEST(config(net::net_cfg::mac, width8) == std::to_integer<std::uint64_t>(nic_mac[0]));
    BOOST_TEST(config(net::net_cfg::mtu, width16) == mtu);
}

BOOST_FIXTURE_TEST_CASE(transmit_tags_frames_with_the_function_nic_id, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    const auto f = frame(peer_mac, nic_mac, net::ethernet_header_size + small_payload);
    const std::uint16_t head = send(with_header(f));
    BOOST_REQUIRE_EQUAL(sink.frames.size(), 1U);
    BOOST_TEST(sink.frames[0] == f);
    BOOST_TEST(sink.sources[0].value == nic_value);
    BOOST_TEST(driver->used_idx(tx) == 1U);
    BOOST_TEST(driver->used_id(tx, 0) == head);
    BOOST_TEST(driver->used_len(tx, 0) == 0U);
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{tx});
    BOOST_TEST(fn->counters().tx_frames == 1U);
    BOOST_TEST(fn->counters().tx_bytes == f.size());
}

BOOST_FIXTURE_TEST_CASE(transmit_gathers_a_split_chain, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    const auto f = frame(peer_mac, nic_mac, net::ethernet_header_size + small_payload);
    std::vector<virtio::Gpa> gpas;
    // Header alone, then the frame split mid-MAC.
    driver->post(tx, {{.len = hdr}, {.len = 9}, {.len = static_cast<std::uint32_t>(f.size() - 9)}},
                 &gpas);
    ram.put_bytes(gpas[0], std::vector<std::byte>(hdr, std::byte{0}));
    ram.put_bytes(gpas[1], std::span{f}.first(9));
    ram.put_bytes(gpas[2], std::span{f}.subspan(9));
    BOOST_REQUIRE(driver->notify(tx));
    BOOST_REQUIRE_EQUAL(sink.frames.size(), 1U);
    BOOST_TEST(sink.frames[0] == f);
}

BOOST_FIXTURE_TEST_CASE(transmit_drops_a_spoofed_source_mac, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    send(with_header(frame(nic_mac, peer_mac, net::ethernet_header_size + small_payload)));
    BOOST_TEST(sink.frames.empty());
    BOOST_TEST(fn->counters().tx_drop_spoofed == 1U);
    BOOST_TEST(driver->used_idx(tx) == 1U);  // the buffer still goes back
}

BOOST_FIXTURE_TEST_CASE(transmit_drops_offload_requests, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    auto bytes = with_header(frame(peer_mac, nic_mac, net::ethernet_header_size + small_payload));
    bytes[0] = std::byte{1};  // VIRTIO_NET_HDR_F_NEEDS_CSUM
    send(bytes);
    bytes[0] = std::byte{0};
    bytes[1] = std::byte{1};  // GSO_TCPV4
    send(bytes);
    BOOST_TEST(sink.frames.empty());
    BOOST_TEST(fn->counters().tx_drop_bad_header == 2U);
}

BOOST_FIXTURE_TEST_CASE(transmit_bounds_frame_length, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    // One byte short of an Ethernet header.
    auto short_frame = with_header(frame(peer_mac, nic_mac, net::ethernet_header_size));
    short_frame.pop_back();
    send(short_frame);
    BOOST_TEST(fn->counters().tx_drop_short == 1U);
    // MTU plus Ethernet header plus one guest VLAN tag is the largest frame
    // (Requirement 2.2: the tag is payload).
    const std::size_t largest = net::ethernet_header_size + net::vlan_tag_size + mtu;
    BOOST_TEST(fn->max_frame() == largest);
    send(with_header(frame(peer_mac, nic_mac, largest)));
    BOOST_TEST(sink.frames.size() == 1U);
    send(with_header(frame(peer_mac, nic_mac, largest + 1)));
    BOOST_TEST(fn->counters().tx_drop_too_long == 1U);
    BOOST_TEST(sink.frames.size() == 1U);
    BOOST_TEST(driver->used_idx(tx) == 3U);
}

BOOST_FIXTURE_TEST_CASE(transmit_drains_every_posted_chain, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    const auto bytes =
        with_header(frame(peer_mac, nic_mac, net::ethernet_header_size + small_payload));
    for (int i = 0; i < 3; ++i) {
        std::vector<virtio::Gpa> gpas;
        driver->post(tx, {{.len = static_cast<std::uint32_t>(bytes.size())}}, &gpas);
        ram.put_bytes(gpas[0], bytes);
    }
    BOOST_REQUIRE(driver->notify(tx));
    BOOST_TEST(sink.frames.size() == 3U);
    BOOST_TEST(driver->used_idx(tx) == 3U);
    BOOST_TEST(!fn->pci().poll());
}

BOOST_FIXTURE_TEST_CASE(transmit_defers_past_the_budget, SmallBudget,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    const auto bytes =
        with_header(frame(peer_mac, nic_mac, net::ethernet_header_size + small_payload));
    for (int i = 0; i < 3; ++i) {
        std::vector<virtio::Gpa> gpas;
        driver->post(tx, {{.len = static_cast<std::uint32_t>(bytes.size())}}, &gpas);
        ram.put_bytes(gpas[0], bytes);
    }
    BOOST_REQUIRE(driver->notify(tx));
    BOOST_TEST(sink.frames.size() == 2U);
    BOOST_TEST(fn->pci().poll() == false);  // the third, then nothing left
    BOOST_TEST(sink.frames.size() == 3U);
    BOOST_TEST(!fn->pci().poll());
}

BOOST_FIXTURE_TEST_CASE(transmit_ring_error_resets_the_function, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    driver->publish(tx, ak::test::test_queue_size);  // head out of range
    BOOST_REQUIRE(driver->notify(tx));
    BOOST_TEST(fn->counters().queue_errors == 1U);
    BOOST_TEST(!fn->pci().live());
    BOOST_TEST((fn->pci().status() & virtio::status_device_needs_reset) != 0);
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{config_vector});
}

BOOST_FIXTURE_TEST_CASE(deliver_fills_a_posted_buffer, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    std::vector<virtio::Gpa> gpas;
    const std::uint16_t head =
        driver->post(rx, {{.len = hdr + net::ethernet_header_size + mtu, .writable = true}}, &gpas);
    const auto f = frame(nic_mac, peer_mac, net::ethernet_header_size + small_payload);
    BOOST_TEST(fn->deliver(f) == RxResult::delivered);
    BOOST_TEST(driver->used_idx(rx) == 1U);
    BOOST_TEST(driver->used_id(rx, 0) == head);
    BOOST_TEST(driver->used_len(rx, 0) == hdr + f.size());
    auto expected_header = std::vector<std::byte>(hdr, std::byte{0});
    expected_header[10] = std::byte{1};  // num_buffers = 1
    BOOST_TEST(ram.bytes(gpas[0], hdr) == expected_header);
    BOOST_TEST(ram.bytes(gpas[0] + hdr, f.size()) == f);
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{rx});
    BOOST_TEST(fn->counters().rx_frames == 1U);
    BOOST_TEST(fn->counters().rx_bytes == f.size());
}

BOOST_FIXTURE_TEST_CASE(deliver_scatters_across_descriptors, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    std::vector<virtio::Gpa> gpas;
    driver->post(rx,
                 {{.len = 5, .writable = true},
                  {.len = 20, .writable = true},
                  {.len = 200, .writable = true}},
                 &gpas);
    const auto f = frame(nic_mac, peer_mac, net::ethernet_header_size + small_payload);
    BOOST_TEST(fn->deliver(f) == RxResult::delivered);
    std::vector<std::byte> got = ram.bytes(gpas[0], 5);
    for (const auto& part : {ram.bytes(gpas[1], 20), ram.bytes(gpas[2], 200)}) {
        got.insert(got.end(), part.begin(), part.end());
    }
    got.resize(hdr + f.size());
    BOOST_TEST(std::vector<std::byte>(got.begin() + hdr, got.end()) == f);
}

BOOST_FIXTURE_TEST_CASE(deliver_drops_without_a_usable_buffer, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto f = frame(nic_mac, peer_mac, net::ethernet_header_size + small_payload);
    BOOST_TEST(fn->deliver(f) == RxResult::not_ready);
    up();
    BOOST_TEST(fn->deliver(f) == RxResult::no_buffer);
    driver->post(rx, {{.len = hdr + 10, .writable = true}});
    BOOST_TEST(fn->deliver(f) == RxResult::buffer_too_small);
    BOOST_TEST(driver->used_idx(rx) == 1U);
    BOOST_TEST(driver->used_len(rx, 0) == 0U);  // returned empty
    // A device-readable-only chain has no room either.
    driver->post(rx, {{.len = 512}});
    BOOST_TEST(fn->deliver(f) == RxResult::buffer_too_small);
    const auto& c = fn->counters();
    BOOST_TEST(c.rx_drop_not_ready == 1U);
    BOOST_TEST(c.rx_drop_no_buffer == 1U);
    BOOST_TEST(c.rx_drop_buffer_too_small == 2U);
    BOOST_TEST(c.rx_frames == 0U);
}

BOOST_FIXTURE_TEST_CASE(deliver_bounds_frame_length, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    driver->post(rx, {{.len = 0x2000, .writable = true}});
    BOOST_TEST(fn->deliver(frame(nic_mac, peer_mac, fn->max_frame() + 1)) ==
               RxResult::frame_too_large);
    BOOST_TEST(fn->deliver(std::vector<std::byte>(net::ethernet_header_size - 1)) ==
               RxResult::frame_too_short);
    BOOST_TEST(fn->counters().rx_drop_bad_frame == 2U);
    BOOST_TEST(fn->deliver(frame(nic_mac, peer_mac, fn->max_frame())) == RxResult::delivered);
}

BOOST_FIXTURE_TEST_CASE(deliver_ring_error_resets_the_function, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    driver->publish(rx, ak::test::test_queue_size);
    BOOST_TEST(fn->deliver(frame(nic_mac, peer_mac, 60)) == RxResult::queue_error);
    BOOST_TEST(fn->counters().queue_errors == 1U);
    BOOST_TEST(!fn->pci().live());
}

BOOST_FIXTURE_TEST_CASE(sink_reentry_that_resets_is_survived, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    const auto bytes =
        with_header(frame(peer_mac, nic_mac, net::ethernet_header_size + small_payload));
    for (int i = 0; i < 2; ++i) {
        std::vector<virtio::Gpa> gpas;
        driver->post(tx, {{.len = static_cast<std::uint32_t>(bytes.size())}}, &gpas);
        ram.put_bytes(gpas[0], bytes);
    }
    sink.on_transmit = [this] { fn->pci().reset(); };
    BOOST_REQUIRE(driver->notify(tx));
    BOOST_TEST(sink.frames.size() == 1U);  // the reset stopped the drain
    BOOST_TEST(!fn->pci().live());
}

BOOST_FIXTURE_TEST_CASE(reassign_resets_and_changes_identity, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    auto next = identity();
    next.mac = peer_mac;
    next.mtu = 9000 - 90;
    next.nic_id = net::geneve::NicId{nic_value + 1};
    BOOST_REQUIRE(fn->reassign(next));
    BOOST_TEST(!fn->pci().live());
    BOOST_TEST(fn->pci().status() == 0U);
    BOOST_TEST(config(net::net_cfg::mac + 3, width8) ==
               std::to_integer<std::uint64_t>(peer_mac[3]));
    BOOST_TEST(config(net::net_cfg::mtu, width16) == next.mtu);
    // The new identity is what the next driver sees and what frames carry.
    up();
    send(with_header(frame(nic_mac, peer_mac, next.mtu + net::ethernet_header_size)));
    BOOST_REQUIRE_EQUAL(sink.frames.size(), 1U);
    BOOST_TEST(sink.sources[0].value == nic_value + 1);

    auto bad = next;
    bad.mtu = 0;
    BOOST_TEST(fn->reassign(bad).error() == net::NetConfigError::bad_mtu);
    BOOST_TEST(fn->identity().mtu == next.mtu);  // unchanged
}

BOOST_FIXTURE_TEST_CASE(flr_clears_queues_and_features, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    up();
    driver->post(rx, {{.len = 2048, .writable = true}});
    fn->pci().reset();
    BOOST_TEST(fn->deliver(frame(nic_mac, peer_mac, 60)) == RxResult::not_ready);
    namespace cc = virtio::common_cfg;
    BOOST_REQUIRE(driver->common_write(cc::driver_feature_select, width32, 0));
    BOOST_TEST(*driver->common_read(cc::driver_feature, width32) == 0U);
    // The driver can bring it back up from scratch.
    up();
    driver->post(rx, {{.len = 2048, .writable = true}});
    BOOST_TEST(fn->deliver(frame(nic_mac, peer_mac, 60)) == RxResult::delivered);
}
