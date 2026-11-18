// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 1.4: the shared virtio core's
// PCI capabilities and common configuration registers, driven the way a
// Linux virtio-pci driver probes and sets up a modern device.

#define BOOST_TEST_MODULE virtio_pci_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "oar/virtio/pci.hpp"
#include "test_support.hpp"

// Failure messages name the error.
namespace ak::oar::virtio {
auto boost_test_print_type(std::ostream& os, AccessError e) -> std::ostream& {
    return os << to_string(e);
}
auto boost_test_print_type(std::ostream& os, ConfigError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::virtio

namespace virtio = ak::oar::virtio;
namespace cc = ak::oar::virtio::common_cfg;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using virtio::AccessError;
using virtio::feature_bit;

namespace {

constexpr std::uint16_t queues = 2;
constexpr std::uint16_t max_size = 256;
constexpr unsigned net_mac_bit = 5;  // VIRTIO_NET_F_MAC, a device-specific feature
constexpr std::uint64_t offered = feature_bit(virtio::feature_version_1) |
                                  feature_bit(virtio::feature_access_platform) |
                                  feature_bit(virtio::feature_event_idx) | feature_bit(net_mac_bit);
constexpr std::uint64_t desc_addr = 0x1'2345'6000;
constexpr std::uint64_t driver_addr = 0x7000;
constexpr std::uint64_t device_addr = 0x8000;
constexpr std::uint16_t small_size = 64;
constexpr std::uint16_t vector = 3;
constexpr unsigned bits_per_word = 32;
constexpr std::uint64_t low_word = 0xFFFF'FFFF;
constexpr std::uint8_t ack_driver = virtio::status_acknowledge | virtio::status_driver;

auto make() -> virtio::CommonConfig {
    auto c = virtio::CommonConfig::create(
        {.device_features = offered, .num_queues = queues, .max_queue_size = max_size});
    BOOST_REQUIRE(c);
    return *c;
}

auto ok(std::expected<void, AccessError> r) -> void {
    BOOST_REQUIRE(r.has_value());
}

auto rd(const virtio::CommonConfig& c, std::uint32_t off, std::size_t width) -> std::uint64_t {
    auto r = c.read(off, width);
    BOOST_REQUIRE(r.has_value());
    return *r;
}

auto wr_error(virtio::CommonConfig& c, std::uint32_t off, std::size_t width, std::uint64_t v)
    -> AccessError {
    auto r = c.write(off, width, v);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

// Negotiates `features` up to FEATURES_OK, as a driver does.
auto negotiate(virtio::CommonConfig& c, std::uint64_t features) -> void {
    ok(c.write(cc::device_status, 1, ack_driver));
    ok(c.write(cc::driver_feature_select, 4, 0));
    ok(c.write(cc::driver_feature, 4, features & low_word));
    ok(c.write(cc::driver_feature_select, 4, 1));
    ok(c.write(cc::driver_feature, 4, features >> bits_per_word));
    ok(c.write(cc::device_status, 1, ack_driver | virtio::status_features_ok));
}

}  // namespace

// --- Capabilities --------------------------------------------------------

BOOST_AUTO_TEST_CASE(capabilities_encode_the_spec_layout,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto common = virtio::encode_capability(
        {.type = virtio::CfgType::common, .bar = 4, .offset = 0x1000, .length = cc::size}, 0x50);
    BOOST_TEST((common == bytes_of(0x09, 0x50, 16, 1, 4, 0, 0, 0, 0x00, 0x10, 0, 0, 60, 0, 0, 0)));
    const auto notify = virtio::encode_capability({.type = virtio::CfgType::notify,
                                                   .bar = 4,
                                                   .offset = 0x3000,
                                                   .length = 0x1000,
                                                   .notify_off_multiplier = 4},
                                                  0);
    BOOST_TEST((notify == bytes_of(0x09, 0, 20, 2, 4, 0, 0, 0, 0x00, 0x30, 0, 0, 0x00, 0x10, 0, 0,
                                   4, 0, 0, 0)));
}

// --- Construction --------------------------------------------------------

BOOST_AUTO_TEST_CASE(create_requires_a_modern_device_with_queues,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    using virtio::ConfigError;
    BOOST_TEST(virtio::CommonConfig::create(
                   {.device_features = 0, .num_queues = 1, .max_queue_size = max_size})
                   .error() == ConfigError::no_version_1);
    BOOST_TEST(virtio::CommonConfig::create(
                   {.device_features = offered, .num_queues = 0, .max_queue_size = max_size})
                   .error() == ConfigError::no_queues);
    BOOST_TEST(virtio::CommonConfig::create(
                   {.device_features = offered, .num_queues = 1, .max_queue_size = 3})
                   .error() == ConfigError::bad_queue_size);
}

// --- Feature negotiation and status --------------------------------------

BOOST_AUTO_TEST_CASE(device_features_read_through_two_windows,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    BOOST_TEST(rd(c, cc::device_feature, 4) == (offered & low_word));
    ok(c.write(cc::device_feature_select, 4, 1));
    BOOST_TEST(rd(c, cc::device_feature, 4) == (offered >> bits_per_word));
    ok(c.write(cc::device_feature_select, 4, 2));
    BOOST_TEST(rd(c, cc::device_feature, 4) == 0U);
    BOOST_TEST(rd(c, cc::num_queues, 2) == queues);
}

BOOST_AUTO_TEST_CASE(features_ok_is_accepted_for_offered_modern_features,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    const std::uint64_t want = feature_bit(virtio::feature_version_1) | feature_bit(net_mac_bit);
    negotiate(c, want);
    BOOST_TEST((c.status() & virtio::status_features_ok) != 0);
    BOOST_TEST(c.negotiated_features() == want);
    // Features are frozen once FEATURES_OK is set.
    BOOST_TEST(wr_error(c, cc::driver_feature, 4, 0) == AccessError::not_now);
}

BOOST_AUTO_TEST_CASE(features_ok_is_refused_for_unoffered_or_legacy_features,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    {
        auto c = make();
        negotiate(c, feature_bit(virtio::feature_version_1) | feature_bit(0));  // not offered
        BOOST_TEST((c.status() & virtio::status_features_ok) == 0);
        BOOST_TEST(c.status() == ack_driver);
    }
    {
        auto c = make();
        negotiate(c, feature_bit(net_mac_bit));  // no VERSION_1
        BOOST_TEST((c.status() & virtio::status_features_ok) == 0);
    }
    {
        auto c = make();
        ok(c.write(cc::driver_feature_select, 4, 2));
        BOOST_TEST(wr_error(c, cc::driver_feature, 4, 1) == AccessError::bad_value);
    }
}

BOOST_AUTO_TEST_CASE(status_bits_clear_only_by_reset,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    BOOST_TEST(!c.take_reset());
    ok(c.write(cc::device_status, 1, ack_driver));
    BOOST_TEST(wr_error(c, cc::device_status, 1, virtio::status_acknowledge) ==
               AccessError::bad_value);
    BOOST_TEST(wr_error(c, cc::device_status, 1, ack_driver | virtio::status_driver_ok) ==
               AccessError::not_now);  // DRIVER_OK before FEATURES_OK
    BOOST_TEST(wr_error(c, cc::device_status, 1, virtio::status_device_needs_reset) ==
               AccessError::bad_value);  // device-owned bit
    BOOST_TEST(c.status() == ack_driver);

    c.set_needs_reset();
    ok(c.write(cc::device_status, 1, ack_driver | virtio::status_failed));
    BOOST_TEST((c.status() & virtio::status_device_needs_reset) != 0);

    ok(c.write(cc::device_status, 1, 0));
    BOOST_TEST(c.status() == 0);
    BOOST_TEST(c.take_reset());
    BOOST_TEST(!c.take_reset());
}

// --- Queue setup ---------------------------------------------------------

BOOST_AUTO_TEST_CASE(queue_setup_programs_an_enabled_queue,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    negotiate(c, feature_bit(virtio::feature_version_1) | feature_bit(virtio::feature_event_idx));
    ok(c.write(cc::queue_select, 2, 1));
    BOOST_TEST(rd(c, cc::queue_size, 2) == max_size);
    ok(c.write(cc::queue_size, 2, small_size));
    ok(c.write(cc::queue_msix_vector, 2, vector));
    ok(c.write(cc::queue_desc, 8, desc_addr));      // one 64-bit access
    ok(c.write(cc::queue_driver, 4, driver_addr));  // two 32-bit halves
    ok(c.write(cc::queue_driver + 4, 4, 0));
    ok(c.write(cc::queue_device + 4, 4, 0));
    ok(c.write(cc::queue_device, 4, device_addr));
    BOOST_TEST(rd(c, cc::queue_desc + 4, 4) == (desc_addr >> bits_per_word));
    BOOST_TEST(rd(c, cc::queue_notify_off, 2) == 1U);
    BOOST_TEST(!c.queue(1).has_value());  // not enabled yet
    ok(c.write(cc::queue_enable, 2, 1));
    BOOST_TEST(rd(c, cc::queue_enable, 2) == 1U);

    const auto q = c.queue(1);
    BOOST_REQUIRE(q.has_value());
    BOOST_TEST(q->size == small_size);
    BOOST_TEST(q->desc == desc_addr);
    BOOST_TEST(q->driver == driver_addr);
    BOOST_TEST(q->device == device_addr);
    BOOST_TEST(q->event_idx);
    BOOST_TEST(!q->indirect_desc);
    BOOST_TEST(c.queue_msix_vector(1) == vector);
    BOOST_TEST(!c.queue(0).has_value());

    // An enabled queue's configuration is frozen until reset.
    BOOST_TEST(wr_error(c, cc::queue_size, 2, small_size / 2) == AccessError::not_now);
    BOOST_TEST(wr_error(c, cc::queue_desc, 8, 0) == AccessError::not_now);

    ok(c.write(cc::device_status, 1,
               ack_driver | virtio::status_features_ok | virtio::status_driver_ok));
    ok(c.write(cc::queue_select, 2, 0));
    BOOST_TEST(wr_error(c, cc::queue_enable, 2, 1) == AccessError::not_now);  // after DRIVER_OK

    ok(c.write(cc::device_status, 1, 0));
    BOOST_TEST(!c.queue(1).has_value());
    ok(c.write(cc::queue_select, 2, 1));
    BOOST_TEST(rd(c, cc::queue_size, 2) == max_size);
}

BOOST_AUTO_TEST_CASE(queue_setup_rejects_bad_values_and_bad_timing,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    // Before FEATURES_OK.
    BOOST_TEST(wr_error(c, cc::queue_size, 2, small_size) == AccessError::not_now);
    BOOST_TEST(wr_error(c, cc::queue_desc, 8, desc_addr) == AccessError::not_now);
    negotiate(c, feature_bit(virtio::feature_version_1));
    for (std::uint64_t bad : {0U, 3U, 512U}) {
        BOOST_TEST(wr_error(c, cc::queue_size, 2, bad) == AccessError::bad_value);
    }
    BOOST_TEST(wr_error(c, cc::queue_enable, 2, 0) == AccessError::bad_value);
    BOOST_TEST(wr_error(c, cc::queue_enable, 2, 2) == AccessError::bad_value);
    // A selector past the last queue reads as a missing queue.
    ok(c.write(cc::queue_select, 2, queues));
    BOOST_TEST(rd(c, cc::queue_size, 2) == 0U);
    BOOST_TEST(wr_error(c, cc::queue_enable, 2, 1) == AccessError::not_now);
    BOOST_TEST(wr_error(c, cc::queue_msix_vector, 2, 1) == AccessError::not_now);
}

// --- Access checking -----------------------------------------------------

BOOST_AUTO_TEST_CASE(accesses_must_use_known_offsets_and_natural_widths,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    BOOST_TEST(c.read(cc::device_feature, 2).error() == AccessError::bad_width);
    BOOST_TEST(c.read(cc::device_status, 4).error() == AccessError::bad_width);
    BOOST_TEST(c.read(cc::queue_desc + 4, 8).error() == AccessError::bad_width);
    BOOST_TEST(c.read(1, 1).error() == AccessError::bad_offset);
    BOOST_TEST(c.read(cc::size, 2).error() == AccessError::bad_offset);
    BOOST_TEST(wr_error(c, cc::queue_select, 4, 0) == AccessError::bad_width);
    BOOST_TEST(wr_error(c, cc::device_status, 1, 0x100) == AccessError::bad_value);
    BOOST_TEST(wr_error(c, cc::num_queues, 2, 1) == AccessError::read_only);
    BOOST_TEST(wr_error(c, cc::device_feature, 4, 1) == AccessError::read_only);
    BOOST_TEST(wr_error(c, cc::config_generation, 1, 1) == AccessError::read_only);
    BOOST_TEST(wr_error(c, cc::size + 2, 2, 1) == AccessError::bad_offset);
}

BOOST_AUTO_TEST_CASE(config_generation_moves_forward_across_reset,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto c = make();
    BOOST_TEST(rd(c, cc::config_generation, 1) == 0U);
    c.bump_config_generation();
    ok(c.write(cc::device_status, 1, 0));
    BOOST_TEST(rd(c, cc::config_generation, 1) == 1U);
    ok(c.write(cc::config_msix_vector, 2, vector));
    BOOST_TEST(c.config_msix_vector() == vector);
}

BOOST_AUTO_TEST_CASE(access_errors_have_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(std::string{virtio::to_string(AccessError::not_now)} == "not_now");
    BOOST_TEST(std::string{virtio::to_string(virtio::ConfigError::no_queues)} == "no_queues");
}
