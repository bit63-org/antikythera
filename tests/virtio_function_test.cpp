// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 1.3, 1.4: the transport seam
// of the shared virtio core. A fake device type sits behind a PciFunction
// and a simulated driver programs it through the BAR only.

#define BOOST_TEST_MODULE virtio_function_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <ostream>
#include <vector>

#include "oar/virtio/function.hpp"
#include "test_support.hpp"
#include "virtio_driver_support.hpp"

namespace ak::oar::virtio {
auto boost_test_print_type(std::ostream& os, AccessError e) -> std::ostream& {
    return os << to_string(e);
}
auto boost_test_print_type(std::ostream& os, FunctionError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::virtio

namespace virtio = ak::oar::virtio;
namespace cc = virtio::common_cfg;
namespace layout = virtio::bar_layout;
using ak::test::unit_timeout_seconds;
using ak::test::width16;
using ak::test::width32;
using ak::test::width8;
using virtio::AccessError;

namespace {

constexpr std::uint16_t num_queues = 3;
constexpr std::uint32_t config_size = 8;
constexpr std::uint16_t device_id = 0x1042;
constexpr std::uint64_t config_value = 0x1122'3344'5566'7788ULL;
constexpr std::uint64_t features =
    virtio::feature_bit(virtio::feature_version_1) | virtio::feature_bit(virtio::feature_event_idx);
constexpr std::uint16_t config_vector = num_queues;

class FakeDevice final : public virtio::Device {
public:
    [[nodiscard]] auto read_config(std::uint32_t offset, std::size_t width) const
        -> std::expected<std::uint64_t, AccessError> override {
        last_offset = offset;
        last_width = width;
        return config_value;
    }
    [[nodiscard]] auto write_config(std::uint32_t /*offset*/, std::size_t /*width*/,
                                    std::uint64_t /*value*/)
        -> std::expected<void, AccessError> override {
        return std::unexpected(AccessError::read_only);
    }
    auto queue_notified(std::uint16_t index) -> void override { notified.push_back(index); }
    [[nodiscard]] auto poll() -> bool override {
        ++polls;
        return false;
    }
    auto queues_dropped() -> void override { ++drops; }

    mutable std::uint32_t last_offset{0};
    mutable std::size_t last_width{0};
    std::vector<std::uint16_t> notified;
    int polls{0};
    int drops{0};
};

struct Fixture {
    Fixture() {
        auto f = virtio::PciFunction::create(device, ram.memory(), irq,
                                             {.identity = {.device_id = device_id, .class_code = 1},
                                              .device_features = features,
                                              .num_queues = num_queues,
                                              .max_queue_size = ak::test::test_queue_size,
                                              .device_config_size = config_size});
        BOOST_REQUIRE(f);
        fn = std::move(*f);
        driver = std::make_unique<ak::test::VirtioDriver>(ram, *fn);
    }

    ak::test::GuestRam ram;
    ak::test::RecordingInterrupts irq;
    FakeDevice device;
    std::unique_ptr<virtio::PciFunction> fn;
    std::unique_ptr<ak::test::VirtioDriver> driver;
};

}  // namespace

BOOST_AUTO_TEST_CASE(create_rejects_bad_parameters,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    ak::test::GuestRam ram;
    ak::test::RecordingInterrupts irq;
    FakeDevice device;
    const virtio::PciFunctionParams good{.identity = {},
                                         .device_features = features,
                                         .num_queues = num_queues,
                                         .max_queue_size = ak::test::test_queue_size,
                                         .device_config_size = config_size};
    auto p = good;
    p.device_config_size = layout::device_max_length + 1;
    BOOST_TEST(virtio::PciFunction::create(device, ram.memory(), irq, p).error() ==
               virtio::FunctionError::device_config_size);
    p = good;
    p.num_queues = (layout::notify_max_length / layout::notify_off_multiplier) + 1;
    BOOST_TEST(virtio::PciFunction::create(device, ram.memory(), irq, p).error() ==
               virtio::FunctionError::too_many_queues);
    p = good;
    p.device_features = 0;  // no VERSION_1
    BOOST_TEST(virtio::PciFunction::create(device, ram.memory(), irq, p).error() ==
               virtio::FunctionError::bad_config);
}

BOOST_FIXTURE_TEST_CASE(capabilities_describe_the_bar, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto caps = fn->capabilities();
    BOOST_REQUIRE_EQUAL(caps.size(), 4U);
    BOOST_TEST((caps[0].type == virtio::CfgType::common));
    BOOST_TEST(caps[0].offset == layout::common_offset);
    BOOST_TEST(caps[0].length == cc::size);
    BOOST_TEST((caps[1].type == virtio::CfgType::notify));
    BOOST_TEST(caps[1].offset == layout::notify_offset);
    BOOST_TEST(caps[1].length == num_queues * layout::notify_off_multiplier);
    BOOST_TEST(caps[1].notify_off_multiplier == layout::notify_off_multiplier);
    BOOST_TEST((caps[2].type == virtio::CfgType::isr));
    BOOST_TEST((caps[3].type == virtio::CfgType::device));
    BOOST_TEST(caps[3].length == config_size);
    for (const auto& c : caps) {
        BOOST_TEST(c.bar == layout::bar_index);
        BOOST_TEST(c.offset + c.length <= layout::bar_size);
    }
    BOOST_TEST(fn->msix_vectors() == num_queues + 1);
    BOOST_TEST(fn->identity().device_id == device_id);
}

BOOST_FIXTURE_TEST_CASE(device_window_is_routed_and_bounded, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto v = fn->bar_read(layout::device_offset + 4, width32);
    BOOST_REQUIRE(v);
    BOOST_TEST(*v == config_value);
    BOOST_TEST(device.last_offset == 4U);
    BOOST_TEST(device.last_width == width32);
    // Crossing the end of the window, and past it.
    BOOST_TEST(fn->bar_read(layout::device_offset + 6, width32).error() == AccessError::bad_width);
    BOOST_TEST(fn->bar_read(layout::device_offset + config_size, width8).error() ==
               AccessError::bad_offset);
    BOOST_TEST(fn->bar_write(layout::device_offset, width8, 1).error() == AccessError::read_only);
    // Gaps in the BAR.
    BOOST_TEST(fn->bar_read(cc::size, width8).error() == AccessError::bad_offset);
    BOOST_TEST(fn->bar_read(layout::bar_size, width8).error() == AccessError::bad_offset);
}

BOOST_FIXTURE_TEST_CASE(bring_up_makes_enabled_queues_live, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!fn->live());
    BOOST_REQUIRE(driver->bring_up(features, {0, 2}));
    BOOST_TEST(fn->live());
    BOOST_TEST(fn->queue(0) != nullptr);
    BOOST_TEST(fn->queue(1) == nullptr);  // not enabled
    BOOST_TEST(fn->queue(2) != nullptr);
    BOOST_TEST(fn->queue(num_queues) == nullptr);
    BOOST_TEST(fn->negotiated(virtio::feature_event_idx));
    BOOST_TEST(!fn->negotiated(virtio::feature_indirect_desc));

    BOOST_REQUIRE(driver->notify(2));
    BOOST_REQUIRE(driver->notify(1));  // a queue that is not live: ignored
    BOOST_TEST(device.notified == std::vector<std::uint16_t>{2});

    BOOST_TEST(fn->bar_write(layout::notify_offset + 1, width16, 0).error() ==
               AccessError::bad_offset);
    BOOST_TEST(fn->bar_write(layout::notify_offset, width32, 0).error() == AccessError::bad_width);
    BOOST_TEST(fn->bar_write(layout::notify_offset + (num_queues * layout::notify_off_multiplier),
                             width16, 0)
                   .error() == AccessError::bad_offset);
}

BOOST_FIXTURE_TEST_CASE(notify_before_driver_ok_is_ignored, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->notify(0));
    BOOST_TEST(device.notified.empty());
    BOOST_TEST(!fn->poll());
    BOOST_TEST(device.polls == 0);
}

BOOST_FIXTURE_TEST_CASE(ring_outside_guest_memory_needs_reset, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Enable queue 0 at an address no region covers.
    BOOST_REQUIRE(driver->common_write(cc::device_status, width8, virtio::status_acknowledge));
    const std::uint8_t s = virtio::status_acknowledge | virtio::status_driver;
    BOOST_REQUIRE(driver->common_write(cc::device_status, width8, s));
    BOOST_REQUIRE(driver->common_write(cc::driver_feature_select, width32, 1));
    BOOST_REQUIRE(driver->common_write(cc::driver_feature, width32, 1));  // VERSION_1
    BOOST_REQUIRE(driver->common_write(cc::device_status, width8, s | virtio::status_features_ok));
    BOOST_REQUIRE(driver->common_write(cc::config_msix_vector, width16, config_vector));
    BOOST_REQUIRE(driver->common_write(cc::queue_select, width16, 0));
    BOOST_REQUIRE(driver->common_write(cc::queue_desc, ak::test::width64, 0x1000));
    BOOST_REQUIRE(driver->common_write(cc::queue_enable, width16, 1));
    BOOST_REQUIRE(driver->common_write(cc::device_status, width8,
                                       s | virtio::status_features_ok | virtio::status_driver_ok));

    BOOST_TEST(!fn->live());
    BOOST_TEST((fn->status() & virtio::status_device_needs_reset) != 0);
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{config_vector});
    auto isr = fn->bar_read(layout::isr_offset, width8);
    BOOST_REQUIRE(isr);
    BOOST_TEST(*isr == virtio::isr_config);
}

BOOST_FIXTURE_TEST_CASE(isr_is_read_to_clear, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    fn->config_changed();
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{config_vector});
    BOOST_TEST(fn->bar_read(layout::isr_offset, width16).error() == AccessError::bad_width);
    BOOST_TEST(fn->bar_write(layout::isr_offset, width8, 0).error() == AccessError::read_only);
    BOOST_TEST(*fn->bar_read(layout::isr_offset, width8) == virtio::isr_config);
    BOOST_TEST(*fn->bar_read(layout::isr_offset, width8) == 0U);
    // The generation moved, so the driver re-reads device configuration.
    BOOST_TEST(*driver->common_read(cc::config_generation, width8) == 1U);
}

BOOST_FIXTURE_TEST_CASE(signal_raises_the_queue_vector, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->bring_up(virtio::feature_bit(virtio::feature_version_1), {1}));
    const std::uint16_t head = driver->post(1, {{.len = 16}});
    auto* q = fn->queue(1);
    BOOST_REQUIRE(q != nullptr);
    auto chain = q->pop();
    BOOST_REQUIRE(chain && chain->has_value());
    BOOST_REQUIRE(q->push(head, 0));
    fn->signal(1);
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{1});
    BOOST_TEST(*fn->bar_read(layout::isr_offset, width8) == virtio::isr_queue);
    fn->signal(1);  // nothing new pushed
    BOOST_TEST(irq.raised.size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(driver_reset_drops_queues, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    BOOST_REQUIRE(driver->common_write(cc::device_status, width8, 0));
    BOOST_TEST(!fn->live());
    BOOST_TEST(fn->queue(0) == nullptr);
    BOOST_TEST(device.drops == 1);
    // And it comes back.
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    BOOST_TEST(fn->live());
}

BOOST_FIXTURE_TEST_CASE(flr_returns_to_a_clean_state, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->bring_up(features, {0, 1, 2}));
    fn->config_changed();
    fn->reset();
    BOOST_TEST(!fn->live());
    BOOST_TEST(device.drops == 1);
    BOOST_TEST(fn->status() == 0U);
    BOOST_TEST(*fn->bar_read(layout::isr_offset, width8) == 0U);
    BOOST_REQUIRE(driver->common_write(cc::queue_select, width16, 0));
    BOOST_TEST(*driver->common_read(cc::queue_enable, width16) == 0U);
    BOOST_TEST(*driver->common_read(cc::queue_msix_vector, width16) == virtio::msix_no_vector);
    BOOST_TEST(*driver->common_read(cc::driver_feature, width32) == 0U);
}

BOOST_FIXTURE_TEST_CASE(fail_sets_needs_reset, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    fn->fail();
    BOOST_TEST(!fn->live());
    BOOST_TEST((fn->status() & virtio::status_device_needs_reset) != 0);
    BOOST_TEST(irq.raised == std::vector<std::uint16_t>{config_vector});
    BOOST_TEST(device.drops == 1);
    // Re-asserting DRIVER_OK does not revive a function that needs reset.
    BOOST_REQUIRE(driver->common_write(cc::device_status, width8,
                                       virtio::status_acknowledge | virtio::status_driver |
                                           virtio::status_features_ok | virtio::status_driver_ok));
    BOOST_TEST(!fn->live());
}

BOOST_FIXTURE_TEST_CASE(memory_change_while_live_needs_reset, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    fn->memory_changing();  // nothing live: no effect
    BOOST_TEST((fn->status() & virtio::status_device_needs_reset) == 0);
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    fn->memory_changing();
    BOOST_TEST(!fn->live());
    BOOST_TEST((fn->status() & virtio::status_device_needs_reset) != 0);
}

BOOST_FIXTURE_TEST_CASE(unmapping_a_range_without_rings_keeps_the_driver, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    using ak::test::VirtioDriver;
    // Far away (another device's BAR window), right below the descriptor
    // table, between the rings, and at the very top of the address space.
    fn->memory_changing(0xFE00'0000, 0x4000);
    fn->memory_changing(VirtioDriver::desc_gpa(0) - 0x1000, 0x1000);
    fn->memory_changing(
        VirtioDriver::desc_gpa(0) + virtio::desc_table_bytes(ak::test::test_queue_size),
        VirtioDriver::avail_gpa(0) - VirtioDriver::desc_gpa(0) -
            virtio::desc_table_bytes(ak::test::test_queue_size));
    fn->memory_changing(~std::uint64_t{0} - 0xFFF, 0x1000);
    fn->memory_changing(VirtioDriver::desc_gpa(0), 0);
    BOOST_TEST(fn->live());
    BOOST_TEST((fn->status() & virtio::status_device_needs_reset) == 0);
}

BOOST_FIXTURE_TEST_CASE(unmapping_a_ring_needs_reset, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    using ak::test::VirtioDriver;
    const std::vector<virtio::Gpa> hits{
        VirtioDriver::desc_gpa(0),       // descriptor table start
        VirtioDriver::avail_gpa(0) + 3,  // inside the available ring
        VirtioDriver::used_gpa(0) + virtio::used_ring_bytes(ak::test::test_queue_size) -
            1,  // last used-ring byte
    };
    for (const virtio::Gpa at : hits) {
        BOOST_REQUIRE(driver->bring_up(features, {0}));
        fn->memory_changing(at, 1);
        BOOST_TEST(!fn->live(), "at " << at);
        BOOST_TEST((fn->status() & virtio::status_device_needs_reset) != 0);
    }
    // A wide range that covers everything.
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    fn->memory_changing(0, ~std::uint64_t{0});
    BOOST_TEST(!fn->live());
}

BOOST_FIXTURE_TEST_CASE(poll_reaches_the_device_only_when_live, Fixture,
                        *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(!fn->poll());
    BOOST_REQUIRE(driver->bring_up(features, {0}));
    BOOST_TEST(!fn->poll());
    BOOST_TEST(device.polls == 1);
}
