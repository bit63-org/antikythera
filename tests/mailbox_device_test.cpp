// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ task 8, Requirement 1: the BAR0 register
// file. The slot is complete before the doorbell and interrupt (1.3), a
// failed interrupt withdraws the command, the host can write only its own
// slots, and access widths and alignment are enforced.

#define BOOST_TEST_MODULE mailbox_device_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

#include "common/wire.hpp"
#include "helm/mailbox.hpp"
#include "helm/mailbox_device.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::helm::HostSlotKind;
using ak::helm::MailboxDevice;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::size_t word = 4;
constexpr std::uint32_t ignored_value = 0xDEAD'BEEF;
constexpr std::byte fill_a{0xA5};
constexpr std::byte fill_b{0x5A};
constexpr int post_rounds = 2000;

struct Fixture {
    bool irq_ok{true};
    int irqs{0};
    std::vector<std::pair<HostSlotKind, mb::Slot>> host_slots;
    MailboxDevice device{
        [this] {
            ++irqs;
            return irq_ok;
        },
        [this](HostSlotKind kind, const mb::Slot& slot) { host_slots.emplace_back(kind, slot); }};

    auto read32(std::size_t offset) -> std::uint32_t {
        std::array<std::byte, word> b{};
        BOOST_REQUIRE(device.read(offset, b));
        ak::wire::Reader r{b};
        return *r.le32();
    }
    auto write32(std::size_t offset, std::uint32_t v) -> bool {
        std::array<std::byte, word> b{};
        ak::wire::SpanWriter w{b};
        (void)w.write(v, ak::wire::Order::little);
        return device.write(offset, b);
    }
    auto read_slot(std::size_t base) -> mb::Slot {
        mb::Slot s{};
        for (std::size_t off = 0; off < mb::slot_size; off += 8) {
            BOOST_REQUIRE(device.read(base + off, std::span{s}.subspan(off, 8)));
        }
        return s;
    }
    auto write_slot(std::size_t base, std::byte fill) -> void {
        for (std::size_t off = 0; off < mb::slot_size; off += word) {
            const std::array b{fill, fill, fill, fill};
            BOOST_REQUIRE(device.write(base + off, b));
        }
    }
};

auto filled(std::byte b) -> mb::Slot {
    mb::Slot s{};
    s.fill(b);
    return s;
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(mailbox_device, Fixture)

BOOST_AUTO_TEST_CASE(identity_registers, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(read32(mb::reg::magic) == mb::magic);
    BOOST_TEST(read32(mb::reg::version) == mb::protocol_version);
    BOOST_TEST(read32(mb::reg::cmd_doorbell) == 0U);
    // Write-only doorbells and unassigned space read as zero.
    BOOST_TEST(read32(mb::reg::rsp_doorbell) == 0U);
    BOOST_TEST(read32(mb::reg::evt_doorbell) == 0U);
    BOOST_TEST(read32(0x0F0) == 0U);
    BOOST_TEST(read32(mb::reg::bar0_size - word) == 0U);
    // Narrow reads see the same little-endian bytes.
    std::array<std::byte, 1> one{};
    BOOST_REQUIRE(device.read(mb::reg::magic, one));
    BOOST_TEST((one[0] == std::byte{'A'}));
    std::array<std::byte, 8> eight{};
    BOOST_REQUIRE(device.read(mb::reg::magic, eight));
    ak::wire::Reader r{eight};
    BOOST_TEST(*r.le32() == mb::magic);
    BOOST_TEST(*r.le32() == mb::protocol_version);
}

BOOST_AUTO_TEST_CASE(post_command_writes_slot_then_rings,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(device.post_command(filled(fill_a)));
    BOOST_TEST(irqs == 1);
    BOOST_TEST(read32(mb::reg::cmd_doorbell) == 1U);
    BOOST_TEST((read_slot(mb::reg::cmd_slot) == filled(fill_a)));
    BOOST_REQUIRE(device.post_command(filled(fill_b)));
    BOOST_TEST(irqs == 2);
    BOOST_TEST(read32(mb::reg::cmd_doorbell) == 2U);
    BOOST_TEST((read_slot(mb::reg::cmd_slot) == filled(fill_b)));
    BOOST_TEST(device.stats().commands_posted == 2U);
}

BOOST_AUTO_TEST_CASE(failed_interrupt_withdraws_command,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(device.post_command(filled(fill_a)));
    irq_ok = false;
    BOOST_TEST(!device.post_command(filled(fill_b)));
    BOOST_TEST(read32(mb::reg::cmd_doorbell) == 1U);
    BOOST_TEST((read_slot(mb::reg::cmd_slot) == filled(fill_a)));
    BOOST_TEST(device.stats().commands_unposted == 1U);

    MailboxDevice no_trigger{{}, {}};
    BOOST_TEST(!no_trigger.post_command(filled(fill_a)));
}

BOOST_AUTO_TEST_CASE(host_writes_only_its_slots, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(device.post_command(filled(fill_a)));
    // Read-only registers and CMD_SLOT are dropped, not errors.
    BOOST_TEST(write32(mb::reg::magic, ignored_value));
    BOOST_TEST(write32(mb::reg::version, ignored_value));
    BOOST_TEST(write32(mb::reg::cmd_doorbell, ignored_value));
    BOOST_TEST(write32(mb::reg::cmd_slot, ignored_value));
    BOOST_TEST(write32(0x800, ignored_value));
    BOOST_TEST(read32(mb::reg::magic) == mb::magic);
    BOOST_TEST(read32(mb::reg::cmd_doorbell) == 1U);
    BOOST_TEST((read_slot(mb::reg::cmd_slot) == filled(fill_a)));
    BOOST_TEST(read32(0x800) == 0U);
    BOOST_TEST(device.stats().dropped_writes == 5U);
    BOOST_TEST(host_slots.empty());
}

BOOST_AUTO_TEST_CASE(doorbells_deliver_slot_copies,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    write_slot(mb::reg::rsp_slot, fill_a);
    write_slot(mb::reg::evt_slot, fill_b);
    BOOST_TEST(host_slots.empty());  // nothing until a doorbell
    BOOST_TEST((read_slot(mb::reg::rsp_slot) == filled(fill_a)));

    BOOST_TEST(write32(mb::reg::rsp_doorbell, ignored_value));
    BOOST_TEST(write32(mb::reg::evt_doorbell, 0));
    BOOST_REQUIRE(host_slots.size() == 2U);
    BOOST_TEST((host_slots[0].first == HostSlotKind::response));
    BOOST_TEST((host_slots[0].second == filled(fill_a)));
    BOOST_TEST((host_slots[1].first == HostSlotKind::event));
    BOOST_TEST((host_slots[1].second == filled(fill_b)));

    // The copy is taken at the doorbell: later slot writes do not change it.
    write_slot(mb::reg::rsp_slot, fill_b);
    BOOST_TEST((host_slots[0].second == filled(fill_a)));

    // A doorbell rung with any width but 32 bits is dropped.
    const std::array<std::byte, 2> half{};
    BOOST_TEST(device.write(mb::reg::rsp_doorbell, half));
    const std::array<std::byte, 8> wide{};
    BOOST_TEST(device.write(mb::reg::evt_doorbell & ~std::size_t{7}, wide));
    BOOST_TEST(host_slots.size() == 2U);
    BOOST_TEST(device.stats().responses == 1U);
    BOOST_TEST(device.stats().events == 1U);
}

BOOST_AUTO_TEST_CASE(rejects_bad_accesses, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::array<std::byte, 3> three{};
    std::array<std::byte, 4> four{};
    std::array<std::byte, 16> sixteen{};
    BOOST_TEST(!device.read(mb::reg::magic, three));             // width
    BOOST_TEST(!device.read(mb::reg::magic, sixteen));           // width
    BOOST_TEST(!device.read(mb::reg::magic + 2, four));          // alignment
    BOOST_TEST(!device.read(mb::reg::bar0_size, four));          // range
    BOOST_TEST(!device.write(mb::reg::rsp_slot + 1, four));      // alignment
    BOOST_TEST(!device.write(mb::reg::bar0_size + word, four));  // range
    BOOST_TEST(!device.read(mb::reg::magic, std::span<std::byte>{}));
    BOOST_TEST(device.stats().bad_accesses == 7U);
    BOOST_TEST(ak::helm::valid_bar0_access(mb::reg::bar0_size - 8, 8));
    BOOST_TEST(!ak::helm::valid_bar0_access(SIZE_MAX - 3, 4));
}

BOOST_AUTO_TEST_CASE(reset_clears_everything, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(device.post_command(filled(fill_a)));
    write_slot(mb::reg::rsp_slot, fill_a);
    write_slot(mb::reg::evt_slot, fill_b);
    device.reset();
    BOOST_TEST(read32(mb::reg::cmd_doorbell) == 0U);
    BOOST_TEST((read_slot(mb::reg::cmd_slot) == mb::Slot{}));
    BOOST_TEST((read_slot(mb::reg::rsp_slot) == mb::Slot{}));
    BOOST_TEST((read_slot(mb::reg::evt_slot) == mb::Slot{}));
    BOOST_TEST(read32(mb::reg::magic) == mb::magic);
    BOOST_TEST(device.stats().resets == 1U);
}

BOOST_AUTO_TEST_CASE(handler_may_post_from_callback,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // The host-slot handler runs without the lock, so a router that answers
    // a response by posting the next command does not deadlock.
    MailboxDevice* self = nullptr;
    int posted = 0;
    MailboxDevice dev{[] { return true; },
                      [&](HostSlotKind, const mb::Slot&) {
                          posted += self->post_command(filled(fill_b)) ? 1 : 0;
                      }};
    self = &dev;
    const std::array<std::byte, word> ring{};
    BOOST_TEST(dev.write(mb::reg::rsp_doorbell, ring));
    BOOST_TEST(posted == 1);
}

BOOST_AUTO_TEST_CASE(concurrent_posts_and_reads_stay_consistent,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A reader polling the doorbell must always find the slot that belongs
    // to it: slot n is filled with byte n, posted as the n-th command.
    MailboxDevice dev{[] { return true; }, {}};
    std::jthread poster{[&] {
        for (int n = 1; n <= post_rounds; ++n) {
            BOOST_REQUIRE(dev.post_command(filled(static_cast<std::byte>(n & 0xFF))));
        }
    }};
    std::uint32_t seen = 0;
    while (seen < static_cast<std::uint32_t>(post_rounds)) {
        std::array<std::byte, word> b{};
        BOOST_REQUIRE(dev.read(mb::reg::cmd_doorbell, b));
        ak::wire::Reader r{b};
        const std::uint32_t doorbell = *r.le32();
        std::array<std::byte, 8> head{};
        BOOST_REQUIRE(dev.read(mb::reg::cmd_slot, head));
        std::array<std::byte, word> again{};
        BOOST_REQUIRE(dev.read(mb::reg::cmd_doorbell, again));
        ak::wire::Reader r2{again};
        if (doorbell != 0 && *r2.le32() == doorbell) {
            BOOST_TEST((head[0] == static_cast<std::byte>(doorbell & 0xFF)));
        }
        seen = doorbell;
    }
}

BOOST_AUTO_TEST_SUITE_END()
