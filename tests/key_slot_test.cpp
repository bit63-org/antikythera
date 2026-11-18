// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirements 2.2 and 2.3, design
// "KeySlot": one key per slot, zeroization on drop, and the page
// protections (locked, excluded from core dumps, wiped on fork) checked
// against the kernel's own view of the mapping in /proc/self/smaps.

#define BOOST_TEST_MODULE key_slot_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "oar/blk/key_slot.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "test_support.hpp"

// Lets BOOST_TEST print a KeySlotError when a comparison fails.
namespace ak::oar::blk {
auto operator<<(std::ostream& os, KeySlotError e) -> std::ostream& {
    return os << to_string(e);
}

// The test hook the design names: the raw page, read after drop().
struct KeySlotTestAccess {
    static auto page(const KeySlot& slot) -> std::span<const std::byte> {
        return {slot._page, slot._page_size};
    }
};
}  // namespace ak::oar::blk

namespace blk = ak::oar::blk;
using ak::test::unit_timeout_seconds;
using blk::KeySlot;
using blk::KeySlotError;
using blk::KeySlotTestAccess;

namespace {

// A key with distinct halves (XtsCipher rejects equal ones) and no zero
// byte, so "all zero" after drop() cannot be a coincidence.
auto test_key(std::uint8_t seed) -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key.at(i) = static_cast<std::byte>(((seed + i) % 255U) + 1U);
    }
    return key;
}

auto make_slot() -> KeySlot {
    auto slot = KeySlot::create();
    BOOST_REQUIRE_MESSAGE(slot.has_value(),
                          "KeySlot::create failed: " << blk::to_string(slot.error()));
    return std::move(*slot);
}

auto is_zero(std::span<const std::byte> bytes) -> bool {
    return std::ranges::all_of(bytes, [](std::byte b) { return b == std::byte{0}; });
}

// The VmFlags line of the /proc/self/smaps entry that contains `addr`.
auto vm_flags_of(const void* addr) -> std::string {
    const auto target = reinterpret_cast<std::uintptr_t>(addr);
    std::ifstream smaps{"/proc/self/smaps"};
    BOOST_REQUIRE(smaps.is_open());
    std::string line;
    bool in_entry = false;
    while (std::getline(smaps, line)) {
        // Entry headers start with "start-end ", in hex.
        const auto dash = line.find('-');
        const auto space = line.find(' ');
        if (dash != std::string::npos && space != std::string::npos && dash < space &&
            line.find_first_not_of("0123456789abcdef") == dash) {
            const auto start = std::stoull(line.substr(0, dash), nullptr, 16);
            const auto end = std::stoull(line.substr(dash + 1, space - dash - 1), nullptr, 16);
            in_entry = target >= start && target < end;
            continue;
        }
        if (in_entry && line.starts_with("VmFlags:")) {
            return line;
        }
    }
    BOOST_FAIL("no smaps entry for the key page");
    return {};
}

auto has_flag(const std::string& vm_flags, const std::string& flag) -> bool {
    std::istringstream words{vm_flags};
    std::string word;
    while (words >> word) {
        if (word == flag) {
            return true;
        }
    }
    return false;
}

// Runs `child` in a forked process and returns its exit status, or -1 if
// it did not exit normally.
template<typename F> auto run_in_child(F child) -> int {
    const pid_t pid = ::fork();
    BOOST_REQUIRE(pid >= 0);
    if (pid == 0) {
        ::_exit(child());
    }
    int status = 0;
    BOOST_REQUIRE(::waitpid(pid, &status, 0) == pid);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

BOOST_AUTO_TEST_CASE(new_slot_is_empty, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto slot = make_slot();
    BOOST_TEST(!slot.holds_key());
    const auto key = slot.key();
    BOOST_REQUIRE(!key.has_value());
    BOOST_TEST(key.error() == KeySlotError::empty);
    BOOST_TEST(is_zero(KeySlotTestAccess::page(slot)));
}

BOOST_AUTO_TEST_CASE(load_then_read_back, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto slot = make_slot();
    const auto key = test_key(1);
    BOOST_REQUIRE(slot.load(key).has_value());
    BOOST_TEST(slot.holds_key());
    const auto held = slot.key();
    BOOST_REQUIRE(held.has_value());
    BOOST_TEST(std::ranges::equal(*held, key));
}

BOOST_AUTO_TEST_CASE(second_load_is_refused, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto slot = make_slot();
    const auto first = test_key(1);
    const auto second = test_key(2);
    BOOST_REQUIRE(slot.load(first).has_value());
    const auto r = slot.load(second);
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error() == KeySlotError::occupied);
    // The held key is untouched.
    BOOST_TEST(std::ranges::equal(*slot.key(), first));
}

BOOST_AUTO_TEST_CASE(drop_zeroizes_the_page, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto slot = make_slot();
    BOOST_REQUIRE(slot.load(test_key(1)).has_value());
    BOOST_TEST(!is_zero(KeySlotTestAccess::page(slot)));

    slot.drop();
    BOOST_TEST(!slot.holds_key());
    BOOST_TEST(is_zero(KeySlotTestAccess::page(slot)));
    BOOST_TEST(slot.key().error() == KeySlotError::empty);

    // Dropping twice is harmless, and the slot takes a new key.
    slot.drop();
    const auto next = test_key(3);
    BOOST_REQUIRE(slot.load(next).has_value());
    BOOST_TEST(std::ranges::equal(*slot.key(), next));
}

BOOST_AUTO_TEST_CASE(page_is_locked_undumpable_and_wiped_on_fork,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto slot = make_slot();
    const auto flags = vm_flags_of(KeySlotTestAccess::page(slot).data());
    BOOST_TEST_INFO("smaps " << flags);
    BOOST_TEST(has_flag(flags, "lo"));  // VM_LOCKED: mlock
    BOOST_TEST(has_flag(flags, "dd"));  // VM_DONTDUMP: MADV_DONTDUMP
    BOOST_TEST(has_flag(flags, "wf"));  // VM_WIPEONFORK: MADV_WIPEONFORK
}

BOOST_AUTO_TEST_CASE(forked_child_sees_no_key, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto slot = make_slot();
    BOOST_REQUIRE(slot.load(test_key(1)).has_value());
    const auto page = KeySlotTestAccess::page(slot);
    // Exit 0 only if the child's copy of the page is all zero.
    const int status = run_in_child([page] { return is_zero(page) ? 0 : 1; });
    BOOST_TEST(status == 0);
    // The parent still holds the key.
    BOOST_TEST(std::ranges::equal(*slot.key(), test_key(1)));
}

BOOST_AUTO_TEST_CASE(move_transfers_the_key, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto a = make_slot();
    const auto key = test_key(1);
    BOOST_REQUIRE(a.load(key).has_value());

    KeySlot b{std::move(a)};
    BOOST_TEST(b.holds_key());
    BOOST_TEST(std::ranges::equal(*b.key(), key));
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the
    // moved-from state is specified.
    BOOST_TEST(!a.holds_key());
    BOOST_TEST(a.load(key).error() == KeySlotError::map_failed);
    a.drop();

    auto c = make_slot();
    BOOST_REQUIRE(c.load(test_key(2)).has_value());
    c = std::move(b);
    BOOST_TEST(std::ranges::equal(*c.key(), key));
    BOOST_TEST(!b.holds_key());
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
}

BOOST_AUTO_TEST_CASE(key_feeds_xts_cipher, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto slot = make_slot();
    const auto key = test_key(7);
    BOOST_REQUIRE(slot.load(key).has_value());

    auto from_slot = blk::XtsCipher::create(*slot.key(), blk::data_unit_512);
    auto from_raw = blk::XtsCipher::create(key, blk::data_unit_512);
    BOOST_REQUIRE(from_slot.has_value());
    BOOST_REQUIRE(from_raw.has_value());

    // The cipher keeps its own key schedule: dropping the slot afterwards
    // does not change what it computes.
    slot.drop();

    std::vector<std::byte> plain(blk::data_unit_512, std::byte{0x5a});
    std::vector<std::byte> a(plain.size());
    std::vector<std::byte> b(plain.size());
    BOOST_REQUIRE(from_slot->encrypt(42, plain, a).has_value());
    BOOST_REQUIRE(from_raw->encrypt(42, plain, b).has_value());
    BOOST_TEST(a == b);
    BOOST_TEST(a != plain);
}

BOOST_AUTO_TEST_CASE(harden_process_disables_core_dumps,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // In a child: PR_SET_DUMPABLE = 0 would stop debuggers attaching to
    // the test runner itself.
    const int status = run_in_child([] {
        if (!blk::harden_process().has_value()) {
            return 1;
        }
        rlimit core{};
        if (::getrlimit(RLIMIT_CORE, &core) != 0 || core.rlim_cur != 0 || core.rlim_max != 0) {
            return 2;
        }
        if (::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
            return 3;
        }
        return 0;
    });
    BOOST_TEST(status == 0);
}

BOOST_AUTO_TEST_CASE(error_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(std::string{blk::to_string(KeySlotError::occupied)} == "occupied");
    BOOST_TEST(std::string{blk::to_string(KeySlotError::lock_failed)} == "lock_failed");
}
