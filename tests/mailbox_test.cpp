// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE mailbox_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <vector>

#include "common/wire.hpp"
#include "helm/mailbox.hpp"

namespace mb = ak::helm::mailbox;
using mb::DecodeError;

namespace {

std::array<std::byte, mb::signature_size> sig(std::uint8_t fill = 0xA5) {
    std::array<std::byte, mb::signature_size> s{};
    s.fill(std::byte{fill});
    return s;
}

std::vector<std::byte> create_vm_body(std::uint64_t vm, std::uint16_t vcpus, std::uint32_t mib, std::uint8_t boot = 1,
                                      std::uint8_t rsvd = 0) {
    std::vector<std::byte> b;
    ak::wire::Writer w{b};
    w.le64(vm);
    w.le16(vcpus);
    w.le32(mib);
    w.u8(boot);
    w.u8(rsvd);
    return b;
}

mb::Slot slot_for(mb::Type type, std::span<const std::byte> body, std::uint64_t seq = 1) {
    mb::Header h;
    h.type = type;
    h.seq = seq;
    h.body_len = static_cast<std::uint16_t>(body.size());
    auto s = mb::encode(h, body, sig());
    BOOST_REQUIRE(s.has_value());
    return *s;
}

}  // namespace

BOOST_AUTO_TEST_CASE(layout_constants_fit_the_slot) {
    static_assert(mb::header_size + mb::max_body + mb::signature_size == mb::slot_size);
    static_assert(mb::reg::evt_slot + mb::slot_size <= mb::reg::bar0_size);
    BOOST_TEST(mb::max_body == 168u);
}

BOOST_AUTO_TEST_CASE(magic_is_akmb_in_little_endian) {
    const auto s = slot_for(mb::Type::list_vms, {});
    BOOST_TEST((s[0] == std::byte{'A'}));
    BOOST_TEST((s[1] == std::byte{'K'}));
    BOOST_TEST((s[2] == std::byte{'M'}));
    BOOST_TEST((s[3] == std::byte{'B'}));
}

BOOST_AUTO_TEST_CASE(round_trip_create_vm) {
    const auto body = create_vm_body(42, 4, 8192);
    const auto s = slot_for(mb::Type::create_vm, body, 77);
    auto msg = mb::decode(s);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.seq == 77u);
    BOOST_TEST(mb::is_command(msg->header.type));
    BOOST_TEST((msg->signature == sig()));
    auto cmd = mb::decode_create_vm(*msg);
    BOOST_REQUIRE(cmd.has_value());
    BOOST_TEST(cmd->vm_id == 42u);
    BOOST_TEST(cmd->vcpus == 4u);
    BOOST_TEST(cmd->memory_mib == 8192u);
}

BOOST_AUTO_TEST_CASE(rejects_bad_header_fields) {
    auto s = slot_for(mb::Type::list_vms, {});
    auto bad_magic = s;
    bad_magic[0] = std::byte{'X'};
    BOOST_TEST((mb::decode(bad_magic).error() == DecodeError::bad_magic));

    auto bad_version = s;
    bad_version[4] = std::byte{2};
    BOOST_TEST((mb::decode(bad_version).error() == DecodeError::bad_version));

    auto bad_type = s;
    bad_type[6] = std::byte{0xEE};
    bad_type[7] = std::byte{0xEE};
    BOOST_TEST((mb::decode(bad_type).error() == DecodeError::unknown_type));

    auto long_body = s;
    long_body[16] = std::byte{mb::max_body + 1};
    BOOST_TEST((mb::decode(long_body).error() == DecodeError::body_too_long));

    auto reserved = s;
    reserved[20] = std::byte{1};
    BOOST_TEST((mb::decode(reserved).error() == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(rejects_hidden_bytes_after_body) {
    const auto body = create_vm_body(42, 4, 8192);
    auto s = slot_for(mb::Type::create_vm, body);
    s[mb::header_size + body.size()] = std::byte{1};
    BOOST_TEST((mb::decode(s).error() == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(create_vm_validates_fields) {
    const auto check = [](std::vector<std::byte> body, mb::BodyError want) {
        auto msg = mb::decode(slot_for(mb::Type::create_vm, body));
        BOOST_REQUIRE(msg.has_value());
        auto r = mb::decode_create_vm(*msg);
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == want));
    };
    check(create_vm_body(0, 4, 8192), mb::BodyError::invalid_field);
    check(create_vm_body(1, 0, 8192), mb::BodyError::invalid_field);
    check(create_vm_body(1, 2000, 8192), mb::BodyError::invalid_field);
    check(create_vm_body(1, 4, 0), mb::BodyError::invalid_field);
    check(create_vm_body(1, 4, 8192, 9), mb::BodyError::invalid_field);
    check(create_vm_body(1, 4, 8192, 1, 1), mb::BodyError::invalid_field);
    auto short_body = create_vm_body(1, 4, 8192);
    short_body.pop_back();
    check(short_body, mb::BodyError::wrong_length);
}

BOOST_AUTO_TEST_CASE(destroy_vm_flags) {
    std::vector<std::byte> body;
    ak::wire::Writer w{body};
    w.le64(5);
    w.u8(0x01);
    auto msg = mb::decode(slot_for(mb::Type::destroy_vm, body));
    BOOST_REQUIRE(msg.has_value());
    auto cmd = mb::decode_destroy_vm(*msg);
    BOOST_REQUIRE(cmd.has_value());
    BOOST_TEST(cmd->persist_volumes);

    body.back() = std::byte{0x02};
    msg = mb::decode(slot_for(mb::Type::destroy_vm, body));
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST((mb::decode_destroy_vm(*msg).error() == mb::BodyError::invalid_field));
    BOOST_TEST((mb::decode_create_vm(*msg).error() == mb::BodyError::wrong_type));
}

BOOST_AUTO_TEST_CASE(encode_rejects_inconsistent_body_len) {
    mb::Header h;
    h.type = mb::Type::list_vms;
    h.body_len = 3;
    std::vector<std::byte> body(2);
    BOOST_TEST(!mb::encode(h, body, sig()).has_value());
}
