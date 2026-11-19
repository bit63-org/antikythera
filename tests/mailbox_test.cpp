// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 1 and 10.1.

#define BOOST_TEST_MODULE mailbox_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <optional>
#include <vector>

#include "common/wire.hpp"
#include "helm/mailbox.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::test::unit_timeout_seconds;
using mb::DecodeError;

namespace {

constexpr std::uint8_t signature_fill = 0xA5;
constexpr std::uint64_t first_seq = 1;
constexpr std::uint64_t later_seq = 77;

constexpr std::uint64_t sample_vm = 42;
constexpr std::uint16_t sample_vcpus = 4;
constexpr std::uint32_t sample_memory_mib = 8192;
constexpr std::uint8_t boot_volume = 1;
constexpr std::uint8_t boot_unknown = 9;
constexpr std::uint8_t reserved_zero = 0;
constexpr std::uint8_t reserved_set = 1;
constexpr std::uint16_t too_many_vcpus = 2000;
constexpr std::uint64_t destroy_vm_id = 5;
constexpr std::uint8_t unknown_destroy_flag = 0x02;

constexpr std::size_t documented_max_body = 160;
constexpr std::uint16_t documented_version = 3;
constexpr std::size_t documented_reserved_size = 4;

constexpr mb::KeyId sample_key = 1;
constexpr mb::KeyId rotated_key = 0xBEEF;
constexpr mb::ServerId sample_server = 7;
constexpr mb::ServerId wide_server = 0x0102'0304'0506'0708;
constexpr std::size_t documented_header_size = 32;

// Byte offsets inside the slot header (see mailbox.hpp).
constexpr std::size_t magic_offset = 0;
constexpr std::size_t version_offset = 4;
constexpr std::size_t type_offset = 6;
constexpr std::size_t body_len_offset = 16;
constexpr std::size_t key_id_offset = 18;
constexpr std::size_t reserved_offset = 20;
constexpr std::size_t last_reserved_offset = 23;
constexpr std::size_t server_id_offset = 24;

constexpr std::byte not_magic{'X'};
constexpr std::byte retired_version{2};
constexpr std::byte future_version{4};
constexpr std::byte unknown_type_byte{0xEE};
constexpr std::byte nonzero{1};

constexpr std::uint16_t inconsistent_body_len = 3;
constexpr std::size_t short_body_size = 2;

auto sig() -> std::array<std::byte, mb::signature_size> {
    std::array<std::byte, mb::signature_size> s{};
    s.fill(std::byte{signature_fill});
    return s;
}

auto create_vm_body(std::uint64_t vm, std::uint16_t vcpus, std::uint32_t mib,
                    std::uint8_t boot = boot_volume, std::uint8_t rsvd = reserved_zero)
    -> std::vector<std::byte> {
    std::vector<std::byte> b;
    ak::wire::Writer w{b};
    w.le64(vm);
    w.le16(vcpus);
    w.le32(mib);
    w.u8(boot);
    w.u8(rsvd);
    return b;
}

auto destroy_vm_body(std::uint64_t vm, std::uint8_t flags) -> std::vector<std::byte> {
    std::vector<std::byte> b;
    ak::wire::Writer w{b};
    w.le64(vm);
    w.u8(flags);
    return b;
}

// Commands get sample_key and sample_server by default; responses and
// events get neither.
auto slot_for(mb::Type type, std::span<const std::byte> body, std::uint64_t seq = first_seq,
              std::optional<mb::KeyId> key = std::nullopt,
              std::optional<mb::ServerId> server = std::nullopt) -> mb::Slot {
    mb::Header h;
    h.type = type;
    h.seq = seq;
    h.body_len = static_cast<std::uint16_t>(body.size());
    h.key_id = key.value_or(mb::is_command(type) ? sample_key : mb::no_key_id);
    h.server_id = server.value_or(mb::is_command(type) ? sample_server : mb::no_server_id);
    auto s = mb::encode(h, body, sig());
    BOOST_REQUIRE(s.has_value());
    return *s;
}

}  // namespace

BOOST_AUTO_TEST_CASE(layout_constants_fit_the_slot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    static_assert(mb::header_size + mb::max_body + mb::signature_size == mb::slot_size);
    static_assert(mb::reg::evt_slot + mb::slot_size <= mb::reg::bar0_size);
    BOOST_TEST(mb::max_body == documented_max_body);
    BOOST_TEST(mb::protocol_version == documented_version);
    BOOST_TEST(mb::header_key_id_offset == key_id_offset);
    BOOST_TEST(mb::header_reserved_offset == reserved_offset);
    BOOST_TEST(mb::header_reserved_size == documented_reserved_size);
    BOOST_TEST(mb::header_server_id_offset == server_id_offset);
    BOOST_TEST(mb::header_size == documented_header_size);
    static_assert(mb::header_reserved_offset + mb::header_reserved_size ==
                  mb::header_server_id_offset);
    static_assert(mb::header_server_id_offset + sizeof(mb::ServerId) == mb::header_size);
}

BOOST_AUTO_TEST_CASE(magic_is_akmb_in_little_endian,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto s = slot_for(mb::Type::list_vms, {});
    BOOST_TEST((s[magic_offset + 0] == std::byte{'A'}));
    BOOST_TEST((s[magic_offset + 1] == std::byte{'K'}));
    BOOST_TEST((s[magic_offset + 2] == std::byte{'M'}));
    BOOST_TEST((s[magic_offset + 3] == std::byte{'B'}));
}

BOOST_AUTO_TEST_CASE(round_trip_create_vm, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto body = create_vm_body(sample_vm, sample_vcpus, sample_memory_mib);
    const auto s = slot_for(mb::Type::create_vm, body, later_seq);
    auto msg = mb::decode(s);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.seq == later_seq);
    BOOST_TEST(mb::is_command(msg->header.type));
    BOOST_TEST((msg->signature == sig()));
    auto cmd = mb::decode_create_vm(*msg);
    BOOST_REQUIRE(cmd.has_value());
    BOOST_TEST(cmd->vm_id == sample_vm);
    BOOST_TEST(cmd->vcpus == sample_vcpus);
    BOOST_TEST(cmd->memory_mib == sample_memory_mib);
}

BOOST_AUTO_TEST_CASE(rejects_bad_header_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto s = slot_for(mb::Type::list_vms, {});

    auto bad_magic = s;
    bad_magic[magic_offset] = not_magic;
    BOOST_TEST((mb::decode(bad_magic).error() == DecodeError::bad_magic));

    auto v1 = s;
    v1[version_offset] = retired_version;
    BOOST_TEST((mb::decode(v1).error() == DecodeError::bad_version));

    auto v3 = s;
    v3[version_offset] = future_version;
    BOOST_TEST((mb::decode(v3).error() == DecodeError::bad_version));

    auto bad_type = s;
    bad_type[type_offset] = unknown_type_byte;
    bad_type[type_offset + 1] = unknown_type_byte;
    BOOST_TEST((mb::decode(bad_type).error() == DecodeError::unknown_type));

    auto long_body = s;
    long_body[body_len_offset] = std::byte{mb::max_body + 1};
    BOOST_TEST((mb::decode(long_body).error() == DecodeError::body_too_long));

    for (std::size_t off = reserved_offset; off <= last_reserved_offset; ++off) {
        auto reserved = s;
        reserved[off] = nonzero;
        BOOST_TEST((mb::decode(reserved).error() == DecodeError::reserved_not_zero));
    }
}

BOOST_AUTO_TEST_CASE(key_id_is_little_endian_in_the_signed_header,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto s = slot_for(mb::Type::list_vms, {}, first_seq, rotated_key);
    BOOST_TEST((s[key_id_offset] == std::byte{0xEF}));
    BOOST_TEST((s[key_id_offset + 1] == std::byte{0xBE}));
    static_assert(key_id_offset + sizeof(mb::KeyId) <= mb::signature_offset);

    auto msg = mb::decode(s);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.key_id == rotated_key);
}

BOOST_AUTO_TEST_CASE(commands_need_a_key_id, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A command slot with its key ID cleared does not decode.
    auto s = slot_for(mb::Type::destroy_vm, destroy_vm_body(destroy_vm_id, 0));
    s[key_id_offset] = std::byte{0};
    s[key_id_offset + 1] = std::byte{0};
    BOOST_TEST((mb::decode(s).error() == DecodeError::bad_key_id));

    // Nor will encode produce one.
    mb::Header h;
    h.type = mb::Type::list_vms;
    h.key_id = mb::no_key_id;
    h.server_id = sample_server;
    BOOST_TEST((mb::encode(h, {}, sig()).error() == DecodeError::bad_key_id));
}

BOOST_AUTO_TEST_CASE(responses_and_events_carry_no_key_id,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto type : {mb::Type::response, mb::Type::vm_exited, mb::Type::device_released,
                            mb::Type::host_fault, mb::Type::scrub_done}) {
        auto s = slot_for(type, {});
        BOOST_REQUIRE(mb::decode(s).has_value());
        BOOST_TEST(mb::decode(s)->header.key_id == mb::no_key_id);

        s[key_id_offset] = std::byte{sample_key};
        BOOST_TEST((mb::decode(s).error() == DecodeError::bad_key_id));

        mb::Header h;
        h.type = type;
        h.key_id = sample_key;
        BOOST_TEST((mb::encode(h, {}, sig()).error() == DecodeError::bad_key_id));
    }
}

BOOST_AUTO_TEST_CASE(server_id_is_little_endian_in_the_signed_header,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto s = slot_for(mb::Type::list_vms, {}, first_seq, sample_key, wide_server);
    for (std::size_t i = 0; i < sizeof(mb::ServerId); ++i) {
        BOOST_TEST((s[server_id_offset + i] == std::byte(sizeof(mb::ServerId) - i)));
    }
    static_assert(server_id_offset + sizeof(mb::ServerId) <= mb::signature_offset);

    auto msg = mb::decode(s);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.server_id == wide_server);
}

BOOST_AUTO_TEST_CASE(commands_need_a_server_id, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto s = slot_for(mb::Type::destroy_vm, destroy_vm_body(destroy_vm_id, 0));
    s[server_id_offset] = std::byte{0};
    BOOST_TEST((mb::decode(s).error() == DecodeError::bad_server_id));

    mb::Header h;
    h.type = mb::Type::list_vms;
    h.key_id = sample_key;
    h.server_id = mb::no_server_id;
    BOOST_TEST((mb::encode(h, {}, sig()).error() == DecodeError::bad_server_id));
}

BOOST_AUTO_TEST_CASE(responses_and_events_carry_no_server_id,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto type : {mb::Type::response, mb::Type::vm_exited, mb::Type::device_released,
                            mb::Type::host_fault, mb::Type::scrub_done}) {
        auto s = slot_for(type, {});
        BOOST_TEST(mb::decode(s)->header.server_id == mb::no_server_id);
        s[server_id_offset + sizeof(mb::ServerId) - 1] = nonzero;
        BOOST_TEST((mb::decode(s).error() == DecodeError::bad_server_id));

        mb::Header h;
        h.type = type;
        h.server_id = sample_server;
        BOOST_TEST((mb::encode(h, {}, sig()).error() == DecodeError::bad_server_id));
    }
}

BOOST_AUTO_TEST_CASE(rejects_hidden_bytes_after_body,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto body = create_vm_body(sample_vm, sample_vcpus, sample_memory_mib);
    auto s = slot_for(mb::Type::create_vm, body);
    s[mb::header_size + body.size()] = nonzero;
    BOOST_TEST((mb::decode(s).error() == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(create_vm_validates_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto check = [](const std::vector<std::byte>& body, mb::BodyError want) {
        auto msg = mb::decode(slot_for(mb::Type::create_vm, body));
        BOOST_REQUIRE(msg.has_value());
        auto r = mb::decode_create_vm(*msg);
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST((r.error() == want));
    };
    check(create_vm_body(0, sample_vcpus, sample_memory_mib), mb::BodyError::invalid_field);
    check(create_vm_body(sample_vm, 0, sample_memory_mib), mb::BodyError::invalid_field);
    check(create_vm_body(sample_vm, too_many_vcpus, sample_memory_mib),
          mb::BodyError::invalid_field);
    check(create_vm_body(sample_vm, sample_vcpus, 0), mb::BodyError::invalid_field);
    check(create_vm_body(sample_vm, sample_vcpus, sample_memory_mib, boot_unknown),
          mb::BodyError::invalid_field);
    check(create_vm_body(sample_vm, sample_vcpus, sample_memory_mib, boot_volume, reserved_set),
          mb::BodyError::invalid_field);
    auto short_body = create_vm_body(sample_vm, sample_vcpus, sample_memory_mib);
    short_body.pop_back();
    check(short_body, mb::BodyError::wrong_length);
}

BOOST_AUTO_TEST_CASE(destroy_vm_flags, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto msg = mb::decode(slot_for(
        mb::Type::destroy_vm, destroy_vm_body(destroy_vm_id, mb::destroy_flag_persist_volumes)));
    BOOST_REQUIRE(msg.has_value());
    auto cmd = mb::decode_destroy_vm(*msg);
    BOOST_REQUIRE(cmd.has_value());
    BOOST_TEST(cmd->persist_volumes);

    msg = mb::decode(
        slot_for(mb::Type::destroy_vm, destroy_vm_body(destroy_vm_id, unknown_destroy_flag)));
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST((mb::decode_destroy_vm(*msg).error() == mb::BodyError::invalid_field));
    BOOST_TEST((mb::decode_create_vm(*msg).error() == mb::BodyError::wrong_type));
}

BOOST_AUTO_TEST_CASE(encode_rejects_inconsistent_body_len,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mb::Header h;
    h.type = mb::Type::list_vms;
    h.body_len = inconsistent_body_len;
    std::vector<std::byte> body(short_body_size);
    BOOST_TEST(!mb::encode(h, body, sig()).has_value());
}
