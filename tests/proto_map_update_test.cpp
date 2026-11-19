// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirements 4.2 and 5: the MapUpdate
// codec, its canonical form, and its strict decode.

#define BOOST_TEST_MODULE proto_map_update_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "proto/map_update.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 0x0A0B;
constexpr std::uint32_t sample_vni = 0x00AB'CDEF;
constexpr std::uint64_t sample_version = 0x1122'3344'5566'7788;
constexpr std::uint8_t sig_fill = 0x5A;
constexpr std::uint8_t local_unicast = 0x02;
constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::size_t last = 15;

// Offsets within the frame, for targeted corruption.
constexpr std::size_t off_key_id = 0x06;
constexpr std::size_t off_server_id = 0x08;
constexpr std::size_t off_vni = 0x10;
constexpr std::size_t off_count = 0x14;
constexpr std::size_t off_reserved = 0x16;
constexpr std::size_t off_version = 0x18;
constexpr std::size_t entry_mac = 0x08;
constexpr std::size_t entry_pad = 0x0E;
constexpr std::size_t entry_vtep = 0x10;

auto entry(std::uint64_t nic, std::uint8_t tag) -> proto::MapEntry {
    proto::MapEntry e{.nic_id = nic};
    e.mac[0] = std::byte{local_unicast};
    e.mac[proto::mac_size - 1] = std::byte{tag};
    e.owner_vtep[0] = std::byte{ula_prefix};
    e.owner_vtep[last] = std::byte{tag};
    return e;
}

auto sample(std::size_t n = 3) -> proto::MapUpdate {
    proto::MapUpdate m{.server_id = sample_server,
                       .key_id = sample_key,
                       .vni = sample_vni,
                       .map_version = sample_version,
                       .entries = {},
                       .signature = {}};
    for (std::size_t i = 0; i < n; ++i) {
        m.entries.push_back(entry(0x100 + (i * 2), static_cast<std::uint8_t>(i + 1)));
    }
    m.signature.fill(std::byte{sig_fill});
    return m;
}

auto encoded(const proto::MapUpdate& m = sample()) -> std::vector<std::byte> {
    auto bytes = proto::encode_map_update(m);
    BOOST_REQUIRE(bytes.has_value());
    return *bytes;
}

auto entry_at(std::size_t i) -> std::size_t {
    return proto::map_update_header_size + (i * proto::map_entry_size);
}

auto decode_error(const std::vector<std::byte>& b) -> DecodeError {
    auto m = proto::decode_map_update(b);
    BOOST_REQUIRE(!m.has_value());
    return m.error();
}

auto encode_error(const proto::MapUpdate& m) -> DecodeError {
    auto b = proto::encode_map_update(m);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(map_update, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(layout) {
    static_assert(proto::map_update_size(0) == 96);
    static_assert(proto::map_update_size(2) == 160);
    static_assert(proto::max_map_update_size == proto::map_update_size(proto::max_map_entries));
    const auto m = sample(1);
    const auto b = encoded(m);
    BOOST_REQUIRE_EQUAL(b.size(), proto::map_update_size(1));
    const auto header =
        ak::test::bytes_of('A', 'K', 'M', 'U', 0x01, 0x00, 0x0B, 0x0A, 0x08, 0x07, 0x06, 0x05, 0x04,
                           0x03, 0x02, 0x01, 0xEF, 0xCD, 0xAB, 0x00, 0x01, 0x00, 0x00, 0x00, 0x88,
                           0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11);
    BOOST_TEST(std::ranges::equal(std::span{b}.first(proto::map_update_header_size), header));
    const auto e = ak::test::bytes_of(0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0x01, 0, 0,
                                      0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01);
    BOOST_TEST(std::ranges::equal(std::span{b}.subspan(entry_at(0), proto::map_entry_size), e));
    BOOST_TEST(std::ranges::equal(std::span{b}.last(proto::ed25519_signature_size), m.signature));
}

BOOST_AUTO_TEST_CASE(round_trips_including_empty) {
    for (const std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{7}}) {
        const auto m = sample(n);
        const auto b = encoded(m);
        auto back = proto::decode_map_update(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == m));
        BOOST_TEST((encoded(*back) == b));
    }
}

BOOST_AUTO_TEST_CASE(maximum_entry_count_round_trips) {
    proto::MapUpdate m = sample(0);
    for (std::size_t i = 0; i < proto::max_map_entries; ++i) {
        m.entries.push_back(entry(i + 1, 1));
    }
    const auto b = encoded(m);
    BOOST_TEST(b.size() == proto::max_map_update_size);
    auto back = proto::decode_map_update(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->entries.size() == proto::max_map_entries);

    m.entries.push_back(entry(proto::max_map_entries + 1, 1));
    BOOST_TEST((encode_error(m) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(signed_bytes_are_all_but_the_signature) {
    auto b = encoded();
    const auto s = proto::map_update_signed_bytes(b);
    BOOST_TEST(s.data() == b.data());
    BOOST_TEST(s.size() == b.size() - proto::ed25519_signature_size);
    BOOST_TEST(proto::map_update_signed_bytes(std::span<const std::byte>{}).empty());

    std::array<std::byte, proto::ed25519_signature_size> sig{};
    sig.fill(std::byte{0x33});
    proto::set_map_update_signature(b, sig);
    auto back = proto::decode_map_update(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->signature == sig));
    BOOST_TEST(std::ranges::equal(proto::map_update_signed_bytes(b), s));
}

BOOST_AUTO_TEST_CASE(every_short_length_is_truncated) {
    const auto b = encoded();
    for (std::size_t n = 0; n < b.size(); ++n) {
        auto m = proto::decode_map_update(std::span{b}.first(n));
        BOOST_REQUIRE(!m.has_value());
        BOOST_TEST((m.error() == DecodeError::truncated), "length " << n);
    }
}

BOOST_AUTO_TEST_CASE(trailing_bytes_are_rejected) {
    auto b = encoded();
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(hostile_entry_count_is_rejected_before_allocation) {
    auto b = encoded(sample(0));
    b[off_count] = std::byte{0xFF};
    b[off_count + 1] = std::byte{0xFF};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    // A legal count with too few bytes behind it is truncation.
    b[off_count] = std::byte{0x00};
    b[off_count + 1] = std::byte{0x10};  // 4096
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(header_fields_are_checked) {
    auto b = encoded();
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));

    b = encoded();
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));

    b = encoded();
    b[off_key_id] = b[off_key_id + 1] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_key_id));

    b = encoded();
    std::fill_n(b.begin() + off_server_id, 8, std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_server_id));

    b = encoded();
    std::fill_n(b.begin() + off_vni, 4, std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_vni));
    b = encoded();
    b[off_vni + 3] = std::byte{0x01};  // 25th bit
    BOOST_TEST((decode_error(b) == DecodeError::bad_vni));

    b = encoded();
    b[off_reserved + 1] = std::byte{0x80};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));

    b = encoded();
    std::fill_n(b.begin() + off_version, 8, std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_map_version));

    auto m = sample();
    m.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(m) == DecodeError::bad_key_id));
    m = sample();
    m.server_id = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_server_id));
    m = sample();
    m.vni = proto::max_vni + 1;
    BOOST_TEST((encode_error(m) == DecodeError::bad_vni));
    m.vni = proto::max_vni;
    BOOST_TEST(proto::encode_map_update(m).has_value());
    m = sample();
    m.map_version = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_map_version));
}

BOOST_AUTO_TEST_CASE(entry_padding_must_be_zero) {
    for (std::size_t i = 0; i < 2; ++i) {
        auto b = encoded();
        b[entry_at(1) + entry_pad + i] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    }
}

BOOST_AUTO_TEST_CASE(nic_ids_are_non_zero_and_strictly_ascending) {
    auto m = sample();
    m.entries[0].nic_id = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_nic_id));

    m = sample();
    m.entries[2].nic_id = m.entries[1].nic_id;  // duplicate
    BOOST_TEST((encode_error(m) == DecodeError::nic_ids_not_ascending));

    m = sample();
    std::swap(m.entries[0], m.entries[1]);  // out of order
    BOOST_TEST((encode_error(m) == DecodeError::nic_ids_not_ascending));

    auto b = encoded();
    b[entry_at(2)] = b[entry_at(1)];  // NIC 0x104 -> 0x102, duplicating entry 1
    BOOST_TEST((decode_error(b) == DecodeError::nic_ids_not_ascending));
}

BOOST_AUTO_TEST_CASE(mac_must_be_locally_administered_unicast) {
    for (const std::uint8_t first : std::array<std::uint8_t, 5>{0x00, 0x03, 0x01, 0xFF, 0x04}) {
        auto m = sample();
        m.entries[1].mac[0] = std::byte{first};
        BOOST_TEST((encode_error(m) == DecodeError::bad_mac), "first octet " << int{first});
        auto b = encoded();
        b[entry_at(1) + entry_mac] = std::byte{first};
        BOOST_TEST((decode_error(b) == DecodeError::bad_mac));
    }
    for (const std::uint8_t first : std::array<std::uint8_t, 3>{0x02, 0x06, 0xFE}) {
        auto m = sample();
        m.entries[1].mac[0] = std::byte{first};
        BOOST_TEST(proto::encode_map_update(m).has_value(), "first octet " << int{first});
    }
}

BOOST_AUTO_TEST_CASE(owner_vtep_must_be_a_unicast_address) {
    auto m = sample();
    m.entries[0].owner_vtep = {};
    BOOST_TEST((encode_error(m) == DecodeError::bad_vtep));
    m = sample();
    m.entries[0].owner_vtep[0] = std::byte{0xFF};
    BOOST_TEST((encode_error(m) == DecodeError::bad_vtep));

    auto b = encoded();
    std::fill_n(b.begin() + static_cast<std::ptrdiff_t>(entry_at(2) + entry_vtep),
                proto::vtep_address_size, std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_vtep));

    // IPv4-mapped (::ffff:a.b.c.d) is a fine underlay address.
    m = sample();
    m.entries[0].owner_vtep = {};
    m.entries[0].owner_vtep[10] = m.entries[0].owner_vtep[11] = std::byte{0xFF};
    m.entries[0].owner_vtep[last] = std::byte{1};
    BOOST_TEST(proto::encode_map_update(m).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
