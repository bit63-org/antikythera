// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 3.6 (task 9): the OAM
// keepalive codec.

#define BOOST_TEST_MODULE oam_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

#include "oar/net/geneve.hpp"
#include "oar/net/oam.hpp"
#include "test_support.hpp"

namespace geneve = ak::oar::net::geneve;
namespace oam = ak::oar::net::oam;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using oam::OamError;

namespace {

constexpr std::uint64_t sample_sequence = 0x0102'0304'0506'0708;
constexpr std::size_t body_version_offset = geneve::base_header_size;
constexpr std::size_t body_type_offset = body_version_offset + 1;
constexpr std::size_t protocol_offset = 2;
constexpr std::size_t vni_offset = 4;

auto decode(const std::vector<std::byte>& bytes) -> geneve::Packet {
    auto p = geneve::decode(bytes);
    BOOST_REQUIRE(p.has_value());
    return *p;
}

auto parse_error(const std::vector<std::byte>& bytes) -> OamError {
    auto m = oam::parse(decode(bytes));
    BOOST_REQUIRE(!m.has_value());
    return m.error();
}

}  // namespace

BOOST_AUTO_TEST_CASE(keepalive_wire_image, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto bytes = oam::encode({.type = oam::Type::keepalive, .sequence = sample_sequence});
    const auto want = bytes_of(0x00, 0x80, 0x88, 0xB6,  // Ver 0, Opt Len 0, O; protocol
                               0x00, 0x00, 0x00, 0x00,  // VNI 0
                               0x01, 0x01, 0x00, 0x00,  // version, keepalive, reserved
                               0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08);
    BOOST_TEST(bytes == want);
    BOOST_TEST(bytes.size() == oam::message_size);
}

BOOST_AUTO_TEST_CASE(round_trip, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const oam::Message msg{.type = oam::Type::keepalive, .sequence = sample_sequence};
    const auto bytes = oam::encode(msg);
    const auto packet = decode(bytes);
    BOOST_TEST(packet.oam);
    BOOST_TEST(!packet.nics.has_value());
    auto parsed = oam::parse(packet);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_TEST((*parsed == msg));
}

BOOST_AUTO_TEST_CASE(reserved_bytes_ignored, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto bytes = oam::encode({.sequence = 1});
    bytes[body_type_offset + 1] = std::byte{0xAB};
    BOOST_TEST(oam::parse(decode(bytes)).has_value());
}

BOOST_AUTO_TEST_CASE(rejects_data_packets, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto frame = std::vector<std::byte>(geneve::ethernet_header_size, std::byte{0x02});
    auto data = geneve::encode({.vni = 1, .nics = {.src = {1}, .dst = {2}}}, frame);
    BOOST_REQUIRE(data.has_value());
    BOOST_TEST((parse_error(*data) == OamError::not_oam));
}

BOOST_AUTO_TEST_CASE(rejects_bad_headers, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto proto = oam::encode({.sequence = 1});
    proto[protocol_offset + 1] = std::byte{0xB5};
    BOOST_TEST((parse_error(proto) == OamError::bad_protocol));

    auto vni = oam::encode({.sequence = 1});
    vni[vni_offset + 2] = std::byte{0x01};
    BOOST_TEST((parse_error(vni) == OamError::nonzero_vni));
}

BOOST_AUTO_TEST_CASE(rejects_bad_bodies, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto good = oam::encode({.sequence = 1});

    for (std::size_t cut = geneve::base_header_size; cut < good.size(); ++cut) {
        const std::vector<std::byte> shorter(good.begin(), good.begin() + static_cast<long>(cut));
        BOOST_TEST((parse_error(shorter) == OamError::truncated));
    }

    auto ver = good;
    ver[body_version_offset] = std::byte{2};
    BOOST_TEST((parse_error(ver) == OamError::bad_version));

    auto type = good;
    type[body_type_offset] = std::byte{2};  // the future MTU probe
    BOOST_TEST((parse_error(type) == OamError::unknown_type));

    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((parse_error(longer) == OamError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(error_names, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (std::size_t i = 0; i < oam::oam_error_count; ++i) {
        BOOST_TEST(std::string{oam::to_string(static_cast<OamError>(i))} != "unknown");
    }
}
