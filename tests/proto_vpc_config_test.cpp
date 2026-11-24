// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 10 (task 14): the signed
// VpcConfig frame, its layout, its rules both ways, and signing.

#define BOOST_TEST_MODULE proto_vpc_config_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/wire.hpp"
#include "ed25519_test_support.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/link.hpp"
#include "proto/vpc_config.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;
using proto::RouteFamily;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 1;
constexpr std::uint32_t sample_vni = 0x00AB'CDEF;
constexpr std::size_t off_flags = 0x14;
constexpr std::size_t off_ipv4_length = 0x15;
constexpr std::size_t off_dns4_count = 0x16;
constexpr std::size_t off_version_field = 0x18;
constexpr std::size_t off_gateway_mac = 0x20;
constexpr std::size_t off_domain_size = 0x26;
constexpr std::size_t off_reserved1 = 0x27;
constexpr std::size_t off_ipv4_prefix = 0x28;
constexpr std::size_t off_ipv6_prefix = 0x30;
constexpr std::size_t off_lease = 0x40;
constexpr std::size_t off_route_count = 0x44;
constexpr std::size_t off_reserved2 = 0x46;
constexpr std::size_t off_dns = 0x48;

auto v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> proto::Ipv4Address {
    return {std::byte{a}, std::byte{b}, std::byte{c}, std::byte{d}};
}

auto v6(std::uint8_t first, std::uint8_t second, std::uint8_t last) -> proto::Ipv6Address {
    proto::Ipv6Address a{};
    a[0] = std::byte{first};
    a[1] = std::byte{second};
    a[15] = std::byte{last};
    return a;
}

auto route4(proto::Ipv4Address prefix, std::uint8_t length, std::uint64_t nic) -> proto::VpcRoute {
    proto::VpcRoute r{
        .family = RouteFamily::ipv4, .length = length, .prefix = {}, .target_nic = nic};
    std::ranges::copy(prefix, r.prefix.begin());
    return r;
}

// Every section populated.
auto full() -> proto::VpcConfigFrame {
    proto::VpcConfigFrame c{};
    c.server_id = sample_server;
    c.key_id = sample_key;
    c.vni = sample_vni;
    c.config_version = 7;
    c.gateway_mac = {std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
                     std::byte{0x00}, std::byte{0xFF}, std::byte{0x01}};
    c.ipv4_prefix = v4(10, 0, 0, 0);
    c.ipv4_length = 16;
    c.ipv4_gateway = v4(10, 0, 0, 1);
    c.has_ipv6 = true;
    c.ipv6_prefix = v6(0xFD, 0x10, 0);
    c.dns4 = {v4(10, 0, 0, 2), v4(1, 1, 1, 1)};
    c.dns6 = {v6(0xFD, 0x10, 2)};
    c.domain = "ec2.internal";
    c.lease_seconds = 3600;
    c.routes = {route4(v4(0, 0, 0, 0), 0, 0x21),
                route4(v4(192, 168, 0, 0), 24, 0x22),
                {.family = RouteFamily::ipv6,
                 .length = 48,
                 .prefix = v6(0xFD, 0x20, 0),
                 .target_nic = 0x23}};
    return c;
}

// Only what every config needs.
auto minimal() -> proto::VpcConfigFrame {
    proto::VpcConfigFrame c{};
    c.server_id = sample_server;
    c.key_id = sample_key;
    c.vni = sample_vni;
    c.config_version = 1;
    c.gateway_mac = {std::byte{0x02}, std::byte{0}, std::byte{0},
                     std::byte{0},    std::byte{0}, std::byte{0xFE}};
    c.ipv4_prefix = v4(172, 16, 0, 0);
    c.ipv4_length = 12;
    c.ipv4_gateway = v4(172, 16, 0, 1);
    c.lease_seconds = proto::min_vpc_lease_seconds;
    return c;
}

auto encoded(const proto::VpcConfigFrame& c) -> std::vector<std::byte> {
    auto b = proto::encode_vpc_config(c);
    BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : proto::to_string(b.error())));
    return *b;
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto r = proto::decode_vpc_config(b);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto encode_error(const proto::VpcConfigFrame& c) -> DecodeError {
    auto r = proto::encode_vpc_config(c);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto le_at(std::span<const std::byte> b, std::size_t off, std::size_t n) -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = n; i-- > 0;) {
        v = (v << 8U) | std::to_integer<std::uint64_t>(b[off + i]);
    }
    return v;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(vpc_config, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips) {
    for (auto c : {full(), minimal()}) {
        c.signature.fill(std::byte{0x5A});
        const auto b = encoded(c);
        BOOST_TEST(b.size() == proto::vpc_config_size(c.dns4.size(), c.dns6.size(), c.routes.size(),
                                                      c.domain.size()));
        auto back = proto::decode_vpc_config(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == c));
    }
    BOOST_TEST(encoded(minimal()).size() == proto::min_vpc_config_size);
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian) {
    const auto c = full();
    const auto b = encoded(c);
    BOOST_TEST(std::to_integer<int>(b[0]) == 'A');
    BOOST_TEST(std::to_integer<int>(b[2]) == 'V');
    BOOST_TEST(std::to_integer<int>(b[3]) == 'C');
    BOOST_TEST(le_at(b, 4, 2) == proto::vpc_config_version);
    BOOST_TEST(le_at(b, 0x08, 8) == sample_server);
    BOOST_TEST(le_at(b, 0x10, 4) == sample_vni);
    BOOST_TEST(std::to_integer<int>(b[off_flags]) == 1);
    BOOST_TEST(std::to_integer<int>(b[off_ipv4_length]) == 16);
    BOOST_TEST(std::to_integer<int>(b[off_dns4_count]) == 2);
    BOOST_TEST(std::to_integer<int>(b[off_dns4_count + 1]) == 1);
    BOOST_TEST(le_at(b, off_version_field, 8) == 7U);
    BOOST_TEST(std::to_integer<int>(b[off_gateway_mac + 5]) == 1);
    BOOST_TEST(std::to_integer<int>(b[off_domain_size]) == 12);
    BOOST_TEST(std::to_integer<int>(b[off_ipv4_prefix]) == 10);
    BOOST_TEST(std::to_integer<int>(b[off_ipv6_prefix + 1]) == 0x10);
    BOOST_TEST(le_at(b, off_lease, 4) == 3600U);
    BOOST_TEST(le_at(b, off_route_count, 2) == 3U);
    // dns4, dns6, routes, then the domain right before the signature.
    BOOST_TEST(std::to_integer<int>(b[off_dns + 3]) == 2);
    const std::size_t routes = off_dns + (2 * 4) + 16;
    BOOST_TEST(le_at(b, routes, 8) == 0x21U);
    BOOST_TEST(std::to_integer<int>(b[routes + 8]) == 4);
    BOOST_TEST(std::to_integer<int>(b[routes + 32 + 9]) == 24);
    const std::size_t domain = routes + (3 * proto::vpc_route_size);
    BOOST_TEST(std::string_view(reinterpret_cast<const char*>(&b[domain]), 12) == "ec2.internal");
    BOOST_TEST(proto::vpc_config_signed_bytes(b).size() == b.size() - 64);
}

// The largest frame fits a link record (and, checked with the OarLink
// bodies, one sideband message).
BOOST_AUTO_TEST_CASE(the_largest_frame_fits_a_record) {
    static_assert(proto::max_vpc_config_size <= proto::max_record_payload);
    auto c = full();
    c.dns4.assign(proto::max_vpc_dns, v4(10, 0, 0, 2));
    c.dns6.assign(proto::max_vpc_dns, v6(0xFD, 0x10, 2));
    c.domain = std::string(63, 'a') + "." + std::string(63, 'b') + "." + std::string(63, 'c') +
               "." + std::string(61, 'd');
    BOOST_REQUIRE(c.domain.size() == proto::max_vpc_domain_size);
    c.routes.clear();
    for (std::size_t i = 0; i < proto::max_vpc_routes; ++i) {
        c.routes.push_back(route4(v4(10, static_cast<std::uint8_t>(i), 0, 0), 16, i + 1));
    }
    BOOST_TEST(encoded(c).size() == proto::max_vpc_config_size);
    BOOST_TEST(proto::encode_record(proto::RecordType::vpc_config, encoded(c)).has_value());
    c.routes.push_back(route4(v4(11, 0, 0, 0), 8, 1));
    BOOST_TEST((encode_error(c) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(header_rules) {
    auto c = full();
    c.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(c) == DecodeError::bad_key_id));
    c = full();
    c.server_id = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_server_id));
    c = full();
    c.vni = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_vni));
    c.vni = proto::max_vni + 1;
    BOOST_TEST((encode_error(c) == DecodeError::bad_vni));
    c = full();
    c.config_version = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_config_version));
    c = full();
    c.gateway_mac[0] = std::byte{0x03};  // group
    BOOST_TEST((encode_error(c) == DecodeError::bad_mac));
    c.gateway_mac[0] = std::byte{0x00};  // universally administered
    BOOST_TEST((encode_error(c) == DecodeError::bad_mac));
}

BOOST_AUTO_TEST_CASE(address_rules) {
    struct Case {
        const char* what;
        void (*change)(proto::VpcConfigFrame&);
        DecodeError want;
    };
    const Case cases[] = {
        {"prefix too short", [](auto& c) { c.ipv4_length = 7; }, DecodeError::bad_vpc_config},
        {"prefix too long", [](auto& c) { c.ipv4_length = 31; }, DecodeError::bad_vpc_config},
        {"prefix past 32 bits", [](auto& c) { c.ipv4_length = 250; }, DecodeError::bad_vpc_config},
        {"host bits", [](auto& c) { c.ipv4_prefix = v4(10, 0, 0, 1); },
         DecodeError::bad_vpc_config},
        {"gateway outside", [](auto& c) { c.ipv4_gateway = v4(10, 1, 0, 1); },
         DecodeError::bad_vpc_config},
        {"gateway is the network", [](auto& c) { c.ipv4_gateway = v4(10, 0, 0, 0); },
         DecodeError::bad_vpc_config},
        {"gateway is broadcast", [](auto& c) { c.ipv4_gateway = v4(10, 0, 255, 255); },
         DecodeError::bad_vpc_config},
        {"ipv6 not a /64", [](auto& c) { c.ipv6_prefix[8] = std::byte{1}; },
         DecodeError::bad_vpc_config},
        {"ipv6 link-local", [](auto& c) { c.ipv6_prefix = v6(0xFE, 0x80, 0); },
         DecodeError::bad_vpc_config},
        {"ipv6 multicast", [](auto& c) { c.ipv6_prefix = v6(0xFF, 0x02, 0); },
         DecodeError::bad_vpc_config},
        {"ipv6 unspecified", [](auto& c) { c.ipv6_prefix = {}; }, DecodeError::bad_vpc_config},
        {"ipv6 prefix without the flag", [](auto& c) { c.has_ipv6 = false; },
         DecodeError::bad_vpc_config},
        {"five DNS servers", [](auto& c) { c.dns4.assign(5, v4(10, 0, 0, 2)); },
         DecodeError::too_many_addresses},
        {"DNS 0.0.0.0", [](auto& c) { c.dns4[0] = v4(0, 0, 0, 0); },
         DecodeError::bad_guest_address},
        {"DNS multicast", [](auto& c) { c.dns4[0] = v4(224, 0, 0, 1); },
         DecodeError::bad_guest_address},
        {"DNS6 multicast", [](auto& c) { c.dns6[0] = v6(0xFF, 0x02, 1); },
         DecodeError::bad_guest_address},
        {"domain label too long", [](auto& c) { c.domain = std::string(64, 'a'); },
         DecodeError::bad_vpc_config},
        {"domain empty label", [](auto& c) { c.domain = "ec2..internal"; },
         DecodeError::bad_vpc_config},
        {"domain hyphen edge", [](auto& c) { c.domain = "-ec2.internal"; },
         DecodeError::bad_vpc_config},
        {"domain bad char", [](auto& c) { c.domain = "ec2_internal"; },
         DecodeError::bad_vpc_config},
        {"lease too short", [](auto& c) { c.lease_seconds = 59; }, DecodeError::bad_vpc_config},
        {"lease too long", [](auto& c) { c.lease_seconds = 0x8000'0000U; },
         DecodeError::bad_vpc_config},
    };
    for (const auto& k : cases) {
        auto c = full();
        k.change(c);
        BOOST_TEST_CONTEXT(k.what) {
            BOOST_TEST((encode_error(c) == k.want));
        }
    }
}

BOOST_AUTO_TEST_CASE(route_rules) {
    auto c = full();
    c.routes[1].target_nic = 0;
    BOOST_TEST((encode_error(c) == DecodeError::bad_nic_id));
    c.routes[1].target_nic = proto::vpc_route_nic_broadcast;
    BOOST_TEST((encode_error(c) == DecodeError::bad_nic_id));
    c = full();
    c.routes[1].length = 16;  // 192.168.0.0/16 has no host bits: fine
    BOOST_TEST(proto::encode_vpc_config(c).has_value());
    c.routes[1].length = 33;
    BOOST_TEST((encode_error(c) == DecodeError::bad_route));
    c = full();
    c.routes[1] = route4(v4(192, 168, 0, 1), 24, 0x22);  // host bits
    BOOST_TEST((encode_error(c) == DecodeError::bad_route));
    c = full();
    c.routes[1].prefix[4] = std::byte{1};  // past an IPv4 prefix
    BOOST_TEST((encode_error(c) == DecodeError::bad_route));
    c = full();
    c.routes[2].length = 129;
    BOOST_TEST((encode_error(c) == DecodeError::bad_route));
    c = full();
    c.routes[2].length = 8;  // fd20::/8 has host bits
    BOOST_TEST((encode_error(c) == DecodeError::bad_route));
    c = full();
    c.routes[2].family = static_cast<RouteFamily>(5);
    BOOST_TEST((encode_error(c) == DecodeError::unknown_value));

    // Strictly ascending by (family, prefix, length): no duplicates, no
    // reordering; the same prefix at two lengths is two routes.
    c = full();
    std::swap(c.routes[0], c.routes[1]);
    BOOST_TEST((encode_error(c) == DecodeError::not_ascending));
    c = full();
    c.routes[1] = c.routes[0];
    BOOST_TEST((encode_error(c) == DecodeError::not_ascending));
    c = full();
    c.routes.insert(c.routes.begin() + 2, route4(v4(192, 168, 0, 0), 25, 0x24));
    BOOST_TEST(proto::encode_vpc_config(c).has_value());
}

BOOST_AUTO_TEST_CASE(strict_framing) {
    const auto good = encoded(full());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST_CONTEXT("length " << n) {
            BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
        }
    }
    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((decode_error(longer) == DecodeError::trailing_bytes));
    BOOST_TEST((decode_error(std::vector<std::byte>(proto::max_vpc_config_size + 1)) ==
                DecodeError::trailing_bytes));
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    for (const std::size_t off : {off_reserved1, off_reserved2, off_reserved2 + 1}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    }
    b = good;
    b[off_flags] = std::byte{0x03};  // an undefined flag
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    const std::size_t routes = off_dns + (2 * 4) + 16;
    b = good;
    b[routes + 0x0A] = std::byte{1};  // a route's reserved bytes
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_dns4_count] = std::byte{5};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_addresses));
    b = good;
    b[off_route_count] = std::byte{101};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    b[off_domain_size] = std::byte{254};
    BOOST_TEST((decode_error(b) == DecodeError::bad_vpc_config));
}

// Signed like the controller signs it, verified like oar-net verifies it:
// every byte before the signature is covered.
BOOST_AUTO_TEST_CASE(signature_covers_the_config) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(sample_key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());

    auto frame = encoded(full());
    proto::set_vpc_config_signature(frame, signer.sign(proto::vpc_config_signed_bytes(frame)));
    const auto decoded = proto::decode_vpc_config(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(
        verifier->verify(proto::vpc_config_signed_bytes(frame), decoded->signature, decoded->key_id)
            .has_value());

    // Pointing the default route somewhere else after signing breaks it,
    // and so does changing the last byte of the domain.
    for (const std::size_t off : {off_dns + (2 * 4) + 16, frame.size() - 65}) {
        auto tampered = frame;
        tampered[off] ^= std::byte{0x01};
        const auto t = proto::decode_vpc_config(tampered);
        BOOST_REQUIRE(t.has_value());
        BOOST_TEST(
            !verifier->verify(proto::vpc_config_signed_bytes(tampered), t->signature, t->key_id)
                 .has_value());
    }
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e :
         {DecodeError::bad_config_version, DecodeError::bad_vpc_config, DecodeError::bad_route}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
