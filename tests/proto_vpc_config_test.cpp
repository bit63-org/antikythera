// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 10 and
// .kiro/specs/vpc-subnets-routing/ Requirements 1, 2, 4 and 5 (task 2):
// the signed VpcConfig version 2 frame, its layout, its rules both ways,
// and signing.

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
using proto::RouteKind;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 1;
constexpr std::uint32_t sample_vni = 0x00AB'CDEF;
constexpr std::size_t off_block_count = 0x14;
constexpr std::size_t off_flags = 0x15;
constexpr std::size_t off_dns4_count = 0x16;
constexpr std::size_t off_version_field = 0x18;
constexpr std::size_t off_gateway_mac = 0x20;
constexpr std::size_t off_domain_size = 0x26;
constexpr std::size_t off_reserved1 = 0x27;
constexpr std::size_t off_lease = 0x28;
constexpr std::size_t off_subnet_count = 0x2C;
constexpr std::size_t off_table_count = 0x2E;
constexpr std::size_t off_route_count = 0x30;
constexpr std::size_t off_reserved2 = 0x32;
constexpr std::size_t off_ipv6_block = 0x38;
constexpr std::size_t off_blocks = 0x48;

auto v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> proto::Ipv4Address {
    return {std::byte{a}, std::byte{b}, std::byte{c}, std::byte{d}};
}

// 2001:db8:<third>:<fourth>::<last>, written bytewise.
auto v6(std::uint8_t third_hi, std::uint8_t third_lo, std::uint8_t fourth_lo, std::uint8_t last)
    -> proto::Ipv6Address {
    proto::Ipv6Address a{};
    a[0] = std::byte{0x20};
    a[1] = std::byte{0x01};
    a[2] = std::byte{0x0D};
    a[3] = std::byte{0xB8};
    a[4] = std::byte{third_hi};
    a[5] = std::byte{third_lo};
    a[7] = std::byte{fourth_lo};
    a[15] = std::byte{last};
    return a;
}

auto route4(RouteKind kind, proto::Ipv4Address prefix, std::uint8_t length, std::uint64_t nic)
    -> proto::VpcRoute {
    proto::VpcRoute r{.kind = kind,
                      .family = RouteFamily::ipv4,
                      .length = length,
                      .prefix = {},
                      .target_nic = nic};
    std::ranges::copy(prefix, r.prefix.begin());
    return r;
}

auto route6(RouteKind kind, const proto::Ipv6Address& prefix, std::uint8_t length,
            std::uint64_t nic) -> proto::VpcRoute {
    return {.kind = kind,
            .family = RouteFamily::ipv6,
            .length = length,
            .prefix = prefix,
            .target_nic = nic};
}

// The local routes every table carries in full(): one per block.
auto full_locals() -> std::vector<proto::VpcRoute> {
    return {route4(RouteKind::local, v4(10, 0, 0, 0), 16, 0),
            route4(RouteKind::local, v4(100, 64, 0, 0), 24, 0),
            route6(RouteKind::local, v6(0x12, 0x00, 0, 0), 56, 0)};
}

// Every section populated: two IPv4 blocks and an IPv6 /56, three subnets
// over two tables, the main table with a middlebox route and table 2 with
// a default route.
auto full() -> proto::VpcConfigFrame {
    proto::VpcConfigFrame c{};
    c.server_id = sample_server;
    c.key_id = sample_key;
    c.vni = sample_vni;
    c.config_version = 7;
    c.gateway_mac = {std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
                     std::byte{0x00}, std::byte{0xFF}, std::byte{0x01}};
    c.ipv4_blocks = {{.prefix = v4(10, 0, 0, 0), .length = 16},
                     {.prefix = v4(100, 64, 0, 0), .length = 24}};
    c.ipv6_block = v6(0x12, 0x00, 0, 0);
    c.dns4 = {v4(10, 0, 0, 2), v4(1, 1, 1, 1)};
    c.dns6 = {v6(0x12, 0x00, 1, 2)};
    c.domain = "ec2.internal";
    c.lease_seconds = 3600;
    c.subnets = {{.subnet_id = 0x11,
                  .table = 1,
                  .ipv4_prefix = v4(10, 0, 1, 0),
                  .ipv4_length = 24,
                  .ipv6_prefix = v6(0x12, 0x00, 1, 0)},
                 {.subnet_id = 0x12,
                  .table = 2,
                  .ipv4_prefix = v4(10, 0, 2, 0),
                  .ipv4_length = 24,
                  .ipv6_prefix = std::nullopt},
                 {.subnet_id = 0x13,
                  .table = 1,
                  .ipv4_prefix = v4(100, 64, 0, 16),
                  .ipv4_length = 28,
                  .ipv6_prefix = v6(0x12, 0x00, 3, 0)}};
    proto::VpcRouteTable main{.table = 1, .main = true, .routes = full_locals()};
    // 10.0.2.0/24 through the appliance: more specific than local.
    main.routes.insert(main.routes.begin() + 1, route4(RouteKind::nic, v4(10, 0, 2, 0), 24, 0x21));
    proto::VpcRouteTable two{.table = 2, .main = false, .routes = full_locals()};
    two.routes.insert(two.routes.begin(), route4(RouteKind::nic, v4(0, 0, 0, 0), 0, 0x22));
    c.tables = {main, two};
    return c;
}

// Only what every config needs: one block, one subnet, one main table
// with the block's local route.
auto minimal() -> proto::VpcConfigFrame {
    proto::VpcConfigFrame c{};
    c.server_id = sample_server;
    c.key_id = sample_key;
    c.vni = sample_vni;
    c.config_version = 1;
    c.gateway_mac = {std::byte{0x02}, std::byte{0}, std::byte{0},
                     std::byte{0},    std::byte{0}, std::byte{0xFE}};
    c.ipv4_blocks = {{.prefix = v4(172, 16, 0, 0), .length = 16}};
    c.lease_seconds = proto::min_vpc_lease_seconds;
    c.subnets = {{.subnet_id = 1,
                  .table = 0,
                  .ipv4_prefix = v4(172, 16, 0, 0),
                  .ipv4_length = 16,
                  .ipv6_prefix = std::nullopt}};
    c.tables = {
        {.table = 0, .main = true, .routes = {route4(RouteKind::local, v4(172, 16, 0, 0), 16, 0)}}};
    return c;
}

auto route_total(const proto::VpcConfigFrame& c) -> std::size_t {
    std::size_t n = 0;
    for (const auto& t : c.tables) {
        n += t.routes.size();
    }
    return n;
}

auto size_of(const proto::VpcConfigFrame& c) -> std::size_t {
    return proto::vpc_config_size(c.ipv4_blocks.size(), c.dns4.size(), c.dns6.size(),
                                  c.subnets.size(), c.tables.size(), route_total(c),
                                  c.domain.size());
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

// Offsets of full()'s lists.
constexpr std::size_t full_dns = off_blocks + (2 * proto::vpc_ipv4_block_size);
constexpr std::size_t full_subnets = full_dns + (2 * 4) + 16;
constexpr std::size_t full_tables = full_subnets + (3 * proto::vpc_subnet_size);
constexpr std::size_t full_routes = full_tables + (2 * proto::vpc_table_size);

}  // namespace

BOOST_AUTO_TEST_SUITE(vpc_config, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips) {
    for (auto c : {full(), minimal()}) {
        c.signature.fill(std::byte{0x5A});
        const auto b = encoded(c);
        BOOST_TEST(b.size() == size_of(c));
        auto back = proto::decode_vpc_config(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == c));
        BOOST_TEST((encoded(*back) == b));
    }
    BOOST_TEST(encoded(minimal()).size() == proto::min_vpc_config_size);
}

BOOST_AUTO_TEST_CASE(layout_is_little_endian) {
    const auto c = full();
    const auto b = encoded(c);
    BOOST_TEST(std::to_integer<int>(b[0]) == 'A');
    BOOST_TEST(std::to_integer<int>(b[2]) == 'V');
    BOOST_TEST(std::to_integer<int>(b[3]) == 'C');
    BOOST_TEST(le_at(b, 4, 2) == 2U);
    BOOST_TEST(le_at(b, 0x08, 8) == sample_server);
    BOOST_TEST(le_at(b, 0x10, 4) == sample_vni);
    BOOST_TEST(std::to_integer<int>(b[off_block_count]) == 2);
    BOOST_TEST(std::to_integer<int>(b[off_flags]) == 1);
    BOOST_TEST(std::to_integer<int>(b[off_dns4_count]) == 2);
    BOOST_TEST(std::to_integer<int>(b[off_dns4_count + 1]) == 1);
    BOOST_TEST(le_at(b, off_version_field, 8) == 7U);
    BOOST_TEST(std::to_integer<int>(b[off_gateway_mac + 5]) == 1);
    BOOST_TEST(std::to_integer<int>(b[off_domain_size]) == 12);
    BOOST_TEST(le_at(b, off_lease, 4) == 3600U);
    BOOST_TEST(le_at(b, off_subnet_count, 2) == 3U);
    BOOST_TEST(le_at(b, off_table_count, 2) == 2U);
    BOOST_TEST(le_at(b, off_route_count, 2) == 8U);
    BOOST_TEST(std::to_integer<int>(b[off_ipv6_block]) == 0x20);
    BOOST_TEST(std::to_integer<int>(b[off_ipv6_block + 4]) == 0x12);
    // Blocks: prefix, length, three reserved bytes; the primary first.
    BOOST_TEST(std::to_integer<int>(b[off_blocks]) == 10);
    BOOST_TEST(std::to_integer<int>(b[off_blocks + 4]) == 16);
    BOOST_TEST(std::to_integer<int>(b[off_blocks + 8]) == 100);
    BOOST_TEST(std::to_integer<int>(b[off_blocks + 12]) == 24);
    BOOST_TEST(std::to_integer<int>(b[full_dns + 3]) == 2);
    // Subnet 0x12: table 2, no IPv6, 10.0.2.0/24.
    const std::size_t s1 = full_subnets + proto::vpc_subnet_size;
    BOOST_TEST(le_at(b, s1, 8) == 0x12U);
    BOOST_TEST(le_at(b, s1 + 8, 2) == 2U);
    BOOST_TEST(std::to_integer<int>(b[s1 + 0x0A]) == 0);
    BOOST_TEST(std::to_integer<int>(b[s1 + 0x0B]) == 24);
    BOOST_TEST(std::to_integer<int>(b[s1 + 0x0E]) == 2);
    BOOST_TEST(std::to_integer<int>(b[full_subnets + 0x0A]) == 1);  // subnet 0x11 has IPv6
    BOOST_TEST(std::to_integer<int>(b[full_subnets + 0x10 + 7]) == 1);
    // Tables: number, main flag, route count.
    BOOST_TEST(le_at(b, full_tables, 2) == 1U);
    BOOST_TEST(std::to_integer<int>(b[full_tables + 2]) == 1);
    BOOST_TEST(le_at(b, full_tables + 4, 2) == 4U);
    BOOST_TEST(le_at(b, full_tables + 8, 2) == 2U);
    BOOST_TEST(std::to_integer<int>(b[full_tables + 10]) == 0);
    // Routes, table 1 first: local 10.0.0.0/16, then the appliance route.
    BOOST_TEST(le_at(b, full_routes, 8) == 0U);
    BOOST_TEST(std::to_integer<int>(b[full_routes + 8]) == 1);
    BOOST_TEST(std::to_integer<int>(b[full_routes + 9]) == 4);
    BOOST_TEST(std::to_integer<int>(b[full_routes + 10]) == 16);
    BOOST_TEST(le_at(b, full_routes + 32, 8) == 0x21U);
    BOOST_TEST(std::to_integer<int>(b[full_routes + 32 + 8]) == 2);
    BOOST_TEST(std::to_integer<int>(b[full_routes + 32 + 0x10 + 2]) == 2);
    // Table 2's default route is the fifth.
    BOOST_TEST(le_at(b, full_routes + (4 * 32), 8) == 0x22U);
    const std::size_t domain = full_routes + (8 * proto::vpc_route_size);
    BOOST_TEST(std::string_view(reinterpret_cast<const char*>(&b[domain]), 12) == "ec2.internal");
    BOOST_TEST(proto::vpc_config_signed_bytes(b).size() == b.size() - 64);
}

BOOST_AUTO_TEST_CASE(the_subnet_gateway_is_base_plus_one) {
    const auto c = full();
    BOOST_TEST((proto::vpc_subnet_gateway(c.subnets[0]) == v4(10, 0, 1, 1)));
    BOOST_TEST((proto::vpc_subnet_gateway(c.subnets[2]) == v4(100, 64, 0, 17)));
}

// The largest frame fits a link record; the sideband carries it in chunks.
BOOST_AUTO_TEST_CASE(the_largest_frame_fits_a_record) {
    static_assert(proto::max_vpc_config_size <= proto::max_record_payload);
    static_assert(proto::max_vpc_config_size == 139'581);
    proto::VpcConfigFrame c = minimal();
    c.ipv4_blocks = {{.prefix = v4(10, 0, 0, 0), .length = 16}};
    for (std::uint8_t i = 1; i < proto::max_vpc_ipv4_blocks; ++i) {
        c.ipv4_blocks.push_back({.prefix = v4(10, i, 0, 0), .length = 16});
    }
    c.ipv6_block = v6(0x12, 0x00, 0, 0);
    c.dns4.assign(proto::max_vpc_dns, v4(10, 0, 0, 2));
    c.dns6.assign(proto::max_vpc_dns, v6(0x12, 0x00, 0, 2));
    c.domain = std::string(63, 'a') + "." + std::string(63, 'b') + "." + std::string(63, 'c') +
               "." + std::string(61, 'd');
    BOOST_REQUIRE(c.domain.size() == proto::max_vpc_domain_size);
    c.subnets.clear();
    for (std::size_t i = 0; i < proto::max_vpc_subnets; ++i) {
        const auto block = static_cast<std::uint8_t>(i / 64);
        const auto quarter = static_cast<std::uint8_t>((i % 64) * 4);
        c.subnets.push_back({.subnet_id = i + 1,
                             .table = static_cast<std::uint16_t>(i),
                             .ipv4_prefix = v4(10, block, quarter, 0),
                             .ipv4_length = 22,
                             .ipv6_prefix = v6(0x12, 0x00, static_cast<std::uint8_t>(i), 0)});
    }
    // 200 tables of six local routes is 1,200; spread 2,896 NIC routes
    // over them to reach 4,096.
    std::vector<proto::VpcRoute> locals;
    for (const auto& b : c.ipv4_blocks) {
        locals.push_back(route4(RouteKind::local, b.prefix, b.length, 0));
    }
    locals.push_back(route6(RouteKind::local, *c.ipv6_block, 56, 0));
    c.tables.clear();
    std::size_t nic_routes = proto::max_vpc_routes - (proto::max_vpc_tables * locals.size());
    for (std::size_t t = 0; t < proto::max_vpc_tables; ++t) {
        proto::VpcRouteTable table{
            .table = static_cast<std::uint16_t>(t), .main = t == 0, .routes = {}};
        // NIC routes in 11.x.0.0/24 sort after the 10.x locals and before
        // the IPv6 one.
        table.routes.assign(locals.begin(), locals.end() - 1);
        const std::size_t here = std::min<std::size_t>(nic_routes, 15);
        for (std::size_t i = 0; i < here; ++i) {
            table.routes.push_back(
                route4(RouteKind::nic, v4(11, static_cast<std::uint8_t>(i), 0, 0), 24, t + 1));
        }
        nic_routes -= here;
        table.routes.push_back(locals.back());
        c.tables.push_back(std::move(table));
    }
    BOOST_REQUIRE(nic_routes == 0U);
    BOOST_REQUIRE(route_total(c) == proto::max_vpc_routes);
    BOOST_TEST(encoded(c).size() == proto::max_vpc_config_size);
    BOOST_TEST(proto::encode_record(proto::RecordType::vpc_config, encoded(c)).has_value());
    c.tables.back().routes.insert(c.tables.back().routes.end() - 1,
                                  route4(RouteKind::nic, v4(12, 0, 0, 0), 8, 1));
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

struct Case {
    const char* what;
    void (*change)(proto::VpcConfigFrame&);
    DecodeError want;
};

auto check_cases(std::span<const Case> cases) -> void {
    for (const auto& k : cases) {
        auto c = full();
        k.change(c);
        BOOST_TEST_CONTEXT(k.what) {
            BOOST_TEST((encode_error(c) == k.want));
        }
    }
}

BOOST_AUTO_TEST_CASE(per_vpc_rules) {
    const Case cases[] = {
        {"five DNS servers", [](auto& c) { c.dns4.assign(5, v4(10, 0, 0, 2)); },
         DecodeError::too_many_addresses},
        {"DNS 0.0.0.0", [](auto& c) { c.dns4[0] = v4(0, 0, 0, 0); },
         DecodeError::bad_guest_address},
        {"DNS multicast", [](auto& c) { c.dns4[0] = v4(224, 0, 0, 1); },
         DecodeError::bad_guest_address},
        {"DNS6 multicast", [](auto& c) { c.dns6[0][0] = std::byte{0xFF}; },
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
    check_cases(cases);
}

// Requirement 1.1: blocks /16 to /28, no host bits, not overlapping, the
// primary first and the secondaries ascending; the IPv6 block a /56 in
// 2000::/3 or fc00::/7.
BOOST_AUTO_TEST_CASE(block_rules) {
    const Case cases[] = {
        {"no blocks", [](auto& c) { c.ipv4_blocks.clear(); }, DecodeError::bad_vpc_config},
        {"six blocks",
         [](auto& c) {
             for (std::uint8_t i = 1; i <= 4; ++i) {
                 c.ipv4_blocks.push_back({.prefix = v4(172, i, 0, 0), .length = 16});
             }
         },
         DecodeError::bad_vpc_config},
        {"block /15", [](auto& c) { c.ipv4_blocks[0].length = 15; }, DecodeError::bad_vpc_config},
        {"block /29", [](auto& c) { c.ipv4_blocks[1].length = 29; }, DecodeError::bad_vpc_config},
        {"block host bits", [](auto& c) { c.ipv4_blocks[1].prefix = v4(100, 64, 0, 1); },
         DecodeError::bad_vpc_config},
        {"blocks overlap",
         [](auto& c) { c.ipv4_blocks[1] = {.prefix = v4(10, 0, 5, 0), .length = 24}; },
         DecodeError::bad_vpc_config},
        {"secondaries descending",
         [](auto& c) { c.ipv4_blocks.push_back({.prefix = v4(100, 63, 0, 0), .length = 24}); },
         DecodeError::not_ascending},
        {"ipv6 block not a /56", [](auto& c) { (*c.ipv6_block)[7] = std::byte{1}; },
         DecodeError::bad_vpc_config},
        {"ipv6 block link-local",
         [](auto& c) {
             c.ipv6_block = proto::Ipv6Address{};
             (*c.ipv6_block)[0] = std::byte{0xFE};
             (*c.ipv6_block)[1] = std::byte{0x80};
         },
         DecodeError::bad_vpc_config},
        {"ipv6 block multicast", [](auto& c) { (*c.ipv6_block)[0] = std::byte{0xFF}; },
         DecodeError::bad_vpc_config},
    };
    check_cases(cases);

    // A primary above its secondaries is fine: only the secondaries ascend.
    auto c = full();
    c.ipv4_blocks = {{.prefix = v4(100, 64, 0, 0), .length = 24},
                     {.prefix = v4(10, 0, 0, 0), .length = 16}};
    BOOST_TEST(proto::encode_vpc_config(c).has_value());

    // A unique local /56 is fine; so is a VPC without IPv6 (its subnets
    // and routes then carry none).
    c = full();
    for (auto* p : {&*c.ipv6_block, &*c.subnets[0].ipv6_prefix, &*c.subnets[2].ipv6_prefix}) {
        (*p)[0] = std::byte{0xFD};
    }
    for (auto& t : c.tables) {
        t.routes.back().prefix[0] = std::byte{0xFD};
    }
    BOOST_TEST(proto::encode_vpc_config(c).has_value());
    c = full();
    c.ipv6_block.reset();
    c.dns6.clear();
    for (auto& s : c.subnets) {
        s.ipv6_prefix.reset();
    }
    for (auto& t : c.tables) {
        t.routes.pop_back();
    }
    BOOST_TEST(proto::encode_vpc_config(c).has_value());
}

// Requirements 2.1 and 2.3: subnets inside a block, not overlapping,
// strictly ascending by ID, naming a table.
BOOST_AUTO_TEST_CASE(subnet_rules) {
    const Case cases[] = {
        {"no subnets", [](auto& c) { c.subnets.clear(); }, DecodeError::too_many_entries},
        {"subnet id 0", [](auto& c) { c.subnets[0].subnet_id = 0; }, DecodeError::bad_id},
        {"ids descending", [](auto& c) { std::swap(c.subnets[0], c.subnets[1]); },
         DecodeError::not_ascending},
        {"id twice", [](auto& c) { c.subnets[1].subnet_id = c.subnets[0].subnet_id; },
         DecodeError::not_ascending},
        {"subnet /15", [](auto& c) { c.subnets[0].ipv4_length = 15; }, DecodeError::bad_vpc_config},
        {"subnet /29", [](auto& c) { c.subnets[0].ipv4_length = 29; }, DecodeError::bad_vpc_config},
        {"subnet host bits", [](auto& c) { c.subnets[0].ipv4_prefix = v4(10, 0, 1, 1); },
         DecodeError::bad_vpc_config},
        {"subnet outside every block", [](auto& c) { c.subnets[1].ipv4_prefix = v4(10, 1, 2, 0); },
         DecodeError::bad_vpc_config},
        {"subnet wider than its block",
         [](auto& c) {
             c.subnets[2].ipv4_prefix = v4(100, 64, 0, 0);
             c.subnets[2].ipv4_length = 23;
         },
         DecodeError::bad_vpc_config},
        {"subnets overlap",
         [](auto& c) {
             c.subnets[1].ipv4_prefix = v4(10, 0, 0, 0);
             c.subnets[1].ipv4_length = 22;
         },
         DecodeError::bad_vpc_config},
        {"ipv6 subnets share a /64",
         [](auto& c) { c.subnets[2].ipv6_prefix = c.subnets[0].ipv6_prefix; },
         DecodeError::bad_vpc_config},
        {"ipv6 subnet not a /64", [](auto& c) { (*c.subnets[0].ipv6_prefix)[8] = std::byte{1}; },
         DecodeError::bad_vpc_config},
        {"ipv6 subnet outside the /56",
         [](auto& c) { (*c.subnets[0].ipv6_prefix)[6] = std::byte{1}; },
         DecodeError::bad_vpc_config},
        {"ipv6 subnet without a VPC block",
         [](auto& c) {
             c.ipv6_block.reset();
             for (auto& t : c.tables) {
                 t.routes.pop_back();
             }
         },
         DecodeError::bad_vpc_config},
        {"unlisted table", [](auto& c) { c.subnets[1].table = 3; }, DecodeError::bad_vpc_config},
    };
    check_cases(cases);
}

// Requirements 4.1 to 4.3: one main table, a local route per block in
// every table, NIC routes bounded and never on a block's own prefix.
BOOST_AUTO_TEST_CASE(table_and_route_rules) {
    const Case cases[] = {
        {"no tables", [](auto& c) { c.tables.clear(); }, DecodeError::too_many_entries},
        {"tables descending", [](auto& c) { std::swap(c.tables[0], c.tables[1]); },
         DecodeError::not_ascending},
        {"no main table", [](auto& c) { c.tables[0].main = false; }, DecodeError::bad_vpc_config},
        {"two main tables", [](auto& c) { c.tables[1].main = true; }, DecodeError::bad_vpc_config},
        {"local route missing",
         [](auto& c) { c.tables[1].routes.erase(c.tables[1].routes.begin() + 1); },
         DecodeError::bad_route},
        {"local route not a block", [](auto& c) { c.tables[0].routes[0].length = 17; },
         DecodeError::bad_route},
        {"local route with a target", [](auto& c) { c.tables[0].routes[0].target_nic = 5; },
         DecodeError::bad_route},
        {"NIC route on a block",
         [](auto& c) {
             c.tables[0].routes[0].kind = RouteKind::nic;
             c.tables[0].routes[0].target_nic = 5;
         },
         DecodeError::bad_route},
        {"NIC route to NIC 0", [](auto& c) { c.tables[0].routes[1].target_nic = 0; },
         DecodeError::bad_nic_id},
        {"NIC route to broadcast",
         [](auto& c) { c.tables[0].routes[1].target_nic = proto::vpc_route_nic_broadcast; },
         DecodeError::bad_nic_id},
        {"route past 32 bits", [](auto& c) { c.tables[0].routes[1].length = 33; },
         DecodeError::bad_route},
        {"route host bits", [](auto& c) { c.tables[0].routes[1].prefix[3] = std::byte{1}; },
         DecodeError::bad_route},
        {"bytes past an IPv4 prefix",
         [](auto& c) { c.tables[0].routes[1].prefix[4] = std::byte{1}; }, DecodeError::bad_route},
        {"route past 128 bits", [](auto& c) { c.tables[0].routes[3].length = 129; },
         DecodeError::bad_route},
        {"unknown family",
         [](auto& c) { c.tables[0].routes[1].family = static_cast<RouteFamily>(5); },
         DecodeError::unknown_value},
        {"unknown kind", [](auto& c) { c.tables[0].routes[1].kind = static_cast<RouteKind>(3); },
         DecodeError::unknown_value},
        {"routes descending",
         [](auto& c) { std::swap(c.tables[0].routes[0], c.tables[0].routes[1]); },
         DecodeError::not_ascending},
        {"route twice", [](auto& c) { c.tables[0].routes[2] = c.tables[0].routes[1]; },
         DecodeError::not_ascending},
    };
    check_cases(cases);

    // The same prefix at two lengths is two routes; a NIC route inside a
    // block but longer than its local route is the middlebox case.
    auto c = full();
    c.tables[0].routes.insert(c.tables[0].routes.begin() + 2,
                              route4(RouteKind::nic, v4(10, 0, 2, 0), 25, 0x23));
    BOOST_TEST(proto::encode_vpc_config(c).has_value());

    // At most max_vpc_nic_routes NIC routes per table.
    c = full();
    auto& routes = c.tables[1].routes;
    routes.erase(routes.begin());
    std::vector<proto::VpcRoute> nics;
    for (std::size_t i = 0; i < proto::max_vpc_nic_routes; ++i) {
        nics.push_back(route4(
            RouteKind::nic,
            v4(11, static_cast<std::uint8_t>(i >> 8U), static_cast<std::uint8_t>(i & 0xFFU), 0), 24,
            0x22));
    }
    routes.insert(routes.begin() + 1, nics.begin(), nics.end());
    BOOST_TEST(proto::encode_vpc_config(c).has_value());
    routes.insert(routes.begin() + 1, route4(RouteKind::nic, v4(10, 0, 9, 0), 24, 0x22));
    BOOST_TEST((encode_error(c) == DecodeError::too_many_entries));
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
    // Version 1 had one VPC-wide prefix and gateway.
    for (const int v : {1, 3}) {
        b = good;
        b[4] = std::byte(v);
        BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    }
    for (const std::size_t off :
         {off_reserved1, off_reserved2, off_reserved2 + 5, off_blocks + 5, off_blocks + 7,
          full_tables + 3, full_tables + 6, full_routes + 0x0B, full_routes + 0x0F}) {
        BOOST_TEST_CONTEXT("offset " << off) {
            b = good;
            b[off] = std::byte{1};
            BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
        }
    }
    for (const std::size_t off : {off_flags, full_subnets + 0x0A, full_tables + 2}) {
        b = good;
        b[off] = std::byte{0x03};  // an undefined flag
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    }
    // An IPv6 block or subnet prefix without its flag.
    b = good;
    b[off_flags] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_vpc_config));
    b = good;
    b[full_subnets + proto::vpc_subnet_size + 0x10] = std::byte{0x20};
    BOOST_TEST((decode_error(b) == DecodeError::bad_vpc_config));
    // Unknown route kinds and families, on the wire.
    b = good;
    b[full_routes + 8] = std::byte{3};
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    b = good;
    b[full_routes + 9] = std::byte{5};
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    // Counts outside their bounds are refused before any list is read.
    b = good;
    b[off_dns4_count] = std::byte{5};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_addresses));
    for (const std::size_t off : {off_subnet_count, off_table_count}) {
        b = good;
        b[off] = std::byte{0};
        BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
        b[off] = std::byte{201};
        BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    }
    b = good;
    b[off_route_count] = std::byte{0x01};
    b[off_route_count + 1] = std::byte{0x10};  // 4097
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    for (const int n : {0, 6}) {
        b = good;
        b[off_block_count] = std::byte(n);
        BOOST_TEST((decode_error(b) == DecodeError::bad_vpc_config));
    }
    b = good;
    b[off_domain_size] = std::byte{254};
    BOOST_TEST((decode_error(b) == DecodeError::bad_vpc_config));
    // Tables whose route counts disagree with the header, frame length
    // unchanged: one more for table 1, one less for table 2.
    b = good;
    b[full_tables + 4] = std::byte{5};
    BOOST_TEST((decode_error(b) == DecodeError::bad_vpc_config));
    b[full_tables + 8 + 4] = std::byte{3};
    BOOST_TEST((decode_error(b) != DecodeError::truncated));
    b = good;
    b[full_tables + 4] = std::byte{3};
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

    // Pointing the appliance route somewhere else after signing breaks it,
    // and so does changing the last byte of the domain.
    for (const std::size_t off : {full_routes + 32, frame.size() - 65}) {
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
