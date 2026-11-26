// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/vpc-subnets-routing/ design "Metadata": EC2 resource IDs
// rendered from, and parsed back to, the 64-bit IDs antikythera carries.

#define BOOST_TEST_MODULE proto_ec2_id_test
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <optional>

#include "proto/ec2_id.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;

BOOST_AUTO_TEST_CASE(ids_render_in_ec2s_shape, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(proto::ec2_id("subnet-", 0x5B01) == "subnet-00000000000005b01");
    BOOST_TEST(proto::ec2_id("vpc-", 0) == "vpc-00000000000000000");
    BOOST_TEST(proto::ec2_id("eni-", std::numeric_limits<std::uint64_t>::max()) ==
               "eni-0ffffffffffffffff");
    BOOST_TEST(proto::ec2_id("subnet-", 1).size() == 7U + proto::ec2_id_digits);
}

BOOST_AUTO_TEST_CASE(ids_parse_back, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::uint64_t id :
         {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{0x5B01},
          std::uint64_t{0x0123'4567'89AB'CDEF}, std::numeric_limits<std::uint64_t>::max()}) {
        BOOST_TEST(proto::parse_ec2_id("subnet-", proto::ec2_id("subnet-", id)).value_or(~id) ==
                   id);
    }
}

BOOST_AUTO_TEST_CASE(other_shapes_do_not_parse, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const char* bad : {"subnet-0000000000005b01",    // 16 digits
                            "subnet-000000000000005b01",  // 18 digits
                            "subnet-10000000000005b01",   // leading digit not 0
                            "subnet-00000000000005B01",   // upper case
                            "subnet-0000000000000xb01",   // not hex
                            "vpc-00000000000005b01xx",    // other prefix
                            ""}) {
        BOOST_TEST(!proto::parse_ec2_id("subnet-", bad).has_value(), bad);
    }
}
