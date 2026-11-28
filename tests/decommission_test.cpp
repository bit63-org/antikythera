// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 5.5: the decommission
// record helm keeps in its sealed store to resume after a power loss.

#define BOOST_TEST_MODULE decommission_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string_view>
#include <vector>

#include "helm/decommission.hpp"
#include "proto/host_lifecycle.hpp"

namespace {

namespace helm = ak::helm;
namespace proto = ak::proto;
using helm::DecommissionStateError;

auto frame() -> std::vector<std::byte> {
    proto::Decommission d{.key_id = 1, .server_id = 7, .seq = 9, .signature = {}};
    d.signature.fill(std::byte{0x5A});
    return proto::encode_decommission(d).value();
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_state_round_trips_with_its_frame) {
    for (const auto phase : {helm::DecommissionPhase::keys, helm::DecommissionPhase::media,
                             helm::DecommissionPhase::identity}) {
        const helm::DecommissionState s{.phase = phase, .frame = frame()};
        const auto bytes = helm::encode_decommission_state(s);
        BOOST_REQUIRE(bytes.has_value());
        BOOST_TEST(bytes->size() == helm::decommission_state_size);
        BOOST_TEST((helm::decode_decommission_state(*bytes).value() == s));
    }
    BOOST_TEST(std::string_view{helm::to_string(helm::DecommissionPhase::media)} == "media");
}

BOOST_AUTO_TEST_CASE(a_bad_state_is_refused) {
    BOOST_TEST((helm::encode_decommission_state(
                    {.phase = helm::DecommissionPhase::keys, .frame = {std::byte{1}}})
                    .error() == DecommissionStateError::wrong_size));
    BOOST_TEST((helm::encode_decommission_state(
                    {.phase = static_cast<helm::DecommissionPhase>(4), .frame = frame()})
                    .error() == DecommissionStateError::bad_phase));

    const auto good =
        helm::encode_decommission_state({.phase = helm::DecommissionPhase::keys, .frame = frame()})
            .value();
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((helm::decode_decommission_state(b).error() == DecommissionStateError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((helm::decode_decommission_state(b).error() == DecommissionStateError::bad_version));
    b = good;
    b[6] = std::byte{0};
    BOOST_TEST((helm::decode_decommission_state(b).error() == DecommissionStateError::bad_phase));
    b = good;
    b[7] = std::byte{1};
    BOOST_TEST(
        (helm::decode_decommission_state(b).error() == DecommissionStateError::reserved_not_zero));
    b = good;
    b.pop_back();
    BOOST_TEST((helm::decode_decommission_state(b).error() == DecommissionStateError::wrong_size));
}
