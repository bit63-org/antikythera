// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirement 13.4 (task 21.3): the network
// role keeps one verified InstanceMetadata record per NIC.

#define BOOST_TEST_MODULE metadata_store_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <string>
#include <vector>

#include "ed25519_test_support.hpp"
#include "hull/signature_verifier.hpp"
#include "oar/net/metadata_store.hpp"
#include "proto/instance_metadata.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using net::MetadataResult;

namespace {

constexpr std::uint64_t server = 7;
constexpr std::uint16_t key_id = 1;

auto verifier() -> net::MetadataVerifier {
    const std::array keys{ak::test::controller_key(key_id, ak::test::rfc_test1_public)};
    auto v = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(v.has_value());
    auto shared = std::make_shared<ak::hull::SignatureVerifier>(std::move(*v));
    return [shared](std::span<const std::byte> msg, std::span<const std::byte, 64> sig,
                    std::uint16_t id) { return shared->verify(msg, sig, id).has_value(); };
}

auto record(std::uint64_t nic, std::uint64_t version, std::uint64_t to = server)
    -> std::vector<std::byte> {
    proto::InstanceMetadata m{};
    m.server_id = to;
    m.key_id = key_id;
    m.nic_id = nic;
    m.metadata_version = version;
    m.vni = 100;
    m.instance_id = "i-0abc";
    m.image_id = "ami-0abc";
    m.instance_type = "m5.large";
    m.account_id = "123456789012";
    m.local_hostname = "ip-10-0-0-17.ec2.internal";
    m.availability_zone = "harbor-1a";
    m.region = "harbor-1";
    m.interface_id = "eni-0abc";
    m.vpc_id = "vpc-0abc";
    m.launch_index = static_cast<std::uint32_t>(version);  // tells versions apart
    auto bytes = proto::encode_instance_metadata(m);
    BOOST_REQUIRE(bytes.has_value());
    static const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    proto::set_instance_metadata_signature(
        *bytes, signer.sign(proto::instance_metadata_signed_bytes(*bytes)));
    return *bytes;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(metadata_store, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(keeps_the_newest_verified_record_per_nic) {
    net::MetadataStore store{server, 4, verifier()};
    BOOST_TEST(store.find(0x11) == nullptr);

    BOOST_TEST((store.put(record(0x11, 2)) == MetadataResult::kept));
    const auto* r = store.find(0x11);
    BOOST_REQUIRE(r != nullptr);
    BOOST_TEST(r->metadata_version == 2U);
    BOOST_TEST(r->instance_id == "i-0abc");

    // helm replays after a reopen: ok, unchanged.
    BOOST_TEST((store.put(record(0x11, 2)) == MetadataResult::redelivered));
    BOOST_TEST((store.put(record(0x11, 1)) == MetadataResult::stale));
    BOOST_TEST(store.find(0x11)->launch_index == 2U);
    BOOST_TEST((store.put(record(0x11, 5)) == MetadataResult::kept));
    BOOST_TEST(store.find(0x11)->launch_index == 5U);
    BOOST_TEST(store.size() == 1U);
    BOOST_TEST(net::accepted(MetadataResult::redelivered));
    BOOST_TEST(!net::accepted(MetadataResult::stale));

    // Clean drops it; a later attach starts from whatever comes next.
    BOOST_TEST(store.drop(0x11));
    BOOST_TEST(!store.drop(0x11));
    BOOST_TEST(store.find(0x11) == nullptr);
    BOOST_TEST((store.put(record(0x11, 1)) == MetadataResult::kept));
    BOOST_TEST(store.counters().kept == 3U);
    BOOST_TEST(store.counters().dropped == 1U);
}

BOOST_AUTO_TEST_CASE(refuses_what_it_cannot_trust) {
    net::MetadataStore store{server, 4, verifier()};
    auto good = record(0x11, 1);
    BOOST_TEST((store.put(std::span{good}.first(good.size() - 1)) == MetadataResult::undecodable));
    BOOST_TEST((store.put(record(0x11, 1, server + 1)) == MetadataResult::wrong_server));
    auto tampered = good;
    tampered[0x25] = std::byte{1};  // http_tokens: required -> stays valid, signature breaks
    BOOST_TEST((store.put(tampered) == MetadataResult::bad_signature));
    BOOST_TEST(store.size() == 0U);
    const auto& c = store.counters();
    BOOST_TEST(c.undecodable == 1U);
    BOOST_TEST(c.wrong_server == 1U);
    BOOST_TEST(c.bad_signature == 1U);

    // No verifier trusts nothing.
    net::MetadataStore blind{server, 4, {}};
    BOOST_TEST((blind.put(good) == MetadataResult::bad_signature));
}

BOOST_AUTO_TEST_CASE(holds_at_most_capacity_records) {
    net::MetadataStore store{server, 2, verifier()};
    BOOST_TEST((store.put(record(1, 1)) == MetadataResult::kept));
    BOOST_TEST((store.put(record(2, 1)) == MetadataResult::kept));
    BOOST_TEST((store.put(record(3, 1)) == MetadataResult::full));
    // A kept NIC can still be updated, and a dropped one frees a place.
    BOOST_TEST((store.put(record(2, 2)) == MetadataResult::kept));
    BOOST_TEST(store.drop(1));
    BOOST_TEST((store.put(record(3, 1)) == MetadataResult::kept));
    BOOST_TEST(store.counters().full == 1U);
    BOOST_TEST(std::string_view{net::to_string(MetadataResult::full)} == "full");
}

// cold-start Requirement 5.4: a NIC's instance secrets, replaced whole,
// dropped with the NIC, within the same capacity.
BOOST_AUTO_TEST_CASE(keeps_instance_secrets_per_nic) {
    net::MetadataStore store{server, 2, verifier()};
    BOOST_TEST(store.secrets(1) == nullptr);
    const auto one = [](std::string name, std::byte b) {
        std::vector<net::InstanceSecret> v;
        v.push_back({.name = std::move(name), .value = {b}});
        return v;
    };
    BOOST_TEST(store.put_secrets(1, one("a", std::byte{1})));
    BOOST_TEST(store.put_secrets(2, one("b", std::byte{2})));
    BOOST_TEST(!store.put_secrets(3, one("c", std::byte{3})));  // full
    BOOST_TEST(store.secrets(3) == nullptr);
    BOOST_TEST(store.put_secrets(1, one("z", std::byte{9})));  // replaced whole
    BOOST_REQUIRE(store.secrets(1) != nullptr);
    BOOST_REQUIRE(store.secrets(1)->size() == 1U);
    BOOST_TEST(store.secrets(1)->front().name == "z");
    BOOST_TEST(store.put_secrets(2, {}));  // removed
    BOOST_TEST(store.secrets(2) == nullptr);
    BOOST_TEST(store.put_secrets(3, one("c", std::byte{3})));  // a place again
    // Cleaning the NIC drops its secrets even with no record.
    BOOST_TEST(!store.drop(3));
    BOOST_TEST(store.secrets(3) == nullptr);
    BOOST_TEST((store.put(record(1, 1)) == MetadataResult::kept));
    BOOST_TEST(store.drop(1));
    BOOST_TEST(store.secrets(1) == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
