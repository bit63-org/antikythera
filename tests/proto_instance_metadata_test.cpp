// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 11 (task 16): the signed
// InstanceMetadata frame, its layout, its rules both ways, and signing.

#define BOOST_TEST_MODULE proto_instance_metadata_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ed25519_test_support.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/instance_metadata.hpp"
#include "proto/link.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr proto::KeyId sample_key = 1;
constexpr std::size_t off_endpoint = 0x24;
constexpr std::size_t off_tokens = 0x25;
constexpr std::size_t off_hop = 0x26;
constexpr std::size_t off_user_data_size = 0x2C;
constexpr std::size_t off_reserved = 0x2E;
constexpr std::size_t off_strings = 0x38;

auto sample() -> proto::InstanceMetadata {
    proto::InstanceMetadata m{};
    m.server_id = sample_server;
    m.key_id = sample_key;
    m.nic_id = 0x11;
    m.metadata_version = 3;
    m.vni = 0x00AB'CDEF;
    m.http_tokens = proto::MetadataTokens::required;
    m.put_hop_limit = 2;
    m.device_index = 1;
    m.launch_index = 7;
    m.pending_time = 1'700'000'000;
    m.instance_id = "i-0123456789abcdef0";
    m.image_id = "ami-0abc";
    m.instance_type = "m5.large";
    m.account_id = "123456789012";
    m.local_hostname = "ip-10-0-0-17.ec2.internal";
    m.availability_zone = "harbor-1a";
    m.region = "harbor-1";
    m.interface_id = "eni-0abc";
    m.vpc_id = "vpc-0abc";
    const std::string_view script = "#!/bin/sh\necho hi\n";
    for (const char c : script) {
        m.user_data.push_back(static_cast<std::byte>(c));
    }
    return m;
}

auto encoded(const proto::InstanceMetadata& m) -> std::vector<std::byte> {
    auto b = proto::encode_instance_metadata(m);
    BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : proto::to_string(b.error())));
    return *b;
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto r = proto::decode_instance_metadata(b);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto encode_error(const proto::InstanceMetadata& m) -> DecodeError {
    auto r = proto::encode_instance_metadata(m);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(instance_metadata, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(layout) {
    static_assert(proto::min_instance_metadata_size == 0x38 + 18 + 64);
    static_assert(proto::max_instance_metadata_size == 18'808);
    static_assert(proto::max_instance_metadata_size <= proto::max_record_payload);
    const auto m = sample();
    const auto b = encoded(m);
    const std::size_t strings = 19 + 8 + 8 + 12 + 25 + 9 + 8 + 8 + 8;
    BOOST_REQUIRE_EQUAL(b.size(), proto::instance_metadata_size(strings, m.user_data.size()));
    const auto header =
        ak::test::bytes_of('A', 'K', 'I', 'M', 0x01, 0x00, 0x01, 0x00,      // magic, version, key
                           0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,  // server
                           0x11, 0, 0, 0, 0, 0, 0, 0,                       // NIC
                           0x03, 0, 0, 0, 0, 0, 0, 0,                       // version
                           0xEF, 0xCD, 0xAB, 0x00, 0x01, 0x01, 0x02, 0x01,  // VNI, options, device
                           0x07, 0, 0, 0, 0x12, 0x00, 0x00, 0x00,  // launch, user data, rsvd
                           0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00);  // pending time
    BOOST_TEST(
        std::ranges::equal(std::span{b}.first(proto::instance_metadata_header_size), header));
    // The first string, length-prefixed; user data then the signature last.
    BOOST_TEST(std::to_integer<int>(b[off_strings]) == 19);
    BOOST_TEST(std::to_integer<char>(b[off_strings + 1]) == 'i');
    BOOST_TEST(std::to_integer<char>(b[b.size() - 64 - 1]) == '\n');
}

BOOST_AUTO_TEST_CASE(round_trips) {
    auto m = sample();
    m.signature[0] = std::byte{0x5A};
    m.signature[63] = std::byte{0xA5};
    const auto b = encoded(m);
    const auto back = proto::decode_instance_metadata(b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == m));
    BOOST_TEST((encoded(*back) == b));
    // EC2's defaults and no user data.
    auto plain = sample();
    plain.http_endpoint = proto::MetadataEndpoint::enabled;
    plain.http_tokens = proto::MetadataTokens::optional;
    plain.put_hop_limit = 1;
    plain.user_data.clear();
    BOOST_TEST((proto::decode_instance_metadata(encoded(plain)).value() == plain));
}

BOOST_AUTO_TEST_CASE(largest_frame_round_trips) {
    auto m = sample();
    const std::string fill(proto::max_metadata_string_size - 4, 'x');
    m.instance_id = "i-x" + std::string(proto::max_metadata_string_size - 3, 'x');
    m.image_id = "ami-" + std::string(proto::max_metadata_string_size - 4, 'x');
    m.instance_type = std::string(proto::max_metadata_string_size, 't');
    m.account_id = std::string(proto::max_metadata_string_size, '1');
    // 63 + 1 + 63 + 1 + 63 + 1 + 63 = 255, every label at its limit.
    m.local_hostname = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                       std::string(63, 'c') + "." + std::string(63, 'd');
    m.availability_zone = std::string(proto::max_metadata_string_size, 'z');
    m.region = std::string(proto::max_metadata_string_size, 'r');
    m.interface_id = "eni-" + fill;
    m.vpc_id = "vpc-" + fill;
    m.user_data.assign(proto::max_user_data_size, std::byte{0xFF});
    // local_hostname is the one string an RFC 1123 name limits to 253.
    BOOST_TEST((encode_error(m) == DecodeError::bad_metadata));
    m.local_hostname.resize(253);
    const auto b = encoded(m);
    BOOST_TEST(b.size() == proto::max_instance_metadata_size - 2);
    BOOST_TEST((proto::decode_instance_metadata(b).value() == m));
}

BOOST_AUTO_TEST_CASE(rules_both_ways) {
    auto m = sample();
    m.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(m) == DecodeError::bad_key_id));
    m = sample();
    m.server_id = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_server_id));
    m = sample();
    m.nic_id = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_nic_id));
    m = sample();
    m.metadata_version = 0;
    BOOST_TEST((encode_error(m) == DecodeError::bad_metadata_version));
    for (const std::uint32_t vni : {0U, proto::max_vni + 1}) {
        m = sample();
        m.vni = vni;
        BOOST_TEST((encode_error(m) == DecodeError::bad_vni));
    }
    m = sample();
    m.http_endpoint = static_cast<proto::MetadataEndpoint>(2);
    BOOST_TEST((encode_error(m) == DecodeError::unknown_value));
    m = sample();
    m.http_tokens = static_cast<proto::MetadataTokens>(2);
    BOOST_TEST((encode_error(m) == DecodeError::unknown_value));
    for (const std::uint8_t hop : {std::uint8_t{0}, std::uint8_t{65}}) {
        m = sample();
        m.put_hop_limit = hop;
        BOOST_TEST((encode_error(m) == DecodeError::bad_metadata));
    }
    m = sample();
    m.put_hop_limit = 64;
    BOOST_TEST(proto::encode_instance_metadata(m).has_value());
    m = sample();
    m.user_data.resize(proto::max_user_data_size + 1);
    BOOST_TEST((encode_error(m) == DecodeError::bad_metadata));

    // Strings: present, printable, no spaces, short enough; IDs keep EC2's
    // prefixes; the host name is a host name.
    const auto bad_string = [](void (*change)(proto::InstanceMetadata&)) {
        auto x = sample();
        change(x);
        BOOST_TEST((encode_error(x) == DecodeError::bad_metadata));
    };
    bad_string([](proto::InstanceMetadata& x) { x.region.clear(); });
    bad_string([](proto::InstanceMetadata& x) { x.instance_type = "m5 large"; });
    bad_string([](proto::InstanceMetadata& x) { x.account_id = "12\n34"; });
    bad_string([](proto::InstanceMetadata& x) { x.availability_zone = "zone\x7F"; });
    bad_string([](proto::InstanceMetadata& x) { x.instance_type = std::string(256, 't'); });
    bad_string([](proto::InstanceMetadata& x) { x.instance_id = "0123"; });
    bad_string([](proto::InstanceMetadata& x) { x.instance_id = "i-"; });
    bad_string([](proto::InstanceMetadata& x) { x.image_id = "img-1"; });
    bad_string([](proto::InstanceMetadata& x) { x.interface_id = "nic-1"; });
    bad_string([](proto::InstanceMetadata& x) { x.vpc_id = "vpc1"; });
    bad_string([](proto::InstanceMetadata& x) { x.local_hostname = "ip_10_0_0_17"; });
    bad_string([](proto::InstanceMetadata& x) { x.local_hostname = "-host"; });
    bad_string([](proto::InstanceMetadata& x) { x.local_hostname = "a..b"; });
}

BOOST_AUTO_TEST_CASE(strict_decode) {
    const auto good = encoded(sample());
    auto b = good;
    b[0] = std::byte{'X'};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    b = good;
    b[off_reserved + 1] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_endpoint] = std::byte{3};
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    b = good;
    b[off_tokens] = std::byte{3};
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    b = good;
    b[off_hop] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_metadata));
    b = good;
    b[off_user_data_size] = std::byte{0x01};  // 16385 bytes
    b[off_user_data_size + 1] = std::byte{0x40};
    BOOST_TEST((decode_error(b) == DecodeError::bad_metadata));
    b = good;
    b[off_strings + 2] = std::byte{' '};  // "i ..."
    BOOST_TEST((decode_error(b) == DecodeError::bad_metadata));
    // Every truncation, and a byte too many.
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
}

// Signed like the controller signs it, verified like oar-net will verify it.
BOOST_AUTO_TEST_CASE(signature_covers_the_record) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(sample_key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());

    auto frame = encoded(sample());
    proto::set_instance_metadata_signature(
        frame, signer.sign(proto::instance_metadata_signed_bytes(frame)));
    const auto decoded = proto::decode_instance_metadata(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(verifier
                   ->verify(proto::instance_metadata_signed_bytes(frame), decoded->signature,
                            decoded->key_id)
                   .has_value());
    // Turning tokens optional after signing breaks it.
    auto tampered = frame;
    tampered[off_tokens] = std::byte{0};
    const auto t = proto::decode_instance_metadata(tampered);
    BOOST_REQUIRE(t.has_value());
    BOOST_TEST(
        !verifier->verify(proto::instance_metadata_signed_bytes(tampered), t->signature, t->key_id)
             .has_value());
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_metadata_version, DecodeError::bad_metadata}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
