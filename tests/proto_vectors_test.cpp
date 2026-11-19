// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirements 1.1 and 5.2: the signing
// test vectors in src/proto/test_vectors.hpp. For each vector this checks
// that encoding the listed fields and signing with the listed RFC 8032 key
// reproduces the bytes exactly, that the frame decodes back to the fields,
// and that the signature verifies under hull's verifier.

#define BOOST_TEST_MODULE proto_vectors_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/envelope.hpp"
#include "proto/map_update.hpp"
#include "proto/test_vectors.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
namespace vec = ak::proto::vectors;
using ak::test::from_hex;
using ak::test::TestSigner;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::uint8_t local_unicast = 0x02;
constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::uint64_t map2_nic_a = 0x10;
constexpr std::uint64_t map2_nic_b = 0x11;
constexpr std::size_t last = 15;

auto verifier() -> ak::hull::SignatureVerifier {
    const std::array keys{ak::test::controller_key(vec::envelope1_key_id, vec::key1_public),
                          ak::test::controller_key(vec::map0_key_id, vec::key2_public)};
    auto v = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(v.has_value());
    return std::move(*v);
}

auto map2_entry(std::uint64_t nic, std::uint8_t vtep_last) -> proto::MapEntry {
    proto::MapEntry e{.nic_id = nic};
    e.mac[0] = std::byte{local_unicast};
    e.mac[proto::mac_size - 1] = std::byte{static_cast<std::uint8_t>(nic)};
    e.owner_vtep[0] = std::byte{ula_prefix};
    e.owner_vtep[last] = std::byte{vtep_last};
    return e;
}

auto signed_map_update(const proto::MapUpdate& m, const TestSigner& signer)
    -> std::vector<std::byte> {
    auto frame = proto::encode_map_update(m);
    BOOST_REQUIRE(frame.has_value());
    const auto sig = signer.sign(proto::map_update_signed_bytes(*frame));
    proto::set_map_update_signature(*frame, sig);
    return *frame;
}

auto check_map_vector(std::string_view frame_hex, std::string_view sig_hex,
                      const proto::MapUpdate& fields, const TestSigner& signer) -> void {
    const auto want = from_hex(frame_hex);
    BOOST_TEST(signed_map_update(fields, signer) == want);
    BOOST_TEST(
        std::ranges::equal(std::span{want}.last(proto::ed25519_signature_size), from_hex(sig_hex)));

    auto m = proto::decode_map_update(want);
    BOOST_REQUIRE(m.has_value());
    auto expect = fields;
    std::ranges::copy(from_hex(sig_hex), expect.signature.begin());
    BOOST_TEST((*m == expect));

    const auto v = verifier();
    const auto sig = std::span<const std::byte, proto::ed25519_signature_size>{m->signature};
    BOOST_TEST(v.verify(proto::map_update_signed_bytes(want), sig, m->key_id).has_value());
    // The key ID is signed: the same bytes under the other key fail.
    const proto::KeyId other = m->key_id == vec::map2_key_id ? vec::map0_key_id : vec::map2_key_id;
    BOOST_TEST(!v.verify(proto::map_update_signed_bytes(want), sig, other).has_value());
}

}  // namespace

BOOST_AUTO_TEST_SUITE(vectors, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(vector_keys_are_rfc8032_test_keys) {
    BOOST_TEST(vec::key1_secret == ak::test::rfc_test1_secret);
    BOOST_TEST(vec::key1_public == ak::test::rfc_test1_public);
    BOOST_TEST(vec::key2_secret == ak::test::rfc_test2_secret);
    BOOST_TEST(vec::key2_public == ak::test::rfc_test2_public);
}

BOOST_AUTO_TEST_CASE(envelope1_reproduces_and_hull_accepts_it) {
    const TestSigner signer{vec::key1_secret};
    const auto body = mb::encode_body(mb::CreateVm{.vm_id = vec::envelope1_vm_id,
                                                   .vcpus = vec::envelope1_vcpus,
                                                   .memory_mib = vec::envelope1_memory_mib,
                                                   .boot_mode = mb::BootMode::volume});
    const mb::Header h{.type = mb::Type::create_vm,
                       .seq = vec::envelope1_seq,
                       .body_len = static_cast<std::uint16_t>(body.size()),
                       .key_id = vec::envelope1_key_id};
    const auto slot = signer.signed_slot(h, body);
    auto bytes = proto::encode_envelope(
        {.server_id = vec::envelope1_server_id, .key_id = vec::envelope1_key_id, .slot = slot});
    BOOST_REQUIRE(bytes.has_value());

    const auto want = from_hex(vec::envelope1);
    BOOST_TEST(std::ranges::equal(*bytes, want));
    BOOST_TEST(std::ranges::equal(std::span{slot}.subspan(mb::signature_offset),
                                  from_hex(vec::envelope1_signature)));

    auto env = proto::decode_envelope(want);
    BOOST_REQUIRE(env.has_value());
    BOOST_TEST(env->server_id == vec::envelope1_server_id);
    BOOST_TEST(env->key_id == vec::envelope1_key_id);
    BOOST_TEST(proto::slot_seq(env->slot) == vec::envelope1_seq);

    // What helm relays is what hull checks: a strict slot decode, then the
    // signature under the key the signed slot header names.
    auto msg = mb::decode(env->slot);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.key_id == vec::envelope1_key_id);
    BOOST_TEST(verifier().verify_slot(env->slot, msg->header.key_id).has_value());
}

BOOST_AUTO_TEST_CASE(map2_reproduces_and_verifies) {
    check_map_vector(vec::map2, vec::map2_signature,
                     {.server_id = vec::map2_server_id,
                      .key_id = vec::map2_key_id,
                      .vni = vec::map2_vni,
                      .map_version = vec::map2_map_version,
                      .entries = {map2_entry(map2_nic_a, 1), map2_entry(map2_nic_b, 2)},
                      .signature = {}},
                     TestSigner{vec::key1_secret});
}

BOOST_AUTO_TEST_CASE(map0_reproduces_and_verifies) {
    check_map_vector(vec::map0, vec::map0_signature,
                     {.server_id = vec::map0_server_id,
                      .key_id = vec::map0_key_id,
                      .vni = vec::map0_vni,
                      .map_version = vec::map0_map_version,
                      .entries = {},
                      .signature = {}},
                     TestSigner{vec::key2_secret});
}

BOOST_AUTO_TEST_SUITE_END()
