// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ Requirement 4.1-4.2 and design
// "SignatureVerifier": RFC 8032 vectors, key table rules, slot verification.

#define BOOST_TEST_MODULE signature_verifier_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <vector>

#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "hull/signature_verifier.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::hull::ControllerKey;
using ak::hull::KeyId;
using ak::hull::KeyTableError;
using ak::hull::SignatureVerifier;
using ak::hull::VerifyError;
using ak::test::unit_timeout_seconds;
using namespace ak::test;  // NOLINT(google-build-using-namespace): RFC vector names

namespace {

constexpr KeyId key_a = 1;
constexpr KeyId key_b = 2;
constexpr KeyId key_c = 3;
constexpr KeyId absent_key = 0x7777;
// Header key ID for sample slots; verify_slot() is told the key explicitly.
constexpr KeyId sample_key_id = key_a;
constexpr std::byte flip{0x01};
constexpr std::uint64_t sample_seq = 9;
constexpr std::uint8_t body_fill = 0x5C;
constexpr std::size_t sample_body_len = 16;
constexpr std::size_t last_signed_byte = mb::signature_offset - 1;

struct Vector {
    std::string_view secret;
    std::string_view pub;
    std::string_view message;
    std::string_view signature;
};

constexpr std::array rfc_vectors{
    Vector{rfc_test1_secret, rfc_test1_public, rfc_test1_message, rfc_test1_signature},
    Vector{rfc_test2_secret, rfc_test2_public, rfc_test2_message, rfc_test2_signature},
    Vector{rfc_test3_secret, rfc_test3_public, rfc_test3_message, rfc_test3_signature},
};

auto make_verifier(std::span<const ControllerKey> keys) -> SignatureVerifier {
    auto v = SignatureVerifier::create(keys);
    BOOST_REQUIRE(v.has_value());
    return std::move(*v);
}

auto sample_slot(const TestSigner& signer) -> mb::Slot {
    std::vector<std::byte> body(sample_body_len, std::byte{body_fill});
    return signer.signed_slot({.type = mb::Type::create_vm,
                               .seq = sample_seq,
                               .body_len = static_cast<std::uint16_t>(body.size()),
                               .key_id = sample_key_id},
                              body);
}

auto sig_span(const std::vector<std::byte>& s) -> ak::hull::Signature {
    return std::span<const std::byte>{s}.first<ak::hull::ed25519_signature_size>();
}

}  // namespace

BOOST_AUTO_TEST_CASE(verifies_rfc8032_vectors, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto& vec : rfc_vectors) {
        const std::array keys{controller_key(key_a, vec.pub)};
        const auto verifier = make_verifier(keys);
        const auto msg = from_hex(vec.message);
        const auto sig = from_hex(vec.signature);
        BOOST_TEST(verifier.verify(msg, sig_span(sig), key_a).has_value());
    }
}

BOOST_AUTO_TEST_CASE(signer_reproduces_rfc8032_signatures,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Guards the test signer itself, which the slot tests rely on.
    for (const auto& vec : rfc_vectors) {
        const TestSigner signer{vec.secret};
        const auto sig = signer.sign(from_hex(vec.message));
        const auto expected = from_hex(vec.signature);
        BOOST_TEST(std::ranges::equal(sig, expected));
    }
}

BOOST_AUTO_TEST_CASE(rejects_tampered_message_and_signature,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::array keys{controller_key(key_a, rfc_test3_public)};
    const auto verifier = make_verifier(keys);
    auto msg = from_hex(rfc_test3_message);
    auto sig = from_hex(rfc_test3_signature);

    auto bad_msg = msg;
    bad_msg.front() ^= flip;
    BOOST_TEST(
        (verifier.verify(bad_msg, sig_span(sig), key_a).error() == VerifyError::bad_signature));

    auto longer = msg;
    longer.push_back(std::byte{0});
    BOOST_TEST(
        (verifier.verify(longer, sig_span(sig), key_a).error() == VerifyError::bad_signature));

    for (std::size_t i = 0; i < sig.size(); ++i) {
        auto bad_sig = sig;
        bad_sig[i] ^= flip;
        BOOST_TEST(
            (verifier.verify(msg, sig_span(bad_sig), key_a).error() == VerifyError::bad_signature));
    }
}

BOOST_AUTO_TEST_CASE(rejects_unknown_and_wrong_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::array keys{controller_key(key_a, rfc_test1_public),
                          controller_key(key_b, rfc_test2_public)};
    const auto verifier = make_verifier(keys);
    const auto msg = from_hex(rfc_test2_message);
    const auto sig = from_hex(rfc_test2_signature);

    BOOST_TEST(verifier.verify(msg, sig_span(sig), key_b).has_value());
    BOOST_TEST((verifier.verify(msg, sig_span(sig), key_a).error() == VerifyError::bad_signature));
    BOOST_TEST(
        (verifier.verify(msg, sig_span(sig), absent_key).error() == VerifyError::unknown_key));
}

BOOST_AUTO_TEST_CASE(key_table_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((SignatureVerifier::create({}).error() == KeyTableError::empty));

    const std::array dup{controller_key(key_a, rfc_test1_public),
                         controller_key(key_a, rfc_test2_public)};
    BOOST_TEST((SignatureVerifier::create(dup).error() == KeyTableError::duplicate_key_id));

    std::vector<ControllerKey> many;
    for (std::size_t i = 0; i <= ak::hull::max_controller_keys; ++i) {
        many.push_back(controller_key(static_cast<KeyId>(i), rfc_test1_public));
    }
    BOOST_TEST((SignatureVerifier::create(many).error() == KeyTableError::too_many_keys));
    many.pop_back();
    BOOST_TEST(SignatureVerifier::create(many).has_value());
}

BOOST_AUTO_TEST_CASE(rotation_accepts_every_compiled_in_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::array keys{controller_key(key_a, rfc_test1_public),
                          controller_key(key_b, rfc_test2_public),
                          controller_key(key_c, rfc_test3_public)};
    const auto verifier = make_verifier(keys);
    BOOST_TEST(verifier.key_count() == keys.size());

    const TestSigner old_key{rfc_test1_secret};
    const TestSigner new_key{rfc_test3_secret};
    BOOST_TEST(verifier.verify_slot(sample_slot(old_key), key_a).has_value());
    BOOST_TEST(verifier.verify_slot(sample_slot(new_key), key_c).has_value());
    BOOST_TEST(
        (verifier.verify_slot(sample_slot(new_key), key_a).error() == VerifyError::bad_signature));
}

BOOST_AUTO_TEST_CASE(slot_signature_covers_header_and_body,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::array keys{controller_key(key_a, rfc_test1_public)};
    const auto verifier = make_verifier(keys);
    const TestSigner signer{rfc_test1_secret};
    const auto slot = sample_slot(signer);
    BOOST_REQUIRE(verifier.verify_slot(slot, key_a).has_value());

    // Every signed byte matters, including the zero padding past body_len.
    for (const std::size_t i :
         {std::size_t{0}, mb::header_size - 1, mb::header_size, mb::header_size + sample_body_len,
          last_signed_byte, mb::signature_offset, mb::slot_size - 1}) {
        auto bad = slot;
        bad[i] ^= flip;
        BOOST_TEST((verifier.verify_slot(bad, key_a).error() == VerifyError::bad_signature),
                   "byte " << i);
    }
}
